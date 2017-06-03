// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
package bft

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/params"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkId uint64

	txpool      txPool
	blockchain  *core.BlockChain
	chaindb     ethdb.Database
	chainconfig *params.ChainConfig

	peers *peerSet

	SubProtocols []p2p.Protocol

	eventMux *event.TypeMux
	txSub    *event.TypeMuxSubscription

	// bft parameters
	bftdb              ethdb.Database // bft database
	validators         []common.Address
	consensusManager   *ConsensusManager
	consensusContract  *ConsensusContract
	privateKeyHex      string
	addTransactionLock sync.Mutex
	eventMu            sync.Mutex
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *params.ChainConfig, networkId uint64, mux *event.TypeMux, txpool *core.TxPool, blockchain *core.BlockChain, chaindb ethdb.Database, bftdb ethdb.Database, validators []common.Address, privateKeyHex string, etherbase common.Address, allowEmpty bool) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:   networkId,
		eventMux:    mux,
		txpool:      txpool,
		blockchain:  blockchain,
		chaindb:     chaindb,
		chainconfig: config,
		peers:       newPeerSet(),
	}

	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				log.Info("Get New Peer2")
				peer := manager.newPeer(int(version), p, rw)
				return manager.handle(peer)
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}

	manager.bftdb = bftdb
	manager.privateKeyHex = privateKeyHex
	manager.validators = validators
	manager.consensusContract = NewConsensusContract(mux, etherbase, txpool, validators)
	manager.consensusManager = NewConsensusManager(manager, blockchain, bftdb, manager.consensusContract, manager.privateKeyHex)
	manager.consensusManager.isAllowEmptyBlocks = allowEmpty

	return manager, nil
}

func (pm *ProtocolManager) Start() {
	go pm.announce()
	pm.consensusManager.Process()
}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

func (pm *ProtocolManager) handle(p *peer) error {
	for {
		if err := pm.handleBFTMsg(p); err != nil {
			p.Log().Debug("Ethereum message handling failed", "err", err)
			return err
		}
	}
}

func (pm *ProtocolManager) announce() {
	pm.eventMu.Lock()
	defer pm.eventMu.Unlock()
	for !pm.consensusManager.isReady() {
		log.Debug("consensusManager not ready ")
		pm.consensusManager.SendReady(false)
		time.Sleep(0.5 * 1000 * 1000 * 1000)
	}
	pm.consensusManager.SendReady(true)
	log.Debug("-----------------consensusManager Ready-------------------------")
}

func (pm *ProtocolManager) handleBFTMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	log.Info("Handle BFT Msg,", "msg", msg)
	if err != nil {
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")
	case msg.Code == GetBlockProposalsMsg:
		log.Debug("GetBlockProposalsMsg from:", p.id)
		var query []types.RequestProposalNumber
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		var found []*types.BlockProposal
		log.Debug("GetBlockProposalsMsg request: ", query)
		for i, height := range query {
			if i == MaxGetproposalsCount {
				log.Info("max get proposal count")
				break
			}
			if height.Number > pm.blockchain.CurrentBlock().NumberU64() {
				log.Info("Request future block")
				break
			}
			bp := pm.consensusManager.getBlockProposalByHeight(height.Number)
			found = append(found, bp)
		}
		if len(found) != 0 {
			log.Info("Send bp: ", found)
			p.SendBlockProposals(found)

			// broadcast highest lastQuorumLockset if it exist
			lastHeight := query[len(query)-1].Number
			if ls := pm.consensusManager.getHeightManager(lastHeight).lastQuorumPrecommitLockSet(); ls != nil {
				log.Info("Send Vote from", lastHeight)
				for _, v := range ls.PrecommitVotes {
					log.Info("vote: ", v)
					p.SendPrecommitVote(v)
					time.Sleep(1000 * 1000 * 500)
				}
			} else {
				log.Info("No Quorum on ", lastHeight)
			}
		}

	case msg.Code == BlockProposalsMsg:
		log.Debug("BlockProposalsMsg")
		var proposals []*types.BlockProposal
		if err := msg.Decode(&proposals); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		pm.consensusManager.synchronizer.receiveBlockproposals(proposals)

	case msg.Code == NewBlockProposalMsg:
		log.Debug("NewBlockProposalMsg")
		var bpData newBlockProposals
		if err := msg.Decode(&bpData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		bp := bpData.BlockProposal
		if p.broadcastFilter.Has(bp.Hash()) {
			log.Debug("NewBlockProposalMsg filtered")
			return nil
		}
		if isValid := pm.consensusManager.AddProposal(bp, p); isValid {
			pm.BroadcastBFTMsg(bp)
			pm.consensusManager.Process()
		} else {
			log.Debug("NewBlockProposalMsg failed")
			return nil
		}
	case msg.Code == VotingInstructionMsg:
		log.Debug("VotingInstructionMsg")
		var viData votingInstructionData
		if err := msg.Decode(&viData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		vi := viData.VotingInstruction
		if p.broadcastFilter.Has(vi.Hash()) {
			log.Debug("votinginstruction filtered")
			return nil
		}
		if isValid := pm.consensusManager.AddProposal(vi, p); isValid {
			pm.BroadcastBFTMsg(vi)
			pm.consensusManager.Process()
		}
	case msg.Code == VoteMsg:
		log.Debug("VoteMsg")
		var vData voteData
		if err := msg.Decode(&vData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		vote := vData.Vote

		if p.broadcastFilter.Has(vote.Hash()) {
			log.Debug("vote filtered")
			return nil
		}
		log.Debug("receive vote with HR ", vote.Height, vote.Round)
		if isValid := pm.consensusManager.AddVote(vote, p); isValid {
			pm.BroadcastBFTMsg(vote)
			pm.consensusManager.Process()
		}
	case msg.Code == PrecommitVoteMsg:
		log.Debug("PrecommitVoteMsg")
		var vData precommitVoteData
		if err := msg.Decode(&vData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		vote := vData.PrecommitVote

		if p.broadcastFilter.Has(vote.Hash()) {
			log.Debug("vote filtered")
			return nil
		}
		log.Debug("receive precommit vote with HR ", vote.Height, vote.Round)
		if isValid := pm.consensusManager.AddPrecommitVote(vote, p); isValid {
			pm.BroadcastBFTMsg(vote)
			pm.consensusManager.Process()
		}
	case msg.Code == ReadyMsg:
		log.Debug("ReadyMsg")
		var r readyData
		if err := msg.Decode(&r); err != nil {
			log.Debug("err: ", err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		ready := r.Ready
		pm.consensusManager.AddReady(ready)
		pm.BroadcastBFTMsg(ready)
		pm.consensusManager.Process()
	case msg.Code == TxMsg:
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.txpool.AddBatch(txs)
	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

func (pm *ProtocolManager) BroadcastBFTMsg(msg interface{}) {
	// TODO: expect origin
	var err error
	switch m := msg.(type) {
	case *types.Ready:
		peers := pm.peers.PeersWithoutHash(m.Hash())
		log.Debug("There are ", "peer count", len(peers))
		for _, peer := range peers {
			log.Info("send Ready msg")
			err = peer.SendReadyMsg(m)
			if err != nil {
				log.Debug("err: ", err)
			}
		}
	case *types.BlockProposal:
		log.Debug("broadcast Blockproposal")
		peers := pm.peers.PeersWithoutHash(m.Hash())
		// log.Info("Send Bp: ", m)
		for _, peer := range peers {
			peer.SendNewBlockProposal(m)
		}
	case *types.VotingInstruction:
		log.Debug("broadcast Votinginstruction")
		peers := pm.peers.PeersWithoutHash(m.Hash())

		for _, peer := range peers {
			peer.SendVotingInstruction(m)
		}
	case *types.Vote:
		log.Debug("broadcast Vote")
		peers := pm.peers.PeersWithoutHash(m.Hash())
		for _, peer := range peers {
			peer.SendVote(m)
		}
	case *types.PrecommitVote:
		log.Debug("broadcast Precommit Vote")
		peers := pm.peers.PeersWithoutPrecommit(m.Hash())
		// log.Debug("peers to broadcast: ", len(peers))
		for _, peer := range peers {
			err := peer.SendPrecommitVote(m)
			if err != nil {
				log.Debug("err: ", err)
			}
		}
	default:
		log.Info("broadcast unknown type:", m)
	}
}

func (self *ProtocolManager) commitBlock(block *types.Block) bool {
	log.Info("commmitBlock")
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	oldHeight := self.blockchain.CurrentBlock().Header().Number.Uint64()
	log.Info("commmitBlock2")
	n, err := self.blockchain.InsertChain(types.Blocks{block})
	if err != nil {
		log.Info("Block error on :", "number", n)
		// log.Debug(err)
		return false
	}
	// wait until block insert to chain
	for oldHeight >= self.blockchain.CurrentBlock().Header().Number.Uint64() {
		// DEBUG
		log.Info("commmitBlock222")

		log.Debug("committing new block")
		time.Sleep(0.2 * 1000 * 1000 * 1000)
	}
	go self.consensusManager.Process()
	log.Info("commmitBlock3")

	log.Info("commited block, new Head Number is %d ", self.blockchain.CurrentBlock().Header().Number)
	return true
}
func (self *ProtocolManager) linkBlock(block *types.Block) *types.Block {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	// _link_block
	if self.blockchain.HasBlock(block.Hash()) {
		log.Debug("KNOWN BLOCK")
		return nil
	}
	if !self.blockchain.HasBlock(block.ParentHash()) {
		log.Debug("missing parent")
		return nil
	}

	return block
}

// BroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for _, peer := range peers {
		peer.SendTransactions(types.Transactions{tx})
	}
	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}

func (self *ProtocolManager) txBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.txSub.Chan() {
		event := obj.Data.(core.TxPreEvent)
		self.BroadcastTx(event.Tx.Hash(), event.Tx)
	}
}

// EthNodeInfo represents a short summary of the Ethereum sub-protocol metadata known
// about the host peer.
type EthNodeInfo struct {
	Network    uint64      `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3)
	Difficulty *big.Int    `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash `json:"genesis"`    // SHA3 hash of the host's genesis block
	Head       common.Hash `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *ProtocolManager) NodeInfo() *EthNodeInfo {
	currentBlock := self.blockchain.CurrentBlock()
	return &EthNodeInfo{
		Network:    self.networkId,
		Difficulty: self.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    self.blockchain.Genesis().Hash(),
		Head:       currentBlock.Hash(),
	}
}
