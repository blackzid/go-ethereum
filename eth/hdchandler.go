package eth

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/pow"
	"github.com/ethereum/go-ethereum/rlp"
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
type HeightManager struct {
	pm *HDCProtocolManager
	height int
	rounds make([int]*RoundManager)
}

type RoundManager struct {
	hm *HeightManager
	pm *HDCProtocolManager
	height int 
	lockset LockSet
	proposal *BlockProposal
	timeout_time float64
	// lock Vote

}
type HDCProtocolManager struct {
	networkId int

	// hdc properties
	allow_empty_blocks   bool
	num_initial_blocks   int
	round_timeout        int
	round_timeout_factor float64
	transaction_timeout  float64

	heights make([int]*HeightManager)


	fastSync uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	synced   uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	blockchain  *core.BlockChain
	chaindb     ethdb.Database
	chainconfig *core.ChainConfig

	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet

	SubProtocols []p2p.Protocol

	eventMux *event.TypeMux
	txSub    event.Subscription
	// minedBlockSub event.Subscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup

	badBlockReportingEnabled bool
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewHDCProtocolManager(config *core.ChainConfig, fastSync bool, networkId int, mux *event.TypeMux, txpool txPool, pow pow.PoW, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &HDCProtocolManager{
		networkId:            networkId,
		allow_empty_blocks:   false,
		num_initial_blocks:   10,
		round_timeout:        3,
		round_timeout_factor: 1.5,
		transaction_timeout:  0.5,
		eventMux:             mux,
		txpool:               txpool,
		blockchain:           blockchain,
		chaindb:              chaindb,
		chainconfig:          config,
		peers:                newPeerSet(),
		newPeerCh:            make(chan *peer),
		noMorePeers:          make(chan struct{}),
		txsyncCh:             make(chan *txsync),
		quitSync:             make(chan struct{}),
	}
	// Figure out whether to allow fast sync or not
	if fastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		glog.V(logger.Info).Infof("blockchain not empty, fast sync disabled")
		fastSync = false
	}
	if fastSync {
		manager.fastSync = uint32(1)
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if fastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
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
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(chaindb, manager.eventMux, blockchain.HasHeader, blockchain.HasBlockAndState, blockchain.GetHeader,
		blockchain.GetBlock, blockchain.CurrentHeader, blockchain.CurrentBlock, blockchain.CurrentFastBlock, blockchain.FastSyncCommitHead,
		blockchain.GetTd, blockchain.InsertHeaderChain, manager.insertChain, blockchain.InsertReceiptChain, blockchain.Rollback,
		manager.removePeer)

	validator := func(block *types.Block, parent *types.Block) error {
		//
		//
		// return core.ValidateHeader(config, pow, block.Header(), parent.Header(), true, false)
		//
		//
		return true
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		atomic.StoreUint32(&manager.synced, 1) // Mark initial sync done on any fetcher import
		return manager.insertChain(blocks)
	}
	manager.fetcher = fetcher.New(blockchain.GetBlock, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	if blockchain.Genesis().Hash().Hex() == defaultGenesisHash && networkId == 1 {
		glog.V(logger.Debug).Infoln("Bad Block Reporting is enabled")
		manager.badBlockReportingEnabled = true
	}

	return manager, nil
}

func (pm *ProtocolManager) insertChain(blocks types.Blocks) (i int, err error) {
	i, err = pm.blockchain.InsertChain(blocks)
	if pm.badBlockReportingEnabled && core.IsValidationErr(err) && i < len(blocks) {
		go sendBadBlockReport(blocks[i], err)
	}
	return i, err
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	glog.V(logger.Debug).Infoln("Removing peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		glog.V(logger.Error).Infoln("Removal failed:", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *ProtocolManager) Start() {
	// broadcast transactions
	pm.txSub = pm.eventMux.Subscribe(core.TxPreEvent{})
	go pm.txBroadcastLoop()
	// // broadcast mined blocks
	// pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	// go pm.minedBroadcastLoop()

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()
}

func (pm *ProtocolManager) Stop() {
	glog.V(logger.Info).Infoln("Stopping ethereum protocol handler...")

	pm.txSub.Unsubscribe() // quits txBroadcastLoop
	// pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	glog.V(logger.Info).Infoln("Ethereum protocol handler stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	glog.V(logger.Debug).Infof("%v: peer connected [%s]", p, p.Name())

	// Execute the Ethereum handshake
	td, head, genesis := pm.blockchain.Status()
	if err := p.Handshake(pm.networkId, td, head, genesis); err != nil {
		glog.V(logger.Debug).Infof("%v: handshake failed: %v", p, err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	glog.V(logger.Detail).Infof("%v: adding peer", p)
	if err := pm.peers.Register(p); err != nil {
		glog.V(logger.Error).Infof("%v: addition failed: %v", p, err)
		return err
	}
	defer pm.removePeer(p.id)

	// change here
	//
	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p.Head, p.RequestHeadersByHash, p.RequestHeadersByNumber, p.RequestBodies, p.RequestReceipts, p.RequestNodeData); err != nil {
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			glog.V(logger.Warn).Infof("%v: timed out DAO fork-check, dropping", p)
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			glog.V(logger.Debug).Infof("%v: message handling failed: %v", p, err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
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
		//
		fmt.Println("on received getblockproposalsmsg")

	case msg.Code == BlockProposalsMsg:
		//received proposals
		fmt.Println("received proposals")
		// consensus_manager.synchronizer.receive_blockproposals(proposals)
	case msg.Code == NewBlockProposalMsg:
		fmt.Println("recv newblockproposal")

	case msg.Code == VotingInstructionMsg:
		fmt.Println("recv votinginstruction")

	case msg.Code == VoteMsg:
		fmt.Println("n_receive_vote")

	case msg.Code == ReadyMsg:
		fmt.Println("recv ready")

	case msg.Code == TxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if atomic.LoadUint32(&pm.synced) == 0 {
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
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
		pm.txpool.AddTransactions(txs)

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}
func (pm *ProtocolManager) 








// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash()); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash()))
		} else {
			glog.V(logger.Error).Infof("propagating dangling block #%d [%x]", block.NumberU64(), hash[:4])
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			peer.SendNewBlock(block, td)
		}
		glog.V(logger.Detail).Infof("propagated block %x to %d peers in %v", hash[:4], len(transfer), time.Since(block.ReceivedAt))
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if pm.blockchain.HasBlock(hash) {
		for _, peer := range peers {
			peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{block.NumberU64()})
		}
		glog.V(logger.Detail).Infof("announced block %x to %d peers in %v", hash[:4], len(peers), time.Since(block.ReceivedAt))
	}
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
	glog.V(logger.Detail).Infoln("broadcast tx to", len(peers), "peers")
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
	Network    int         `json:"network"`    // Ethereum network ID (0=Olympic, 1=Frontier, 2=Morden)
	Difficulty *big.Int    `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash `json:"genesis"`    // SHA3 hash of the host's genesis block
	Head       common.Hash `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *ProtocolManager) NodeInfo() *EthNodeInfo {
	return &EthNodeInfo{
		Network:    self.networkId,
		Difficulty: self.blockchain.GetTd(self.blockchain.CurrentBlock().Hash()),
		Genesis:    self.blockchain.Genesis().Hash(),
		Head:       self.blockchain.CurrentBlock().Hash(),
	}
}
