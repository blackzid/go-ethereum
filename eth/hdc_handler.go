package eth

import (
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
)

type HDCProtocolManager struct {
	networkId int

	fastSync uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	synced   uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	blockchain  *core.BlockChain
	chaindb     ethdb.Database
	chainconfig *core.ChainConfig
	hdcDb       ethdb.Database // hdc database

	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet

	SubProtocols []p2p.Protocol

	eventMux *event.TypeMux
	txSub    event.Subscription
	// hdc proposal
	// newProposalSub event.Subscription
	msgSub event.Subscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup

	badBlockReportingEnabled bool
	// hdc parameters
	validators         []common.Address
	consensusManager   *ConsensusManager
	consensusContract  *ConsensusContract
	privateKeyHex      string
	addTransactionLock sync.Mutex
	eventMu            sync.Mutex
}

func NewHDCProtocolManager(config *core.ChainConfig, fastSync bool, networkId int, mux *event.TypeMux, txpool txPool, pow pow.PoW, blockchain *core.BlockChain, chaindb ethdb.Database, validators []common.Address, privatekeyhex string, eth *Ethereum, extra []byte, gasPrice *big.Int, hdcDb ethdb.Database) (*HDCProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &HDCProtocolManager{
		networkId:   networkId,
		eventMux:    mux,
		txpool:      txpool,
		blockchain:  blockchain,
		chaindb:     chaindb,
		chainconfig: config,
		peers:       newPeerSet(),
		newPeerCh:   make(chan *peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
		// hdc parameters
		privateKeyHex: privatekeyhex,
		validators:    validators,
		hdcDb:         hdcDb,
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
		return core.ValidateHeader(config, pow, block.Header(), parent.Header(), true, false)
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		atomic.StoreUint32(&manager.synced, 1) // Mark initial sync done on any fetcher import
		return manager.insertChain(blocks)
	}
	// TODO: change broadcastblock
	manager.fetcher = fetcher.New(blockchain.GetBlock, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	if blockchain.Genesis().Hash().Hex() == defaultGenesisHash && networkId == 1 {
		glog.V(logger.Debug).Infoln("Bad Block Reporting is enabled")
		manager.badBlockReportingEnabled = true
	}

	manager.validators = validators
	manager.consensusContract = NewConsensusContract(eth.EventMux(), eth.etherbase, eth.TxPool(), validators)
	manager.consensusManager = NewConsensusManager(manager, blockchain, hdcDb, manager.consensusContract, manager.privateKeyHex, extra, gasPrice)
	return manager, nil
}

func (pm *HDCProtocolManager) insertChain(blocks types.Blocks) (i int, err error) {
	i, err = pm.blockchain.InsertChain(blocks)
	if pm.badBlockReportingEnabled && core.IsValidationErr(err) && i < len(blocks) {
		go sendBadBlockReport(blocks[i], err)
	}
	return i, err
}
func (pm *HDCProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	glog.V(logger.Debug).Infoln("Removing peer", id)

	// Unregister the peer from the downloader and Ethereum peer set

	// hdc disable downloader
	// pm.downloader.UnregisterPeer(id)

	if err := pm.peers.Unregister(id); err != nil {
		glog.V(logger.Error).Infoln("Removal failed:", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *HDCProtocolManager) Start() {
	// broadcast transactions
	pm.txSub = pm.eventMux.Subscribe(core.TxPreEvent{})
	go pm.txBroadcastLoop()
	// // broadcast mined blocks
	pm.msgSub = pm.eventMux.Subscribe(core.NewMsgEvent{})
	go pm.msgBroadcastLoop()

	// // start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()

	// start consensus mangaer
	go pm.announce()
	pm.consensusManager.Process()
}
func (pm *HDCProtocolManager) announce() {
	pm.eventMu.Lock()
	defer pm.eventMu.Unlock()
	for !pm.consensusManager.isReady() {
		glog.V(logger.Debug).Infoln("consensusManager not ready ")
		pm.consensusManager.SendReady(false)
		time.Sleep(0.5 * 1000 * 1000 * 1000)
	}
	pm.consensusManager.SendReady(true)
	glog.V(logger.Debug).Infoln("-----------------consensusManager Ready-------------------------")
}
func (pm *HDCProtocolManager) Stop() {
	glog.V(logger.Info).Infoln("Stopping ethereum protocol handler...")

	pm.txSub.Unsubscribe()  // quits txBroadcastLoop
	pm.msgSub.Unsubscribe() // quits msgBroadcastLoop

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

func (pm *HDCProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}
func (pm *HDCProtocolManager) handle(p *peer) error {
	glog.V(logger.Debug).Infof("%v: peer connected [%s]", p, p.Name())
	glog.V(logger.Info).Infof("manager handling")

	// Execute the Ethereum handshake
	td, head, genesis := pm.blockchain.Status()
	if err := p.Handshake(pm.networkId, td, head, genesis); err != nil {
		glog.V(logger.Info).Infof("%v: handshake failed: %v", p, err)
		glog.V(logger.Debug).Infof("%v: handshake failed: %v", p, err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	glog.V(logger.Detail).Infof("%v: adding peer", p)
	if err := pm.peers.Register(p); err != nil {
		glog.V(logger.Info).Infof("%v: addition failed: %v", p, err)
		glog.V(logger.Error).Infof("%v: addition failed: %v", p, err)
		return err
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect

	// hdc disable downloader
	// if err := pm.downloader.RegisterPeer(p.id, p.version, p.Head, p.RequestHeadersByHash, p.RequestHeadersByNumber, p.RequestBodies, p.RequestReceipts, p.RequestNodeData); err != nil {
	// 	glog.V(logger.Info).Infof("%v: downloader handling failed: %v", p, err)
	// 	return err
	// }

	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.

	pm.syncTransactions(p)

	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			glog.V(logger.Info).Infof("%v: message handling failed: %v", p, err)
			glog.V(logger.Debug).Infof("%v: message handling failed: %v", p, err)
			return err
		}
	}
}
func (pm *HDCProtocolManager) handleMsg(p *peer) error {
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
		glog.V(logger.Debug).Infoln("GetBlockProposalsMsg")
		var query []types.RequestProposalNumber
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		var found []*types.BlockProposal
		for i, height := range query {
			if i == MaxGetproposalsCount {
				glog.V(logger.Info).Infoln("max get proposal count")
				break
			}
			if height.Number > pm.blockchain.CurrentBlock().NumberU64() {
				glog.V(logger.Info).Infoln("Request future block")
				break
			}
			bp := pm.consensusManager.getBlockProposalByHeight(height.Number)
			found = append(found, bp)
		}
		if len(found) != 0 {
			p.SendBlockProposals(found)
		}

	case msg.Code == BlockProposalsMsg:
		glog.V(logger.Debug).Infoln("BlockProposalsMsg")
		var proposals []*types.BlockProposal
		if err := msg.Decode(&proposals); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		pm.consensusManager.synchronizer.receiveBlockproposals(proposals)

	case msg.Code == NewBlockProposalMsg:
		glog.V(logger.Debug).Infoln("NewBlockProposalMsg")
		var bpData newBlockProposals
		if err := msg.Decode(&bpData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		bp := bpData.BlockProposal
		if p.broadcastFilter.Has(bp.Hash()) {
			glog.V(logger.Debug).Infoln("NewBlockProposalMsg filtered")
			return nil
		}
		glog.V(logger.Debug).Infof("new NewBlockProposal on %d, going to add it\n", bp.From().Hex())
		if isValid := pm.consensusManager.AddProposal(bp, p); isValid {
			pm.Broadcast(bp)
		} else {
			glog.V(logger.Debug).Infoln("NewBlockProposalMsg failed")
			return nil
		}
		pm.consensusManager.Process()

	case msg.Code == VotingInstructionMsg:
		glog.V(logger.Debug).Infoln("VotingInstructionMsg")
		var viData votingInstructionData
		if err := msg.Decode(&viData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		vi := viData.VotingInstruction
		if p.broadcastFilter.Has(vi.Hash()) {
			glog.V(logger.Debug).Infoln("votinginstruction filtered")
			return nil
		}
		if isValid := pm.consensusManager.AddProposal(vi, p); isValid {
			pm.Broadcast(vi)
		}
		pm.consensusManager.Process()
	case msg.Code == VoteMsg:
		glog.V(logger.Debug).Infoln("VoteMsg")
		var vData voteData
		if err := msg.Decode(&vData); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		vote := vData.Vote

		if p.broadcastFilter.Has(vote.Hash()) {
			glog.V(logger.Debug).Infoln("vote filtered")
			return nil
		}
		glog.V(logger.Debug).Infoln("receive vote with HR ", vote.Height, vote.Round)
		if isValid := pm.consensusManager.AddVote(vote, p); isValid {
			pm.Broadcast(vote)
		}
		pm.consensusManager.Process()
	case msg.Code == ReadyMsg:
		var r readyData
		if err := msg.Decode(&r); err != nil {
			glog.V(logger.Debug).Infoln(err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		ready := r.Ready
		pm.consensusManager.AddReady(ready)
		pm.Broadcast(ready)
		pm.consensusManager.Process()
	case msg.Code == TxMsg:
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		glog.V(logger.Debug).Infoln("add txs")
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.addTransactions(txs)
	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}
func (pm *HDCProtocolManager) Broadcast(msg interface{}) {
	// TODO: expect origin
	var err error

	switch m := msg.(type) {
	case *types.Ready:
		peers := pm.peers.PeersWithoutHash(m.Hash())
		glog.V(logger.Debug).Infoln("There are ", len(peers), " peers to broadcast.")
		for _, peer := range peers {
			// glog.V(logger.Info).Infoln("send Ready msg to ", peer.String())
			err = peer.SendReadyMsg(m)
			if err != nil {
				glog.V(logger.Debug).Infoln(err)
			}
		}

	case *types.BlockProposal:
		glog.V(logger.Debug).Infoln("broadcast Blockproposal")
		peers := pm.peers.PeersWithoutHash(m.Hash())
		// glog.V(logger.Info).Infoln("Send Bp: ", m)
		for _, peer := range peers {
			peer.SendNewBlockProposal(m)
		}
	case *types.VotingInstruction:
		glog.V(logger.Debug).Infoln("broadcast Votinginstruction")
		peers := pm.peers.PeersWithoutHash(m.Hash())

		for _, peer := range peers {
			peer.SendVotingInstruction(m)
		}
	case *types.Vote:
		glog.V(logger.Debug).Infoln("broadcast Vote")
		peers := pm.peers.PeersWithoutHash(m.Hash())

		for _, peer := range peers {
			peer.SendVote(m)
		}
	default:
		glog.V(logger.Info).Infoln("broadcast unknown type:", m)
	}

}

func (pm *HDCProtocolManager) BroadcastTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for _, peer := range peers {
		peer.SendTransactions(types.Transactions{tx})
	}
	glog.V(logger.Detail).Infoln("broadcast tx to", len(peers), "peers")
}
func (pm *HDCProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
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
func (self *HDCProtocolManager) txBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.txSub.Chan() {
		event := obj.Data.(core.TxPreEvent)
		self.BroadcastTx(event.Tx.Hash(), event.Tx)
	}
}
func (self *HDCProtocolManager) msgBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.msgSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMsgEvent:
			self.Broadcast(ev)
		}
	}
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *HDCProtocolManager) NodeInfo() *EthNodeInfo {
	return &EthNodeInfo{
		Network:    self.networkId,
		Difficulty: self.blockchain.GetTd(self.blockchain.CurrentBlock().Hash()),
		Genesis:    self.blockchain.Genesis().Hash(),
		Head:       self.blockchain.CurrentBlock().Hash(),
	}
}
func (self *HDCProtocolManager) commitBlock(block *types.Block) bool {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	oldHeight := self.blockchain.CurrentBlock().Header().Number.Uint64()
	n, err := self.blockchain.InsertChain(types.Blocks{block})
	if err != nil {
		glog.V(logger.Info).Infoln("Block error on :", n)
		glog.V(logger.Info).Infoln(err)
		return false
	}
	// wait until block insert to chain
	for oldHeight >= self.blockchain.CurrentBlock().Header().Number.Uint64() {
		// DEBUG
		glog.V(logger.Debug).Infof("committing new block")
		time.Sleep(0.2 * 1000 * 1000 * 1000)
	}
	glog.V(logger.Info).Infof("commited block, new Head Number is %d ", self.blockchain.CurrentBlock().Header().Number)
	return true
}
func (self *HDCProtocolManager) linkBlock(block *types.Block) *types.Block {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	// _link_block
	if self.blockchain.HasBlock(block.Hash()) {
		glog.V(logger.Debug).Infoln("KNOWN BLOCK")
		return block
	}
	if !self.blockchain.HasBlock(block.ParentHash()) {
		glog.V(logger.Debug).Infoln("missing parent")
		return nil
	}

	return block
}
func (self *HDCProtocolManager) addTransactions(txs []*types.Transaction) {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	self.txpool.AddBatch(txs)
}
