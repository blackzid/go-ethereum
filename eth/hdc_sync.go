package eth

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
	// "github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/p2p/discover"

	"gopkg.in/fatih/set.v0"
)

type HDCSynchronizer struct {
	timeout              int
	maxGetProposalsCount int
	maxQueued            int
	cm                   *ConsensusManager
	requested            *set.Set
	received             *set.Set
	lastActiveProtocol   *peer
	addProposalLock      sync.Mutex
}

func NewHDCSynchronizer(cm *ConsensusManager) *HDCSynchronizer {
	return &HDCSynchronizer{
		timeout:              5,
		cm:                   cm,
		requested:            set.New(),
		received:             set.New(),
		maxGetProposalsCount: MaxGetproposalsCount,
		maxQueued:            MaxGetproposalsCount * 3,
	}
}
func (self *HDCSynchronizer) Missing() []uint64 {

	ls := self.cm.highestCommittingLockset()
	if ls == nil {
		return []uint64{}
	}
	maxHeight := ls.Height()

	current := self.cm.Head().Number()

	if maxHeight < current.Uint64() {
		return []uint64{}
	}
	var missing []uint64

	for i := current.Uint64(); i < maxHeight; i++ {
		missing = append(missing, i)
	}
	return missing
}

func (self *HDCSynchronizer) request() bool {
	if self.requested.Size() != 0 {
		fmt.Println("waiting for requested")
		return false
	}

	if self.received.Size()+self.maxGetProposalsCount >= self.maxQueued {
		fmt.Println("queue is full")
		return false
	}

	missing := self.Missing()

	if len(missing) == 0 {
		fmt.Println("insync")
		return false
	}
	fmt.Println("start syncing")
	var blockNumbers []uint64
	for _, v := range missing {
		if !self.received.Has(v) && !self.requested.Has(v) {
			blockNumbers = append(blockNumbers, v)
			self.requested.Add(v)
			if len(blockNumbers) == self.maxGetProposalsCount {
				break
			}
		}
	}
	if len(blockNumbers) == 0 {
		return false
	}
	self.lastActiveProtocol.RequestBlockProposals(blockNumbers)
	// setup alarm
	// self.cm.setupAlarm()
	return false
}
func (self *HDCSynchronizer) receiveBlockproposals(bps []*types.BlockProposal) {
	for _, bp := range bps {
		self.received.Add(bp.Height)
		self.requested.Remove(bp.Height)
		for _, v := range bp.SigningLockset.Votes {
			self.cm.AddVote(v)
		}
	}
	self.request()
	for _, bp := range bps {
		self.cm.AddProposal(bp, nil)
	}
	self.cleanup()
}
func (self *HDCSynchronizer) onProposal(proposal types.Proposal, p *peer) {
	glog.V(logger.Info).Infoln("synchronizer on proposal")
	if proposal.GetHeight() > self.cm.Height() {
		if !proposal.LockSet().IsValid() {
			panic("onProposal error")
		}
		self.lastActiveProtocol = p
	}
}
func (self *HDCSynchronizer) process() {
	self.request()
}
func (self *HDCSynchronizer) cleanup() {
	// set.List() may have error
	height := self.cm.Height()
	for _, v := range self.received.List() {
		if v.(uint64) < height {
			self.received.Remove(v)
		}
	}
	for _, v := range self.requested.List() {
		if v.(uint64) < height {
			self.requested.Remove(v)
		}
	}
}
func (pm *HDCProtocolManager) syncTransactions(p *peer) {
	var txs types.Transactions
	for _, batch := range pm.txpool.Pending() {
		txs = append(txs, batch...)
	}
	if len(txs) == 0 {
		return
	}
	select {
	case pm.txsyncCh <- &txsync{p, txs}:
	case <-pm.quitSync:
	}
}

// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (pm *HDCProtocolManager) txsyncLoop() {
	var (
		pending = make(map[discover.NodeID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send
	)

	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			pack.txs = append(pack.txs, s.txs[i])
			size += s.txs[i].Size()
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		glog.V(logger.Detail).Infof("%v: sending %d transactions (%v)", s.p.Peer, len(pack.txs), size)
		sending = true
		go func() { done <- pack.p.SendTransactions(pack.txs) }()
	}

	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {
		case s := <-pm.txsyncCh:
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}
		case err := <-done:
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				glog.V(logger.Debug).Infof("%v: tx send failed: %v", pack.p.Peer, err)
				delete(pending, pack.p.ID())
			}
			// Schedule the next send.
			if s := pick(); s != nil {
				send(s)
			}
		case <-pm.quitSync:
			return
		}
	}
}

// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (pm *HDCProtocolManager) syncer() {
	// Start and ensure cleanup of sync mechanisms
	pm.fetcher.Start()
	defer pm.fetcher.Stop()
	defer pm.downloader.Terminate()

	// Wait for different events to fire synchronisation operations
	forceSync := time.Tick(forceSyncCycle)
	for {
		select {
		case <-pm.newPeerCh:
			// Make sure we have peers to select from, then sync
			if pm.peers.Len() < minDesiredPeerCount {
				break
			}
			go pm.synchronise(pm.peers.BestPeer())

		case <-forceSync:
			// Force a sync even if not enough peers are present
			go pm.synchronise(pm.peers.BestPeer())

		case <-pm.noMorePeers:
			return
		}
	}
}

// synchronise tries to sync up our local block chain with a remote peer.
func (pm *HDCProtocolManager) synchronise(peer *peer) {
	// Short circuit if no peers are available
	if peer == nil {
		return
	}
	// Make sure the peer's TD is higher than our own
	currentBlock := pm.blockchain.CurrentBlock()
	td := pm.blockchain.GetTd(currentBlock.Hash())

	pHead, pTd := peer.Head()
	if pTd.Cmp(td) <= 0 {
		return
	}
	// Otherwise try to sync with the downloader
	mode := downloader.FullSync
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		mode = downloader.FastSync
	}
	if err := pm.downloader.Synchronise(peer.id, pHead, pTd, mode); err != nil {
		return
	}
	atomic.StoreUint32(&pm.synced, 1) // Mark initial sync done

	// If fast sync was enabled, and we synced up, disable it
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		// Disable fast sync if we indeed have something in our chain
		if pm.blockchain.CurrentBlock().NumberU64() > 0 {
			glog.V(logger.Info).Infof("fast sync complete, auto disabling")
			atomic.StoreUint32(&pm.fastSync, 0)
		}
	}
}
