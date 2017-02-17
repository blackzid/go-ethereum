package eth

import (
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
)

func (pm *ProtocolManager) StartBFT() {
	// broadcast transactions
	pm.txSub = pm.eventMux.Subscribe(core.TxPreEvent{})
	go pm.txBroadcastLoop()
	// // // broadcast mined blocks
	// pm.msgSub = pm.eventMux.Subscribe(core.NewMsgEvent{})
	// go pm.msgBroadcastLoop()

	// // start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()

	// start consensus mangaer
	go pm.announce()
	pm.consensusManager.Process()
}

func (pm *ProtocolManager) announce() {
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

func (pm *ProtocolManager) handleBFTMsg(p *peer) error {
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
		glog.V(logger.Debug).Infoln("GetBlockProposalsMsg from:", p.id)
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
			glog.V(logger.Info).Infoln("Send bp: ", found)
			p.SendBlockProposals(found)

			// broadcast highest lastQuorumLockset if it exist
			lastHeight := query[len(query)-1].Number
			if ls := pm.consensusManager.getHeightManager(lastHeight).lastQuorumLockset(); ls != nil {
				glog.V(logger.Info).Infoln("Send Vote from", lastHeight)
				for _, v := range ls.Votes {
					glog.V(logger.Info).Infoln("vote: ", v)
					p.SendVote(v)
				}
			} else {
				glog.V(logger.Info).Infoln("No Quorum on ", lastHeight)
			}
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
		if isValid := pm.consensusManager.AddProposal(bp, p); isValid {
			time.Sleep(1000 * 1000 * 0.5)
			pm.BroadcastBFTMsg(bp)
			pm.consensusManager.Process()
		} else {
			glog.V(logger.Debug).Infoln("NewBlockProposalMsg failed")
			return nil
		}
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
			time.Sleep(1000 * 1000 * 0.5)
			pm.BroadcastBFTMsg(vi)
			pm.consensusManager.Process()
		}

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
			time.Sleep(1000 * 1000 * 0.5)
			pm.BroadcastBFTMsg(vote)
			pm.consensusManager.Process()
		}

	case msg.Code == ReadyMsg:
		var r readyData
		if err := msg.Decode(&r); err != nil {
			glog.V(logger.Debug).Infoln(err)
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
func (pm *ProtocolManager) BroadcastBFTMsg(msg interface{}) {
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

func (self *ProtocolManager) commitBlock(block *types.Block) bool {
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
func (self *ProtocolManager) linkBlock(block *types.Block) *types.Block {
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
func (self *ProtocolManager) addTransactions(txs []*types.Transaction) {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	self.txpool.AddBatch(txs)
}
