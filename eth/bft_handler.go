package eth

import (
	"time"

	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
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
		log.Debug("add txs")
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
		log.Debug("There are ", len(peers), " peers to broadcast.")
		for _, peer := range peers {
			// log.Info("send Ready msg to ", peer.String())
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
		log.Debug("peers to broadcast: ", len(peers))
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
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	oldHeight := self.blockchain.CurrentBlock().Header().Number.Uint64()
	n, err := self.blockchain.InsertChain(types.Blocks{block})
	if err != nil {
		log.Info("Block error on :", n)
		log.Debug("err: ", err)
		return false
	}
	// wait until block insert to chain
	for oldHeight >= self.blockchain.CurrentBlock().Header().Number.Uint64() {
		// DEBUG
		log.Debug("committing new block")
		time.Sleep(0.2 * 1000 * 1000 * 1000)
	}
	go self.consensusManager.Process()
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
func (self *ProtocolManager) addTransactions(txs []*types.Transaction) {
	self.addTransactionLock.Lock()
	defer self.addTransactionLock.Unlock()
	self.txpool.AddBatch(txs)
}

// BFT APIs
func (s *PublicEthereumAPI) StartConsensus() bool {
	return s.e.protocolManager.consensusManager.Start()
}
func (s *PublicEthereumAPI) StopConsensus() bool {
	return s.e.protocolManager.consensusManager.Stop()
}
