package eth

import (
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"gopkg.in/fatih/set.v0"
)

type HDCSynchronizer struct {
	timeout              int
	maxGetProposalsCount int
	maxQueued            int
	cm                   *ConsensusManager
	Requested            *set.Set
	Received             *set.Set
	lastActiveProtocol   *peer
	addProposalLock      sync.Mutex
}

func NewHDCSynchronizer(cm *ConsensusManager) *HDCSynchronizer {
	return &HDCSynchronizer{
		timeout:              5,
		cm:                   cm,
		Requested:            set.New(),
		Received:             set.New(),
		maxGetProposalsCount: MaxGetproposalsCount,
		maxQueued:            MaxGetproposalsCount * 3,
	}
}
func (self *HDCSynchronizer) Missing() []types.RequestProposalNumber {

	ls := self.cm.HighestCommittingLockset()

	if ls == nil {
		glog.V(logger.Debug).Infoln("no highest comitting lockest")
		return []types.RequestProposalNumber{}
	}
	maxHeight := ls.Height()
	current := self.cm.Head().Number()
	glog.V(logger.Debug).Infoln("max height: %d current: %d\n", maxHeight, current)

	if maxHeight < current.Uint64() {
		return []types.RequestProposalNumber{}
	}
	var missing []types.RequestProposalNumber

	for i := current.Uint64() + 1; i < maxHeight+1; i++ {
		missing = append(missing, types.RequestProposalNumber{i})
	}
	return missing
}

func (self *HDCSynchronizer) request() bool {
	if self.Requested.Size() != 0 {
		glog.V(logger.Debug).Infoln("waiting for requested")
		return false
	}

	if self.Received.Size()+self.maxGetProposalsCount >= self.maxQueued {
		glog.V(logger.Debug).Infoln("queue is full")
		return false
	}

	missing := self.Missing()

	if len(missing) == 0 {
		return false
	}
	var blockNumbers []types.RequestProposalNumber
	for _, v := range missing {
		if !self.Received.Has(v.Number) && !self.Requested.Has(v.Number) {
			blockNumbers = append(blockNumbers, v)
			self.Requested.Add(v.Number)
			if len(blockNumbers) == self.maxGetProposalsCount {
				break
			}
		}
	}
	if len(blockNumbers) == 0 {
		return false
	}
	if self.lastActiveProtocol != nil {
		err := self.lastActiveProtocol.RequestBlockProposals(blockNumbers)
		glog.V(logger.Debug).Infoln("request end, err:", err)
	} else {
		glog.V(logger.Debug).Infof("no active protocol")

	}
	// setup alarm

	self.cm.setupAlarm()
	return true
}
func (self *HDCSynchronizer) requestHeight(height uint64, peer *peer) bool {
	var blockNumbers []types.RequestProposalNumber
	blockNumbers = append(blockNumbers, types.RequestProposalNumber{height})
	if peer != nil {
		err := peer.RequestBlockProposals(blockNumbers)
		glog.V(logger.Debug).Infoln("request end, err:", err)
	} else {
		glog.V(logger.Debug).Infof("unknown peer")
		return false
	}
	return true
}
func (self *HDCSynchronizer) receiveBlockproposals(bps []*types.BlockProposal) {
	for _, bp := range bps {
		glog.V(logger.Info).Infoln("received Blocks", bp.Height)
		self.Received.Add(bp.Height)
		self.Requested.Remove(bp.Height)
		for _, v := range bp.SigningLockset.PrecommitVotes {
			self.cm.AddPrecommitVote(v, nil)
		}
	}
	self.cm.Process()
	self.request()
	for _, bp := range bps {
		glog.V(logger.Info).Infoln("add Bps", bp)
		self.cm.AddProposal(bp, nil)
		self.cm.Process()
	}
	self.cleanup()
}
func (self *HDCSynchronizer) onProposal(proposal types.Proposal, p *peer) {
	glog.V(logger.Debug).Infoln("synchronizer on proposal")
	if proposal.GetHeight() >= self.cm.Height() {
		if !proposal.LockSet().IsValid() && proposal.LockSet().EligibleVotesNum != 0 {
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
	for _, v := range self.Received.List() {
		if v.(uint64) < height {
			self.Received.Remove(v)
		}
	}
	for _, v := range self.Requested.List() {
		if v.(uint64) < height {
			self.Requested.Remove(v)
		}
	}
}
