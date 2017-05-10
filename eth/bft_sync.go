package eth

import (
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
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
	self.cm.getHeightMu.Lock()
	ls := self.cm.lastCommittingLockset().Copy()
	self.cm.getHeightMu.Unlock()
	if ls == nil {
		log.Debug("no highest comitting lockest")
		return []types.RequestProposalNumber{}
	}
	maxHeight := ls.Height()
	current := self.cm.Head().Number()
	log.Debug("max height: %d current: %d\n", maxHeight, current)

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
		log.Debug("waiting for requested")
		return false
	}

	if self.Received.Size()+self.maxGetProposalsCount >= self.maxQueued {
		log.Debug("queue is full")
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
		log.Debug("request end, err:", err)
	} else {
		log.Debug("no active protocol")

	}
	// setup alarm

	self.cm.setupAlarm()
	return true
}
func (self *HDCSynchronizer) receiveBlockproposals(bps []*types.BlockProposal) {
	for _, bp := range bps {
		log.Info("received Blocks", bp.Height)
		self.Received.Add(bp.Height)
		self.Requested.Remove(bp.Height)
		for _, v := range bp.SigningLockset.PrecommitVotes {
			self.cm.AddPrecommitVote(v, nil)
		}
	}
	self.cm.Process()
	self.request()
	for _, bp := range bps {
		log.Info("add Bps", bp)
		self.cm.AddProposal(bp, nil)
		self.cm.Process()
	}
	self.cleanup()
}
func (self *HDCSynchronizer) onProposal(proposal types.Proposal, p *peer) {
	log.Debug("synchronizer on proposal")
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
