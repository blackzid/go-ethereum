package eth

import (
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core/state"
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
	requested            *set.Set
	received             *set.Set
	lastActiveProtocol   *peer
}

func NewHDCSynchronizer(cm *ConsensusManager) *HDCSynchronizer {
	return &HDCSynchronizer{
		timeout:              5,
		cm:                   cm,
		requested:            false,
		maxGetProposalsCount: MaxGetproposalsCount,
		maxQueued:            MaxGetproposalsCount * 3,
	}
}
func (self *HDCSynchronizer) Missing() []int {
	ls := self.cm.highestCommittingLockset()
	if ls == nil {
		return []int{}
	}
	maxHeight := ls.Height()
	current := self.cm.Head().Number()
	if maxHeight < int(current.Int64()) {
		return []int{}
	}
	var missing []int
	for i := int(current.Int64()); i < maxHeight; i++ {
		missing = append(missing, i)
	}
	return missing

}

func (self *HDCSynchronizer) request() bool {
	missing := self.Missing()
	if self.requested.Size() == 0 {
		return false
	}
	if self.received.Size()+self.maxGetProposalsCount >= self.maxQueued {
		return false
	}
	if len(missing) == 0 {
		return false
	}
	var blockNumbers []int
	for _, v := range missing {
		if !self.received.Has(v) && !self.requested.Has(v) {
			blocknumbers = append(blockNumbers, v)
			self.requested.Add(v)
			if len(blockNumbers) == self.maxGetProposalsCount {
				break
			}
		}
	}
	if len(blockNumbers) == 0 {
		return false
	}
	self.lastActiveProtocol.RequestBlokcProposals(blockNumbers)
	// setup alarm
	self.cm.setupAlarm()
	return false
}
func (self *HDCSynchronizer) receiveBlockproposals(bps []types.Proposal) {
	for _, bp := range bps {
		self.received.Add(bp.Height())
		self.requested.Remove
		for _, v := range bp.SigningLockset().Votes() {
			self.cm.AddVote(v)
		}
	}
	self.cm.Process()
	self.request()
	for _, bp := range bps {
		self.cm.AddProposal(bp)
		self.cm.Process()
	}
	self.cleanup()

}
func (self *HDCSynchronizer) onProposal(proposal types.Proposal, p *peer) {
	glog.V(logger.Info).Infoln("synchronizer on proposal")
	if proposal.Height() > self.cm.Height() {
		if !proposal.LockSet.IsValid() {
			panic("onProposal error")
		}
		self.lastActiveProtocol = p
	}

	return nil
}
func (self *HDCSynchronizer) process() {
	self.request()
}
func (self *HDCSynchronizer) cleanup() {
	height := self.cm.Height()
	for _, v := range self.received.List() {
		if v < height {
			self.received.Remove(v)
		}
	}
	for _, v := range self.requested.List() {
		if v < height {
			self.requested.Remove(v)
		}
	}

}
