package core

import (
	// "github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
)

type HDCSynchronizer struct {
	timeout              int
	maxGetProposalsCount int
	max_queued           int
	cm                   *ConsensusManager
	requested            bool
	// lastActiveProtocol   types.Proposal
}

func NewHDCSynchronizer(cm *ConsensusManager) *HDCSynchronizer {
	return &HDCSynchronizer{
		timeout:   5,
		cm:        cm,
		requested: false,
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
	if self.requested {
		return false
	} else if len(missing) == 0 {
		return false
	}
	return false
}

func (self *HDCSynchronizer) onProposal() types.Proposal {
	glog.V(logger.Info).Infoln("synchronizer on proposal")
	return nil
}
func (self *HDCSynchronizer) process() {
	self.request()
}
