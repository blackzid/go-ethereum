package core

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/pow"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/hashicorp/golang-lru"
)

type ConsensusContract struct {
	eth        core.Backend
	validators []common.Address
}

func (cc *ConsensusContract) proposer(height int, round int) common.Address {
	// v := abs(hash(repr((height, round))))
	v := 3
	return cc.validators[v%len(cc.validators)]
}

type ConsensusManager struct {
	allow_empty_blocks        bool
	num_initial_blocks        int
	round_timeout             int
	round_timeout_factor      float64
	transaction_timeout       float64
	e                         *Ethereum
	chain                     *BlockChain
	coinbase                  common.Address
	privkey                   *ecdsa.PrivateKey
	contract                  *ConsensusContract
	tracked_protocol_failures []string
	heights                   []*HeightManager
	last_valid_lockset        *LockSet
	last_committing_lockset   *LockSet
}

func NewConsensusManager(heightmanager *HeightManager, round int) *RoundManager {
	return &ConsensusManager{
		allow_empty_blocks:   false,
		num_initial_blocks:   10,
		round_timeout:        3,
		round_timeout_factor: 1.5,
		transaction_timeout:  0.5,
	}
}
func (cm *ConsensusManager) Now() float64 {
	return time.Now().UnixNano()
}
func (cm *ConsensusManager) height() int {
	h := cm.chain.currentBlock.NumberU64()
	return h
}
func (cm *ConsensusManager) round() int {
	return cm.heights[cm.height()].round
}

type HeightManager struct {
	cm     *ConsensusManager
	round  int
	height int
}

type RoundManager struct {
	hm           *HeightManager
	cm           *ConsensusManager
	round        int
	height       int
	lockset      *LockSet
	proposal     *BlockProposal
	lock         *Vote
	timeout_time float64
}

func NewRoundManager(heightmanager *HeightManager, round int) *RoundManager {
	return &RoundManager{
		hm: heightmanager,
		cm: heightmanager.cm,
	}
}
func (rm *RoundManager) getTimeout() float64 {
	now := rm.cm.Now()
	round_timeout := rm.cm.round_timeout
	round_timeout_factor := rm.cm.round_timeout_factor
	delay := round_timeout * math.Pow(round_timeout_factor, rm.round)
	rm.timeout_time = rm.timeout_time + delay
	return delay
}
func (rm *RoundManager) add_vote(vote *Vote, force_replace bool) {
	if !rm.lockset.contaion(vote) {
		success := rm.lockset.add(vote, force_replace)

		// report faliure
		if rm.lockset.isValid() {
			hasquroum, _ := rm.lockset.hasQuorum()
			if rm.proposal != nil && hasquroum {
				glog.V(logger.Error).Infof("FailedToProposeEvidence")
				tracked_protocol_failures = append(tracked_protocol_failures, "FailedToProposeEvidence")
			}
		}
		return success
	}
	glog.V(logger.Error).Infof("vote already in lockset")
	return false
}
func (rm *RoundManager) add_proposal(proposal *BlockProposal) bool {
	if rm.proposal != nil || rm.proposal == proposal {
		glog.V(logger.Error).Infof("add_proposal error")
	}
	rm.proposal = proposal
	return true
}
func (rm *RoundManager) process() {
	if rm.cm.round() != rm.round {
		glog.V(logger.Error).Infof("round process error")
	}
	if rm.cm.height() != rm.height {
		glog.V(logger.Error).Infof("round process error")
	}

}

func (rm *RoundManager) propose() *BlockProposal {
	if !rm.cm.is_waiting_for_proposal() {
		glog.V(logger.Error).Infof("round propose error")
		return nil
	}
	proposer := rm.cm.contract.proposer(rm.height, rm.round)
	glog.V(logger.Error).Infof("in propose")
	if proposer != rm.cm.coinbase() {
		return nil
	}
	glog.V(logger.Error).Infof("is proposer")
	round_lockset := rm.cm.last_valid_lockset
	if round_lockset == nil {
		glog.V(logger.Error).Infof("no valid round lockset for height")
		return nil
	}
	var proposal *BlockProposal
	if round_lockset.height == rm.height && round_lockset.hasQuorum() {
		glog.V(logger.Error).Infof("have quorum on height, not proposing")
		return nil
	} else if rm.round == 0 || round_lockset.hasQuorum() {
		proposal = mk_proposal()
	} else if round_lockset.quorumPossible() {
		return nil
	}

}
func (rm *RoundManager) mk_proposal() {
	var round_lockset *LockSet
	signing_lockset := rm.cm.last_committing_lockset.copy()
	if rm.round > 0 {
		round_lockset = rm.cm.last_valid_lockset.copy()
	} else {
		round_lockset = nil
	}
	if !signing_lockset.hasQuorum() {
		panic("mk_proposal error")
	}
	if round_lockset != nil || rm.round == 0 {
		panic("mk_proposal error")
	}
	// block := rm.cm.chain.
}

func newBlock(cm *ConsensusManager) *types.Block {
	tstart := time.Now()
	parent := cm.chain.CurrentBlock()
	tstamp := tstart.Unix()
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		Difficulty: core.CalcDifficulty(cm.chain.config, uint64(tstamp), parent.Time().Uint64(), parent.Number(), parent.Difficulty()),
		GasLimit:   core.CalcGasLimit(parent),
		GasUsed:    new(big.Int),
		Coinbase:   cm.coinbase,
		Extra:      []byte{},
		Time:       big.NewInt(tstamp),
	}
	txs := types.NewTransactionsByPriceAndNonce(cm.contract.eth.TxPool().Pending())

}
