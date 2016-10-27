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
	"github.com/ethereum/go-ethereum/miner"
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
	proposalLock              *typtes.Block
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
func (cm *ConsensusManager) sign(bp *BlockProposal) {
	bp.sign(cm.privkey)
}
func (cm *ConsensusManager) set_proposal_lock(block *type.Block) {
	
	// TODO: update this
	cm.proposalLock = block
}

type HeightManager struct {
	cm     *ConsensusManager
	round  int
	height int
	lastVoteLock *Vote // voteblock
}

type RoundManager struct {
	hm           *HeightManager
	cm           *ConsensusManager
	round        int
	height       int
	lockset      *LockSet
	proposal     Proposal
	voteLock         *Vote
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
	var proposal Proposal
	if round_lockset.height == rm.height && round_lockset.hasQuorum() {
		glog.V(logger.Error).Infof("have quorum on height, not proposing")
		return nil
	} else if rm.round == 0 || round_lockset.noQuorum() {
		proposal = rm.mk_proposal()
	} else if round_lockset.quorumPossible() {
		proposal = types.NewVotingInstruction(rm.height, rm.round, round_lockset)
		rm.cm.sign(proposal)
	} else {
		panic('invalid round_lockset')
	}
	rm.proposal = proposal
	glog.V(logger.Info).Infof("created proposal")

	return proposal
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
	block := newBlock(rm.cm)
	blockproposal := types.NewBlockProposal(rm.height, rm.round, block, signing_lockset, round_lockset)
	rm.cm.sign(blockProposal)
	rm.cm.set_proposal_lock(block)
	return blockProposal
}
func (rm *RoundManager) vote() {
	if rm.voteLock != nil {
		glog.V(logger.Info).Infof("voted ")
		return nil
	}
	glog.V(logger.Info).Infof("in vote")
	lastVoteLock := rm.hm.lastVoteLock
	var vote *Vote 
	if rm.proposal != nil {
		switch t := rm.proposal.(type) {
		case default:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_noquorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			glog.V(logger.Info).Infoln("voting proposed block")
			v := types.NewVote(rm.height, rm.round, rm.proposal.blockhash)
			vote = &VoteBlock{v}
		case *VotingInstruction:
			if !rm.proposal.lockset.quorumPossible() {
				panic("vote error")
			}
			glog.V(logger.Info).Infoln("voting on instruction")
			v := types.NewVote(rm.height, rm.round, rm.proposal.blockhash)
			vote = &VoteBlock{v}
		case *BlockProposal:
			glog.V(logger.Info).Infoln("voting on last vote")
			v := types.NewVote(rm.height, rm.round, lastVoteLock.blockhash)
			vote = &VoteBLock{v}
		}

	}
}
func newBlock(cm *ConsensusManager) *types.Block {
	config := cm.chain.chainConfig
	coinbase := common.Address{}
	eth := cm.contract.eth
	worker := &worker{
		config:         config,
		eth:            eth,
		mux:            eth.EventMux(),
		chainDb:        eth.ChainDb(),
		recv:           make(chan *Result, resultQueueSize),
		gasPrice:       new(big.Int),
		chain:          eth.BlockChain(),
		proc:           eth.BlockChain().Validator(),
		possibleUncles: make(map[common.Hash]*types.Block),
		coinbase:       coinbase,
		txQueue:        make(map[common.Hash]*types.Transaction),
		agents:         make(map[Agent]struct{}),
		fullValidation: false,
	}
	return worker.newBlock()
	// worker.events = worker.mux.Subscribe(core.ChainHeadEvent{}, core.ChainSideEvent{}, core.TxPreEvent{})

}
func (self *miner.worker) newBlock() *types.Block{
	self.mu.Lock()
	defer self.mu.Unlock()
	self.uncleMu.Lock()
	defer self.uncleMu.Unlock()
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	tstart := time.Now()
	parent := self.chain.CurrentBlock()
	tstamp := tstart.Unix()
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); tstamp > now+4 {
		wait := time.Duration(tstamp-now) * time.Second
		glog.V(logger.Info).Infoln("We are too far in the future. Waiting for", wait)
		time.Sleep(wait)
	}

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		Difficulty: core.CalcDifficulty(self.config, uint64(tstamp), parent.Time().Uint64(), parent.Number(), parent.Difficulty()),
		GasLimit:   core.CalcGasLimit(parent),
		GasUsed:    new(big.Int),
		Coinbase:   self.coinbase,
		Extra:      self.extra,
		Time:       big.NewInt(tstamp),
	}
	previous := self.current
	// Could potentially happen if starting to mine in an odd state.
	err := self.makeCurrent(parent, header)
	if err != nil {
		glog.V(logger.Info).Infoln("Could not create new env for mining, retrying on next block.")
		return
	}
	// Create the current work task and check any fork transitions needed
	work := self.current

	txs := types.NewTransactionsByPriceAndNonce(self.eth.TxPool().Pending())
	work.commitTransactions(self.mux, txs, self.gasPrice, self.chain)

	self.eth.TxPool().RemoveBatch(work.lowGasTxs)
	self.eth.TxPool().RemoveBatch(work.failedTxs)

	// compute uncles for the new block.
	var (
		uncles    []*types.Header
		badUncles []common.Hash
	)
	for hash, uncle := range self.possibleUncles {
		if len(uncles) == 2 {
			break
		}
		if err := self.commitUncle(work, uncle.Header()); err != nil {
			if glog.V(logger.Ridiculousness) {
				glog.V(logger.Detail).Infof("Bad uncle found and will be removed (%x)\n", hash[:4])
				glog.V(logger.Detail).Infoln(uncle)
			}
			badUncles = append(badUncles, hash)
		} else {
			glog.V(logger.Debug).Infof("commiting %x as uncle\n", hash[:4])
			uncles = append(uncles, uncle.Header())
		}
	}
	for _, hash := range badUncles {
		delete(self.possibleUncles, hash)
	}

	if atomic.LoadInt32(&self.mining) == 1 {
		// commit state root after all state transitions.
		core.AccumulateRewards(work.state, header, uncles)
		header.Root = work.state.IntermediateRoot()
	}

	// create the new block whose nonce will be mined.
	work.Block = types.NewBlock(header, work.txs, uncles, work.receipts)

	// We only care about logging if we're actually mining.
	if atomic.LoadInt32(&self.mining) == 1 {
		glog.V(logger.Info).Infof("create new work on block %v with %d txs & %d uncles. Took %v\n", work.Block.Number(), work.tcount, len(uncles), time.Since(tstart))
		self.logLocalMinedBlocks(work, previous)
	}

	return work.Block
}
