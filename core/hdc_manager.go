package core

import (
	"crypto/ecdsa"
	// "errors"
	"fmt"
	// "io"
	"math"
	"math/big"
	// mrand "math/rand"
	// "runtime"
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
	// "github.com/ethereum/go-ethereum/metrics"
	// "github.com/ethereum/go-ethereum/pow"
	"github.com/ethereum/go-ethereum/rlp"
	"gopkg.in/fatih/set.v0"
	// "github.com/ethereum/go-ethereum/trie"
	// "github.com/hashicorp/golang-lru"
)

type ConsensusContract struct {
	eth        Backend
	validators []common.Address
}

func (cc *ConsensusContract) proposer(height int, round int) common.Address {
	// v := abs(hash(repr((height, round))))
	v := 3
	return cc.validators[v%len(cc.validators)]
}
func (cc *ConsensusContract) isValidators(v common.Address) bool {
	return containsAddress(cc.validators, v)
}
func (cc *ConsensusContract) isProposer(p types.Proposal) bool {
	return p == cc.proposer(p.height, p.round)
}

func containsAddress(s []common.Address, e common.Address) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

type ConsensusManager struct {
	allow_empty_blocks        bool
	num_initial_blocks        int
	round_timeout             int
	round_timeout_factor      float64
	transaction_timeout       float64
	chain                     *BlockChain
	coinbase                  common.Address
	readyValidators           map[common.Address]struct{}
	privkey                   *ecdsa.PrivateKey
	contract                  *ConsensusContract
	tracked_protocol_failures []string
	heights                   map[int]*HeightManager
	last_valid_lockset        *types.LockSet
	last_committing_lockset   *types.LockSet
	proposalLock              *types.Block
	readyNonce                int
	blockCandidates           map[common.Hash]types.Proposal
	hdcDb                     ethdb.Database

	// create bock mu
	mu        sync.Mutex
	currentMu sync.Mutex
	uncleMu   sync.Mutex
	mux       *event.TypeMux
	extraData []byte
	gasPrice  *big.Int
}

func NewConsensusManager(chain *BlockChain, db ethdb.Database, cc *ConsensusContract, privkeyhex string, extraData []byte, gasPrice *big.Int) *ConsensusManager {
	eth := cc.eth
	return &ConsensusManager{
		allow_empty_blocks:   false,
		num_initial_blocks:   10,
		round_timeout:        3,
		round_timeout_factor: 1.5,
		transaction_timeout:  0.5,
		hdcDb:                db,
		chain:                chain,
		privkey:              crypto.HexToECDSA(privkeyhex),
		readyValidators:      make(map[common.Address]struct{}),
		heights:              make(map[int]*HeightManager),
		readyNonce:           0,
		blockCandidates:      make(map[common.Hash]types.Proposal),
		contract:             cc,
		extraData:            extraData,
		gasPrice:             gasPrice,
		mux:                  eth.EventMux(),
		coinbase:             eth.etherbase,
	}
}

// func (cm *ConsensusManager) initializeLocksets() {

// }
func (cm *ConsensusManager) initializeLocksets() {
	// initializing locksets
	// sign genesis
	v := types.NewVote(0, 0, cm.chain.genesisBlock.Hash())
	vote := &VoteBlock{Vote: v}
	cm.addVote(vote)
	// add initial lockset
	var headProposal *types.BlockProposal
	headProposal = cm.loadProposal(cm.Head().Hash())
	for _, v := range headProposal.signingLockset.votes {
		cm.addVote(v)
	}
	result, _ := cm.heights[cm.Head().header.Number-1].hasQuorum()
	if result {
		panic("initialize_locksets error")
	}
	lastCommittingLockset := cm.loadLastCommittingLockset()
	for _, v := range lastCommittingLockset.votes {
		cm.addVote(v)
	}
	result, _ = cm.heights[cm.Head().header.Number].hasQuorum()

	if result {
		panic("initialize_locksets error")
	}

}

// persist proposals and last committing lockset

func (cm *ConsensusManager) storeLastCommittingLockset(ls *types.LockSet) error {
	bytes, err := rlp.EncodeToBytes(ls)
	if err != nil {
		return err
	}
	if err := cm.hdcDb.Put("last_committing_lockset", bytes); err != nil {
		glog.Fatalf("failed to store last committing lockset into database: %v", err)
		return err
	}
	return nil
}
func (cm *ConsensusManager) loadLastCommittingLockset() *types.LockSet {
	key := fmt.Sprintf("last_committing_lockset")
	data, _ := cm.hdcDb.Get(key)
	if len(data) == 0 {
		return nil
	}
	var lockset *types.LockSet
	if err := rlp.Decode(bytes.NewReader(data), &lockset); err != nil {
		glog.V(logger.Error).Infof("invalid last_committing_lockset %v", err)
		return nil
	}
	return lockset
}

func (cm *ConsensusManager) storeProposal(p types.Proposal) {
	bytes, err := rlp.EncodeToBytes(p)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("blockproposal:%s", p.blockhash)
	if err := cm.hdcDb.Put(key, bytes); err != nil {
		glog.Fatalf("failed to store proposal into database: %v", err)
		return err
	}
	return nil
}

func (cm *ConsensusManager) loadProposal(blockhash common.Hash) types.Proposal {
	key := fmt.Sprintf("blockproposal:%s", blockhash)
	data, _ := cm.hdcDb.Get(key)
	if len(data) == 0 {
		return nil
	}
	var proposal types.Proposal
	if err := rlp.Decode(bytes.NewReader(data), &proposal); err != nil {
		glog.V(logger.Error).Infof("invalid proposal RLP for hash %x: %v", blockhash, err)
		return nil
	}
	return proposal
}
func (cm *ConsensusManager) hasProposal(blockhash common.Hash) bool {
	key := fmt.Sprintf("blockproposal:%s", blockhash)
	data, _ := cm.hdcDb.Get(key)
	if len(data) != 0 {
		return true
	}
	return false
}

// properties
func (cm *ConsensusManager) Head() *types.Block {
	return cm.chain.currentBlock
}
func (cm *ConsensusManager) Now() float64 {
	return time.Now().UnixNano()
}
func (cm *ConsensusManager) Height() int {
	h := cm.chain.currentBlock.NumberU64()
	return h
}
func (cm *ConsensusManager) Round() int {
	return cm.heights[cm.height()].round
}
func (cm *ConsensusManager) activeRound() *RoundManager {
	hm := cm.heights[cm.Height()]
	return hm.rounds[hm.Round()]
}
func (cm *ConsensusManager) setupAlarm() {
	ar := cm.activeRound()
	delay = ar.getTimeout()
	glog.V(logger.Error).Infof("in set up alarm")
	if cm.isWaitingForProposal() {
		// TODO
	}
}
func (cm *ConsensusManager) onAlarm(round *RoundManager) {
	if cm.activeRound() == round {

	}
}
func (cm *ConsensusManager) isWaitingForProposal() bool {
	if cm.allow_empty_blocks || cm.hasPendingTransactions() || cm.Height() < cm.num_initial_blocks {
		return true
	} else {
		return false
	}
}
func (cm *ConsensusManager) hasPendingTransactions() bool {
	return len(cm.chain.CurrentBlock().transactions) > 0
}
func (cm *ConsensusManager) process() {
	glog.V(logger.Info).Infoln("in process")
	if !cm.isReady() {
		cm.setupAlarm()
	}
	cm.commit()
	cm.heights[cm.Height()].process()
	cm.cleanup()
	cm.synchronizer.process()
	cm.setup_alarm()
}
func (cm *ConsensusManager) commit() bool {
	glog.V(logger.Info).Infoln("in commit")
	for hash, p := range cm.blockCandidates {
		ls = cm.heights[p.height].lastQuorumLockset()
		_, hash := ls.lockset.hasQuorum()
		if p.blockhash == hash {
			cm.storeProposal(p)
			cm.storeLastCommittingLockset(ls)
			// success := cm.pm.commitBlock(p.block)
			if success {
				glog.V(logger.Info).Infoln("commited")
				cm.commit()
				return true
			} else {
				glog.V(logger.Info).Infoln("could not commit")
			}
		} else {
			glog.V(logger.Info).Infoln("no quorum for ", p)
			if ls != nil {
				glog.V(logger.Info).Infoln("votes ", ls.votes)
			}
		}
	}
}
func (cm *ConsensusManager) cleanup() {
	for hash, p := range cm.blockCandidates {
		if cm.Head().Number() <= p.height {
			delete(cm.blockCandidates, hash)
		}
	}
	for i, h := range cm.heights {
		if cm.heights[i].height < cm.Head().Number() {
			delete(cm.heights, i)
		}
	}
}
func (cm *ConsensusManager) sign(s *types.Signed) {
	s.sign(cm.privkey)
}

func (cm *ConsensusManager) setProposalLock(block *types.Block) {

	// TODO: update this
	cm.proposalLock = block
}

func (cm *ConsensusManager) broadcast(message interface{}) bool {
	return false
}
func (cm *ConsensusManager) isReady() bool {
	return len(cm.readyValidators) > len(cm.contract.validators)*2/3
}
func (cm *ConsensusManager) sendReady() {
	r := types.NewReady(cm.readyNonce, cm.activeRound().lockset)
	cm.sign(r)
	cm.broadcast(r)
	cm.readyNonce += 1
}
func (cm *ConsensusManager) addReady(ready *types.Ready) {
	if !cm.contract.isValidators(ready.signed.sender) {
		panic("receive ready from invalid sender")
	}
	cm.readyValidators[ready.signed.sender] = struct{}{}
	if !cm.isReady() {
		cm.sendReady()
	}
}
func (cm *ConsensusManager) addVote(v *types.Vote) bool {
	if v == nil {
		panic("cm addvote error")
	}
	if !cm.contract.isValidators(v.signed.sender) {
		panic("invalid sender")
	}
	readyValidators[v.signed.sender] = struct{}{}
	// TODO FIX
	return cm.heights[v.height].addVote(v, false)
}
func (cm *ConsensusManager) addProposal(p types.Proposal) bool {
	if p.height < cm.Height() {
		glog.V(logger.Info).Infoln("proposal from past")
	}
	if !cm.contract.isValidators(p.signed.sender) || !cm.contract.isProposer(p) {
		glog.V(logger.Info).Infoln("proposal sender invalid")
		return false
	}
	if !p.lockset.isValid() {
		glog.V(logger.Info).Infoln("proposal invalid")
		return false
	}
	if !(p.lockset.height == p.height || p.round == 0) {
		glog.V(logger.Info).Infoln("proposal invalid")
		return false
	}
	if !(p.round-p.lockset.round == 1 || p.round == 0) {
		glog.V(logger.Info).Infoln("proposal invalid")
		return false
	}
	// cm.synchronizer.on_proposal(p, proto)
	cm.addLockset(p.lockset) // implicit check

	// TODO: link block

	isValid := cm.heights[p.height].addProposal(p)
	return isValid
}
func (cm *ConsensusManager) addLockset(ls *types.LockSet) bool {
	if !ls.isValid() {
		return false
	}
	for _, v := range ls {
		cm.addVote(v)
		// implicitly checks their validity
	}
}
func (cm *ConsensusManager) addBlockProposal(p *types.BlockProposal) bool {
	if cm.hasProposal(p.blockhash) {
		return false
	}
	result, _ := p.signingLockset.hasQuorum()
	if !result {
		panic("proposal error")
	}
	cm.addLockset(p.signingLockset)
	cm.blockCandidates[p.blockhash] = p
	return true
}

func (cm *ConsensusManager) lastCommittingLockset() *types.LockSet {
	return cm.heights[cm.Height()-1].lastQuorumLockset()
}
func (cm *ConsensusManager) highestCommittingLockset() *types.LockSet {
	for _, height := range cm.Heights {
		ls := height.lastQuorumLockset()
		if height.lastQuorumLockset() != nil {
			return ls
		}
	}
	return nil
}
func (cm *ConsensusManager) lastValidLockset() *types.LockSet {
	ls := cm.heights[cm.Height()].lastValidLockset()
	if ls == nil {
		return cm.lastCommittingLockset()
	}
	return ls
}

func (cm *ConsensusManager) lastLock() *types.Vote {
	return cm.heights[cm.Height()].LastVoteLock()
}
func (cm *ConsensusManager) lastBlockProposal() *types.BlockProposal {
	p := cm.heights[cm.Height()].LastVotedProposal()
	if p != nil {
		return p
	} else {
		// TODO
		// cm.get_blockproposal
		return nil
	}
}

type HeightManager struct {
	cm     *ConsensusManager
	rounds []*RoundManager
	height int
	// lastValidLockset *types.LockSet
}

func NewHeightManager(consensusmanager *ConsensusManager, height int) *HeightManager {
	glog.V(logger.Info).Infoln("Created HeightManager H:", height)
	return &HeightManager{
		cm:     consensusmanager,
		height: height,
	}
}

func (hm *HeightManager) Round() int {
	l := hm.lastValidLockset().round()
	return l + 1
}
func (hm *HeightManager) LastVoteLock() *types.Vote {
	// highest lock
	l := hm.rounds[len(sl)-1].lockset
	if l != nil {
		return l
	} else {
		return nil
	}
}
func (hm *HeightManager) LastVotedProposal() *types.Proposal {
	// the last block proposal node voted on
	b1 := hm.rounds[len(sl)-1].proposal.blockhash
	b2 := hm.rounds[len(sl)-1].voteLock.blockhash
	if b1 == b2 {
		return hm.rounds[len(sl)-1].proposal
	} else {
		return nil
	}
}
func (hm *HeightManager) lastValidLockset() *types.LockSet {
	// highest valid lockset on height
	for i := len(rounds) - 1; i >= 0; i++ {
		if hm.rounds[i].lockset.isValid() {
			return hm.rounds[i].lockset
		}
	}
	return nil
}
func (hm *HeightManager) lastQuorumLockset() *types.LockSet {
	var found *types.LockSet

	for i := len(hm.rounds) - 1; i >= 0; i++ {
		ls := hm.rounds[i].lockset.isValid()
		if result, _ := ls.hasQuorum(); ls.isValid() && result {
			if found != nil {
				panic("multiple valid lockset")
			}
			found = ls
		}
	}
	return found
}
func (hm *HeightManager) hasQuorum() (bool, common.Hash) {
	ls := hm.lastQuorumLockset()
	if ls != nil {
		return ls.hasQuorum()
	} else {
		return nil, common.Hash{}
	}
}
func (hm *HeightManager) addVote(v *types.Vote, forceReplace bool) bool {
	return hm.rounds[v.round].addVote(v, forceReplace)
}
func (hm *HeightManager) process() {
	glog.V(logger.Info).Infoln("In HM Process", hm.height)
	hm.rounds[hm.round].process()
}

type RoundManager struct {
	hm           *HeightManager
	cm           *ConsensusManager
	round        int
	height       int
	lockset      *types.LockSet
	proposal     types.Proposal
	voteLock     *types.Vote
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
func (rm *RoundManager) addVote(vote *types.Vote, force_replace bool) bool {
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
func (rm *RoundManager) addProposal(proposal *types.BlockProposal) bool {
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
	p := rm.propose()
	if p != nil {
		rm.addProposal(p)
		rm.cm.broadcast(p)
	}
	v := rm.vote()
	if v != nil {
		rm.cm.broadcast(v)
	}

}

func (rm *RoundManager) propose() *types.BlockProposal {
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
		panic("invalid round_lockset")
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
	rm.cm.setProposalLock(block)
	return blockProposal
}
func (rm *RoundManager) vote() *types.Vote {
	if rm.voteLock != nil {
		glog.V(logger.Info).Infof("voted ")
		return nil
	}
	glog.V(logger.Info).Infof("in vote")
	lastVoteLock := rm.hm.lastVoteLock
	var vote *types.Vote
	if rm.proposal != nil {
		switch t := rm.proposal.(type) {
		default:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_noquorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			switch vt := lastVoteLock.(type) {
			default: // vote to proposed vote
				glog.V(logger.Info).Infoln("voting proposed block")
				v := types.NewVote(rm.height, rm.round, rm.proposal.blockhash)
				vote = &VoteBlock{v}
			case *types.VoteBlock: //repeat vote
				glog.V(logger.Info).Infoln("voting on last vote")
				v := types.NewVote(rm.height, rm.round, lastVoteLock.blockhash)
				vote = &VoteBLock{v}
			}

		case *types.VotingInstruction: // vote for votinginstruction
			if !rm.proposal.lockset.quorumPossible() {
				panic("vote error")
			}
			glog.V(logger.Info).Infoln("voting on instruction")
			v := types.NewVote(rm.height, rm.round, rm.proposal.blockhash)
			vote = &VoteBlock{v}
		}
	} else if rm.timeout_time != 0 && rm.cm.Now() > rm.timeout_time {
		switch vt := lastVoteLock.(type) {
		default: // vote nil
			glog.V(logger.Info).Infoln("voting proposed block")
			v := types.NewVote(rm.height, rm.round, rm.proposal.blockhash)
			vote = &types.VoteNil{v}
		case *types.VoteBlock: // repeat vote
			glog.V(logger.Info).Infoln("voting on last vote")
			v := types.NewVote(rm.height, rm.round, lastVoteLock.blockhash)
			vote = &types.VoteBLock{v}
		}
	} else {
		panic("voting error")
	}
	rm.cm.sign(vote)
	rm.voteLock = vote
	rm.lockset.add(vote)
	return vote
}

func (cm *ConsensusManager) newBlock() *types.Block {
	config := cm.chain.chainConfig
	eth := cm.contract.eth

	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.uncleMu.Lock()
	defer cm.uncleMu.Unlock()
	cm.currentMu.Lock()
	defer cm.currentMu.Unlock()
	tstart := time.Now()
	parent := cm.chain.CurrentBlock()
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
		Coinbase:   cm.coinbase,
		Extra:      cm.extra,
		Time:       big.NewInt(tstamp),
	}
	// previous := self.current
	// Could potentially happen if starting to mine in an odd state.
	err := self.makeCurrent(parent, header)
	if err != nil {
		glog.V(logger.Info).Infoln("Could not create new env for mining, retrying on next block.")
		return
	}
	work := &Work{
		config:    config,
		state:     state,
		ancestors: set.New(),
		family:    set.New(),
		uncles:    set.New(),
		header:    header,
		createdAt: time.Now(),
	}

	txs := types.NewTransactionsByPriceAndNonce(eth.TxPool().Pending())
	work.commitTransactions(cm.mux, txs, cm.gasPrice, cm.chain)

	eth.TxPool().RemoveBatch(work.lowGasTxs)
	eth.TxPool().RemoveBatch(work.failedTxs)

	// compute uncles for the new block.
	// var (
	var uncles []*types.Header
	// 	badUncles []common.Hash
	// )
	// for hash, uncle := range self.possibleUncles {
	// 	if len(uncles) == 2 {
	// 		break
	// 	}
	// 	if err := self.commitUncle(work, uncle.Header()); err != nil {
	// 		if glog.V(logger.Ridiculousness) {
	// 			glog.V(logger.Detail).Infof("Bad uncle found and will be removed (%x)\n", hash[:4])
	// 			glog.V(logger.Detail).Infoln(uncle)
	// 		}
	// 		badUncles = append(badUncles, hash)
	// 	} else {
	// 		glog.V(logger.Debug).Infof("commiting %x as uncle\n", hash[:4])
	// 		uncles = append(uncles, uncle.Header())
	// 	}
	// }
	// for _, hash := range badUncles {
	// 	delete(self.possibleUncles, hash)
	// }

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
		// self.logLocalMinedBlocks(work, previous)
	}

	return work.Block
}

type Work struct {
	config        *ChainConfig
	state         *state.StateDB // apply state changes here
	ancestors     *set.Set       // ancestor set (used for checking uncle parent validity)
	family        *set.Set       // family set (used for checking uncle invalidity)
	uncles        *set.Set       // uncle set
	tcount        int            // tx count in cycle
	ownedAccounts *set.Set
	lowGasTxs     types.Transactions
	failedTxs     types.Transactions
	// localMinedBlocks *uint64RingBuffer // the most recent block numbers that were mined locally (used to check block inclusion)

	Block *types.Block // the new block

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt

	createdAt time.Time
}

func (env *Work) commitTransactions(mux *event.TypeMux, txs *types.TransactionsByPriceAndNonce, gasPrice *big.Int, bc *core.BlockChain) {
	gp := new(core.GasPool).AddGas(env.header.GasLimit)

	var coalescedLogs vm.Logs
	for {
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		from, _ := tx.From()

		// Ignore any transactions (and accounts subsequently) with low gas limits
		if tx.GasPrice().Cmp(gasPrice) < 0 && !env.ownedAccounts.Has(from) {
			// Pop the current low-priced transaction without shifting in the next from the account
			glog.V(logger.Info).Infof("Transaction (%x) below gas price (tx=%v ask=%v). All sequential txs from this address(%x) will be ignored\n", tx.Hash().Bytes()[:4], common.CurrencyToString(tx.GasPrice()), common.CurrencyToString(gasPrice), from[:4])

			env.lowGasTxs = append(env.lowGasTxs, tx)
			txs.Pop()

			continue
		}
		// Start executing the transaction
		env.state.StartRecord(tx.Hash(), common.Hash{}, 0)

		err, logs := env.commitTransaction(tx, bc, gp)
		switch {
		case core.IsGasLimitErr(err):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			glog.V(logger.Detail).Infof("Gas limit reached for (%x) in this block. Continue to try smaller txs\n", from[:4])
			txs.Pop()

		case err != nil:
			// Pop the current failed transaction without shifting in the next from the account
			glog.V(logger.Detail).Infof("Transaction (%x) failed, will be removed: %v\n", tx.Hash().Bytes()[:4], err)
			env.failedTxs = append(env.failedTxs, tx)
			txs.Pop()

		default:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()
		}
	}
	if len(coalescedLogs) > 0 || env.tcount > 0 {
		go func(logs vm.Logs, tcount int) {
			if len(logs) > 0 {
				mux.Post(core.PendingLogsEvent{Logs: logs})
			}
			if tcount > 0 {
				mux.Post(core.PendingStateEvent{})
			}
		}(coalescedLogs, env.tcount)
	}
}

func (env *Work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, gp *core.GasPool) (error, vm.Logs) {
	snap := env.state.Snapshot()

	// this is a bit of a hack to force jit for the miners
	config := env.config.VmConfig
	if !(config.EnableJit && config.ForceJit) {
		config.EnableJit = false
	}
	config.ForceJit = false // disable forcing jit

	receipt, logs, _, err := core.ApplyTransaction(env.config, bc, gp, env.state, env.header, tx, env.header.GasUsed, config)
	if err != nil {
		env.state.RevertToSnapshot(snap)
		return err, nil
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)

	return nil, logs
}
