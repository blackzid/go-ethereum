package eth

import (
	"bytes"
	"crypto/ecdsa"
	// "errors"
	"fmt"
	// "io"
	"math"
	"math/big"
	// mrand "math/rand"
	// "runtime"
	"sync"
	// "sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
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
	// eth eth.Ethereum
	eventMux   *event.TypeMux
	coinbase   common.Address
	txpool     *core.TxPool
	validators []common.Address
}

func NewConsensusContract(eventMux *event.TypeMux, coinbase common.Address, txpool *TxPool, validators []common.Address) *ConsensusContract {
	return &ConsensusContract{
		eventMux:   eventMux,
		txpool:     txpool,
		coinbase:   coinbase,
		validators: validators,
	}
}
func (cc *ConsensusContract) proposer(height int, round int) common.Address {
	// v := abs(hash(repr((height, round))))
	v := 3
	return cc.validators[v%len(cc.validators)]
}
func (cc *ConsensusContract) isValidators(v common.Address) bool {
	glog.V(logger.Info).Infoln("isvalidator ,", len(cc.validators))

	return containsAddress(cc.validators, v)
}
func (cc *ConsensusContract) isProposer(p types.Proposal) bool {
	return p.Sender() == cc.proposer(p.Height(), p.Round())
}
func (cc *ConsensusContract) numEligibleVotes(height int) int {
	if height == 0 {
		return 0
	} else {
		return len(cc.validators)
	}
}
func containsAddress(s []common.Address, e common.Address) bool {
	for _, a := range s {
		glog.V(logger.Info).Infoln("a:", a)
		glog.V(logger.Info).Infoln("e:", e)

		if a == e {
			return true
		}
	}
	return false
}

type ConsensusManager struct {
	pm                        *HDCProtocolManager
	allow_empty_blocks        bool
	num_initial_blocks        int
	round_timeout             int
	round_timeout_factor      float64
	transaction_timeout       float64
	chain                     *core.BlockChain
	coinbase                  common.Address
	readyValidators           map[common.Address]struct{}
	privkey                   *ecdsa.PrivateKey
	contract                  *ConsensusContract
	tracked_protocol_failures []string
	heights                   map[int]*HeightManager
	last_committing_lockset   *types.LockSet
	proposalLock              *types.Block
	readyNonce                int
	blockCandidates           map[common.Hash]*types.BlockProposal
	hdcDb                     ethdb.Database
	broadcastFilter           *set.Set
	// create bock mu
	mu        sync.Mutex
	currentMu sync.Mutex
	uncleMu   sync.Mutex
	mux       *event.TypeMux
	extraData []byte
	gasPrice  *big.Int
}

func NewConsensusManager(chain *core.BlockChain, db ethdb.Database, cc *ConsensusContract, privkeyhex string, extraData []byte, gasPrice *big.Int) *ConsensusManager {

	privkey, _ := crypto.HexToECDSA(privkeyhex)
	cm := &ConsensusManager{
		allow_empty_blocks:   false,
		num_initial_blocks:   10,
		round_timeout:        3,
		round_timeout_factor: 1.5,
		transaction_timeout:  0.5,
		hdcDb:                db,
		chain:                chain,
		privkey:              privkey,
		readyValidators:      make(map[common.Address]struct{}),
		heights:              make(map[int]*HeightManager),
		readyNonce:           0,
		blockCandidates:      make(map[common.Hash]*types.BlockProposal),
		contract:             cc,
		extraData:            extraData,
		gasPrice:             gasPrice,
		mux:                  cc.eventMux,
		coinbase:             cc.coinbase,
		broadcastFilter:      set.New(),
	}
	cm.readyValidators[cm.coinbase] = struct{}{}
	cm.initializeLocksets()
	return cm
}

// func (cm *ConsensusManager) initializeLocksets() {

// }
func (cm *ConsensusManager) initializeLocksets() {
	// initializing locksets
	// sign genesis
	glog.V(logger.Info).Infoln("initialize locksets")
	v := types.NewVote(0, 0, cm.chain.genesisBlock.Hash(), 1) // voteBlock

	cm.Sign(v)
	cm.addVote(v)
	// add initial lockset
	glog.V(logger.Info).Infoln("add inintial lockset")
	headProposal := cm.loadProposal(cm.Head().Hash())
	if headProposal != nil {
		headBlockProposal := headProposal.(*types.BlockProposal)
		ls := headBlockProposal.SigningLockset()

		for _, v := range ls.Votes() {
			cm.addVote(v)
		}
		headNumber := int(cm.Head().Header().Number.Int64())

		result, _ := cm.heights[headNumber-1].HasQuorum()
		if result {
			panic("initialize_locksets error")
		}
	}

	lastCommittingLockset := cm.loadLastCommittingLockset()
	if lastCommittingLockset != nil {
		for _, v := range lastCommittingLockset.Votes() {
			cm.addVote(v)
		}
		headNumber := int(cm.Head().Header().Number.Int64())
		result, _ := cm.heights[headNumber].HasQuorum()

		if result {
			panic("initialize_locksets error")
		}
	} else if int(cm.Head().Header().Number.Int64()) != 0 {
		panic("not init state")
	}
}

// persist proposals and last committing lockset

func (cm *ConsensusManager) storeLastCommittingLockset(ls *types.LockSet) error {
	bytes, err := rlp.EncodeToBytes(ls)
	if err != nil {
		return err
	}
	if err := cm.hdcDb.Put([]byte("last_committing_lockset"), bytes); err != nil {
		glog.Fatalf("failed to store last committing lockset into database: %v", err)
		return err
	}
	return nil
}
func (cm *ConsensusManager) loadLastCommittingLockset() *types.LockSet {
	key := fmt.Sprintf("last_committing_lockset")
	data, _ := cm.hdcDb.Get([]byte(key))
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

func (cm *ConsensusManager) storeProposal(p types.Proposal) error {
	bytes, err := rlp.EncodeToBytes(p)
	if err != nil {
		return err
	}
	bp := p.(*types.BlockProposal)
	key := fmt.Sprintf("blockproposal:%s", bp.Blockhash())
	if err := cm.hdcDb.Put([]byte(key), bytes); err != nil {
		glog.Fatalf("failed to store proposal into database: %v", err)
		return err
	}
	return nil
}

func (cm *ConsensusManager) loadProposal(blockhash common.Hash) types.Proposal {
	key := fmt.Sprintf("blockproposal:%s", blockhash)
	data, _ := cm.hdcDb.Get([]byte(key))
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
func (cm *ConsensusManager) getBlockProposal(blockhash common.Hash) *types.BlockProposal {
	if cm.blockCandidates[blockhash] != nil {
		return cm.blockCandidates[blockhash]
	} else {
		return cm.loadProposal(blockhash).(*types.BlockProposal)
	}
}
func (cm *ConsensusManager) hasProposal(blockhash common.Hash) bool {
	key := fmt.Sprintf("blockproposal:%s", blockhash)
	data, _ := cm.hdcDb.Get([]byte(key))
	if len(data) != 0 {
		return true
	}
	return false
}

// properties
func (cm *ConsensusManager) Head() *types.Block {
	return cm.chain.currentBlock
}
func (cm *ConsensusManager) Now() int64 {
	return time.Now().Unix()
}
func (cm *ConsensusManager) Height() int {

	h := cm.chain.currentBlock.NumberU64()
	glog.V(logger.Info).Infoln("cm Height()", int(h)+1)

	return int(h) + 1
}
func (cm *ConsensusManager) Round() int {
	glog.V(logger.Info).Infoln("cm round")

	return cm.heights[cm.Height()].Round()
}
func (cm *ConsensusManager) activeRound() *RoundManager {
	hm := cm.heights[cm.Height()]
	return hm.rounds[hm.Round()]
}
func (cm *ConsensusManager) setupAlarm() {
	// ar := cm.activeRound()
	// delay := ar.getTimeout()
	glog.V(logger.Error).Infof("in set up alarm")
	// if cm.isWaitingForProposal() {
	// 	// TODO
	// }
}
func (cm *ConsensusManager) onAlarm(round *RoundManager) {
	// if cm.activeRound() == round {

	// }
}
func (cm *ConsensusManager) isWaitingForProposal() bool {
	if cm.allow_empty_blocks || cm.hasPendingTransactions() || cm.Height() < cm.num_initial_blocks {
		return true
	} else {
		return false
	}
}
func (cm *ConsensusManager) hasPendingTransactions() bool {
	return len(cm.chain.CurrentBlock().Transactions()) > 0
}
func (cm *ConsensusManager) Process() {
	glog.V(logger.Info).Infoln("in process")
	if !cm.isReady() {
		cm.setupAlarm()
	}
	cm.commit()
	glog.V(logger.Info).Infoln("in cm process:", cm.Height())
	if _, ok := cm.heights[cm.Height()]; !ok {
		cm.heights[cm.Height()] = NewHeightManager(cm, cm.Height())
	}
	cm.heights[cm.Height()].process()
	cm.cleanup()
	// cm.synchronizer.process()
	cm.setupAlarm()
	glog.V(logger.Info).Infoln("end cm process:", cm.Height())

}
func (cm *ConsensusManager) commit() bool {
	glog.V(logger.Info).Infoln("in commit")

	for _, p := range cm.blockCandidates {
		// if prehash == haed hash
		glog.V(logger.Info).Infoln("in commit: height:%s", p.Height())
		ls := cm.heights[p.Height()].lastQuorumLockset()
		_, hash := ls.HasQuorum()

		if p.Blockhash() == hash {
			cm.storeProposal(p)
			cm.storeLastCommittingLockset(ls)
			// may use channel
			// success := cm.pm.commitBlock(p.block)
			if false {
				glog.V(logger.Info).Infoln("commited")
				cm.commit()
				return true
			} else {
				glog.V(logger.Info).Infoln("could not commit")
			}
		} else {
			glog.V(logger.Info).Infoln("no quorum for ", p)
			if ls != nil {
				glog.V(logger.Info).Infoln("votes ", ls.Votes())
			}
		}
	}
	glog.V(logger.Info).Infoln("end CM commit")
	return true
}
func (cm *ConsensusManager) cleanup() {
	glog.V(logger.Info).Infoln("in cleanup")

	for hash, p := range cm.blockCandidates {
		if int(cm.Head().Header().Number.Int64()) <= p.Height() {
			delete(cm.blockCandidates, hash)
		}
	}
	for i, _ := range cm.heights {
		if cm.heights[i].height < int(cm.Head().Header().Number.Int64()) {
			delete(cm.heights, i)
		}
	}
	glog.V(logger.Info).Infoln("end cleanup")

}
func (cm *ConsensusManager) Sign(s interface{}) {
	glog.V(logger.Info).Infoln("CM Sign")
	switch s.(type) {
	case *types.BlockProposal:
		s.(*types.BlockProposal).Sign(cm.privkey)
	case *types.Vote:
		s.(*types.Vote).Sign(cm.privkey)
	case *types.LockSet:
		s.(*types.LockSet).Sign(cm.privkey)
	case *types.VotingInstruction:
		s.(*types.VotingInstruction).Sign(cm.privkey)
	default:
		glog.V(logger.Info).Infoln("consensus mangaer sign error")
	}
}

func (cm *ConsensusManager) setProposalLock(block *types.Block) {

	// TODO: update this
	cm.proposalLock = block
}

func (cm *ConsensusManager) broadcast(msg interface{}) {
	cm.pm.Broadcast(msg)
}
func (cm *ConsensusManager) isReady() bool {
	return len(cm.readyValidators) > len(cm.contract.validators)*2/3
}
func (cm *ConsensusManager) sendReady() {
	r := types.NewReady(big.NewInt(int64(cm.readyNonce)), cm.activeRound().lockset)
	cm.Sign(r)
	cm.broadcast(r)
	cm.readyNonce += 1
}
func (cm *ConsensusManager) addReady(ready *types.Ready) {
	if !cm.contract.isValidators(ready.Sender()) {
		panic("receive ready from invalid sender")
	}
	cm.readyValidators[ready.Sender()] = struct{}{}
	if !cm.isReady() {
		cm.sendReady()
	}
}
func (cm *ConsensusManager) addVote(v *types.Vote) bool {
	glog.V(logger.Info).Infoln("addVote", v.Sender())

	if v == nil {
		panic("cm addvote error")
	}
	if !cm.contract.isValidators(v.Sender()) {
		panic("invalid sender")
	}
	glog.V(logger.Info).Infoln("addVote")

	cm.readyValidators[v.Sender()] = struct{}{}
	// TODO FIX

	if _, ok := cm.heights[v.Height()]; !ok {
		cm.heights[v.Height()] = NewHeightManager(cm, v.Height())
	}
	glog.V(logger.Info).Infoln("addVote: ", cm.heights[v.Height()])
	return cm.heights[v.Height()].addVote(v, false)
}
func (cm *ConsensusManager) AddProposal(p types.Proposal) bool {
	if p.Height() < cm.Height() {
		glog.V(logger.Info).Infoln("proposal from past")
	}
	if !cm.contract.isValidators(p.Sender()) || !cm.contract.isProposer(p) {
		glog.V(logger.Info).Infoln("proposal sender invalid")
		return false
	}

	// if proposal is valid

	switch p := p.(type) {
	case *types.BlockProposal:
		// cm.addLockset(p.LockSet()) // check validity

		ls := p.LockSet()
		if !ls.IsValid() {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}
		if !(ls.Height() == p.Height() || p.Round() == 0) {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}

		if !(p.Round()-ls.Round() == 1 || p.Round() == 0) {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}
		// cm.synchronizer.on_proposal(p, proto)

		// TODO: link block
		cm.addLockset(p.LockSet()) // implicit check
		isValid := cm.heights[p.Height()].addProposal(p)
		return isValid
	default:
		glog.V(logger.Info).Infoln("proposal type invalid")
		return false
	}

	return false
}
func (cm *ConsensusManager) addLockset(ls *types.LockSet) bool {
	if !ls.IsValid() {
		return false
	}
	for _, v := range ls.Votes() {
		cm.addVote(v)
		// implicitly checks their validity
	}
	return true
}
func (cm *ConsensusManager) addBlockProposal(p *types.BlockProposal) bool {
	if cm.hasProposal(p.Blockhash()) {
		return false
	}
	result, _ := p.SigningLockset().HasQuorum()
	if !result {
		panic("proposal error")
	}
	cm.addLockset(p.SigningLockset())
	cm.blockCandidates[p.Blockhash()] = p
	return true
}

func (cm *ConsensusManager) lastCommittingLockset() *types.LockSet {
	if cm.Height()-1 == 0 { // committing first block
		return nil
	}
	return cm.heights[cm.Height()-1].lastQuorumLockset()
}
func (cm *ConsensusManager) highestCommittingLockset() *types.LockSet {
	for _, height := range cm.heights {
		ls := height.lastQuorumLockset()
		if height.lastQuorumLockset() != nil {
			return ls
		}
	}
	return nil
}
func (cm *ConsensusManager) lastValidLockset() *types.LockSet {
	glog.V(logger.Info).Infoln("cm lastValidLockset ")

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
	p := cm.heights[cm.Height()].LastVotedBlockProposal()
	if p != nil {
		return p
	} else {
		return cm.getBlockProposal(cm.Head().Hash())
	}
}
func (cm *ConsensusManager) mkLockSet(height int) *types.LockSet {
	return types.NewLockSet(cm.contract.numEligibleVotes(height), []*types.Vote{})
}

type HeightManager struct {
	cm     *ConsensusManager
	height int
	rounds map[int]*RoundManager
	// lastValidLockset *types.LockSet
}

func NewHeightManager(consensusmanager *ConsensusManager, height int) *HeightManager {
	glog.V(logger.Info).Infoln("Created HeightManager H:", height)
	return &HeightManager{
		cm:     consensusmanager,
		height: height,
		rounds: make(map[int]*RoundManager),
	}
}

func (hm *HeightManager) Round() int {

	l := hm.lastValidLockset()
	if l != nil {
		if l.IsValid() {
			glog.V(logger.Info).Infoln("hm Round()", l.Round()+1)
			return l.Round() + 1
		}
	}
	glog.V(logger.Info).Infoln("hm Round()", 0)

	return 0
}
func (hm *HeightManager) LastVoteLock() *types.Vote {
	// highest lock
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		if hm.rounds[i].voteLock != nil {
			return hm.rounds[i].voteLock
		}
	}
	return nil
}
func (hm *HeightManager) LastVotedBlockProposal() *types.BlockProposal {
	// the last block proposal node voted on
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		switch p := hm.rounds[i].proposal.(type) {
		case *types.BlockProposal:
			v := hm.rounds[i].voteLock
			if p.Blockhash() == v.Blockhash() {
				return p
			}
		default:
			return nil
		}
	}
	return nil
}
func (hm *HeightManager) lastValidLockset() *types.LockSet {
	// highest valid lockset on height
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		glog.V(logger.Info).Infoln("lastValidLockset in ", i, hm.rounds[i].round)
		if hm.rounds[i].lockset.IsValid() {
			return hm.rounds[i].lockset
		}
	}
	glog.V(logger.Info).Infoln("end lastValidLockset ")
	return nil
}
func (hm *HeightManager) lastQuorumLockset() *types.LockSet {
	var found *types.LockSet
	for i := len(hm.rounds) - 1; i >= 0; i++ {
		ls := hm.rounds[i].lockset
		result, _ := ls.HasQuorum()
		if ls.IsValid() && result {
			if found != nil {
				panic("multiple valid lockset")
			}
			found = ls
		}
	}
	return found
}
func (hm *HeightManager) HasQuorum() (bool, common.Hash) {
	ls := hm.lastQuorumLockset()
	if ls != nil {
		return ls.HasQuorum()
	} else {
		return false, common.Hash{}
	}
}
func (hm *HeightManager) addVote(v *types.Vote, forceReplace bool) bool {
	glog.V(logger.Info).Infoln("hm addvote:", hm)

	r := v.Round()
	glog.V(logger.Info).Infoln("hm addvote: hm", hm)
	if _, ok := hm.rounds[r]; !ok {
		hm.rounds[r] = NewRoundManager(hm, r)
	}
	return hm.rounds[r].addVote(v, forceReplace)
}
func (hm *HeightManager) addProposal(p types.Proposal) bool {
	return hm.rounds[p.Round()].addProposal(p)
}
func (hm *HeightManager) process() {
	glog.V(logger.Info).Infoln("In HM Process", hm.height)
	r := hm.Round()
	if _, ok := hm.rounds[r]; !ok {
		hm.rounds[r] = NewRoundManager(hm, r)
	}

	hm.rounds[r].process()
	glog.V(logger.Info).Infoln("end HM Process")

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
	glog.V(logger.Info).Infoln("new rm", round)
	lockset := heightmanager.cm.mkLockSet(heightmanager.height)
	return &RoundManager{
		hm:      heightmanager,
		cm:      heightmanager.cm,
		round:   round,
		height:  heightmanager.height,
		lockset: lockset,
	}
}
func (rm *RoundManager) getTimeout() float64 {
	now := rm.cm.Now()
	round_timeout := rm.cm.round_timeout
	round_timeout_factor := rm.cm.round_timeout_factor
	delay := float64(round_timeout) * math.Pow(round_timeout_factor, float64(rm.round))
	rm.timeout_time = float64(now) + delay
	return delay
}
func (rm *RoundManager) addVote(vote *types.Vote, force_replace bool) bool {
	glog.V(logger.Info).Infoln("In RM addvote", vote)
	if !rm.lockset.Contain(vote) {
		success := rm.lockset.Add(vote, force_replace)
		// report faliure
		if rm.lockset.IsValid() {
			hasquroum, _ := rm.lockset.HasQuorum()
			if rm.proposal != nil && hasquroum {
				glog.V(logger.Error).Infof("FailedToProposeEvidence")
				rm.cm.tracked_protocol_failures = append(rm.cm.tracked_protocol_failures, "FailedToProposeEvidence")
			}
		}
		return success
	}
	glog.V(logger.Error).Infof("vote already in lockset")
	return false
}
func (rm *RoundManager) addProposal(p types.Proposal) bool {
	if rm.proposal != nil || rm.proposal == p {
		glog.V(logger.Error).Infof("add_proposal error")
	}
	rm.proposal = p

	return true
}
func (rm *RoundManager) process() {
	glog.V(logger.Info).Infoln("In RM Process", rm.height, rm.round)

	if rm.cm.Round() != rm.round {
		glog.V(logger.Error).Infof("round process error")
	}
	if rm.cm.Height() != rm.height {
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

func (rm *RoundManager) propose() types.Proposal {
	if !rm.cm.isWaitingForProposal() {
		glog.V(logger.Error).Infof("round propose error")
		return nil
	}
	proposer := rm.cm.contract.proposer(rm.height, rm.round)
	glog.V(logger.Error).Infof("in propose")
	if proposer != rm.cm.coinbase {
		return nil
	}
	glog.V(logger.Error).Infof("is proposer")

	round_lockset := rm.cm.lastValidLockset()
	if round_lockset == nil {
		glog.V(logger.Error).Infof("no valid round lockset for height")
		return nil
	}
	glog.V(logger.Info).Infoln("creating proposal")

	var proposal types.Proposal
	quorum, _ := round_lockset.HasQuorum()
	quroumpossible, _ := round_lockset.QuorumPossible()
	glog.V(logger.Info).Infoln("creating proposal2")

	if round_lockset.Height() == rm.height && quorum {
		glog.V(logger.Error).Infof("have quorum on height, not proposing")
		return nil
	} else if rm.round == 0 || round_lockset.NoQuorum() {
		proposal = rm.mk_proposal()
	} else if quroumpossible {
		proposal = types.NewVotingInstruction(rm.height, rm.round, round_lockset)
		rm.cm.Sign(proposal)
	} else {
		panic("invalid round_lockset")
	}
	rm.proposal = proposal
	glog.V(logger.Info).Infof("created proposal")

	return proposal
}

func (rm *RoundManager) mk_proposal() *types.BlockProposal {
	var round_lockset *types.LockSet
	signing_lockset := rm.cm.last_committing_lockset.Copy()
	if rm.round > 0 {
		round_lockset = rm.cm.lastValidLockset().Copy()
	} else {
		round_lockset = nil
	}
	isQuorum, _ := signing_lockset.HasQuorum()
	if !isQuorum {
		panic("mk_proposal error")
	}
	if round_lockset != nil || rm.round == 0 {
		panic("mk_proposal error")
	}
	block := rm.cm.newBlock()
	blockProposal := types.NewBlockProposal(rm.height, rm.round, block, signing_lockset, round_lockset)
	rm.cm.Sign(blockProposal)
	rm.cm.setProposalLock(block)
	return blockProposal
}
func (rm *RoundManager) vote() *types.Vote {
	if rm.voteLock != nil {
		glog.V(logger.Info).Infof("voted ")
		return nil
	}
	glog.V(logger.Info).Infof("in vote")
	lastVoteLock := rm.hm.LastVoteLock()
	var vote *types.Vote
	if rm.proposal != nil {
		switch t := rm.proposal.(type) {
		default:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_NoQuorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			vt := lastVoteLock.VoteType
			switch vt {
			default: // vote to proposed vote
				glog.V(logger.Info).Infoln("voting proposed block")
				vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 1)
			case 1: //repeat vote
				glog.V(logger.Info).Infoln("voting on last vote")
				vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash(), 1)
			}
		case *types.VotingInstruction: // vote for votinginstruction
			quorumPossible, _ := t.LockSet().QuorumPossible()
			if !quorumPossible {
				panic("vote error")
			}
			glog.V(logger.Info).Infoln("voting on instruction")
			vote = types.NewVote(rm.height, rm.round, t.Blockhash(), 1)
		}
	} else if rm.timeout_time != 0 && float64(rm.cm.Now()) > rm.timeout_time {
		vt := lastVoteLock.VoteType
		switch vt {
		case 1: // repeat vote
			glog.V(logger.Info).Infoln("voting on last vote")
			vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash(), 1)
		default: // vote nil
			glog.V(logger.Info).Infoln("voting proposed block")
			vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 2)
		}
	} else {
		return nil
	}
	rm.cm.Sign(vote)
	rm.voteLock = vote
	glog.V(logger.Info).Infoln("rm vote():", vote)

	rm.lockset.Add(vote, false)
	return vote
}

func (cm *ConsensusManager) newBlock() *types.Block {
	config := cm.chain.Config()
	// eth := cm.contract.eth
	contract := cm.contract

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
		Difficulty: CalcDifficulty(config, uint64(tstamp), parent.Time().Uint64(), parent.Number(), parent.Difficulty()),
		GasLimit:   CalcGasLimit(parent),
		GasUsed:    new(big.Int),
		Coinbase:   cm.coinbase,
		Extra:      cm.extraData,
		Time:       big.NewInt(tstamp),
	}
	// previous := self.current
	// Could potentially happen if starting to mine in an odd state.
	// err := self.makeCurrent(parent, header)
	// if err != nil {
	// 	glog.V(logger.Info).Infoln("Could not create new env for mining, retrying on next block.")
	// 	return
	// }
	state, err := cm.chain.StateAt(parent.Root())
	if err != nil {
		panic(err)
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

	txs := types.NewTransactionsByPriceAndNonce(contract.txpool.Pending())
	work.commitTransactions(cm.mux, txs, cm.gasPrice, cm.chain)

	contract.txpool.RemoveBatch(work.lowGasTxs)
	contract.txpool.RemoveBatch(work.failedTxs)

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

	// if atomic.LoadInt32(&self.mining) == 1 {
	// commit state root after all state transitions.
	AccumulateRewards(work.state, header, uncles)
	header.Root = work.state.IntermediateRoot()
	// }

	// create the new block whose nonce will be mined.
	work.Block = types.NewBlock(header, work.txs, uncles, work.receipts)

	// We only care about logging if we're actually mining.
	// if atomic.LoadInt32(&self.mining) == 1 {
	glog.V(logger.Info).Infof("create new work on block %v with %d txs & %d uncles. Took %v\n", work.Block.Number(), work.tcount, len(uncles), time.Since(tstart))
	// self.logLocalMinedBlocks(work, previous)
	// }

	return work.Block
}

type Work struct {
	config        *core.ChainConfig
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
	gp := new(GasPool).AddGas(env.header.GasLimit)

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
		case IsGasLimitErr(err):
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
				mux.Post(PendingLogsEvent{Logs: logs})
			}
			if tcount > 0 {
				mux.Post(PendingStateEvent{})
			}
		}(coalescedLogs, env.tcount)
	}
}

func (env *Work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, gp *GasPool) (error, vm.Logs) {
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
