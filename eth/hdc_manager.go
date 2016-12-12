package eth

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"hash/fnv"
	"math"
	"math/big"
	"sync"
	"time"
	// "errors"
	// "sync/atomic"
	// mrand "math/rand"
	// "runtime"
	// "io"

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
	"github.com/ethereum/go-ethereum/rlp"
	"gopkg.in/fatih/set.v0"
	// "github.com/ethereum/go-ethereum/metrics"
	// "github.com/ethereum/go-ethereum/pow"
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

func NewConsensusContract(eventMux *event.TypeMux, coinbase common.Address, txpool *core.TxPool, validators []common.Address) *ConsensusContract {
	return &ConsensusContract{
		eventMux:   eventMux,
		txpool:     txpool,
		coinbase:   coinbase,
		validators: validators,
	}
}
func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}
func (cc *ConsensusContract) proposer(height uint64, round uint64) common.Address {
	// v := abs(hash(repr((height, round))))
	s := fmt.Sprintf("(%d, %d)", height, round)

	addr := cc.validators[int(hash(s))%len(cc.validators)]
	return addr
}
func (cc *ConsensusContract) isValidators(v common.Address) bool {
	return containsAddress(cc.validators, v)
}
func (cc *ConsensusContract) isProposer(p types.Proposal) bool {
	return p.From() == cc.proposer(p.GetHeight(), p.GetRound())
}
func (cc *ConsensusContract) numEligibleVotes(height uint64) uint64 {
	if height == 0 {
		return 0
	} else {
		return uint64(len(cc.validators))
	}
}
func containsAddress(s []common.Address, e common.Address) bool {
	for _, a := range s {
		// glog.V(logger.Info).Infoln("a:", a)
		// glog.V(logger.Info).Infoln("e:", e)

		if a == e {
			return true
		}
	}
	return false
}

type ConsensusManager struct {
	pm                      *HDCProtocolManager
	isAllowEmptyBlocks      bool
	numInitialBlocks        uint64
	roundTimeout            uint64
	roundTimeoutFactor      float64
	transactionTimeout      float64
	chain                   *core.BlockChain
	coinbase                common.Address
	readyValidators         map[common.Address]struct{}
	privkey                 *ecdsa.PrivateKey
	contract                *ConsensusContract
	trackedProtocolFailures []string
	heights                 map[uint64]*HeightManager
	proposalLock            *types.Block
	readyNonce              uint64
	blockCandidates         map[common.Hash]*types.BlockProposal
	hdcDb                   ethdb.Database
	synchronizer            *HDCSynchronizer
	// lastCommittingLockset   *types.LockSet

	// create bock mu
	mu        sync.Mutex
	currentMu sync.Mutex
	uncleMu   sync.Mutex

	processMu sync.Mutex
	mux       *event.TypeMux
	extraData []byte
	gasPrice  *big.Int
}

func NewConsensusManager(manager *HDCProtocolManager, chain *core.BlockChain, db ethdb.Database, cc *ConsensusContract, privkeyhex string, extraData []byte, gasPrice *big.Int) *ConsensusManager {

	privkey, _ := crypto.HexToECDSA(privkeyhex)
	cm := &ConsensusManager{
		pm:                 manager,
		isAllowEmptyBlocks: false,
		numInitialBlocks:   10,
		roundTimeout:       3,
		roundTimeoutFactor: 1.5,
		transactionTimeout: 0.5,
		hdcDb:              db,
		chain:              chain,
		privkey:            privkey,
		readyValidators:    make(map[common.Address]struct{}),
		heights:            make(map[uint64]*HeightManager),
		readyNonce:         0,
		blockCandidates:    make(map[common.Hash]*types.BlockProposal),
		contract:           cc,
		extraData:          extraData,
		gasPrice:           gasPrice,
		mux:                cc.eventMux,
		coinbase:           cc.coinbase,
	}

	if !cm.contract.isValidators(cm.coinbase) {
		panic("Not Validators")
	}

	cm.initializeLocksets()

	// old votes don't count
	cm.readyValidators = make(map[common.Address]struct{})
	cm.readyValidators[cm.coinbase] = struct{}{}

	cm.synchronizer = NewHDCSynchronizer(cm)
	return cm
}

func (cm *ConsensusManager) initializeLocksets() {
	// initializing locksets
	// sign genesis
	glog.V(logger.Info).Infoln("initialize locksets")
	v := types.NewVote(0, 0, cm.chain.Genesis().Hash(), 1) // voteBlock

	cm.Sign(v)
	cm.AddVote(v)
	// add initial lockset
	glog.V(logger.Info).Infoln("add inintial lockset")
	headProposal := cm.loadProposal(cm.Head().Hash())
	if headProposal != nil {
		headBlockProposal := headProposal
		ls := headBlockProposal.SigningLockset

		for _, v := range ls.Votes {
			cm.AddVote(v)
		}
		headNumber := cm.Head().Header().Number.Uint64()

		result, _ := cm.getHeightManager(headNumber - 1).HasQuorum()
		if !result {
			panic("initialize_locksets error: headProposal")
		}
	}

	lastCommittingLockset := cm.loadLastCommittingLockset()
	if lastCommittingLockset != nil {
		// headNumber := cm.Head().Header().Number.Uint64()
		_, hash := lastCommittingLockset.HasQuorum()
		if hash != cm.Head().Hash() {
			panic("initialize_locksets error: lastCommittingLockset1")
		}
		for _, v := range lastCommittingLockset.Votes {
			cm.AddVote(v)
		}
		headNumber := cm.Head().Header().Number.Uint64()
		result, _ := cm.getHeightManager(headNumber).HasQuorum()
		if !result {
			panic("initialize_locksets error: lastCommittingLockset2")
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

func (cm *ConsensusManager) storeProposal(bp *types.BlockProposal) error {
	bytes, err := rlp.EncodeToBytes(bp)
	if err != nil {
		panic(err)
	}
	key := fmt.Sprintf("blockproposal:%s", bp.Blockhash())
	if err := cm.hdcDb.Put([]byte(key), bytes); err != nil {
		glog.Fatalf("failed to store proposal into database: %v", err)
		return err
	}
	return nil
}

func (cm *ConsensusManager) loadProposal(blockhash common.Hash) *types.BlockProposal {
	key := fmt.Sprintf("blockproposal:%s", blockhash)
	data, _ := cm.hdcDb.Get([]byte(key))
	if len(data) == 0 {
		return nil
	}
	var bp *types.BlockProposal
	if err := rlp.Decode(bytes.NewReader(data), &bp); err != nil {
		glog.V(logger.Error).Infof("invalid proposal RLP for hash %x: %v", blockhash, err)
		return nil
	}
	return bp
}
func (cm *ConsensusManager) getBlockProposal(blockhash common.Hash) *types.BlockProposal {
	if cm.blockCandidates[blockhash] != nil {
		return cm.blockCandidates[blockhash]
	} else {
		return cm.loadProposal(blockhash)
	}
}
func (cm *ConsensusManager) getBlockProposalByHeight(height uint64) *types.BlockProposal {
	if height >= cm.Height() {
		panic("getBlockProposalRlpByHeight error")
	} else {
		bh := cm.chain.GetBlockByNumber(uint64(height)).Hash()
		return cm.loadProposal(bh)
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
	return cm.chain.CurrentBlock()
}
func (cm *ConsensusManager) Now() int64 {
	return time.Now().Unix()
}
func (cm *ConsensusManager) Height() uint64 {
	h := cm.chain.CurrentBlock().NumberU64()
	return h + 1
}
func (cm *ConsensusManager) Round() uint64 {
	return cm.getHeightManager(cm.Height()).Round()
}
func (cm *ConsensusManager) getHeightManager(h uint64) *HeightManager {
	if _, ok := cm.heights[h]; !ok {
		fmt.Println("Create new hm in ", h)
		cm.heights[h] = NewHeightManager(cm, h)
	}
	return cm.heights[h]
}
func (cm *ConsensusManager) activeRound() *RoundManager {
	hm := cm.getHeightManager(cm.Height())
	return hm.getRoundManager(hm.Round())
}
func (cm *ConsensusManager) setupAlarm() {
	// glog.V(logger.Error).Infof("in set up alarm")

	ar := cm.activeRound()
	delay := ar.getTimeout()
	if cm.isWaitingForProposal() && delay > 0 {
		fmt.Println("delay time :", delay)
		go cm.waitProposalAlarm(ar, delay)
	} else {
		// glog.V(logger.Info).Infoln("wait txs alarm")
		go cm.waitProposalAlarm(ar, 1)
	}
}

func (cm *ConsensusManager) waitProposalAlarm(rm *RoundManager, delay float64) {
	cm.pm.eventMu.Lock()
	defer cm.pm.eventMu.Unlock()
	time.Sleep(time.Duration(delay * 1000 * 1000 * 1000))
	if cm.activeRound() == rm {
		if !cm.isReady() {
			// glog.V(logger.Info).Infoln("on Alarm")
			cm.setupAlarm()
			return
		} else if !cm.isWaitingForProposal() {
			glog.V(logger.Info).Infoln("waiting for txs")
			cm.setupAlarm()
			return
		} else {
			cm.Process()
		}
	}
}
func (cm *ConsensusManager) isWaitingForProposal() bool {
	// fmt.Println(cm.isAllowEmptyBlocks, cm.hasPendingTransactions(), cm.Height() <= cm.numInitialBlocks)
	return cm.isAllowEmptyBlocks || cm.hasPendingTransactions() || cm.Height() <= cm.numInitialBlocks
}
func (cm *ConsensusManager) hasPendingTransactions() bool {
	return len(cm.pm.txpool.Pending()) > 0
}
func (cm *ConsensusManager) Process() {
	glog.V(logger.Info).Infoln("in process")
	if !cm.isReady() {
		cm.setupAlarm()
		return
	} else {
		success := cm.commit()
		h := cm.getHeightManager(cm.Height())
		h.process()
		if success {
			cm.Process()
			return
		}
		cm.cleanup()
		// cm.synchronizer.process()
		cm.setupAlarm()
	}
}
func (cm *ConsensusManager) commit() bool {
	cm.processMu.Lock()
	defer cm.processMu.Unlock()
	glog.V(logger.Info).Infoln("blockCandidates number:", len(cm.blockCandidates))

	for _, p := range cm.blockCandidates {
		// if prehash == haed hash
		if p.Height <= cm.Head().Header().Number.Uint64() {
			//DEBUG glog.V(logger.Info).Infoln("past proposal")
			continue
		}
		ls := cm.getHeightManager(p.GetHeight()).lastQuorumLockset()
		if ls != nil {
			_, hash := ls.HasQuorum()
			if p.Blockhash() == hash {
				cm.storeProposal(p)
				cm.storeLastCommittingLockset(ls)
				success := cm.pm.commitBlock(p.Block)
				if success {
					glog.V(logger.Info).Infoln("commited")
					// cm.commit() // cause infinite loop
					return true
				} else {
					glog.V(logger.Info).Infoln("could not commit")
				}
			}
		} else {
			//DEBUG glog.V(logger.Info).Infoln("no quorum for ", p.GetHeight(), p.GetRound())
			if ls != nil {
				//DEBUG glog.V(logger.Info).Infoln("votes ", ls.Votes)
			}
		}
	}
	//DEBUG glog.V(logger.Info).Infoln("no blockcandidate to commit")
	return false
}
func (cm *ConsensusManager) cleanup() {
	glog.V(logger.Info).Infoln("in cleanup,current Head Number is ", cm.Head().Header().Number.Uint64())

	for hash, p := range cm.blockCandidates {
		if cm.Head().Header().Number.Uint64() >= p.GetHeight() {
			delete(cm.blockCandidates, hash)
		}
	}
	for i, _ := range cm.heights {
		if cm.getHeightManager(i).height < cm.Head().Header().Number.Uint64() {
			//DEBUG fmt.Println("Delete BlockCandidte", i)
			delete(cm.heights, i)
		}
	}
}
func (cm *ConsensusManager) Sign(s interface{}) {
	glog.V(logger.Info).Infoln("CM Sign")
	switch t := s.(type) {
	case *types.BlockProposal:
		t.Sign(cm.privkey)
	case *types.Vote:
		t.Sign(cm.privkey)
	case *types.LockSet:
		t.Sign(cm.privkey)
	case *types.VotingInstruction:
		t.Sign(cm.privkey)
	case *types.Ready:
		t.Sign(cm.privkey)
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
	// fmt.Println("ready has", cm.readyValidators)
	return float32(len(cm.readyValidators)) > float32(len(cm.contract.validators))*2.0/3.0
}
func (cm *ConsensusManager) SendReady(force bool) {

	if cm.isReady() && !force {
		fmt.Println("cm already ready")
		return
	}
	ls := cm.activeRound().lockset
	r := types.NewReady(big.NewInt(int64(cm.readyNonce)), ls)
	cm.Sign(r)
	r.From()
	fmt.Println("cm SendReady: ", r)
	cm.broadcast(r)
	cm.readyNonce += 1
}
func (cm *ConsensusManager) AddReady(ready *types.Ready) {
	cc := cm.contract
	addr := ready.From()
	if !cc.isValidators(addr) {
		panic("receive ready from invalid sender")
	}
	// fmt.Println("add addr:", add, "to readyValidators")
	cm.readyValidators[addr] = struct{}{}
}
func (cm *ConsensusManager) AddVote(v *types.Vote) bool {

	if v == nil {
		panic("cm addvote error")
	}
	if !cm.contract.isValidators(v.From()) {
		panic("invalid sender")
	}
	cm.readyValidators[v.From()] = struct{}{}
	// TODO FIX
	isOwnVote := (v.From() == cm.contract.coinbase)
	h := cm.getHeightManager(v.Height)
	// glog.V(logger.Info).Infoln("addVote", v.From())
	glog.V(logger.Info).Infoln("addVote to ", v.Height, v.Round)

	return h.addVote(v, isOwnVote)
}
func (cm *ConsensusManager) AddProposal(p types.Proposal, peer *peer) bool {
	if p == nil {
		panic("nil peer in cm AddProposal")
	}
	if p.GetHeight() < cm.Height() {
		glog.V(logger.Info).Infoln("proposal from past")
		return false
	}
	if !cm.contract.isValidators(p.From()) || !cm.contract.isProposer(p) {
		glog.V(logger.Info).Infoln("proposal sender invalid")
		return false
	}
	cm.readyValidators[p.From()] = struct{}{}
	// if proposal is valid

	switch proposal := p.(type) {
	case *types.BlockProposal:
		// cm.addLockset(p.LockSet()) // check validity
		glog.V(logger.Info).Infoln("adding bp in :", proposal.Height, proposal.Round)
		ls := p.LockSet()
		if !ls.IsValid() {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}

		if !(ls.Height() == proposal.Height || proposal.Round == 0) {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}

		if !(proposal.Round-ls.Round() == 1 || proposal.Round == 0) {
			glog.V(logger.Info).Infoln("proposal invalid")
			return false
		}
		if peer != nil {
			cm.synchronizer.onProposal(p, peer)
		}
		for _, v := range proposal.LockSet().Votes {
			glog.V(logger.Info).Infoln("check votes")
			cm.AddVote(v) // implicit check
		}
		if proposal.Block.Number().Uint64() != proposal.Height {
			return false
		}
		if proposal.Round != 0 && !proposal.LockSet().NoQuorum() {
			return false
		}
		if proposal.Height > cm.Height() {
			glog.V(logger.Info).Infoln("proposal from the future")
			return false
		}
		blk := cm.pm.linkBlock(proposal.Block)
		if blk == nil {
			glog.V(logger.Info).Infoln("link block: already linked or wrong block")
			lqls := cm.getHeightManager(proposal.Height).lastQuorumLockset()
			if lqls != nil {
				_, hash := lqls.HasQuorum()
				if hash == proposal.Blockhash() {
					panic("Fork Detected")
				}
			}
			return false
		}
		proposal.Block = blk
		glog.V(logger.Info).Infoln("link block success, add block proposal")
		cm.addBlockProposal(proposal)
	case *types.VotingInstruction:
		if !(proposal.LockSet().Round() == proposal.Round-1 && proposal.Height == proposal.LockSet().Height()) {
			panic("Invalid votingInstruction")
		} else if proposal.Round == 0 {
			panic("Invalid votingInstruction")
		} else if result, _ := proposal.LockSet().QuorumPossible(); !result {
			panic("Invalid votingInstruction")
		} else if result, _ := proposal.LockSet().HasQuorum(); result {
			panic("Invalid votingInstruction")
		}
	}
	isValid := cm.getHeightManager(p.GetHeight()).addProposal(p)
	return isValid
}
func (cm *ConsensusManager) addLockset(ls *types.LockSet) bool {
	if !ls.IsValid() {
		glog.V(logger.Info).Infoln("cm add LockSet is fail")
		return false
	}
	for _, v := range ls.Votes {
		cm.AddVote(v)
		// implicitly checks their validity
	}
	return true
}
func (cm *ConsensusManager) addBlockProposal(bp *types.BlockProposal) bool {
	glog.V(logger.Info).Infoln("cm add BlockProposal")

	if cm.hasProposal(bp.Blockhash()) {
		glog.V(logger.Info).Infoln("Known BlockProposal")
		return false
	}
	result, _ := bp.SigningLockset.HasQuorum()
	slH := bp.SigningLockset.Height()
	if !result || slH != bp.Height-1 {
		panic("proposal error")
	}
	for _, v := range bp.SigningLockset.Votes {
		cm.AddVote(v)
	}
	cm.blockCandidates[bp.Blockhash()] = bp
	glog.V(logger.Info).Infoln("cm add BlockProposal success")

	return true
}

func (cm *ConsensusManager) lastCommittingLockset() *types.LockSet {
	return cm.getHeightManager(cm.Height() - 1).lastQuorumLockset()
}
func (cm *ConsensusManager) HighestCommittingLockset() *types.LockSet {

	for i := len(cm.heights) - 1; i >= 0; i-- {
		index := uint64(i)

		ls := cm.getHeightManager(index).lastQuorumLockset()
		if ls != nil {
			return ls
		}
	}
	return nil
}
func (cm *ConsensusManager) lastValidLockset() *types.LockSet {
	// glog.V(logger.Info).Infoln("cm lastValidLockset ")

	ls := cm.getHeightManager(cm.Height()).lastValidLockset()

	if ls == nil {
		fmt.Println("There is no last valid lockset")
		return cm.lastCommittingLockset()
	}
	return ls
}

func (cm *ConsensusManager) lastLock() *types.Vote {
	return cm.getHeightManager(cm.Height()).LastVoteLock()
}
func (cm *ConsensusManager) lastBlockProposal() *types.BlockProposal {
	p := cm.getHeightManager(cm.Height()).LastVotedBlockProposal()
	if p != nil {
		return p
	} else {
		return cm.getBlockProposal(cm.Head().Hash())
	}
}
func (cm *ConsensusManager) mkLockSet(height uint64) *types.LockSet {
	fmt.Println("make Lockset", height, cm.contract.numEligibleVotes(height))
	return types.NewLockSet(cm.contract.numEligibleVotes(height), []*types.Vote{})
}

type HeightManager struct {
	cm     *ConsensusManager
	height uint64
	rounds map[uint64]*RoundManager
	// lastValidLockset *types.LockSet
}

func NewHeightManager(consensusmanager *ConsensusManager, height uint64) *HeightManager {
	return &HeightManager{
		cm:     consensusmanager,
		height: height,
		rounds: make(map[uint64]*RoundManager),
	}
}

func (hm *HeightManager) Round() uint64 {

	l := hm.lastValidLockset()
	if l != nil {
		if l.IsValid() {
			// glog.V(logger.Info).Infoln("hm Round()", l.Round()+1)
			return l.Round() + 1
		}
	}

	return 0
}
func (hm *HeightManager) getRoundManager(r uint64) *RoundManager {
	if _, ok := hm.rounds[r]; !ok {
		fmt.Println("Create new rM in", hm.height, r)
		hm.rounds[r] = NewRoundManager(hm, r)
	}
	return hm.rounds[r]
}
func (hm *HeightManager) LastVoteLock() *types.Vote {
	glog.V(logger.Info).Infoln("lastVoteLock ", hm.height)

	// highest lock
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		if hm.getRoundManager(index).voteLock != nil {
			return hm.getRoundManager(index).voteLock
		}
	}
	return nil
}
func (hm *HeightManager) LastVotedBlockProposal() *types.BlockProposal {
	// the last block proposal node voted on
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		switch p := hm.getRoundManager(index).proposal.(type) {
		case *types.BlockProposal:
			v := hm.getRoundManager(index).voteLock
			if p.Blockhash() == v.Blockhash {
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
	// fmt.Printf("HM has %d in %d", len(hm.rounds), hm.Round())
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		// glog.V(logger.Info).Infoln("lastvalidlockset i", i)
		if hm.getRoundManager(index).lockset.IsValid() {
			return hm.getRoundManager(index).lockset
		}
	}
	return nil
}
func (hm *HeightManager) lastQuorumLockset() *types.LockSet {
	var found *types.LockSet
	for i := 0; i < len(hm.rounds); i++ {
		index := uint64(i)
		ls := hm.getRoundManager(index).lockset
		if ls.IsValid() {
			result, _ := ls.HasQuorum()
			if result {
				if found != nil {
					fmt.Println(len(hm.rounds), index)
					panic("multiple valid lockset")
				}
				found = ls
			}
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
	r := v.Round
	return hm.getRoundManager(r).addVote(v, forceReplace)
}
func (hm *HeightManager) addProposal(p types.Proposal) bool {
	return hm.getRoundManager(p.GetRound()).addProposal(p)
}
func (hm *HeightManager) process() {
	//DEBUG glog.V(logger.Info).Infoln("In HM Process", hm.height)
	r := hm.Round()

	hm.getRoundManager(r).process()
	//DEBUG glog.V(logger.Info).Infoln("end HM Process")
}

type RoundManager struct {
	hm             *HeightManager
	cm             *ConsensusManager
	round          uint64
	height         uint64
	lockset        *types.LockSet
	proposal       types.Proposal
	voteLock       *types.Vote
	timeoutTime    float64
	roundProcessMu sync.Mutex
}

func NewRoundManager(heightmanager *HeightManager, round uint64) *RoundManager {
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
	if rm.timeoutTime != 0 || rm.proposal != nil {
		return 0
	}
	now := rm.cm.Now()
	roundTimeout := rm.cm.roundTimeout
	roundTimeoutFactor := rm.cm.roundTimeoutFactor
	delay := float64(roundTimeout) * math.Pow(roundTimeoutFactor, float64(rm.round))
	rm.timeoutTime = float64(now) + delay
	return delay
}
func (rm *RoundManager) addVote(vote *types.Vote, force_replace bool) bool {
	//DEBUG glog.V(logger.Info).Infoln("In RM addvote", vote)
	if !rm.lockset.Contain(vote) {
		success := rm.lockset.Add(vote, force_replace)
		// report faliure
		if rm.lockset.IsValid() {
			if rm.proposal == nil && rm.lockset.NoQuorum() {
				glog.V(logger.Info).Infof("FailedToProposeEvidence")
				rm.cm.trackedProtocolFailures = append(rm.cm.trackedProtocolFailures, "FailedToProposeEvidence")
			}
		}
		glog.V(logger.Info).Infoln("added", success)
		return success
	}
	//DEBUG glog.V(logger.Info).Infof("vote already in lockset")
	return false
}
func (rm *RoundManager) addProposal(p types.Proposal) bool {
	if rm.proposal == nil {
		rm.proposal = p
		return true
	} else if rm.proposal.Blockhash() == p.Blockhash() {
		return true
	} else {
		fmt.Println(rm.proposal, p)
		panic("add_proposal error")
	}
}
func (rm *RoundManager) process() {
	rm.roundProcessMu.Lock()
	defer rm.roundProcessMu.Unlock()
	//DEBUG glog.V(logger.Info).Infoln("In RM Process", rm.height, rm.round)

	if rm.cm.Round() != rm.round {
		glog.V(logger.Info).Infof("round process error")
	}
	if rm.cm.Height() != rm.height {
		glog.V(logger.Info).Infof("round process error")
	}

	p := rm.propose()
	switch proposal := p.(type) {
	case *types.BlockProposal:
		if proposal != nil {
			rm.cm.addBlockProposal(proposal)
			rm.cm.broadcast(proposal)
		}
	case *types.VotingInstruction:
		rm.cm.broadcast(proposal)
	}
	v := rm.vote()
	if v != nil {
		rm.cm.broadcast(v)
	}
}

func (rm *RoundManager) propose() types.Proposal {

	if !rm.cm.isWaitingForProposal() {
		glog.V(logger.Info).Infof("proposing is not waiting for proposal")
		return nil
	}
	proposer := rm.cm.contract.proposer(rm.height, rm.round)
	if proposer != rm.cm.coinbase {
		glog.V(logger.Info).Infoln("I am not proposer in", rm.height, rm.round)
		return nil
	}
	glog.V(logger.Info).Infoln("I am a proposer in ", rm.height, rm.round)
	if rm.proposal != nil {
		if rm.proposal.From() != rm.cm.coinbase {
			glog.V(logger.Info).Infof(rm.proposal.From().Hex(), rm.cm.coinbase.Hex())
			panic("Propose Error: coinbase not the same")
		}
		if rm.voteLock == nil {
			panic("Propose Error: voteLock nil")
		}
		glog.V(logger.Info).Infoln("already propose in this HR", rm.height, rm.round)
		return rm.proposal
	}
	round_lockset := rm.cm.lastValidLockset()
	if round_lockset == nil {
		glog.V(logger.Info).Infof("no valid round lockset for height")
		return nil
	}
	var proposal types.Proposal
	quorum, _ := round_lockset.HasQuorum()
	quroumpossible, _ := round_lockset.QuorumPossible()
	if round_lockset.Height() == rm.height && quorum {
		glog.V(logger.Info).Infof("have quorum on height, not proposing")
		return nil
	} else if rm.round == 0 || round_lockset.NoQuorum() {
		proposal = rm.mkProposal()
	} else if quroumpossible {
		proposal = types.NewVotingInstruction(rm.height, rm.round, round_lockset)
		rm.cm.Sign(proposal)
	} else {
		panic("invalid round_lockset")
	}
	rm.proposal = proposal

	return proposal
}

func (rm *RoundManager) mkProposal() *types.BlockProposal {
	var roundLockset *types.LockSet
	signingLockset := rm.cm.lastCommittingLockset().Copy()
	if rm.round > 0 {
		roundLockset = rm.cm.lastValidLockset().Copy()
		if !roundLockset.NoQuorum() {
			panic("MkProposal Error")
		}
	} else {
		roundLockset = nil
	}
	isQuorum, _ := signingLockset.HasQuorum()
	if !isQuorum {
		panic("mkProposal error")
	}
	if !(roundLockset != nil || rm.round == 0) {
		panic("mkProposal error")
	}
	block := rm.cm.newBlock()
	blockProposal := types.NewBlockProposal(rm.height, rm.round, block, signingLockset, roundLockset)
	rm.cm.Sign(blockProposal)
	rm.cm.setProposalLock(block)
	return blockProposal
}
func (rm *RoundManager) vote() *types.Vote {

	if rm.voteLock != nil {
		glog.V(logger.Info).Infof("voted")
		return nil
	}
	glog.V(logger.Info).Infoln("in vote in RM", rm.height, rm.round)
	lastVoteLock := rm.hm.LastVoteLock()

	var vote *types.Vote
	if rm.proposal != nil {
		switch bp := rm.proposal.(type) {
		case *types.VotingInstruction: // vote for votinginstruction

			quorumPossible, _ := bp.LockSet().QuorumPossible()
			if !quorumPossible {
				panic("vote error")
			}

			glog.V(logger.Info).Infoln("voting on instruction")
			vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
		default:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_NoQuorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			if lastVoteLock == nil {
				glog.V(logger.Info).Infoln("voting on new proporsal")
				vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
			} else {
				vt := lastVoteLock.VoteType
				switch vt {
				case 1: //repeat vote
					glog.V(logger.Info).Infoln("voting on last vote")
					vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash, 1)
				default: // vote to proposed vote
					glog.V(logger.Info).Infoln("voting proposed block")
					vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 1)
				}
			}
		}
	} else if rm.timeoutTime != 0 && float64(rm.cm.Now()) > rm.timeoutTime {
		glog.V(logger.Info).Infoln("voting timeout", float64(rm.cm.Now()), rm.timeoutTime)
		if lastVoteLock == nil {
			glog.V(logger.Info).Infoln("rm proposal", rm.proposal)
			vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
		} else {
			vt := lastVoteLock.VoteType

			switch vt {
			case 1: // repeat vote
				glog.V(logger.Info).Infoln("voting on last vote")
				vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash, 1)
			default: // vote nil
				glog.V(logger.Info).Infoln("voting proposed block")
				vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
			}
		}
	} else {
		return nil
	}
	rm.cm.Sign(vote)
	rm.voteLock = vote
	glog.V(logger.Info).Infoln("vote success in H:", rm.height, vote)

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
		Difficulty: core.CalcDifficulty(config, uint64(tstamp), parent.Time().Uint64(), parent.Number(), parent.Difficulty()),
		GasLimit:   core.CalcGasLimit(parent),
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
	core.AccumulateRewards(work.state, header, uncles)
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
