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
	if addr, err := p.From(); err != nil {
		glog.V(logger.Error).Infof("invalid sender %v", err)
		return false
	} else {
		return addr == cc.proposer(p.GetHeight(), p.GetRound())
	}

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
		// glog.V(logger.Debug).Infoln("a:", a)
		// glog.V(logger.Debug).Infoln("e:", e)

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
	Enable    bool
}

func NewConsensusManager(manager *HDCProtocolManager, chain *core.BlockChain, db ethdb.Database, cc *ConsensusContract, privkeyhex string, extraData []byte) *ConsensusManager {

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
		mux:                cc.eventMux,
		coinbase:           cc.coinbase,
		Enable:             true,
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
func (cm *ConsensusManager) Start() bool {
	cm.Enable = true
	cm.Process()
	glog.V(logger.Debug).Infoln("Start Consensus")
	return true
}
func (cm *ConsensusManager) Stop() bool {
	cm.Enable = false
	cm.Process()
	glog.V(logger.Debug).Infoln("Stop Consensus")

	return true
}
func (cm *ConsensusManager) initializeLocksets() {
	// initializing locksets
	// sign genesis
	glog.V(logger.Debug).Infoln("initialize locksets")
	v := types.NewVote(0, 0, cm.chain.Genesis().Hash(), 1) // voteBlock

	cm.Sign(v)
	cm.AddVote(v, nil)
	// add initial lockset
	glog.V(logger.Debug).Infoln("add inintial lockset")
	headProposal := cm.loadProposal(cm.Head().Hash())
	if headProposal != nil {
		headBlockProposal := headProposal
		ls := headBlockProposal.SigningLockset

		for _, v := range ls.Votes {
			cm.AddVote(v, nil)
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
			cm.AddVote(v, nil)
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
	if cm.isWaitingForProposal() {
		// if timeout is setup already, skip
		if delay > 0 {
			glog.V(logger.Debug).Infoln("delay time :", delay)
			go cm.waitProposalAlarm(ar, delay)
		}
	} else {
		glog.V(logger.Debug).Infoln("wait txs alarm")

		go cm.waitProposalAlarm(ar, 1)
	}
}

func (cm *ConsensusManager) waitProposalAlarm(rm *RoundManager, delay float64) {
	cm.pm.eventMu.Lock()
	defer cm.pm.eventMu.Unlock()
	time.Sleep(time.Duration(delay * 1000 * 1000 * 1000))
	if cm.activeRound() == rm {
		if !cm.isReady() {
			// glog.V(logger.Debug).Infoln("on Alarm")
			cm.setupAlarm()
			return
		} else if !cm.isWaitingForProposal() {
			// there is no txs
			glog.V(logger.Debug).Infoln("waiting for txs")
			cm.setupAlarm()
			return
		} else {
			cm.Process()
		}
	}
}
func (cm *ConsensusManager) isWaitingForProposal() bool {
	return cm.isAllowEmptyBlocks || cm.hasPendingTransactions() || cm.Height() <= cm.numInitialBlocks
}
func (cm *ConsensusManager) hasPendingTransactions() bool {
	return len(cm.pm.txpool.Pending()) > 0
}
func (cm *ConsensusManager) Process() {

	if !cm.Enable {
		return
	}
	glog.V(logger.Debug).Infoln("---------------process------------------")
	if !cm.isReady() {
		cm.setupAlarm()
		return
	} else {
		cm.commit()
		h := cm.getHeightManager(cm.Height())
		h.process()
		if success := cm.commit(); success {
			cm.Process()
			return
		}
		cm.cleanup()
		cm.synchronizer.process()
		cm.setupAlarm()
		// check failed nodes
	}
}
func (cm *ConsensusManager) commit() bool {
	cm.processMu.Lock()
	defer cm.processMu.Unlock()
	glog.V(logger.Debug).Infoln("blockCandidates number:", len(cm.blockCandidates))

	for _, p := range cm.blockCandidates {
		if p.Block.ParentHash() != cm.Head().Hash() {
			//DEBUG
			glog.V(logger.Debug).Infoln("wrong parent hash")
			continue
		}
		if p.Height <= cm.Head().Header().Number.Uint64() {
			//DEBUG
			glog.V(logger.Debug).Infoln("past proposal")
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
					glog.V(logger.Debug).Infoln("commited")
					glog.V(logger.Debug).Infoln("lockest is", ls.Height(), ls.Round())
					// cm.commit()
					return true
				} else {
					glog.V(logger.Debug).Infoln("could not commit")
				}
			}
			glog.V(logger.Debug).Infoln("ls is ", ls)
			for _, v := range ls.Votes {
				glog.V(logger.Debug).Infoln(v)
			}
			glog.V(logger.Debug).Infoln("block hashes not the same,", p.Blockhash(), hash)
		} else {
			//DEBUG
			glog.V(logger.Debug).Infoln("no quorum for ", p.GetHeight(), p.GetRound())
			if ls != nil {
				//DEBUG
				glog.V(logger.Debug).Infoln("votes ", ls.Votes)
			}
		}
	}
	//DEBUG
	glog.V(logger.Debug).Infoln("no blockcandidate to commit")
	return false
}
func (cm *ConsensusManager) cleanup() {
	glog.V(logger.Debug).Infoln("in cleanup,current Head Number is ", cm.Head().Header().Number.Uint64())

	for hash, p := range cm.blockCandidates {
		if cm.Head().Header().Number.Uint64() >= p.GetHeight() {
			delete(cm.blockCandidates, hash)
		}
	}
	for i, _ := range cm.heights {
		if cm.getHeightManager(i).height < cm.Head().Header().Number.Uint64() {
			////DEBUG
			glog.V(logger.Debug).Infoln("Delete BlockCandidte", i)
			delete(cm.heights, i)
		}
	}
}
func (cm *ConsensusManager) Sign(s interface{}) {
	glog.V(logger.Debug).Infoln("CM Sign")
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
		glog.V(logger.Debug).Infoln("consensus mangaer sign error")
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
	return float32(len(cm.readyValidators)) > float32(len(cm.contract.validators))*2.0/3.0
}
func (cm *ConsensusManager) SendReady(force bool) {

	if cm.isReady() && !force {
		return
	}
	ls := cm.activeRound().lockset
	r := types.NewReady(cm.readyNonce, ls)
	cm.Sign(r)
	r.From()
	cm.broadcast(r)
	cm.readyNonce += 1
}
func (cm *ConsensusManager) AddReady(ready *types.Ready) {
	cc := cm.contract
	addr, err := ready.From()
	if err != nil {
		glog.V(logger.Error).Infoln(err)
		return
	}
	if !cc.isValidators(addr) {
		glog.V(logger.Info).Infoln(addr.Hex())
		glog.V(logger.Debug).Infoln("receive ready from invalid sender")
		return
	}
	cm.readyValidators[addr] = struct{}{}
}
func (cm *ConsensusManager) AddVote(v *types.Vote, peer *peer) bool {
	if v == nil {
		glog.V(logger.Debug).Infoln("cm addvote error")
		return false
	}
	addr, _ := v.From()
	if !cm.contract.isValidators(addr) {
		glog.V(logger.Debug).Infoln("non-validator vote")
		return false
	}
	cm.readyValidators[addr] = struct{}{}
	// TODO FIX
	isOwnVote := (addr == cm.contract.coinbase)
	h := cm.getHeightManager(v.Height)
	// glog.V(logger.Debug).Infoln("addVote", v.From())
	glog.V(logger.Debug).Infoln("addVote to ", v.Height, v.Round)
	success := h.addVote(v, isOwnVote)
	if !success {
		ls := cm.getHeightManager(v.Height).getRoundManager(v.Round).lockset
		glog.V(logger.Debug).Infoln("add vote failed in LockSet:", ls, v.Height, v.Round)
	}
	if success && h.height == cm.Height()+1 {
		glog.V(logger.Info).Infoln("may havev double vote attack on height : ", h.height)
		cm.synchronizer.requestHeight(h.height, peer)
	}
	return success
}
func (cm *ConsensusManager) AddProposal(p types.Proposal, peer *peer) bool {
	if p == nil {
		panic("nil peer in cm AddProposal")
	}
	if p.GetHeight() < cm.Height() {
		glog.V(logger.Debug).Infoln("proposal from past")
		return false
	}
	addr, err := p.From()
	if err != nil {
		glog.V(logger.Debug).Infoln("proposal sender invalid", err)
		return false
	}
	if !cm.contract.isValidators(addr) || !cm.contract.isProposer(p) {
		glog.V(logger.Debug).Infoln("proposal sender invalid")
		return false
	}
	cm.readyValidators[addr] = struct{}{}
	// if proposal is valid

	switch proposal := p.(type) {
	case *types.BlockProposal:
		// cm.addLockset(p.LockSet()) // check validity
		glog.V(logger.Debug).Infoln("adding bp in :", proposal.Height, proposal.Round)
		ls := p.LockSet()
		if !ls.IsValid() {
			glog.V(logger.Debug).Infoln("proposal invalid")
			return false
		}

		if !(ls.Height() == proposal.Height || proposal.Round == 0) {
			glog.V(logger.Debug).Infoln("proposal invalid")
			return false
		}

		if !(proposal.Round-ls.Round() == 1 || proposal.Round == 0) {
			glog.V(logger.Debug).Infoln("proposal invalid")
			return false
		}
		if peer != nil {
			cm.synchronizer.onProposal(p, peer)
		}
		for _, v := range proposal.LockSet().Votes {
			glog.V(logger.Debug).Infoln("check votes")
			cm.AddVote(v, nil) // implicit check
		}
		if proposal.Block.Number().Uint64() != proposal.Height {
			return false
		}
		if proposal.Round != 0 && !proposal.LockSet().NoQuorum() {
			return false
		}
		if proposal.Height > cm.Height() {
			glog.V(logger.Debug).Infoln("proposal from the future")
			return false
		}
		blk := cm.pm.linkBlock(proposal.Block)
		if blk == nil {
			glog.V(logger.Debug).Infoln("link block: already linked or wrong block")
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
		glog.V(logger.Debug).Infoln("link block success, add block proposal")
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
		glog.V(logger.Debug).Infoln("cm add LockSet is fail")
		return false
	}
	for _, v := range ls.Votes {
		cm.AddVote(v, nil)
		// implicitly checks their validity
	}
	return true
}
func (cm *ConsensusManager) addBlockProposal(bp *types.BlockProposal) bool {
	glog.V(logger.Debug).Infoln("cm add BlockProposal")

	if cm.hasProposal(bp.Blockhash()) {
		glog.V(logger.Debug).Infoln("Known BlockProposal")
		return false
	}
	result, _ := bp.SigningLockset.HasQuorum()
	slH := bp.SigningLockset.Height()
	if !result || slH != bp.Height-1 {
		panic("proposal error")
	}
	glog.V(logger.Debug).Infof("bp signinglockset %d votes has %d\n", bp.SigningLockset.Height(), len(bp.SigningLockset.Votes))
	for _, v := range bp.SigningLockset.Votes {
		cm.AddVote(v, nil)
	}
	cm.blockCandidates[bp.Blockhash()] = bp
	glog.V(logger.Debug).Infoln("cm add BlockProposal success")

	return true
}

func (cm *ConsensusManager) lastCommittingLockset() *types.LockSet {
	return cm.getHeightManager(cm.Height() - 1).lastQuorumLockset()
}
func (cm *ConsensusManager) HighestCommittingLockset() *types.LockSet {
	var hcls *types.LockSet
	hcls = nil
	for i, height := range cm.heights {
		ls := height.lastQuorumLockset()
		if ls != nil {
			if hcls == nil {
				hcls = ls
			} else if i > hcls.Height() {
				hcls = ls
			}
		}
	}
	return hcls
}
func (cm *ConsensusManager) lastValidLockset() *types.LockSet {
	// glog.V(logger.Debug).Infoln("cm lastValidLockset ")

	ls := cm.getHeightManager(cm.Height()).lastValidLockset()

	if ls == nil {
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
			// glog.V(logger.Debug).Infoln("hm Round()", l.Round()+1)
			return l.Round() + 1
		}
	}

	return 0
}
func (hm *HeightManager) getRoundManager(r uint64) *RoundManager {
	if _, ok := hm.rounds[r]; !ok {
		hm.rounds[r] = NewRoundManager(hm, r)
	}
	return hm.rounds[r]
}
func (hm *HeightManager) LastVoteLock() *types.Vote {
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
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		// glog.V(logger.Debug).Infoln("lastvalidlockset i", i)
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
			result, hash := ls.HasQuorum()
			if result {
				if found != nil {
					glog.V(logger.Info).Infoln(len(hm.rounds), index)
					glog.V(logger.Info).Infoln("multiple valid lockset")
					if _, h := found.HasQuorum(); h != hash {
						glog.V(logger.Info).Infoln("multiple valid lockset")
						panic("multiple valid locksets on different proposals")
					}
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
	////DEBUG
	r := hm.Round()

	hm.getRoundManager(r).process()
	////DEBUG
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
	glog.V(logger.Debug).Infoln("RM gettimout", rm.height, rm.round)
	return delay
}
func (rm *RoundManager) addVote(vote *types.Vote, force_replace bool) bool {
	glog.V(logger.Debug).Infof("In RM %d addvote", rm.round)
	if !rm.lockset.Contain(vote) {
		err := rm.lockset.Add(vote, force_replace)
		if err != nil {
			glog.V(logger.Error).Infoln("Add vote to lockset error", err)
			return false
		}
		// report faliure
		if rm.lockset.IsValid() {
			if rm.proposal == nil && rm.lockset.NoQuorum() {
				glog.V(logger.Debug).Infof("FailedToProposeEvidence")
				rm.cm.trackedProtocolFailures = append(rm.cm.trackedProtocolFailures, "FailedToProposeEvidence")
			}
		}
		return true
	}
	glog.V(logger.Debug).Infof("vote already in lockset")
	return false
}
func (rm *RoundManager) addProposal(p types.Proposal) bool {
	if rm.proposal == nil {
		rm.proposal = p
		return true
	} else if rm.proposal.Blockhash() == p.Blockhash() {
		return true
	} else {
		glog.V(logger.Info).Infoln(rm.proposal, p)
		panic("add_proposal error")
	}
}
func (rm *RoundManager) process() {
	rm.roundProcessMu.Lock()
	defer rm.roundProcessMu.Unlock()
	////DEBUG
	glog.V(logger.Debug).Infoln("In RM Process", rm.height, rm.round)

	if rm.cm.Round() != rm.round {
		glog.V(logger.Debug).Infof("round process error")
	}
	if rm.cm.Height() != rm.height {
		glog.V(logger.Debug).Infof("round process error")
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
	if !(rm.proposal == nil || rm.voteLock != nil) {
		panic("RM Process Error")
	}
}

func (rm *RoundManager) propose() types.Proposal {

	if !rm.cm.isWaitingForProposal() {
		glog.V(logger.Debug).Infof("proposing is not waiting for proposal")
		return nil
	}
	proposer := rm.cm.contract.proposer(rm.height, rm.round)
	if proposer != rm.cm.coinbase {
		glog.V(logger.Debug).Infoln("I am not proposer in", rm.height, rm.round)
		return nil
	}
	glog.V(logger.Debug).Infoln("I am a proposer in ", rm.height, rm.round)
	if rm.proposal != nil {
		addr, err := rm.proposal.From()
		if err != nil {
			glog.V(logger.Error).Infof("error occur %v", err)
			return nil
		}
		if addr != rm.cm.coinbase {
			addr, _ := rm.proposal.From()
			glog.V(logger.Debug).Infof(addr.Hex(), rm.cm.coinbase.Hex())
			panic("Propose Error: coinbase not the same")
		}
		if rm.voteLock == nil {
			panic("Propose Error: voteLock nil")
		}
		glog.V(logger.Debug).Infoln("already propose in this HR", rm.height, rm.round)
		return rm.proposal
	}
	round_lockset := rm.cm.lastValidLockset()
	if round_lockset == nil {
		glog.V(logger.Debug).Infof("no valid round lockset for height")
		return nil
	}
	var proposal types.Proposal
	quorum, _ := round_lockset.HasQuorum()
	quroumpossible, _ := round_lockset.QuorumPossible()
	if round_lockset.Height() == rm.height && quorum {
		glog.V(logger.Debug).Infof("have quorum on height, not proposing")
		return nil
	} else if rm.round == 0 || round_lockset.NoQuorum() {
		proposal = rm.mkProposal()
	} else if quroumpossible {
		if p, err := types.NewVotingInstruction(rm.height, rm.round, round_lockset); err != nil {
			glog.V(logger.Error).Infof("error occur %v", err)
			return nil
		} else {
			proposal = p
			rm.cm.Sign(proposal)
		}
	} else {
		glog.V(logger.Info).Infoln("invalid ls: ", len(round_lockset.Votes))
		for _, v := range round_lockset.Votes {
			glog.V(logger.Info).Infoln(v)
		}
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

	// Try to wait more Tx per block
	time.Sleep(1000 * 1000 * 500)

	block := rm.cm.newBlock()
	blockProposal, err := types.NewBlockProposal(rm.height, rm.round, block, signingLockset, roundLockset)
	if err != nil {
		glog.V(logger.Error).Infof("error occur %v", err)
		return nil
	}
	rm.cm.Sign(blockProposal)
	rm.cm.setProposalLock(block)
	return blockProposal
}
func (rm *RoundManager) vote() *types.Vote {

	if rm.voteLock != nil {
		//DEBUG glog.V(logger.Debug).Infof("voted")
		return nil
	}
	//DEBUG glog.V(logger.Debug).Infoln("in vote in RM", rm.height, rm.round)
	lastVoteLock := rm.hm.LastVoteLock()

	var vote *types.Vote
	if rm.proposal != nil {
		switch bp := rm.proposal.(type) {
		case *types.VotingInstruction: // vote for votinginstruction
			quorumPossible, _ := bp.LockSet().QuorumPossible()
			if !quorumPossible {
				panic("vote error")
			}
			glog.V(logger.Debug).Infoln("voting on instruction")
			vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
		default:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_NoQuorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			if lastVoteLock == nil {
				glog.V(logger.Debug).Infoln("voting on new proporsal")
				vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
			} else {
				vt := lastVoteLock.VoteType
				switch vt {
				case 1: //repeat vote
					glog.V(logger.Debug).Infoln("voting on last vote")
					vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash, 1)
				default: // vote to proposed vote
					glog.V(logger.Debug).Infoln("voting proposed block")
					vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 1)
				}
			}
		}
	} else if rm.timeoutTime != 0 && float64(rm.cm.Now()) > rm.timeoutTime {
		glog.V(logger.Debug).Infoln("voting timeout", float64(rm.cm.Now()), rm.timeoutTime)
		if lastVoteLock == nil {
			glog.V(logger.Debug).Infoln("rm proposal", rm.proposal)
			vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
		} else {
			vt := lastVoteLock.VoteType
			switch vt {
			case 1: // repeat vote
				glog.V(logger.Debug).Infoln("voting on last vote")
				vote = types.NewVote(rm.height, rm.round, lastVoteLock.Blockhash, 1)
			default: // vote nil
				glog.V(logger.Debug).Infoln("voting proposed block")
				vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
			}
		}
	} else {
		return nil
	}
	rm.cm.Sign(vote)
	rm.voteLock = vote
	glog.V(logger.Debug).Infoln("vote success in H:", rm.height, vote)
	rm.lockset.Add(vote, false)
	return vote
}

func (cm *ConsensusManager) newBlock() *types.Block {
	config := cm.chain.Config()
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

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		Difficulty: new(big.Int).SetInt64(0),
		GasLimit:   new(big.Int).SetInt64(50000000),
		GasUsed:    new(big.Int),
		Coinbase:   cm.coinbase,
		Extra:      cm.extraData,
		Time:       big.NewInt(tstamp),
	}
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
	work.commitTransactions(cm.mux, txs, cm.chain)

	var uncles []*types.Header

	core.AccumulateRewards(work.state, header, uncles)
	header.Root = work.state.IntermediateRoot()

	work.Block = types.NewBlock(header, work.txs, uncles, work.receipts)
	glog.V(logger.Debug).Infof("create new work on block %v with %d txs & %d uncles. Took %v\n", work.Block.Number(), work.tcount, len(uncles), time.Since(tstart))

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

func (env *Work) commitTransactions(mux *event.TypeMux, txs *types.TransactionsByPriceAndNonce, bc *core.BlockChain) {
	gp := new(core.GasPool).AddGas(env.header.GasLimit)

	var coalescedLogs vm.Logs
	for {
		// limit the tcount in one block to reduce block creating time
		if env.tcount >= 1000 {
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		from, _ := tx.From()

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