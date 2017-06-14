package bft

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	TimeoutRound     = 3 // basic timeout time for
	TimeoutPrecommit = 0.5
	TimeoutFactor    = 1.5
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

func chosen(h uint64, r uint64, length int) int {
	sum := h - r
	return int(math.Abs(float64(sum))) % length
}

func (cc *ConsensusContract) proposer(height uint64, round uint64) common.Address {
	addr := cc.validators[chosen(height, round, len(cc.validators))]
	return addr
}

func (cc *ConsensusContract) isValidators(v common.Address) bool {
	return containsAddress(cc.validators, v)
}

func (cc *ConsensusContract) isProposer(p types.Proposal) bool {
	if addr, err := p.From(); err != nil {
		log.Error("invalid sender %v", err)
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
		if a == e {
			return true
		}
	}
	return false
}

type ConsensusManager struct {
	pm                      *ProtocolManager
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
	synchronizer            *Synchronizer
	// lastCommittingLockset   *types.LockSet

	currentBlock *types.Block
	blockCh      chan *types.Block

	mu          sync.Mutex
	currentMu   sync.Mutex
	uncleMu     sync.Mutex
	writeMapMu  sync.RWMutex
	getHeightMu sync.RWMutex

	processMu sync.Mutex

	Enable bool
}

func NewConsensusManager(manager *ProtocolManager, chain *core.BlockChain, db ethdb.Database, cc *ConsensusContract, privkeyhex string) *ConsensusManager {

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
		coinbase:           cc.coinbase,
		Enable:             true,
		getHeightMu:        sync.RWMutex{},
	}

	if !cm.contract.isValidators(cm.coinbase) {
		panic("Not Validators")
	}

	cm.initializeLocksets()

	// old votes don't count
	cm.readyValidators = make(map[common.Address]struct{})
	cm.readyValidators[cm.coinbase] = struct{}{}

	cm.synchronizer = NewSynchronizer(cm)
	return cm
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

func (cm *ConsensusManager) Start() bool {
	cm.Enable = true
	cm.Process(cm.Height())
	log.Debug("Start Consensus")
	return true
}

func (cm *ConsensusManager) Stop() bool {
	cm.Enable = false
	log.Debug("Stop Consensus")
	return true
}

func (cm *ConsensusManager) initializeLocksets() {
	// initializing locksets
	// sign genesis
	log.Debug("initialize locksets")
	v := types.NewPrecommitVote(0, 0, cm.chain.Genesis().Hash(), 1) // voteBlock

	cm.Sign(v)
	cm.AddPrecommitVote(v, nil)
	// add initial lockset
	log.Debug("add inintial lockset")
	headProposal := cm.loadProposal(cm.Head().Hash())
	if headProposal != nil {
		headBlockProposal := headProposal
		ls := headBlockProposal.SigningLockset

		for _, v := range ls.PrecommitVotes {
			cm.AddPrecommitVote(v, nil)
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
			log.Error("initialize_locksets error: hash not match")
			// panic("initialize_locksets error: hash not match")
		}
		for _, v := range lastCommittingLockset.PrecommitVotes {
			cm.AddPrecommitVote(v, nil)
		}
		headNumber := cm.Head().Header().Number.Uint64()
		result, _ := cm.getHeightManager(headNumber).HasQuorum()
		if !result {

			panic("initialize_locksets error: lastCommittingLockset2")
		}
	} else if int(cm.Head().Header().Number.Int64()) != 0 {
		panic("Error occur in init state")
	}
}

// persist proposals and last committing lockset
func (cm *ConsensusManager) storeLastCommittingLockset(ls *types.PrecommitLockSet) error {
	bytes, err := rlp.EncodeToBytes(ls)
	if err != nil {
		return err
	}
	if err := cm.hdcDb.Put([]byte("last_committing_lockset"), bytes); err != nil {
		log.Error("failed to store last committing lockset into database", "err", err)
		return err
	}
	return nil
}

func (cm *ConsensusManager) loadLastCommittingLockset() *types.PrecommitLockSet {
	key := fmt.Sprintf("last_committing_lockset")
	data, _ := cm.hdcDb.Get([]byte(key))
	if len(data) == 0 {
		return nil
	}
	var lockset *types.PrecommitLockSet
	if err := rlp.Decode(bytes.NewReader(data), &lockset); err != nil {
		log.Error("invalid last_committing_lockset ", "err:", err)
		return nil
	}
	return lockset
}

func (cm *ConsensusManager) storePrecommitLockset(blockhash common.Hash, pls *types.PrecommitLockSet) error {
	bytes, err := rlp.EncodeToBytes(pls)
	if err != nil {
		panic(err)
	}
	key := fmt.Sprintf("precommitLockset:%s", blockhash)
	if err := cm.hdcDb.Put([]byte(key), bytes); err != nil {
		log.Error("failed to store proposal into database", "err", err)
		return err
	}
	return nil
}

func (cm *ConsensusManager) loadPrecommitLockset(blockhash common.Hash) *types.PrecommitLockSet {
	key := fmt.Sprintf("precommitLockset:%s", blockhash)
	data, _ := cm.hdcDb.Get([]byte(key))
	if len(data) == 0 {
		return nil
	}
	var pls *types.PrecommitLockSet
	if err := rlp.Decode(bytes.NewReader(data), &pls); err != nil {
		log.Error("invalid precommitLockset RLP for hash", "blockhash", blockhash, "err", err)
		return nil
	}
	return pls
}

func (cm *ConsensusManager) storeProposal(bp *types.BlockProposal) error {
	bytes, err := rlp.EncodeToBytes(bp)
	if err != nil {
		panic(err)
	}
	key := fmt.Sprintf("blockproposal:%s", bp.Blockhash())
	if err := cm.hdcDb.Put([]byte(key), bytes); err != nil {
		log.Error("failed to store proposal into database: %v", err)
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
		log.Error("invalid proposal RLP for hash %x: %v", blockhash, err)
		return nil
	}
	return bp
}

func (cm *ConsensusManager) getPrecommitLocksetByHeight(height uint64) *types.PrecommitLockSet {
	if height >= cm.Height() {
		log.Error("getPrecommitLocksetByHeight error")
		return nil
	} else {
		bh := cm.chain.GetBlockByNumber(uint64(height)).Hash()
		return cm.loadPrecommitLockset(bh)
	}
}

func (cm *ConsensusManager) receivePrecommitLocksets(pls []*types.PrecommitLockSet) {
	for _, ls := range pls {
		if result, hash := ls.HasQuorum(); result == true {
			cm.storePrecommitLockset(hash, ls)
		} else {
			log.Error("receive PrecommitLocksets invalid")
			return
		}
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

func (cm *ConsensusManager) setupAlarm(h uint64) {
	log.Error("in set up alarm", "height", h)
	cm.getHeightMu.Lock()
	ar := cm.activeRound()
	cm.getHeightMu.Unlock()
	if cm.isWaitingForProposal() {
		delay := ar.getTimeout()
		ar.setTimeoutPrecommit()
		// if timeout is setup already, skip
		if delay > 0 {
			log.Debug("delay time :", "delay", delay)
			go cm.waitProposalAlarm(ar, delay, h)
		} else {
			log.Debug("delay time already setup in", "height", ar.height, "round", ar.round)
		}
	} else {
		log.Debug("wait Proposal")
		go cm.waitProposalAlarm(ar, 1, h)
	}
}

func (cm *ConsensusManager) waitProposalAlarm(rm *RoundManager, delay float64, h uint64) {
	time.Sleep(time.Duration(delay * 1000 * 1000 * 1000))
	cm.getHeightMu.Lock()
	acr := cm.activeRound()
	cm.getHeightMu.Unlock()
	if acr == rm {
		if !cm.isReady() {
			log.Debug("on Alarm, is not ready")
			cm.setupAlarm(h)
			return
		} else if !cm.isWaitingForProposal() {
			// there is no txs
			log.Debug("waiting for txs")
			cm.setupAlarm(h)
			return
		} else {
			log.Debug("delay time up", "height", h)
			cm.Process(h)
		}
	} else {
		log.Debug("pre active round,", "h", rm.height, "r", rm.round)
		log.Debug("curr active round, to cm Process", "h", acr.height, "r", acr.round)
		cm.Process(acr.height)
	}
}

func (cm *ConsensusManager) isWaitingForProposal() bool {
	return cm.isAllowEmptyBlocks || cm.hasPendingTransactions() || cm.Height() <= cm.numInitialBlocks
}

func (cm *ConsensusManager) hasPendingTransactions() bool {
	if txs, err := cm.pm.txpool.Pending(); err != nil {
		log.Debug("error occur")
		panic(err)
	} else {
		return len(txs) > 0
	}
}

func (cm *ConsensusManager) Process(h uint64) {
	if cm.Height() != h || !cm.Enable {
		return
	}

	log.Debug("---------------process------------------")
	if !cm.isReady() {
		cm.setupAlarm(h)
		return
	} else {
		cm.cleanup()
		cm.getHeightMu.Lock()
		heightManager := cm.getHeightManager(cm.Height())
		heightManager.process()
		cm.commit()
		cm.getHeightMu.Unlock()
		// cm.synchronizer.process()
		cm.setupAlarm(h)
		// check failed nodes
	}
}

func (cm *ConsensusManager) commit() bool {
	log.Debug("in commit")
	cm.processMu.Lock()
	defer cm.processMu.Unlock()
	log.Debug("commit, blockcandidates:", "len", len(cm.blockCandidates))
	cm.writeMapMu.Lock()
	defer cm.writeMapMu.Unlock()
	// cm.getHeightMu.Lock()
	// defer cm.getHeightMu.Unlock()
	for _, p := range cm.blockCandidates {

		if p.Block.ParentHash() != cm.Head().Hash() {
			//DEBUG
			log.Debug("wrong parent hash: ", p.Block.ParentHash(), cm.Head().Hash())
			// log.Debug("candidate: ", p)
			continue
		}
		if p.Height <= cm.Head().Header().Number.Uint64() {
			//DEBUG
			log.Debug("past proposal")
			continue
		}
		ls := cm.getHeightManager(p.GetHeight()).lastQuorumPrecommitLockSet()
		if ls != nil {
			_, hash := ls.HasQuorum()
			if p.Blockhash() == hash {
				if cm.blockCh != nil {
					log.Debug("cm.blockCh is not nil")
					select {
					case cm.blockCh <- p.Block:
						cm.storeProposal(p)
						cm.storePrecommitLockset(p.Blockhash(), ls)
						cm.storeLastCommittingLockset(ls)
					default:
						log.Debug("commit failed")
					}
				}
				return true
			}
			log.Debug("block hashes not the same,", p.Blockhash(), hash)
		} else {
			log.Debug("commit failed, no last quorum pls")
		}
	}
	//DEBUG
	log.Debug("no blockcandidate to commit")

	return false
}

func (cm *ConsensusManager) verifyVotes(header *types.Header) error {
	log.Debug("verify votes")

	number := header.Number.Uint64()
	blockhash := header.Hash()

	if pls := cm.loadPrecommitLockset(blockhash); pls != nil {
		_, hash := pls.HasQuorum()
		if blockhash == hash {
			return nil
		} else {
			log.Error("verify Votes Error Occur")
			return errors.New("store PrecommitLockset hash is not the same")
		}
	} else {
		log.Debug("verify Votes Failed, sync with others")
		cm.synchronizer.request(number)
		time.Sleep(500 * 1000 * 1000) // wait for request from others
		return cm.verifyVotes(header)
	}
}

func (cm *ConsensusManager) cleanup() {
	log.Debug("in cleanup,current Head Number is ", "number", cm.Head().Header().Number.Uint64())
	cm.writeMapMu.Lock()
	for hash, p := range cm.blockCandidates {
		if cm.Head().Header().Number.Uint64() >= p.GetHeight() {
			delete(cm.blockCandidates, hash)
		}
	}
	cm.writeMapMu.Unlock()
	cm.getHeightMu.Lock()
	for i, _ := range cm.heights {
		if cm.getHeightManager(i).height < cm.Head().Header().Number.Uint64() {
			////DEBUG
			log.Debug("Delete BlockCandidte", i)
			delete(cm.heights, i)
		}
	}
	cm.getHeightMu.Unlock()
}

func (cm *ConsensusManager) Sign(s interface{}) {
	log.Debug("CM Sign")
	switch t := s.(type) {
	case *types.BlockProposal:
		t.Sign(cm.privkey)
	case *types.Vote:
		t.Sign(cm.privkey)
	case *types.PrecommitVote:
		t.Sign(cm.privkey)
	case *types.LockSet:
		t.Sign(cm.privkey)
	case *types.PrecommitLockSet:
		t.Sign(cm.privkey)
	case *types.VotingInstruction:
		t.Sign(cm.privkey)
	case *types.Ready:
		t.Sign(cm.privkey)
	default:
		log.Debug("consensus mangaer sign error")
	}
}

func (cm *ConsensusManager) setProposalLock(block *types.Block) {
	// TODO: update this
	cm.proposalLock = block
}

func (cm *ConsensusManager) broadcast(msg interface{}) {
	cm.pm.BroadcastBFTMsg(msg)
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
		log.Error("AddReady err ", "err", err)
		return
	}
	if !cc.isValidators(addr) {
		log.Debug(addr.Hex())
		log.Debug("receive ready from invalid sender")
		return
	}
	if _, ok := cm.readyValidators[addr]; !ok {
		cm.writeMapMu.Lock()
		cm.readyValidators[addr] = struct{}{}
		cm.writeMapMu.Unlock()
	}
}

func (cm *ConsensusManager) AddVote(v *types.Vote, peer *peer) bool {
	if v == nil {
		log.Debug("cm addvote error")
		return false
	}
	addr, _ := v.From()
	if _, ok := cm.readyValidators[addr]; !ok {
		cm.writeMapMu.Lock()
		cm.readyValidators[addr] = struct{}{}
		cm.writeMapMu.Unlock()
	}
	// TODO FIX
	cm.getHeightMu.Lock()
	h := cm.getHeightManager(v.Height)
	success := h.addVote(v, true)
	log.Debug("addVote to ", "height", v.Height, "round", v.Round, "from", addr, "success", success)
	// if !success {
	// 	// ls := h.getRoundManager(v.Round).lockset
	// 	// log.Debug("add vote failed in LockSet:", ls, v.Height,"round", v.Round)
	// }

	cm.getHeightMu.Unlock()
	return success
}

func (cm *ConsensusManager) AddPrecommitVote(v *types.PrecommitVote, peer *peer) bool {
	if v == nil {
		log.Debug("cm AddPrecommitVote fail")
		return false
	}
	// log.Debug("addVote", v.From())
	addr, _ := v.From()
	cm.getHeightMu.Lock()
	h := cm.getHeightManager(v.Height)
	success := h.addPrecommitVote(v, true)
	log.Debug("addPrecommitVote to ", "h", v.Height, "r", v.Round, "from", addr, "success", success)
	// if !success {
	// 	ls := h.getRoundManager(v.Round).precommitLockset
	// 	log.Debug("add vote failed in Precommit LockSet:", ls, v.Height, v.Round)
	// }
	cm.getHeightMu.Unlock()
	return success
}

func (cm *ConsensusManager) AddProposal(p types.Proposal, peer *peer) bool {
	if p == nil {
		panic("nil peer in cm AddProposal")
	}
	if p.GetHeight() < cm.Height() {
		log.Debug("proposal from past")
		return false
	}
	addr, err := p.From()
	if err != nil {
		log.Debug("proposal sender error ", "err", err)
		return false
	}
	if !cm.contract.isValidators(addr) || !cm.contract.isProposer(p) {
		log.Debug("proposal sender invalid", "validator?", cm.contract.isValidators(addr), "proposer?", cm.contract.isProposer(p))
		return false
	}
	if _, ok := cm.readyValidators[addr]; !ok {
		cm.writeMapMu.Lock()
		cm.readyValidators[addr] = struct{}{}
		cm.writeMapMu.Unlock()
	}
	// if proposal is valid
	ls := p.LockSet()
	if !ls.IsValid() && ls.EligibleVotesNum != 0 {
		log.Debug("proposal invalid")
		return false
	} else {
		if p.GetRound() != 0 {
			if ls.Height() != p.GetHeight() {
				log.Debug("proposal invalid, height not the same or not the first round")
				return false
			}
			if p.GetRound()-ls.Round() != 1 {
				log.Debug("proposal invalid, ")
				return false
			}
			// replace with the quorum votes
			// if result, _ := ls.HasQuorum(); result {
			// 	delete(cm.heights, ls.Height())
			// }
			log.Debug("check votes")
			cm.getHeightMu.Lock()
			h := cm.getHeightManager(ls.Height())
			for _, v := range ls.Votes {
				h.addVote(v, false) // implicit check
			}
			cm.getHeightMu.Unlock()
		}
	}
	switch proposal := p.(type) {
	case *types.BlockProposal:
		// log.Debug("adding bp in :", proposal.Height, proposal.Round, proposal.Blockhash())

		if peer != nil {
			cm.synchronizer.onProposal(p, peer)
		}
		if proposal.Block.Number().Uint64() != proposal.Height {
			log.Debug("proposal different height")
			return false
		}
		if proposal.Round != 0 && !ls.NoQuorum() {
			log.Debug("proposal invalid: round !=0 & not noquorum")
			return false
		}
		if quorum, _ := proposal.SigningLockset.HasQuorum(); !quorum {
			log.Debug("signing lockset error")
			return false
		}
		// if proposal.Height > cm.Height() {
		// 	log.Debug("proposal from the future")
		// 	return false
		// }
		// blk := cm.pm.linkBlock(proposal.Block)
		// if blk == nil {
		// 	log.Debug("link block: already linked or wrong block")
		// 	// lqls := cm.getHeightManager(proposal.Height).lastQuorumLockset()
		// 	// if lqls != nil {
		// 	// 	_, hash := lqls.HasQuorum()
		// 	// 	if hash == proposal.Blockhash() {
		// 	// 		panic("Fork Detected")
		// 	// 	}
		// 	// }
		// 	return false
		// }
		cm.addBlockProposal(proposal)
	case *types.VotingInstruction:
		if !(proposal.LockSet().Round() == proposal.Round-1 && proposal.Height == proposal.LockSet().Height()) {
			log.Debug("Invalid VotingInstruction")
			return false
		} else if proposal.Round == 0 {
			log.Debug("Invalid VotingInstruction")
			return false
		} else if result, _ := proposal.LockSet().HasQuorum(); !result {
			log.Debug("Invalid VotingInstruction")
			return false
		}
	}
	cm.getHeightMu.Lock()
	isValid := cm.getHeightManager(p.GetHeight()).addProposal(p)
	cm.getHeightMu.Unlock()
	return isValid
}

func (cm *ConsensusManager) addBlockProposal(bp *types.BlockProposal) bool {
	log.Debug("cm add BlockProposal", "h", bp.Height, "r", bp.Round)

	if cm.hasProposal(bp.Blockhash()) {
		log.Debug("Known BlockProposal")
		return false
	}
	result, _ := bp.SigningLockset.HasQuorum()
	slH := bp.SigningLockset.Height()
	if !result || slH != bp.Height-1 {
		log.Debug("Error: proposal error")
		return false
	}
	cm.getHeightMu.Lock()
	h := cm.getHeightManager(slH)
	for _, v := range bp.SigningLockset.PrecommitVotes {
		h.addPrecommitVote(v, false)
	}
	cm.getHeightMu.Unlock()
	cm.addBlockCandidates(bp)
	return true
}

func (cm *ConsensusManager) addBlockCandidates(bp *types.BlockProposal) {
	cm.writeMapMu.Lock()
	cm.blockCandidates[bp.Blockhash()] = bp
	cm.writeMapMu.Unlock()
}

func (cm *ConsensusManager) lastCommittingLockset() *types.PrecommitLockSet {
	ls := cm.getHeightManager(cm.Height() - 1).lastQuorumPrecommitLockSet()
	if ls == nil {
		log.Info("lastCommittingLockset ERROR")
		return nil
	}
	return ls
}

func (cm *ConsensusManager) HighestCommittingLockset() *types.PrecommitLockSet {
	var hcls *types.PrecommitLockSet
	hcls = nil
	for i, height := range cm.heights {
		ls := height.lastQuorumPrecommitLockSet()
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
	// log.Debug("cm lastValidLockset ")

	ls := cm.getHeightManager(cm.Height()).lastValidLockset()
	return ls
}

func (cm *ConsensusManager) lastValidPrecommitLockset() *types.PrecommitLockSet {
	// log.Debug("cm lastValidPrecommitLockset ")
	ls := cm.getHeightManager(cm.Height()).lastValidPrecommitLockset()
	return ls
}

func (cm *ConsensusManager) lastLock() *types.Vote {
	return cm.getHeightManager(cm.Height()).LastVoteLock()
}

// func (cm *ConsensusManager) getBlockProposal(blockhash common.Hash) *types.BlockProposal {
// 	if cm.blockCandidates[blockhash] != nil {
// 		return cm.blockCandidates[blockhash]
// 	} else {
// 		return cm.loadProposal(blockhash)
// 	}
// }
//
// func (cm *ConsensusManager) lastBlockProposal() *types.BlockProposal {
// 	p := cm.getHeightManager(cm.Height()).LastVotedBlockProposal()
// 	if p != nil {
// 		return p
// 	} else {
// 		return cm.getBlockProposal(cm.Head().Hash	())
// 	}
// }

func (cm *ConsensusManager) mkLockSet(height uint64) *types.LockSet {
	return types.NewLockSet(cm.contract.numEligibleVotes(height), []*types.Vote{})
}

func (cm *ConsensusManager) mkPLockSet(height uint64) *types.PrecommitLockSet {
	return types.NewPrecommitLockSet(cm.contract.numEligibleVotes(height), []*types.PrecommitVote{})
}

type HeightManager struct {
	cm         *ConsensusManager
	height     uint64
	rounds     map[uint64]*RoundManager
	writeMapMu sync.RWMutex
}

func NewHeightManager(consensusmanager *ConsensusManager, height uint64) *HeightManager {
	return &HeightManager{
		cm:         consensusmanager,
		height:     height,
		rounds:     make(map[uint64]*RoundManager),
		writeMapMu: sync.RWMutex{},
	}
}

func (hm *HeightManager) Round() uint64 {

	l := hm.lastValidPrecommitLockset()
	if l != nil {
		if l.IsValid() {
			// log.Debug("hm Round()", l.Round()+1)
			return l.Round() + 1
		}
	}
	return 0
}

func (hm *HeightManager) getRoundManager(r uint64) *RoundManager {
	hm.writeMapMu.Lock()
	defer hm.writeMapMu.Unlock()
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

func (hm *HeightManager) LastPrecommitVoteLock() *types.PrecommitVote {
	// highest lock
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		if hm.getRoundManager(index).voteLock != nil {
			return hm.getRoundManager(index).precommitVoteLock
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
		// log.Debug("lastvalidlockset i", i)
		if hm.getRoundManager(index).lockset.IsValid() {
			return hm.getRoundManager(index).lockset
		}
	}
	return nil
}

func (hm *HeightManager) lastValidPrecommitLockset() *types.PrecommitLockSet {
	// highest valid lockset on height
	for i := len(hm.rounds) - 1; i >= 0; i-- {
		index := uint64(i)
		if hm.getRoundManager(index).precommitLockset.IsValid() {
			return hm.getRoundManager(index).precommitLockset
		}
	}
	return nil
}

// PoLC_Lockset
func (hm *HeightManager) lastQuorumLockset() *types.LockSet {
	var found *types.LockSet
	for i := 0; i < len(hm.rounds); i++ {
		index := uint64(i)
		ls := hm.getRoundManager(index).lockset
		if ls.IsValid() {
			result, hash := ls.HasQuorum()
			if result {
				if found != nil {
					log.Info("height: ", hm.height, index)
					if _, h := found.HasQuorum(); h != hash {
						log.Info("multiple valid lockset")
					}
				}
				found = ls
			}
		}
	}
	return found
}

func (hm *HeightManager) lastQuorumPrecommitLockSet() *types.PrecommitLockSet {
	var found *types.PrecommitLockSet
	for i := 0; i < len(hm.rounds); i++ {
		index := uint64(i)
		ls := hm.getRoundManager(index).precommitLockset
		if ls.IsValid() {
			result, hash := ls.HasQuorum()
			if result {
				if found != nil {
					log.Info("multiple valid lockset on precommit lockset")
					if _, h := found.HasQuorum(); h != hash {
						log.Info("multiple valid lockset")
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
	ls := hm.lastQuorumPrecommitLockSet()
	if ls != nil {
		return ls.HasQuorum()
	} else {
		return false, common.Hash{}
	}
}

func (hm *HeightManager) addVote(v *types.Vote, process bool) bool {
	addr, _ := v.From()
	if !hm.cm.contract.isValidators(addr) {
		log.Debug("non-validator vote")
		return false
	}
	isOwnVote := (addr == hm.cm.contract.coinbase)
	r := v.Round
	return hm.getRoundManager(r).addVote(v, isOwnVote, process)
}

func (hm *HeightManager) addPrecommitVote(v *types.PrecommitVote, process bool) bool {
	addr, _ := v.From()
	if !hm.cm.contract.isValidators(addr) {
		log.Debug("non-validator vote")
		return false
	}
	isOwnVote := (addr == hm.cm.contract.coinbase)
	r := v.Round
	return hm.getRoundManager(r).addPrecommitVote(v, isOwnVote, process)
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
	hm                *HeightManager
	cm                *ConsensusManager
	round             uint64
	height            uint64
	lockset           *types.LockSet
	precommitLockset  *types.PrecommitLockSet
	proposal          types.Proposal
	voteLock          *types.Vote
	precommitVoteLock *types.PrecommitVote
	timeoutTime       float64
	timeoutPrecommit  float64
	roundProcessMu    sync.Mutex
}

func NewRoundManager(heightmanager *HeightManager, round uint64) *RoundManager {
	lockset := heightmanager.cm.mkLockSet(heightmanager.height)
	pLockset := heightmanager.cm.mkPLockSet(heightmanager.height)
	return &RoundManager{
		hm:                heightmanager,
		cm:                heightmanager.cm,
		round:             round,
		height:            heightmanager.height,
		lockset:           lockset,
		precommitLockset:  pLockset,
		timeoutTime:       0,
		timeoutPrecommit:  0,
		proposal:          nil,
		voteLock:          nil,
		precommitVoteLock: nil,
	}
}

func (rm *RoundManager) getTimeout() float64 {
	if rm.timeoutTime != 0 {
		return 0
	}
	now := rm.cm.Now()
	roundTimeout := rm.cm.roundTimeout
	roundTimeoutFactor := rm.cm.roundTimeoutFactor
	delay := float64(roundTimeout) * math.Pow(roundTimeoutFactor, float64(rm.round))
	rm.timeoutTime = float64(now) + delay
	log.Debug("RM gettimout", "height", rm.height, "round", rm.round)
	return delay
}

func (rm *RoundManager) setTimeoutPrecommit() {
	if rm.timeoutPrecommit != 0 {
		return
	}
	now := rm.cm.Now()
	timeout := 1
	timeoutFactor := 1.5
	delay := float64(timeout) * math.Pow(timeoutFactor, float64(rm.round))
	rm.timeoutPrecommit = float64(now) + delay
	log.Debug("RM get timeoutPrecommit", "height", rm.height, "round", rm.round)
}

func (rm *RoundManager) addVote(vote *types.Vote, force_replace bool, process bool) bool {
	// log.Debug("In RM addvote", "round", rm.round)
	if !rm.lockset.Contain(vote) {
		err := rm.lockset.Add(vote, force_replace)
		if err != nil {
			log.Error("err: ", "Add vote to lockset error", err)
			return false
		}
		if rm.lockset.IsValid() && process {
			log.Debug("To cm process")
			go rm.cm.Process(rm.height)
		} else {
			log.Debug("lockset is not valid")
		}
		return true
	}
	// log.Debug("vote already in lockset")
	return false
}

func (rm *RoundManager) addPrecommitVote(vote *types.PrecommitVote, force_replace bool, process bool) bool {
	if !rm.precommitLockset.Contain(vote) {
		err := rm.precommitLockset.Add(vote, force_replace)
		if err != nil {
			log.Debug("Add precommit vote to lockset error", err)
			return false
		}
		if rm.precommitLockset.IsValid() && process {
			if float64(rm.cm.Now()) >= rm.timeoutPrecommit {
				go rm.cm.Process(rm.height)
			} else {
				log.Debug("timeoutPrecommit not reach")
			}
		} else {
			log.Debug("pr lockset is not valid")
		}
		return true
	}
	// log.Debug("precommitVote already in lockset")
	return false
}

func (rm *RoundManager) addProposal(p types.Proposal) bool {
	rm.roundProcessMu.Lock()
	defer rm.roundProcessMu.Unlock()

	// log.Debug("addProposal in ", rm.round, p)
	if rm.proposal == nil {
		rm.proposal = p
		return true
	} else if rm.proposal.Blockhash() == p.Blockhash() {
		return true
	} else {
		log.Debug("addProposal Error:", rm.proposal, p)
		return false
	}
}

func (rm *RoundManager) process() {
	rm.roundProcessMu.Lock()
	defer rm.roundProcessMu.Unlock()
	////DEBUG
	log.Debug("In RM Process", "height", rm.height, "round", rm.round)
	if rm.hm.Round() != rm.round {
		return
	}
	if rm.cm.Height() != rm.height {
		return
	}

	p := rm.propose()
	switch proposal := p.(type) {
	case *types.BlockProposal:
		if proposal != nil {
			rm.cm.addBlockCandidates(proposal)
			rm.cm.broadcast(proposal)
		}
	case *types.VotingInstruction:
		rm.cm.broadcast(proposal)
	default:
		log.Debug("propose nothing")
	}
	if rm.voteLock != nil {
		log.Debug("voteLock is not nil", "height", rm.height, "roound", rm.round)
	} else {
		v := rm.vote()
		if v != nil {
			rm.cm.broadcast(v)
		}
	}

	if rm.lockset.IsValid() {
		if rm.precommitVoteLock == nil {
			pv := rm.votePrecommit()
			if pv != nil {
				rm.cm.broadcast(pv)
			}
		} else {
			log.Debug("precommitVoteLock is not nil in ", "height", rm.height, "round", rm.round)
		}
	} else {
		log.Debug("rm lockset is not valid yet")
	}
	// if !(rm.proposal == nil || rm.voteLock != nil) {
	// 	log.Debug("proposal: ", rm.proposal, rm.voteLock)
	// 	panic("RM Process Error")
	// }
}

func (rm *RoundManager) propose() types.Proposal {
	if !rm.cm.isWaitingForProposal() {
		log.Debug("proposing is not waiting for proposal")
		return nil
	}
	proposer := rm.cm.contract.proposer(rm.height, rm.round)
	if proposer != rm.cm.coinbase {
		log.Debug("I am not proposer in", "height", rm.height, "round", rm.round)
		return nil
	}
	log.Debug("I am a proposer in ", "height", rm.height, "round", rm.round)
	if rm.proposal != nil {
		addr, err := rm.proposal.From()
		if err != nil {
			log.Error("error occur %v", err)
			return nil
		}
		if addr != rm.cm.coinbase {
			addr, _ := rm.proposal.From()
			log.Error(addr.Hex(), rm.cm.coinbase.Hex())
			return nil
		}
		if rm.voteLock == nil {
			log.Error("Propose Error: voteLock nil")
			return nil
		}
		log.Debug("already propose in this HR", rm.height, rm.round)
		return rm.proposal
	}
	roundLockset := rm.cm.lastValidLockset()
	var proposal types.Proposal

	if roundLockset == nil && rm.round == 0 {
		log.Debug("make proposal")
		if bp := rm.mkProposal(); bp != nil {
			proposal = bp
		} else {
			return nil
		}
	} else if roundLockset == nil {
		log.Error("no valid round lockset for height")
		return nil
	} else {
		quorum, _ := roundLockset.HasQuorum()
		if !quorum {
			proposal = rm.mkProposal()
		} else {
			if p, err := types.NewVotingInstruction(rm.height, rm.round, roundLockset); err != nil {
				log.Error("error occur %v", err)
				return nil
			} else {
				proposal = p
				rm.cm.Sign(proposal)
			}
		}
	}
	rm.proposal = proposal

	return proposal
}

func (rm *RoundManager) mkProposal() *types.BlockProposal {
	var roundLockset *types.LockSet
	signingLockset := rm.cm.lastCommittingLockset().Copy()
	if rm.round > 0 {
		lastPrecommitVoteLock := rm.hm.LastPrecommitVoteLock()
		if lastPrecommitVoteLock != nil {
			log.Error("error occur: MkProposal error, there is precommit votelock")
			return nil
		}
		roundLockset = rm.cm.lastValidLockset().Copy()
	} else {
		roundLockset = nil
	}
	isQuorum, _ := signingLockset.HasQuorum()
	if !isQuorum {
		log.Error("error occur: MkProposal error ")
		return nil
	}
	if !(roundLockset != nil || rm.round == 0) {
		log.Error("error occur: MkProposal error ")
		return nil
	}

	// Try to wait more Tx per block
	// time.Sleep(1000 * 1000 * 1000 * 0.2)
	var block *types.Block
	if rm.cm.currentBlock != nil {
		log.Debug("block is prepared")
		block = rm.cm.currentBlock
	} else {
		log.Debug("block is not prepared")
		return nil
	}
	blockProposal, err := types.NewBlockProposal(rm.height, rm.round, block, signingLockset, roundLockset)
	if err != nil {
		log.Error("error occur %v", err)
		return nil
	}
	rm.cm.Sign(blockProposal)
	rm.cm.setProposalLock(block)
	log.Debug("Create block blockhash : ", blockProposal.Blockhash())
	return blockProposal
}

func (rm *RoundManager) vote() *types.Vote {

	if rm.voteLock != nil {
		//DEBUG
		log.Debug("voted")
		return nil
	}
	// DEBUG
	// log.Debug("in vote in RM", "height", rm.height, "round", rm.round)
	lastPrecommitVoteLock := rm.hm.LastPrecommitVoteLock()

	var vote *types.Vote
	if rm.proposal != nil {
		switch bp := rm.proposal.(type) {
		case *types.VotingInstruction: // vote for votinginstruction
			quorum, _ := bp.LockSet().HasQuorum()
			// quorumPossible, _ := bp.LockSet().QuorumPossible()
			if quorum {
				log.Debug("vote votinginstruction quorum")
				vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
			} else {
				if lastPrecommitVoteLock == nil {
					vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
				} else {
					vt := lastPrecommitVoteLock.VoteType
					switch vt {
					case 1: // repeat vote
						log.Debug("voting on last vote")
						vote = types.NewVote(rm.height, rm.round, lastPrecommitVoteLock.Blockhash, 1)
					default: // vote nil
						vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
					}
				}
			}
			log.Debug("voting on instruction")
			vote = types.NewVote(rm.height, rm.round, bp.Blockhash(), 1)
		case *types.BlockProposal:
			// assert isinstance(self.proposal, BlockProposal)
			// assert isinstance(self.proposal.block, Block)  # already linked to chain
			// assert self.proposal.lockset.has_NoQuorum or self.round == 0
			// assert self.proposal.block.prevhash == self.cm.head.hash
			if lastPrecommitVoteLock == nil {
				log.Debug("voting on new proporsal")
				vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 1)
			} else {
				vt := lastPrecommitVoteLock.VoteType
				switch vt {
				case 1: //repeat vote
					log.Debug("voting on last vote")
					vote = types.NewVote(rm.height, rm.round, lastPrecommitVoteLock.Blockhash, 1)
				default: // vote to proposed vote
					log.Debug("voting proposed block")
					vote = types.NewVote(rm.height, rm.round, rm.proposal.Blockhash(), 1)
				}
			}
		}
	} else if rm.timeoutTime != 0 && float64(rm.cm.Now()) >= rm.timeoutTime {
		if lastPrecommitVoteLock == nil {
			vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
		} else {
			vt := lastPrecommitVoteLock.VoteType
			switch vt {
			case 1: // repeat vote
				log.Debug("voting on last vote")
				vote = types.NewVote(rm.height, rm.round, lastPrecommitVoteLock.Blockhash, 1)
			default: // vote nil
				log.Debug("voting nil")
				vote = types.NewVote(rm.height, rm.round, common.StringToHash(""), 2)
			}
		}
	} else {
		log.Debug("Timeout time not reach, curr vs timeout:", "curr", float64(rm.cm.Now()), "timeout", rm.timeoutTime)
		return nil
	}
	if vote == nil {
		return nil
	}
	rm.cm.Sign(vote)
	rm.voteLock = vote
	log.Debug("vote success in", "height", rm.height, "round", rm.round)
	rm.addVote(vote, false, true)
	// rm.setTimeoutPrecommit()
	return vote
}

func (rm *RoundManager) votePrecommit() *types.PrecommitVote {
	if rm.precommitVoteLock != nil {
		log.Debug("precommit voted")
		return nil
	}
	var vote *types.PrecommitVote
	if rm.lockset.IsValid() {
		if quorum, blockhash := rm.lockset.HasQuorum(); quorum {
			log.Debug("prevote quorum. vote precommit on block")
			vote = types.NewPrecommitVote(rm.height, rm.round, blockhash, 1)
		} else if rm.timeoutTime != 0 && float64(rm.cm.Now()) >= rm.timeoutTime {
			log.Debug("prevote no quorum. vote precommit nil")
			vote = types.NewPrecommitVote(rm.height, rm.round, common.StringToHash(""), 2)
		} else {
			log.Debug("wait timeoutTime")
		}
	} else {
		log.Debug("prevote invalid")
	}
	if vote != nil {
		rm.cm.Sign(vote)
		if vote.VoteType == 1 {
			rm.precommitVoteLock = vote
		}
		// log.Debug("precommit vote success in H:", "height", rm.height)
		rm.addPrecommitVote(vote, false, true)
	}
	return vote
}
