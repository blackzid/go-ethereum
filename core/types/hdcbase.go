package types

import (
	// "container/heap"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	// "sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/rlp"
)

type signed struct {
	Sender *common.Address
	V      byte     // signature
	R, S   *big.Int // signature
}

func (signed *signed) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, signed)
}

func (signed *signed) DecodeRLP(s *rlp.Stream) error {
	err := s.Decode(signed)
	return err
}

// recover_sender
func (signed *signed) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := signed.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	signed.Sender = &addr
	return addr, nil
}
func (signed *signed) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(signed.V, signed.R, signed.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := signed.R.Bytes(), signed.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = signed.V - 27

	// recover the public key from the signature
	// hash := signed.SigHash()
	pub, err := crypto.Ecrecover(hash[:], sig)
	if err != nil {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", err)
		return nil, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return nil, errors.New("invalid public key")
	}
	return pub, nil
}

//sign
func (signed *signed) WithSignature(sig []byte) (*signed, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	signed.R = new(big.Int).SetBytes(sig[:32])
	signed.S = new(big.Int).SetBytes(sig[32:64])
	signed.V = sig[64] + 27
	return signed, nil
}

// Sign this with a privacy key
func (signed *signed) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*signed, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return signed.WithSignature(sig)
}

type Vote struct {
	signed signed

	Height    uint64
	Round     uint64
	Blockhash common.Hash
	VoteType  uint64 // 0: vote , 1: voteblock , 2: votenil
}
type Votes []*Vote

func NewVote(height uint64, round uint64, blockhash common.Hash, voteType uint64) *Vote {
	s := signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &Vote{
		signed:    s,
		Height:    height,
		Round:     round,
		Blockhash: blockhash,
		VoteType:  voteType,
	}
}
func (v *Vote) Sender() common.Address {
	if v.signed.Sender != nil {
		return *v.signed.Sender
	} else {
		addr, err := v.signed.recoverSender(v.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			v.signed.Sender = &addr
			return addr
		}
	}
}
func (v *Vote) Hash() common.Hash {
	h := rlpHash(v)
	return h
}
func (v *Vote) SigHash() common.Hash {
	return rlpHash([]interface{}{
		v.Height,
		v.Round,
		v.VoteType,
		v.Blockhash,
	})
}
func (v *Vote) Sign(prv *ecdsa.PrivateKey) {
	_, err := v.signed.SignECDSA(prv, v.SigHash())
	if err != nil {
		panic(err)
	}
}
func (vote *Vote) hr() (uint64, uint64) {
	return vote.Height, vote.Round
}

type LockSet struct {
	signed           signed
	EligibleVotesNum uint64
	Votes            Votes
	processed        bool
}

func NewLockSet(eligibleVotesNum uint64, vs Votes) *LockSet {
	s := signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	ls := &LockSet{
		signed:           s,
		EligibleVotesNum: eligibleVotesNum,
		Votes:            []*Vote{},
		processed:        false,
	}
	for _, v := range vs {
		ls.Add(v, false)
	}
	return ls
}

// TODO FIXME
func (ls *LockSet) Copy() *LockSet { return NewLockSet(ls.EligibleVotesNum, ls.Votes) }

type HashCount struct {
	blockhash common.Hash
	count     int
}
type HashCounts []HashCount

func (s HashCounts) Len() int           { return len(s) }
func (s HashCounts) Less(i, j int) bool { return s[i].count > s[j].count }
func (s HashCounts) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (lockset *LockSet) sortByBlockhash() HashCounts {
	// bhs := make(HashCount, 0, len(lockset.votes))
	bhs := make(map[common.Hash]int)
	for _, v := range lockset.Votes {
		bhs[v.Blockhash] += 1
	}
	hs := make(HashCounts, 0)
	for bh := range bhs {
		hs = append(hs, HashCount{blockhash: bh, count: bhs[bh]})
	}
	sort.Sort(hs)
	return hs
}

func (lockset *LockSet) hr() (uint64, uint64) {
	if len(lockset.Votes) == 0 {
		panic("no vote for hr()")
	}
	hset := make(map[uint64]struct{})
	rset := make(map[uint64]struct{})

	for _, v := range lockset.Votes {
		hset[v.Height] = struct{}{}
		rset[v.Round] = struct{}{}
	}
	if len(hset) != 1 && len(rset) != 1 {
		glog.V(logger.Error).Infof("different hr in lockset")
	}
	return lockset.Votes[0].Round, lockset.Votes[0].Round
}
func (lockset *LockSet) Sender() common.Address {
	if lockset.signed.Sender != nil {
		return *lockset.signed.Sender
	} else {
		addr, err := lockset.signed.recoverSender(lockset.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			lockset.signed.Sender = &addr
			return addr
		}
	}
}
func (lockset *LockSet) Hash() common.Hash {
	h := rlpHash(lockset)
	return h
}

func (lockset *LockSet) Height() uint64 {
	h, _ := lockset.hr()
	return h
}
func (lockset *LockSet) Round() uint64 {
	_, r := lockset.hr()
	return r
}
func (lockset *LockSet) SigHash() common.Hash {
	return rlpHash([]interface{}{
		lockset.EligibleVotesNum,
		lockset.Votes,
	})
}
func (lockset *LockSet) Sign(prv *ecdsa.PrivateKey) {
	_, err := lockset.signed.SignECDSA(prv, lockset.SigHash())
	if err != nil {
		panic(err)
	}
}

var ErrInvalidVote = errors.New("no signature")

func (lockset *LockSet) Add(vote *Vote, force bool) bool {
	// glog.V(logger.Info).Infoln(*vote.signed.Sender)
	if vote.signed.Sender == nil {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", ErrInvalidVote)
		return false
	}
	//
	// FIX ME
	//
	if !lockset.Contain(vote) {
		lockset.Votes = append(lockset.Votes, vote)
	}
	return true
}

func (lockset *LockSet) Contain(vote *Vote) bool {
	return containsVote(lockset.Votes, vote)
}

func containsVote(s []*Vote, e *Vote) bool {
	for _, a := range s {
		if *a == *e {
			return true
		}
	}
	return false
}
func (lockset *LockSet) IsValid() bool {
	if float64(len(lockset.Votes)) > 2/3.*float64(lockset.EligibleVotesNum) {
		lockset.hr() // check votes' validation
		return true
	}
	return false
}

func (lockset *LockSet) HasQuorum() (bool, common.Hash) {
	lockset.IsValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) > 2/3.*float64(lockset.EligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}

func (lockset *LockSet) NoQuorum() bool {
	lockset.IsValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) < 1/3.*float64(lockset.EligibleVotesNum) {
		return true
	} else {
		return false
	}
}

func (lockset *LockSet) QuorumPossible() (bool, common.Hash) {
	if result, hs := lockset.HasQuorum(); result != false {
		return false, hs
	}
	lockset.IsValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) > 1/3.*float64(lockset.EligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}
func checkVotes(lockset *LockSet, validators []common.Address) bool {
	if int(lockset.EligibleVotesNum) != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range lockset.Votes {
		if containsAddress(validators, *v.signed.Sender) {
			panic("invalid signer")
		}
	}
	return true
}

// func (lockset *Lockset) check() {
// 'check either invalid or one of quorum, noquorum, quorumpossible'
// }

/////////////////////////////////////////////

func genesisSigningLockset(genesis *common.Address, prv *ecdsa.PrivateKey) *LockSet {
	v := NewVote(0, 0, genesis.Hash(), 0)
	v.signed.SignECDSA(prv, v.SigHash())
	ls := NewLockSet(1, Votes{})
	ls.Add(v, false)
	if result, _ := ls.QuorumPossible(); result == false {
		panic("Genesis Signing Lockset error")
	}
	return ls
}

type Ready struct {
	signed         signed
	Nonce          *big.Int
	CurrentLockSet *LockSet
}

func NewReady(nonce *big.Int, currentLockSet *LockSet) *Ready {
	return &Ready{
		signed: signed{
			R: new(big.Int),
			S: new(big.Int),
		},
		Nonce:          nonce,
		CurrentLockSet: currentLockSet,
	}
}
func (r *Ready) Hash() common.Hash {
	h := rlpHash(r)
	return h
}
func (r *Ready) SigHash() common.Hash {
	return rlpHash([]interface{}{
		r.Nonce,
		r.CurrentLockSet,
	})
}
func (r *Ready) Sender() common.Address {
	if r.signed.Sender != nil {
		return *r.signed.Sender
	} else {
		addr, err := r.signed.recoverSender(r.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			r.signed.Sender = &addr
			return addr
		}
	}
}
func (r *Ready) Sign(prv *ecdsa.PrivateKey) {
	_, err := r.signed.SignECDSA(prv, r.SigHash())
	if err != nil {
		panic(err)
	}
}

type Proposal interface {
	Sign(prv *ecdsa.PrivateKey)
	Sender() common.Address
	GetHeight() uint64
	GetRound() uint64
	Blockhash() common.Hash
	LockSet() *LockSet
}
type BlockProposal struct {
	signed signed

	Height         uint64
	Round          uint64
	Block          *Block
	SigningLockset *LockSet
	RoundLockset   *LockSet
}

func NewBlockProposal(height uint64, round uint64, block *Block, signingLockset *LockSet, round_lockset *LockSet) *BlockProposal {
	s := signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &BlockProposal{
		signed:         s,
		Height:         height,
		Round:          round,
		Block:          block,
		SigningLockset: signingLockset,
		RoundLockset:   round_lockset,
	}
}
func (bp *BlockProposal) GetHeight() uint64 { return bp.Height }
func (bp *BlockProposal) GetRound() uint64  { return bp.Round }

func (bp *BlockProposal) Sender() common.Address {
	if bp.signed.Sender != nil {
		return *bp.signed.Sender
	} else {
		addr, err := bp.signed.recoverSender(bp.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			bp.signed.Sender = &addr
			return addr
		}
	}
}
func (bp *BlockProposal) Hash() common.Hash {
	h := rlpHash(bp)
	return h
}
func (bp *BlockProposal) SigHash() common.Hash {
	return rlpHash([]interface{}{
		bp.signed.Sender,
		bp.Height,
		bp.Round,
		bp.SigningLockset,
		bp.RoundLockset,
	})
}

// func (bp *BlockProposal) SigningLockset() *LockSet { return bp.SigningLockset }
func (bp *BlockProposal) Blockhash() common.Hash { return bp.Block.Hash() }
func (bp *BlockProposal) LockSet() *LockSet {
	if bp.RoundLockset != nil {
		return bp.RoundLockset
	} else {
		return bp.SigningLockset
	}
}

func (bp *BlockProposal) Sign(prv *ecdsa.PrivateKey) {
	_, err := bp.signed.SignECDSA(prv, bp.SigHash())
	if err != nil {
		panic(err)
	}
}

func (bp *BlockProposal) validateVotes(validators_H []common.Address, validators_prevH []common.Address) bool {
	if bp.RoundLockset != nil {
		return checkVotes(bp.RoundLockset, validators_H)
	} else {
		return checkVotes(bp.SigningLockset, validators_prevH)
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

type VotingInstruction struct {
	signed signed

	Height       uint64
	Round        uint64
	RoundLockset *LockSet
}

func NewVotingInstruction(height uint64, round uint64, roundLockset *LockSet) *VotingInstruction {
	s := signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &VotingInstruction{
		signed:       s,
		Height:       height,
		Round:        round,
		RoundLockset: roundLockset,
	}
}
func (vi *VotingInstruction) GetHeight() uint64 { return vi.Height }
func (vi *VotingInstruction) GetRound() uint64  { return vi.Round }

func (vi *VotingInstruction) Sender() common.Address {
	if vi.signed.Sender != nil {
		return *vi.signed.Sender
	} else {
		addr, err := vi.signed.recoverSender(vi.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			vi.signed.Sender = &addr
			return addr
		}
	}
}
func (vi *VotingInstruction) Hash() common.Hash {
	h := rlpHash(vi)
	return h
}
func (vi *VotingInstruction) SigHash() common.Hash {
	return rlpHash([]interface{}{
		vi.Height,
		vi.Round,
		vi.RoundLockset,
	})
}
func (vi *VotingInstruction) Blockhash() common.Hash {
	_, hash := vi.RoundLockset.HasQuorum()
	return hash
}
func (vi *VotingInstruction) LockSet() *LockSet { return vi.RoundLockset }
func (vi *VotingInstruction) validateVotes(validators []common.Address) {
	if int(vi.RoundLockset.EligibleVotesNum) != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range vi.RoundLockset.Votes {
		if containsAddress(validators, *v.signed.Sender) {
			panic("invalid signer")
		}
	}
}
func (vi *VotingInstruction) Sign(prv *ecdsa.PrivateKey) {
	_, err := vi.signed.SignECDSA(prv, vi.SigHash())
	if err != nil {
		panic(err)
	}
}
