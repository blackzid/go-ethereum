package types

import (
	// "container/heap"
	"crypto/ecdsa"
	"errors"
	"fmt"
	// "io"
	"math/big"
	"sort"
	// "sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	// "github.com/ethereum/go-ethereum/rlp"
)

type Vote struct {
	// signed signed
	sender    *common.Address
	V         byte     // signature
	R, S      *big.Int // signature
	Height    uint64
	Round     uint64
	Blockhash common.Hash
	VoteType  uint64 // 0: vote , 1: voteblock , 2: votenil
}
type Votes []*Vote

func NewVote(height uint64, round uint64, blockhash common.Hash, voteType uint64) *Vote {
	return &Vote{
		R:         new(big.Int),
		S:         new(big.Int),
		Height:    height,
		Round:     round,
		Blockhash: blockhash,
		VoteType:  voteType,
	}
}

func (v *Vote) Hash() common.Hash {
	return rlpHash([]interface{}{
		v.sender,
		v.Height,
		v.Round,
		v.VoteType,
		v.Blockhash,
	})
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
	_, err := v.SignECDSA(prv, v.SigHash())
	if err != nil {
		panic(err)
	}
}
func (vote *Vote) hr() (uint64, uint64) {
	return vote.Height, vote.Round
}
func (v *Vote) From() common.Address {
	if v.sender != nil {
		return *v.sender
	} else {
		addr, err := v.recoverSender(v.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			v.sender = &addr
			return addr
		}
	}
}
func (vote *Vote) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := vote.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	vote.sender = &addr
	return addr, nil
}
func (vote *Vote) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(vote.V, vote.R, vote.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := vote.R.Bytes(), vote.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = vote.V - 27

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
func (vote *Vote) WithSignature(sig []byte) (*Vote, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	vote.R = new(big.Int).SetBytes(sig[:32])
	vote.S = new(big.Int).SetBytes(sig[32:64])
	vote.V = sig[64] + 27
	return vote, nil
}

// Sign this with a privacy key
func (vote *Vote) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*Vote, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return vote.WithSignature(sig)
}

type LockSet struct {
	// signed           signed
	sender           *common.Address
	V                byte     // signature
	R, S             *big.Int // signature
	EligibleVotesNum uint64
	Votes            Votes
	processed        bool
}

func NewLockSet(eligibleVotesNum uint64, vs Votes) *LockSet {

	ls := &LockSet{
		R:                new(big.Int),
		S:                new(big.Int),
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
		if v.VoteType == 1 {
			bhs[v.Blockhash] += 1
		}
	}
	hs := make(HashCounts, 0)
	for bh, count := range bhs {
		hs = append(hs, HashCount{blockhash: bh, count: count})
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
	return lockset.Votes[0].Height, lockset.Votes[0].Round
}
func (lockset *LockSet) From() common.Address {
	if lockset.sender != nil {
		return *lockset.sender
	} else {
		addr, err := lockset.recoverSender(lockset.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			lockset.sender = &addr
			return addr
		}
	}
}
func (lockset *LockSet) Hash() common.Hash {
	return rlpHash([]interface{}{
		lockset.sender,
		lockset.EligibleVotesNum,
		lockset.Votes,
	})
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
	_, err := lockset.SignECDSA(prv, lockset.SigHash())
	if err != nil {
		panic(err)
	}
}

var ErrInvalidVote = errors.New("no signature")

func (lockset *LockSet) Add(vote *Vote, force bool) bool {
	// glog.V(logger.Info).Infoln(*vote.signed.sender)
	vote.From()
	if vote.sender == nil {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", ErrInvalidVote)
		panic("Lockset Adding error")
	}

	if !lockset.Contain(vote) {

		if len(lockset.Votes) != 0 && (vote.Height != lockset.Height() || vote.Round != lockset.Round()) {
			fmt.Printf("votes len:%d, lockset.Height: %d, lockset.Round: %d \n", len(lockset.Votes), lockset.Height(), lockset.Round())
			fmt.Printf("vote.Height: %d, vote.Round: %d \n", vote.Height, vote.Round)
			panic("Inconsistent height and round")
		}
		if containsAddress(lockset.signee(), *vote.sender) {
			if !force {
				panic("Different Votes on same V,R")
			}
			//
			// FIX ME
			//
		} else {
			lockset.Votes = append(lockset.Votes, vote)
		}
	}
	return true
}

func (lockset *LockSet) signee() []common.Address {
	signee := []common.Address{}
	for _, v := range lockset.Votes {
		signee = append(signee, *v.sender)
	}
	return signee
}
func (lockset *LockSet) Contain(vote *Vote) bool {
	return containsVote(lockset.Votes, vote)
}

func containsVote(s []*Vote, e *Vote) bool {
	for _, a := range s {
		if a.Height == e.Height && a.Round == e.Round && a.Blockhash == e.Blockhash && a.VoteType == e.VoteType && *a.sender == *e.sender {
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
	if !lockset.IsValid() {
		panic("Lockset invalid")
	}
	hs := lockset.sortByBlockhash()
	if len(hs) == 0 {
		return false, common.Hash{}
	}
	if float64(hs[0].count) > 2/3.0*float64(lockset.EligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}

func (lockset *LockSet) NoQuorum() bool {
	if !lockset.IsValid() {
		panic("Lockset invalid")
	}

	hs := lockset.sortByBlockhash()
	if len(hs) == 0 {
		return true
	}
	if float64(hs[0].count) <= 1/3.*float64(lockset.EligibleVotesNum) {
		return true
	} else {
		return false
	}
}

func (lockset *LockSet) QuorumPossible() (bool, common.Hash) {

	if result, hs := lockset.HasQuorum(); result != false {
		return false, hs
	}
	if !lockset.IsValid() {
		panic("Lockset invalid")
	}
	hs := lockset.sortByBlockhash()
	if len(hs) == 0 {
		return false, common.Hash{}
	}
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
		if containsAddress(validators, *v.sender) {
			panic("invalid signer")
		}
	}
	return true
}
func (lockset *LockSet) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := lockset.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	lockset.sender = &addr
	return addr, nil
}
func (lockset *LockSet) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(lockset.V, lockset.R, lockset.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := lockset.R.Bytes(), lockset.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = lockset.V - 27

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
func (lockset *LockSet) WithSignature(sig []byte) (*LockSet, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	lockset.R = new(big.Int).SetBytes(sig[:32])
	lockset.S = new(big.Int).SetBytes(sig[32:64])
	lockset.V = sig[64] + 27
	return lockset, nil
}

// Sign this with a privacy key
func (lockset *LockSet) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*LockSet, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return lockset.WithSignature(sig)
}

// func (lockset *Lockset) check() {
// 'check either invalid or one of quorum, noquorum, quorumpossible'
// }

/////////////////////////////////////////////

func genesisSigningLockset(genesis *common.Address, prv *ecdsa.PrivateKey) *LockSet {
	v := NewVote(0, 0, genesis.Hash(), 0)
	v.SignECDSA(prv, v.SigHash())
	ls := NewLockSet(1, Votes{})
	ls.Add(v, false)
	if result, _ := ls.QuorumPossible(); result == false {
		panic("Genesis Signing Lockset error")
	}
	return ls
}

type Ready struct {
	// signed         signed
	sender         *common.Address
	V              byte     // signature
	R, S           *big.Int // signature
	Nonce          *big.Int
	CurrentLockSet *LockSet
}

func NewReady(nonce *big.Int, currentLockSet *LockSet) *Ready {
	return &Ready{
		R:              new(big.Int),
		S:              new(big.Int),
		Nonce:          nonce,
		CurrentLockSet: currentLockSet,
	}
}
func (r *Ready) Hash() common.Hash {
	return rlpHash([]interface{}{
		r.sender,
		r.Nonce,
		r.CurrentLockSet,
	})
}
func (r *Ready) SigHash() common.Hash {
	return rlpHash([]interface{}{
		r.Nonce,
		r.CurrentLockSet,
	})
}
func (r *Ready) From() common.Address {
	if r.sender != nil {
		return *r.sender
	} else {
		addr, err := r.recoverSender(r.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			r.sender = &addr
			return addr
		}
	}
}
func (r *Ready) Sign(prv *ecdsa.PrivateKey) {
	_, err := r.SignECDSA(prv, r.SigHash())
	if err != nil {
		panic(err)
	}
}
func (r *Ready) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := r.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	r.sender = &addr
	return addr, nil
}
func (ready *Ready) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(ready.V, ready.R, ready.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := ready.R.Bytes(), ready.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = ready.V - 27

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
func (r *Ready) WithSignature(sig []byte) (*Ready, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	r.R = new(big.Int).SetBytes(sig[:32])
	r.S = new(big.Int).SetBytes(sig[32:64])
	r.V = sig[64] + 27
	return r, nil
}

// Sign this with a privacy key
func (r *Ready) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*Ready, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return r.WithSignature(sig)
}

type Proposal interface {
	Sign(prv *ecdsa.PrivateKey)
	From() common.Address
	GetHeight() uint64
	GetRound() uint64
	Blockhash() common.Hash
	LockSet() *LockSet
}
type BlockProposal struct {
	// signed signed
	sender         *common.Address
	V              byte     // signature
	R, S           *big.Int // signature
	Height         uint64
	Round          uint64
	Block          *Block
	SigningLockset *LockSet
	RoundLockset   *LockSet
}

func NewBlockProposal(height uint64, round uint64, block *Block, signingLockset *LockSet, roundLockset *LockSet) *BlockProposal {

	if roundLockset == nil {
		roundLockset = NewLockSet(0, Votes{})
	}

	return &BlockProposal{
		R:              new(big.Int),
		S:              new(big.Int),
		Height:         height,
		Round:          round,
		Block:          block,
		SigningLockset: signingLockset,
		RoundLockset:   roundLockset,
	}
}
func (bp *BlockProposal) GetHeight() uint64 { return bp.Height }
func (bp *BlockProposal) GetRound() uint64  { return bp.Round }

func (bp *BlockProposal) From() common.Address {
	if bp.sender != nil {
		return *bp.sender
	} else {
		addr, err := bp.recoverSender(bp.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			bp.sender = &addr
			return addr
		}
	}
}
func (bp *BlockProposal) Hash() common.Hash {
	return rlpHash([]interface{}{
		bp.sender,
		bp.Height,
		bp.Round,
		bp.SigningLockset,
		bp.RoundLockset,
	})
}
func (bp *BlockProposal) SigHash() common.Hash {
	return rlpHash([]interface{}{
		bp.Height,
		bp.Round,
		bp.SigningLockset,
		bp.RoundLockset,
	})
}

// func (bp *BlockProposal) SigningLockset() *LockSet { return bp.SigningLockset }
func (bp *BlockProposal) Blockhash() common.Hash { return bp.Block.Hash() }
func (bp *BlockProposal) LockSet() *LockSet {
	if bp.RoundLockset != nil && bp.RoundLockset.EligibleVotesNum != 0 {
		return bp.RoundLockset
	} else {
		return bp.SigningLockset
	}
}

func (bp *BlockProposal) Sign(prv *ecdsa.PrivateKey) {
	_, err := bp.SignECDSA(prv, bp.SigHash())
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
func (bp *BlockProposal) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := bp.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	bp.sender = &addr
	return addr, nil
}
func (bp *BlockProposal) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(bp.V, bp.R, bp.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := bp.R.Bytes(), bp.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = bp.V - 27

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
func (bp *BlockProposal) WithSignature(sig []byte) (*BlockProposal, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	bp.R = new(big.Int).SetBytes(sig[:32])
	bp.S = new(big.Int).SetBytes(sig[32:64])
	bp.V = sig[64] + 27
	return bp, nil
}

// Sign this with a privacy key
func (bp *BlockProposal) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*BlockProposal, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return bp.WithSignature(sig)
}

type VotingInstruction struct {
	// signed signed
	sender       *common.Address
	V            byte     // signature
	R, S         *big.Int // signature
	Height       uint64
	Round        uint64
	RoundLockset *LockSet
}

func NewVotingInstruction(height uint64, round uint64, roundLockset *LockSet) *VotingInstruction {
	return &VotingInstruction{
		R:            new(big.Int),
		S:            new(big.Int),
		Height:       height,
		Round:        round,
		RoundLockset: roundLockset,
	}
}
func (vi *VotingInstruction) GetHeight() uint64 { return vi.Height }
func (vi *VotingInstruction) GetRound() uint64  { return vi.Round }

func (vi *VotingInstruction) From() common.Address {
	if vi.sender != nil {
		return *vi.sender
	} else {
		addr, err := vi.recoverSender(vi.SigHash())
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			vi.sender = &addr
			return addr
		}
	}
}
func (vi *VotingInstruction) Hash() common.Hash {
	return rlpHash([]interface{}{
		vi.sender,
		vi.Height,
		vi.Round,
		vi.RoundLockset,
	})
}
func (vi *VotingInstruction) SigHash() common.Hash {
	return rlpHash([]interface{}{
		vi.Height,
		vi.Round,
		vi.RoundLockset,
	})
}
func (vi *VotingInstruction) Blockhash() common.Hash {
	_, hash := vi.RoundLockset.QuorumPossible()
	return hash
}
func (vi *VotingInstruction) LockSet() *LockSet { return vi.RoundLockset }
func (vi *VotingInstruction) validateVotes(validators []common.Address) {
	if int(vi.RoundLockset.EligibleVotesNum) != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range vi.RoundLockset.Votes {
		if containsAddress(validators, *v.sender) {
			panic("invalid signer")
		}
	}
}
func (vi *VotingInstruction) Sign(prv *ecdsa.PrivateKey) {
	_, err := vi.SignECDSA(prv, vi.SigHash())
	if err != nil {
		panic(err)
	}
}
func (vi *VotingInstruction) recoverSender(hash common.Hash) (common.Address, error) {

	pubkey, err := vi.publicKey(hash)
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	vi.sender = &addr
	return addr, nil
}
func (vi *VotingInstruction) publicKey(hash common.Hash) ([]byte, error) {
	if !crypto.ValidateSignatureValues(vi.V, vi.R, vi.S, true) {
		return nil, ErrInvalidSig
	}

	// encode the signature in uncompressed format
	r, s := vi.R.Bytes(), vi.S.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = vi.V - 27

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
func (vi *VotingInstruction) WithSignature(sig []byte) (*VotingInstruction, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	vi.R = new(big.Int).SetBytes(sig[:32])
	vi.S = new(big.Int).SetBytes(sig[32:64])
	vi.V = sig[64] + 27
	return vi, nil
}

// Sign this with a privacy key
func (vi *VotingInstruction) SignECDSA(prv *ecdsa.PrivateKey, hash common.Hash) (*VotingInstruction, error) {
	sig, err := crypto.Sign(hash[:], prv)
	if err != nil {
		return nil, err
	}
	return vi.WithSignature(sig)
}

type RequestProposalNumber struct {
	Number uint64
}
