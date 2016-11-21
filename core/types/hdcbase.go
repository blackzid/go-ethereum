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

type Signed struct {
	Sender *common.Address
	V      byte     // signature
	R, S   *big.Int // signature
}

// func (signed *Signed) Hash() common.Hash {
// 	v := rlpHash(signed)
// 	return v
// }

func (signed *Signed) SigHash() common.Hash {
	return rlpHash([]interface{}{
		signed.Sender,
	})
}

func (signed *Signed) From() (common.Address, error) {
	return recoverSender(signed)
}

func (signed *Signed) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, signed)
}

func (signed *Signed) DecodeRLP(s *rlp.Stream) error {
	err := s.Decode(signed)
	return err
}

// recover_sender
func recoverSender(signed *Signed) (common.Address, error) {

	pubkey, err := signed.publicKey()
	if err != nil {
		return common.Address{}, err
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubkey[1:])[12:])
	return addr, nil
}

func (signed *Signed) publicKey() ([]byte, error) {
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
	hash := signed.SigHash()
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

func (signed *Signed) WithSignature(sig []byte) (*Signed, error) {
	if len(sig) != 65 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	cpy := &Signed{Sender: signed.Sender}
	cpy.R = new(big.Int).SetBytes(sig[:32])
	cpy.S = new(big.Int).SetBytes(sig[32:64])
	cpy.V = sig[64] + 27
	return cpy, nil
}

// Sign this with a privacy key
func (signed *Signed) SignECDSA(prv *ecdsa.PrivateKey) (*Signed, error) {
	h := signed.SigHash()
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return signed.WithSignature(sig)
}

type Vote struct {
	signed *Signed

	height    uint64
	round     uint64
	blockhash common.Hash
	VoteType  uint64 // 0: vote , 1: voteblock , 2: votenil
}
type Votes []*Vote

// type VoteBlock struct {
// 	Vote
// }
// type VoteNil struct {
// 	Vote
// }

// implements sort interface

func NewVote(height uint64, round uint64, blockhash common.Hash, voteType uint64) *Vote {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &Vote{
		height:    height,
		round:     round,
		blockhash: blockhash,
		signed:    s,
		VoteType:  voteType,
	}
}
func (v *Vote) Height() uint64 { return v.height }
func (v *Vote) Round() uint64  { return v.round }
func (v *Vote) Hash() common.Hash {
	h := rlpHash(v)
	return h
}
func (v *Vote) Blockhash() common.Hash { return v.blockhash }

func (v *Vote) Sender() common.Address {
	if v.signed.Sender != nil {
		return *v.signed.Sender
	} else {
		addr, err := recoverSender(v.signed)
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			v.signed.Sender = &addr
			return addr
		}
	}
}
func (v *Vote) Sign(prv *ecdsa.PrivateKey) {
	s, err := v.signed.SignECDSA(prv)
	if err != nil {
		panic(err)
	} else {
		v.signed = s
	}
}
func (vote *Vote) hr() (uint64, uint64) {
	return vote.height, vote.round
}

type LockSet struct {
	signed           *Signed
	eligibleVotesNum uint64
	votes            Votes
	processed        bool
}

func NewLockSet(eligibleVotesNum uint64, vs Votes) *LockSet {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	ls := &LockSet{
		eligibleVotesNum: eligibleVotesNum,
		votes:            []*Vote{},
		processed:        false,
		signed:           s,
	}
	for _, v := range vs {
		ls.Add(v, false)
	}
	return ls
}

// TODO FIXME
func (ls *LockSet) Copy() *LockSet { return NewLockSet(ls.eligibleVotesNum, ls.votes) }
func (ls *LockSet) Votes() Votes   { return ls.votes }

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
	for _, v := range lockset.votes {
		bhs[v.blockhash] += 1
	}
	hs := make(HashCounts, 0)
	for bh := range bhs {
		hs = append(hs, HashCount{blockhash: bh, count: bhs[bh]})
	}
	sort.Sort(hs)
	return hs
}

func (lockset *LockSet) hr() (uint64, uint64) {
	if len(lockset.votes) == 0 {
		panic("no vote for hr()")
	}
	hset := make(map[uint64]struct{})
	rset := make(map[uint64]struct{})

	for _, v := range lockset.votes {
		hset[v.height] = struct{}{}
		rset[v.round] = struct{}{}
	}
	if len(hset) != 1 && len(rset) != 1 {
		glog.V(logger.Error).Infof("different hr in lockset")
	}
	return lockset.votes[0].round, lockset.votes[0].round
}
func (lockset *LockSet) Sender() common.Address {
	if lockset.signed.Sender != nil {
		return *lockset.signed.Sender
	} else {
		addr, err := recoverSender(lockset.signed)
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
func (lockset *LockSet) Sign(prv *ecdsa.PrivateKey) {
	s, err := lockset.signed.SignECDSA(prv)
	if err != nil {
		panic(err)
	} else {
		lockset.signed = s
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
		lockset.votes = append(lockset.votes, vote)
	}
	return true
}

func (lockset *LockSet) Contain(vote *Vote) bool {
	return containsVote(lockset.votes, vote)
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
	if float64(len(lockset.votes)) > 2/3.*float64(lockset.eligibleVotesNum) {
		lockset.hr() // check votes' validation
		return true
	}
	return false
}

func (lockset *LockSet) HasQuorum() (bool, common.Hash) {
	lockset.IsValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) > 2/3.*float64(lockset.eligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}

func (lockset *LockSet) NoQuorum() bool {
	lockset.IsValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) < 1/3.*float64(lockset.eligibleVotesNum) {
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
	if float64(hs[0].count) > 1/3.*float64(lockset.eligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}

// func (lockset *Lockset) check() {
// 'check either invalid or one of quorum, noquorum, quorumpossible'
// }

/////////////////////////////////////////////

func genesisSigningLockset(genesis *common.Address, prv *ecdsa.PrivateKey) *LockSet {
	v := NewVote(0, 0, genesis.Hash(), 0)
	v.signed.SignECDSA(prv)
	ls := NewLockSet(1, Votes{})
	ls.Add(v, false)
	if result, _ := ls.QuorumPossible(); result == false {
		panic("Genesis Signing Lockset error")
	}
	return ls
}

type Ready struct {
	signed         Signed
	nonce          *big.Int
	currentLockSet *LockSet
}

func NewReady(nonce *big.Int, currentLockSet *LockSet) *Ready {
	return &Ready{
		signed: Signed{
			R: new(big.Int),
			S: new(big.Int),
		},
		nonce:          nonce,
		currentLockSet: currentLockSet,
	}
}
func (r *Ready) Sender() common.Address {
	if r.signed.Sender != nil {
		return *r.signed.Sender
	} else {
		addr, err := recoverSender(&r.signed)
		if err != nil {
			glog.V(logger.Error).Infof("sender() error ", err)
			panic("recoversender error")
		} else {
			r.signed.Sender = &addr
			return addr
		}
	}
}
func (r *Ready) Hash() common.Hash {
	h := rlpHash(r)
	return h
}
func (r *Ready) Nonce() *big.Int {
	return r.nonce
}

func (r *Ready) Sign(prv *ecdsa.PrivateKey) {
	s, err := r.signed.SignECDSA(prv)
	if err != nil {
		panic(err)
	} else {
		r.signed = *s
	}
}

type Proposal interface {
	Sign(prv *ecdsa.PrivateKey)
	Height() uint64
	Round() uint64
	Sender() common.Address
	Blockhash() common.Hash
	LockSet() *LockSet
}
type BlockProposal struct {
	signed *Signed

	height         uint64
	round          uint64
	block          *Block
	signingLockset *LockSet
	round_lockset  *LockSet
	rawhash        common.Hash
	blockhash      common.Hash
}

func NewBlockProposal(height uint64, round uint64, block *Block, signingLockset *LockSet, round_lockset *LockSet) *BlockProposal {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &BlockProposal{
		signed:         s,
		height:         height,
		round:          round,
		block:          block,
		signingLockset: signingLockset,
		round_lockset:  round_lockset,
		blockhash:      block.Hash(),
	}
}
func (bp *BlockProposal) Height() uint64 { return bp.height }
func (bp *BlockProposal) Round() uint64  { return bp.round }
func (bp *BlockProposal) Sender() common.Address {
	if bp.signed.Sender != nil {
		return *bp.signed.Sender
	} else {
		addr, err := recoverSender(bp.signed)
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

func (bp *BlockProposal) SigningLockset() *LockSet { return bp.signingLockset }
func (bp *BlockProposal) Blockhash() common.Hash   { return bp.blockhash }
func (bp *BlockProposal) LockSet() *LockSet {
	if bp.round_lockset != nil {
		return bp.round_lockset
	} else {
		return bp.signingLockset
	}
}

func (bp *BlockProposal) SigHash() common.Hash {
	return rlpHash([]interface{}{
		bp.signed.Sender,
		bp.height,
		bp.round,
		bp.signingLockset,
		bp.round_lockset,
	})
}

func (bp *BlockProposal) Sign(prv *ecdsa.PrivateKey) {
	s, err := bp.signed.SignECDSA(prv)
	if err != nil {
		panic(err)
	} else {
		bp.signed = s
	}
}

func (bp *BlockProposal) validateVotes(validators_H []common.Address, validators_prevH []common.Address) bool {
	if bp.round_lockset != nil {
		return checkVotes(bp.round_lockset, validators_H)
	} else {
		return checkVotes(bp.signingLockset, validators_prevH)
	}
}
func checkVotes(lockset *LockSet, validators []common.Address) bool {
	if int(lockset.eligibleVotesNum) != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range lockset.votes {
		if containsAddress(validators, *v.signed.Sender) {
			panic("invalid signer")
		}
	}
	return true
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
	signed *Signed

	height        uint64
	round         uint64
	round_lockset *LockSet
	blockhash     common.Hash
}

func NewVotingInstruction(height uint64, round uint64, round_lockset *LockSet) *VotingInstruction {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	b, hash := round_lockset.QuorumPossible()
	if b == false {
		panic("hash error")
	}
	return &VotingInstruction{
		signed:        s,
		height:        height,
		round:         round,
		round_lockset: round_lockset,
		blockhash:     hash,
	}
}
func (vi *VotingInstruction) Height() uint64 { return vi.height }
func (vi *VotingInstruction) Round() uint64  { return vi.round }
func (vi *VotingInstruction) Sender() common.Address {
	if vi.signed.Sender != nil {
		return *vi.signed.Sender
	} else {
		addr, err := recoverSender(vi.signed)
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
func (vi *VotingInstruction) Blockhash() common.Hash { return vi.blockhash }
func (vi *VotingInstruction) LockSet() *LockSet      { return vi.round_lockset }
func (vi *VotingInstruction) validateVotes(validators []common.Address) {
	if int(vi.round_lockset.eligibleVotesNum) != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range vi.round_lockset.votes {
		if containsAddress(validators, *v.signed.Sender) {
			panic("invalid signer")
		}
	}
}
func (vi *VotingInstruction) Sign(prv *ecdsa.PrivateKey) {
	s, err := vi.signed.SignECDSA(prv)
	if err != nil {
		panic(err)
	} else {
		vi.signed = s
	}
}
