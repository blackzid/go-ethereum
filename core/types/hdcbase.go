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
	sender *common.Address
	V      byte     // signature
	R, S   *big.Int // signature
}

func (signed *Signed) Hash() common.Hash {
	v := rlpHash(signed)
	return v
}

func (signed *Signed) SigHash() common.Hash {
	return rlpHash([]interface{}{
		signed.sender,
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
	cpy := &Signed{sender: signed.sender}
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

	height    int
	round     int
	blockhash common.Hash
}
type Votes []*Vote
type VoteBlock struct {
	Vote
}
type VoteNil struct {
	Vote
}

// implements sort interface

func NewVote(height int, round int, blockhash common.Hash) *Vote {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &Vote{
		height:    height,
		round:     round,
		blockhash: blockhash,
		signed:    s,
	}
}

func (vote *Vote) hr() (int, int) {
	return vote.height, vote.round
}

type LockSet struct {
	signed           *Signed
	eligibleVotesNum int
	votes            Votes
	processed        bool
}

func NewLockSet(eligibleVotesNum int, votes Votes) *LockSet {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &LockSet{
		eligibleVotesNum: eligibleVotesNum,
		votes:            []*Vote{},
		processed:        false,
		signed:           s,
	}
}

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

func (lockset *LockSet) hr() (int, int) {
	hset := make(map[int]struct{})
	rset := make(map[int]struct{})

	for _, v := range lockset.votes {
		hset[v.height] = struct{}{}
		rset[v.round] = struct{}{}
	}
	if len(hset) != 1 && len(rset) != 1 {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", "different hr in lockset")
	}
	return lockset.votes[0].round, lockset.votes[0].round
}

func (lockset *LockSet) height() int {
	h, _ := lockset.hr()
	return h
}
func (lockset *LockSet) round() int {
	_, r := lockset.hr()
	return r
}

var ErrInvalidVote = errors.New("no signature")

func (lockset *LockSet) add(vote *Vote, force bool) bool {

	if vote.signed.sender == nil {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", ErrInvalidVote)
		return false
	}
	//
	// FIX ME
	//
	if !lockset.contain(vote) {
		lockset.votes = append(lockset.votes, vote)
	}
	return true
}

func (lockset *LockSet) contain(vote *Vote) bool {
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
func (lockset *LockSet) isValid() bool {
	lockset.hr() // check votes' validation
	return float64(len(lockset.votes)) > 2/3.*float64(lockset.eligibleVotesNum)
}

func (lockset *LockSet) hasQuorum() (bool, common.Hash) {
	lockset.isValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) > 2/3.*float64(lockset.eligibleVotesNum) {
		return true, hs[0].blockhash
	} else {
		return false, common.Hash{}
	}
}

func (lockset *LockSet) noQuorum() bool {
	lockset.isValid()
	hs := lockset.sortByBlockhash()
	if float64(hs[0].count) < 1/3.*float64(lockset.eligibleVotesNum) {
		return true
	} else {
		return false
	}
}

func (lockset *LockSet) quorumPossible() (bool, common.Hash) {
	if result, hs := lockset.hasQuorum(); result != false {
		return false, hs
	}
	lockset.isValid()
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
	v := NewVote(0, 0, genesis.Hash())
	v.signed.SignECDSA(prv)
	ls := NewLockSet(1, Votes{})
	ls.add(v, false)
	if result, _ := ls.quorumPossible(); result == false {
		panic("Genesis Signing Lockset error")
	}
	return ls
}

type Ready struct {
	signed         *Signed
	nonce          *big.Int
	currentLockSet *LockSet
}

func NewReady(nonce *big.Int, currentLockSet *LockSet) *Ready {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}

	return &Ready{
		signed:         s,
		nonce:          nonce,
		currentLockSet: currentLockSet,
	}
}
func (r *Ready) sign(prv *ecdsa.PrivateKey) {
	r.signed.SignECDSA(prv)
}

type Proposal interface {
	sign(prv *ecdsa.PrivateKey)
}
type BlockProposal struct {
	signed *Signed

	height         int
	round          int
	block          *Block
	signingLockset *LockSet
	round_lockset  *LockSet
	rawhash        common.Hash
	blockhash      common.Hash
}

func (bp *BlockProposal) SigHash() common.Hash {
	return rlpHash([]interface{}{
		bp.signed.sender,
		bp.height,
		bp.round,
		bp.signingLockset,
		bp.round_lockset,
	})
}

func NewBlockProposal(height int, round int, block *Block, signingLockset *LockSet, round_lockset *LockSet) *BlockProposal {
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

func (bp *BlockProposal) lockset() *LockSet {
	if bp.round_lockset != nil {
		return bp.round_lockset
	} else {
		return bp.signingLockset
	}
}
func (bp *BlockProposal) sign(prv *ecdsa.PrivateKey) {
	bp.signed.SignECDSA(prv)
}
func (bp *BlockProposal) validateVotes(validators_H []common.Address, validators_prevH []common.Address) bool {
	if bp.round_lockset != nil {
		return checkVotes(bp.round_lockset, validators_H)
	} else {
		return checkVotes(bp.signingLockset, validators_prevH)
	}
}
func checkVotes(lockset *LockSet, validators []common.Address) bool {
	if lockset.eligibleVotesNum != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range lockset.votes {
		if containsAddress(validators, *v.signed.sender) {
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

	height        int
	round         int
	round_lockset *LockSet
	blockhash     common.Hash
}

func NewVotingInstruction(height int, round int, round_lockset *LockSet) *VotingInstruction {
	s := &Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	b, hash := round_lockset.quorumPossible()
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

func (vi *VotingInstruction) validateVotes(validators []common.Address) {
	if vi.round_lockset.eligibleVotesNum != len(validators) {
		panic("lockset num_eligible_votes mismatch")
	}
	for _, v := range vi.round_lockset.votes {
		if containsAddress(validators, *v.signed.sender) {
			panic("invalid signer")
		}
	}
}
func (vi *VotingInstruction) sign(prv *ecdsa.PrivateKey) {
	vi.signed.SignECDSA(prv)
}
