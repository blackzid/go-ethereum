package types

import (
	"container/heap"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"sync/atomic"

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
	signed Signed

	eligibleVotesNum    *big.Int
	votes               []*Vote
	processed           bool
	is_valid            bool
	has_quorum          bool
	has_quorum_possible bool
	has_noquorum        bool
	height              *big.Int
	round               *big.Int
	blockhash           common.Hash
}

func NewVote(height *big.Int, round *big.Int, blockhash common.Hash) *Vote {
	s := Signed{
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

type LockSet struct {
	signed              Signed
	eligibleVotesNum    *big.Int
	votes               []*Vote
	processed           bool
	is_valid            bool
	has_quorum          bool
	has_quorum_possible bool
	has_noquorum        bool
}

func NewLockSet(eligibleVotesNum *big.Int, votes []*Vote) *Vote {
	s := Signed{
		R: new(big.Int),
		S: new(big.Int),
	}
	return &Vote{
		eligibleVotesNum:    eligibleVotesNum,
		votes:               []*Vote{},
		processed:           false,
		is_valid:            false,
		has_quorum:          false,
		has_quorum_possible: false,
		has_noquorum:        false,
		signed:              s,
	}
}

var ErrInvalidVote = errors.New("no signature")

func (lockset *LockSet) add(vote *Vote, force bool) bool {

	if vote.signed.sender == nil {
		glog.V(logger.Error).Infof("Could not get pubkey from signature: ", ErrInvalidVote)
		return false
	}
	if !contains(lockset.votes, vote) {
		return true
	}
}

func contains(s []*Vote, e Vote) bool {
	for _, a := range s {
		if *a == e {
			return true
		}
	}
	return false
}

func (lockset *LockSet) hr() (big.Int, big.Int) {

}

type BlockProposal struct {
	signed *Signed

	height          *big.Int
	round           *big.Int
	block           *big.Int
	signing_lockset *big.Int
	round_lockset   *big.Int
}

type VotingInstruction struct {
	signed *Signed

	height        *big.Int
	round         *big.Int
	round_lockset LockSet
}
