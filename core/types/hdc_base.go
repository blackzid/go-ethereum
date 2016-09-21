package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sort"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rlp"
)

type Signed struct {
	sender *common.Address
}

type Vote struct {
	signed *Signed

	height    *big.Int
	round     *big.Int
	blockhash common.Hash
}

type LockSet struct {
	num_eligible_votes *big.Int
	votes              []Vote
	processed          bool
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
