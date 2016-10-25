package core

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/pow"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/hashicorp/golang-lru"
)

type ConsensusManager struct {
	allow_empty_blocks   bool
	num_initial_blocks   int
	round_timeout        int
	round_timeout_factor float64
	transaction_timeout  float64
	e                    *Ethereum
	chain                *BlockChain
	privkey              *ecdsa.PrivateKey
}

type HeightManager struct {
}

type RoundManager struct {
	hm           *HeightManager
	cm           *ConsensusManager
	round        int
	height       int
	lockset      *LockSet
	proposal     *BlockProposal
	lock         *Vote
	timeout_time int
}

func NewRoundManager(heightmanager *HeightManager, round int) *RoundManager {
	return &RoundManager{
		hm: heightmanager,
		cm: heightmanager.cm,
	}
}
