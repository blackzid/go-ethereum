package core

import (
	"crypto/esdca"
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
	allowEmptyBlocks   bool
	numInitialBlocks   int
	roundTimeout       int     // timeout when waiting for proposal
	roundTimeoutFactor float64 // timeout increase per round
	transactionTimeout float64 // delay when waiting for new transaction

	chain *BlockChain
	// contract ConsensusContract
	privkey *ecdsa.PrivateKey
	// synchronizer *HDCSynchronizer
	// heights map[int]*HeightManager
	blockCandidates map[common.Hash]*BlockProposal
	// trackedProtocolFailures
	readyValidators []common.Address
	readyNonce      *big.Int
}
