package eth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/ethash"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/compiler"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/net/context"
)

const defaultGas = uint64(90000)

type HydrachainAPI struct {
	h   *Hydrachain
	gpo *GasPriceOracle
}

func NewHydrachainAPI(h *Hydrachain) *HydrachainAPI {
	return &HydrachainAPI{
		h:   h,
		gpo: h.gpo,
	}
}

func (s *HydrachainAPI) GasPrice() *big.Int {
	return s.gpo.SuggestPrice()
}

// GetCompilers returns the collection of available smart contract compilers
func (s *HydrachainAPI) GetCompilers() ([]string, error) {
	solc, err := s.e.Solc()
	if err == nil && solc != nil {
		return []string{"Solidity"}, nil
	}

	return []string{}, nil
}

// CompileSolidity compiles the given solidity source
func (s *HydrachainAPI) CompileSolidity(source string) (map[string]*compiler.Contract, error) {
	solc, err := s.e.Solc()
	if err != nil {
		return nil, err
	}

	if solc == nil {
		return nil, errors.New("solc (solidity compiler) not found")
	}

	return solc.Compile(source)
}

// Etherbase is the address that mining rewards will be send to
func (s *HydrachainAPI) Etherbase() (common.Address, error) {
	return s.e.Etherbase()
}

// Coinbase is the address that mining rewards will be send to (alias for Etherbase)
func (s *HydrachainAPI) Coinbase() (common.Address, error) {
	return s.Etherbase()
}

// ProtocolVersion returns the current Ethereum protocol version this node supports
func (s *HydrachainAPI) ProtocolVersion() *rpc.HexNumber {
	return rpc.NewHexNumber(s.e.EthVersion())
}

// Hashrate returns the POW hashrate
func (s *HydrachainAPI) Hashrate() *rpc.HexNumber {
	return rpc.NewHexNumber(s.e.Miner().HashRate())
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up to date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronise from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *HydrachainAPI) Syncing() (interface{}, error) {
	origin, current, height, pulled, known := s.e.Downloader().Progress()

	// Return not syncing if the synchronisation already completed
	if current >= height {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock": rpc.NewHexNumber(origin),
		"currentBlock":  rpc.NewHexNumber(current),
		"highestBlock":  rpc.NewHexNumber(height),
		"pulledStates":  rpc.NewHexNumber(pulled),
		"knownStates":   rpc.NewHexNumber(known),
	}, nil
}
