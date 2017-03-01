package eth

// import (
// 	"crypto/ecdsa"
// 	"math/big"
// 	"sync"

// 	"gopkg.in/fatih/set.v0"

// 	"fmt"

// 	"time"

// 	"github.com/ethereum/go-ethereum/accounts"
// 	"github.com/ethereum/go-ethereum/accounts/abi/bind"
// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/core"
// 	"github.com/ethereum/go-ethereum/core/state"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/ethereum/go-ethereum/eth/downloader"
// 	"github.com/ethereum/go-ethereum/ethclient"
// 	"github.com/ethereum/go-ethereum/ethdb"
// 	"github.com/ethereum/go-ethereum/event"
// 	"github.com/ethereum/go-ethereum/logger"
// 	"github.com/ethereum/go-ethereum/logger/glog"
// 	"github.com/ethereum/go-ethereum/params"
// 	"github.com/ethereum/go-ethereum/rpc"
// )

// const (
// 	// Create bindings with: go run cmd/abigen/main.go -abi <definition> -pkg quorum -type VotingContract > core/quorum/binding.go
// 	ABI = `[{"constant":true,"inputs":[{"name":"","type":"uint256"}],"name":"validators","outputs":[{"name":"","type":"address"}],"payable":false,"type":"function"},{"constant":true,"inputs":[],"name":"getValidators","outputs":[{"name":"","type":"address[]"}],"payable":false,"type":"function"}]`

// 	// browser solidity with optimizations: 0.4.2+commit.af6afb04.mod.Emscripten.clang
// 	RuntimeCode = "6060604052341561000c57fe5b5b6102308061001c6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806335aa2e4414610046578063b7ab4db5146100a6575bfe5b341561004e57fe5b610064600480803590602001909190505061011b565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34156100ae57fe5b6100b661015b565b6040518080602001828103825283818151815260200191508051906020019060200280838360008314610108575b805182526020831115610108576020820191506020810190506020830392506100e4565b5050509050019250505060405180910390f35b60008181548110151561012a57fe5b906000526020600020900160005b915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6101636101f0565b60008054806020026020016040519081016040528092919081815260200182805480156101e557602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001906001019080831161019b575b505050505090505b90565b6020604051908101604052806000815250905600a165627a7a723058200ea75f983f214e31fb51ae302d0c5caf94593082dc265786658fd180c8afb90f0029"

// 	contractAddress
// )

// var (
// 	ValidatorsContractAddr = common.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32}
// )

// type ValidatorsContract struct {
// 	contract *bind.BoundContract
// }

// func NewValidatorsContract(address common.Address, backend bind.ContractBackend) (*ValidatorsContract, error) {
// 	contract, err := bindVotingContract(address, backend, backend)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &ValidatorsContract{VotingContractCaller: VotingContractCaller{contract: contract}, VotingContractTransactor: VotingContractTransactor{contract: contract}}, nil
// }
