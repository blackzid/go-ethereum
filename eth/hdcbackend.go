package eth

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/ethash"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/compiler"
	"github.com/ethereum/go-ethereum/common/httpclient"
	"github.com/ethereum/go-ethereum/common/registrar/ethreg"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

type Hydrachain struct {
	chainConfig *core.ChainConfig
	// Channel for shutting down the ethereum
	shutdownChan chan bool

	// DB interfaces
	chainDb ethdb.Database // Block chain database
	dappDb  ethdb.Database // Dapp database

	// Handlers
	txPool         *core.TxPool
	txMu           sync.Mutex
	blockchain     *core.BlockChain
	accountManager *accounts.Manager
	// pow             *ethash.Ethash
	protocolManager *ProtocolManager
	SolcPath        string
	solc            *compiler.Solidity
	// gpo             *GasPriceOracle

	// GpoMinGasPrice          *big.Int
	// GpoMaxGasPrice          *big.Int
	// GpoFullBlockRatio       int
	// GpobaseStepDown         int
	// GpobaseStepUp           int
	// GpobaseCorrectionFactor int

	httpclient *httpclient.HTTPClient

	eventMux *event.TypeMux
	// miner    *miner.Miner

	// Mining        bool
	// MinerThreads  int
	NatSpec bool
	AutoDAG bool
	// PowTest       bool
	autodagquit   chan bool
	etherbase     common.Address
	netVersionId  int
	netRPCService *PublicNetAPI
	// hdc validators
	hdcvalidators []common.Address
}

func NewHDC(ctx *node.ServiceContext, config *Config) (*Hydrachain, error) {
	// Open the chain database and perform any upgrades needed
	chainDb, err := ctx.OpenDatabase("chaindata", config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := chainDb.(*ethdb.LDBDatabase); ok {
		db.Meter("eth/db/chaindata/")
	}
	if err := upgradeChainDatabase(chainDb); err != nil {
		return nil, err
	}
	if err := addMipmapBloomBins(chainDb); err != nil {
		return nil, err
	}

	dappDb, err := ctx.OpenDatabase("dapp", config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	if db, ok := dappDb.(*ethdb.LDBDatabase); ok {
		db.Meter("eth/db/dapp/")
	}
	glog.V(logger.Info).Infof("Protocol Versions: %v, Network Id: %v", ProtocolVersions, config.NetworkId)

	// Load up any custom genesis block if requested
	if len(config.Genesis) > 0 {
		block, err := core.WriteGenesisBlock(chainDb, strings.NewReader(config.Genesis))
		if err != nil {
			return nil, err
		}
		glog.V(logger.Info).Infof("Successfully wrote custom genesis block: %x", block.Hash())
	}

	// Load up a test setup if directly injected
	if config.TestGenesisState != nil {
		chainDb = config.TestGenesisState
	}
	if config.TestGenesisBlock != nil {
		core.WriteTd(chainDb, config.TestGenesisBlock.Hash(), config.TestGenesisBlock.Difficulty())
		core.WriteBlock(chainDb, config.TestGenesisBlock)
		core.WriteCanonicalHash(chainDb, config.TestGenesisBlock.Hash(), config.TestGenesisBlock.NumberU64())
		core.WriteHeadBlockHash(chainDb, config.TestGenesisBlock.Hash())
	}

	if !config.SkipBcVersionCheck {
		bcVersion := core.GetBlockChainVersion(chainDb)
		if bcVersion != config.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run geth upgradedb.\n", bcVersion, config.BlockChainVersion)
		}
		core.WriteBlockChainVersion(chainDb, config.BlockChainVersion)
	}
	glog.V(logger.Info).Infof("Blockchain DB Version: %d", config.BlockChainVersion)

	hdc := &Hydrachain{
		shutdownChan:   make(chan bool),
		chainDb:        chainDb,
		dappDb:         dappDb,
		eventMux:       ctx.EventMux,
		accountManager: config.AccountManager,
		etherbase:      config.Etherbase,
		netVersionId:   config.NetworkId,
		NatSpec:        config.NatSpec,
		SolcPath:       config.SolcPath,
		AutoDAG:        config.AutoDAG,
		httpclient:     httpclient.New(config.DocRoot),
		hdcvalidators:  config.Validators,
	}
	genesis := core.GetBlock(chainDb, core.GetCanonicalHash(chainDb, 0))
	if genesis == nil {
		genesis, err = core.WriteDefaultGenesisBlock(chainDb)
		if err != nil {
			return nil, err
		}
		glog.V(logger.Info).Infoln("WARNING: Wrote default ethereum genesis block")
	}

}
