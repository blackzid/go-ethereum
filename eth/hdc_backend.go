package eth

// import (
// 	"bytes"
// 	"errors"
// 	"fmt"
// 	"math/big"
// 	"os"
// 	"path/filepath"
// 	"regexp"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/ethereum/ethash"
// 	"github.com/ethereum/go-ethereum/accounts"
// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/common/compiler"
// 	"github.com/ethereum/go-ethereum/common/httpclient"
// 	"github.com/ethereum/go-ethereum/common/registrar/ethreg"
// 	"github.com/ethereum/go-ethereum/core"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/core/vm"
// 	"github.com/ethereum/go-ethereum/eth/downloader"
// 	"github.com/ethereum/go-ethereum/eth/filters"
// 	"github.com/ethereum/go-ethereum/ethdb"
// 	"github.com/ethereum/go-ethereum/event"
// 	"github.com/ethereum/go-ethereum/logger"
// 	"github.com/ethereum/go-ethereum/logger/glog"
// 	"github.com/ethereum/go-ethereum/miner"
// 	"github.com/ethereum/go-ethereum/node"
// 	"github.com/ethereum/go-ethereum/p2p"
// 	"github.com/ethereum/go-ethereum/rlp"
// 	"github.com/ethereum/go-ethereum/rpc"
// )

// type Hydrachain struct {
// 	chainConfig *core.ChainConfig
// 	// Channel for shutting down the ethereum
// 	shutdownChan chan bool

// 	// DB interfaces
// 	chainDb ethdb.Database // Block chain database
// 	dappDb  ethdb.Database // Dapp database

// 	// Handlers
// 	txPool          *core.TxPool
// 	txMu            sync.Mutex
// 	blockchain      *core.HDCBlockChain
// 	accountManager  *accounts.Manager
// 	protocolManager *ProtocolManager
// 	SolcPath        string
// 	solc            *compiler.Solidity
// 	// gpo             *GasPriceOracle

// 	httpclient *httpclient.HTTPClient

// 	eventMux *event.TypeMux
// 	// miner    *miner.Miner

// 	// Mining        bool
// 	// MinerThreads  int
// 	NatSpec bool
// 	AutoDAG bool

// 	autodagquit   chan bool
// 	etherbase     common.Address
// 	netVersionId  int
// 	netRPCService *PublicNetAPI
// 	// hdc validators
// 	hdcvalidators []common.Address
// }

// func NewHDC(ctx *node.ServiceContext, config *Config) (*Hydrachain, error) {
// 	// Open the chain database and perform any upgrades needed
// 	chainDb, err := ctx.OpenDatabase("chaindata", config.DatabaseCache, config.DatabaseHandles)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if db, ok := chainDb.(*ethdb.LDBDatabase); ok {
// 		db.Meter("eth/db/chaindata/")
// 	}
// 	if err := upgradeChainDatabase(chainDb); err != nil {
// 		return nil, err
// 	}
// 	if err := addMipmapBloomBins(chainDb); err != nil {
// 		return nil, err
// 	}

// 	dappDb, err := ctx.OpenDatabase("dapp", config.DatabaseCache, config.DatabaseHandles)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if db, ok := dappDb.(*ethdb.LDBDatabase); ok {
// 		db.Meter("eth/db/dapp/")
// 	}
// 	glog.V(logger.Info).Infof("Protocol Versions: %v, Network Id: %v", ProtocolVersions, config.NetworkId)

// 	// Load up any custom genesis block if requested
// 	if len(config.Genesis) > 0 {
// 		block, err := core.WriteGenesisBlock(chainDb, strings.NewReader(config.Genesis))
// 		if err != nil {
// 			return nil, err
// 		}
// 		glog.V(logger.Info).Infof("Successfully wrote custom genesis block: %x", block.Hash())
// 	}

// 	// Load up a test setup if directly injected
// 	if config.TestGenesisState != nil {
// 		chainDb = config.TestGenesisState
// 	}
// 	if config.TestGenesisBlock != nil {
// 		core.WriteTd(chainDb, config.TestGenesisBlock.Hash(), config.TestGenesisBlock.Difficulty())
// 		core.WriteBlock(chainDb, config.TestGenesisBlock)
// 		core.WriteCanonicalHash(chainDb, config.TestGenesisBlock.Hash(), config.TestGenesisBlock.NumberU64())
// 		core.WriteHeadBlockHash(chainDb, config.TestGenesisBlock.Hash())
// 	}

// 	if !config.SkipBcVersionCheck {
// 		bcVersion := core.GetBlockChainVersion(chainDb)
// 		if bcVersion != config.BlockChainVersion && bcVersion != 0 {
// 			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d). Run geth upgradedb.\n", bcVersion, config.BlockChainVersion)
// 		}
// 		core.WriteBlockChainVersion(chainDb, config.BlockChainVersion)
// 	}
// 	glog.V(logger.Info).Infof("Blockchain DB Version: %d", config.BlockChainVersion)

// 	hdc := &Hydrachain{
// 		shutdownChan:   make(chan bool),
// 		chainDb:        chainDb,
// 		dappDb:         dappDb,
// 		eventMux:       ctx.EventMux,
// 		accountManager: config.AccountManager,
// 		etherbase:      config.Etherbase,
// 		netVersionId:   config.NetworkId,
// 		NatSpec:        config.NatSpec,
// 		SolcPath:       config.SolcPath,
// 		AutoDAG:        config.AutoDAG,
// 		httpclient:     httpclient.New(config.DocRoot),
// 		hdcvalidators:  config.Validators,
// 	}
// 	genesis := core.GetBlock(chainDb, core.GetCanonicalHash(chainDb, 0))
// 	if genesis == nil {
// 		genesis, err = core.WriteDefaultGenesisBlock(chainDb)
// 		if err != nil {
// 			return nil, err
// 		}
// 		glog.V(logger.Info).Infoln("WARNING: Wrote default ethereum genesis block")
// 	}
// 	core.WriteChainConfig(chainDb, genesis.Hash(), config.ChainConfig)

// 	hdc.chainConfig = config.ChainConfig
// 	hdc.chainConfig.VmConfig = vm.Config{
// 		EnableJit: config.EnableJit,
// 		ForceJit:  config.ForceJit,
// 	}

// 	hdc.blockchain, err = core.NewHDCBlockChain(chainDb, hdc.chainConfig, nil, hdc.EventMux())

// 	if err != nil {
// 		if err == core.ErrNoGenesis {
// 			return nil, fmt.Errorf(`No chain found. Please initialise a new chain using the "init" subcommand.`)
// 		}
// 		return nil, err
// 	}
// 	// hdc.gpo = NewGasPriceOracle(hdc)

// 	newPool := core.NewTxPool(hdc.chainConfig, hdc.EventMux(), hdc.blockchain.State, nil)
// 	hdc.txPool = newPool

// 	if hdc.protocolManager, err = NewProtocolManager(hdc.chainConfig, config.FastSync, config.NetworkId, hdc.eventMux, hdc.txPool, nil, hdc.blockchain, chainDb); err != nil {
// 		return nil, err
// 	}
// 	return hdc, nil
// }

// func (s *Hydrachain) APIs() []rpc.API {
// 	return []rpc.API{
// 		{
// 			Namespace: "hdc",
// 			Version:   "1.0",
// 			Service:   NewHydrachainAPI(s),
// 			Public:    true,
// 		},
// 	}
// }

// func (s *Hydrachain) ResetWithGenesisBlock(gb *types.Block) {
// 	s.blockchain.ResetWithGenesisBlock(gb)
// }

// func (s *Hydrachain) Etherbase() (eb common.Address, err error) {
// 	eb = s.etherbase
// 	if (eb == common.Address{}) {
// 		firstAccount, err := s.AccountManager().AccountByIndex(0)
// 		eb = firstAccount.Address
// 		if err != nil {
// 			return eb, fmt.Errorf("etherbase address must be explicitly specified")
// 		}
// 	}
// 	return eb, nil
// }

// // set in js console via admin interface or wrapper from cli flags
// func (self *Hydrachain) SetEtherbase(etherbase common.Address) {
// 	self.etherbase = etherbase
// 	self.miner.SetEtherbase(etherbase)
// }

// func (s *Hydrachain) AccountManager() *accounts.Manager  { return s.accountManager }
// func (s *Hydrachain) BlockChain() *core.BlockChain       { return s.blockchain }
// func (s *Hydrachain) TxPool() *core.TxPool               { return s.txPool }
// func (s *Hydrachain) EventMux() *event.TypeMux           { return s.eventMux }
// func (s *Hydrachain) ChainDb() ethdb.Database            { return s.chainDb }
// func (s *Hydrachain) DappDb() ethdb.Database             { return s.dappDb }
// func (s *Hydrachain) IsListening() bool                  { return true } // Always listening
// func (s *Hydrachain) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
// func (s *Hydrachain) NetVersion() int                    { return s.netVersionId }
// func (s *Hydrachain) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
// func (s *Hydrachain) Protocols() []p2p.Protocol {
// 	return s.protocolManager.SubProtocols
// }

// // Start implements node.Service, starting all internal goroutines needed by the
// // Ethereum protocol implementation.
// func (s *Hydrachain) Start(srvr *p2p.Server) error {
// 	if s.AutoDAG {
// 		s.StartAutoDAG()
// 	}
// 	s.protocolManager.Start()
// 	s.netRPCService = NewPublicNetAPI(srvr, s.NetVersion())
// 	return nil
// }

// // Stop implements node.Service, terminating all internal goroutines used by the
// // Ethereum protocol.
// func (s *Hydrachain) Stop() error {
// 	s.blockchain.Stop()
// 	s.protocolManager.Stop()
// 	s.txPool.Stop()
// 	s.eventMux.Stop()

// 	s.StopAutoDAG()

// 	s.chainDb.Close()
// 	s.dappDb.Close()
// 	close(s.shutdownChan)

// 	return nil
// }
// func (s *Hydrachain) WaitForShutdown() {
// 	<-s.shutdownChan
// }

// func (self *Hydrachain) StartAutoDAG() {
// 	if self.autodagquit != nil {
// 		return // already started
// 	}
// 	go func() {
// 		glog.V(logger.Info).Infof("Automatic pregeneration of ethash DAG ON (ethash dir: %s)", ethash.DefaultDir)
// 		var nextEpoch uint64
// 		timer := time.After(0)
// 		self.autodagquit = make(chan bool)
// 		for {
// 			select {
// 			case <-timer:
// 				glog.V(logger.Info).Infof("checking DAG (ethash dir: %s)", ethash.DefaultDir)
// 				currentBlock := self.BlockChain().CurrentBlock().NumberU64()
// 				thisEpoch := currentBlock / epochLength
// 				if nextEpoch <= thisEpoch {
// 					if currentBlock%epochLength > autoDAGepochHeight {
// 						if thisEpoch > 0 {
// 							previousDag, previousDagFull := dagFiles(thisEpoch - 1)
// 							os.Remove(filepath.Join(ethash.DefaultDir, previousDag))
// 							os.Remove(filepath.Join(ethash.DefaultDir, previousDagFull))
// 							glog.V(logger.Info).Infof("removed DAG for epoch %d (%s)", thisEpoch-1, previousDag)
// 						}
// 						nextEpoch = thisEpoch + 1
// 						dag, _ := dagFiles(nextEpoch)
// 						if _, err := os.Stat(dag); os.IsNotExist(err) {
// 							glog.V(logger.Info).Infof("Pregenerating DAG for epoch %d (%s)", nextEpoch, dag)
// 							err := ethash.MakeDAG(nextEpoch*epochLength, "") // "" -> ethash.DefaultDir
// 							if err != nil {
// 								glog.V(logger.Error).Infof("Error generating DAG for epoch %d (%s)", nextEpoch, dag)
// 								return
// 							}
// 						} else {
// 							glog.V(logger.Error).Infof("DAG for epoch %d (%s)", nextEpoch, dag)
// 						}
// 					}
// 				}
// 				timer = time.After(autoDAGcheckInterval)
// 			case <-self.autodagquit:
// 				return
// 			}
// 		}
// 	}()
// }

// // stopAutoDAG stops automatic DAG pregeneration by quitting the loop
// func (self *Hydrachain) StopAutoDAG() {
// 	if self.autodagquit != nil {
// 		close(self.autodagquit)
// 		self.autodagquit = nil
// 	}
// 	glog.V(logger.Info).Infof("Automatic pregeneration of ethash DAG OFF (ethash dir: %s)", ethash.DefaultDir)
// }

// // HTTPClient returns the light http client used for fetching offchain docs
// // (natspec, source for verification)
// func (self *Hydrachain) HTTPClient() *httpclient.HTTPClient {
// 	return self.httpclient
// }

// func (self *Hydrachain) Solc() (*compiler.Solidity, error) {
// 	var err error
// 	if self.solc == nil {
// 		self.solc, err = compiler.New(self.SolcPath)
// 	}
// 	return self.solc, err
// }

// // set in js console via admin interface or wrapper from cli flags
// func (self *Hydrachain) SetSolc(solcPath string) (*compiler.Solidity, error) {
// 	self.SolcPath = solcPath
// 	self.solc = nil
// 	return self.Solc()
// }

// // dagFiles(epoch) returns the two alternative DAG filenames (not a path)
// // 1) <revision>-<hex(seedhash[8])> 2) full-R<revision>-<hex(seedhash[8])>
// func dagFiles(epoch uint64) (string, string) {
// 	seedHash, _ := ethash.GetSeedHash(epoch * epochLength)
// 	dag := fmt.Sprintf("full-R%d-%x", ethashRevision, seedHash[:8])
// 	return dag, "full-R" + dag
// }

// // upgradeChainDatabase ensures that the chain database stores block split into
// // separate header and body entries.
// func upgradeChainDatabase(db ethdb.Database) error {
// 	// Short circuit if the head block is stored already as separate header and body
// 	data, err := db.Get([]byte("LastBlock"))
// 	if err != nil {
// 		return nil
// 	}
// 	head := common.BytesToHash(data)

// 	if block := core.GetBlockByHashOld(db, head); block == nil {
// 		return nil
// 	}
// 	// At least some of the database is still the old format, upgrade (skip the head block!)
// 	glog.V(logger.Info).Info("Old database detected, upgrading...")

// 	if db, ok := db.(*ethdb.LDBDatabase); ok {
// 		blockPrefix := []byte("block-hash-")
// 		for it := db.NewIterator(); it.Next(); {
// 			// Skip anything other than a combined block
// 			if !bytes.HasPrefix(it.Key(), blockPrefix) {
// 				continue
// 			}
// 			// Skip the head block (merge last to signal upgrade completion)
// 			if bytes.HasSuffix(it.Key(), head.Bytes()) {
// 				continue
// 			}
// 			// Load the block, split and serialize (order!)
// 			block := core.GetBlockByHashOld(db, common.BytesToHash(bytes.TrimPrefix(it.Key(), blockPrefix)))

// 			if err := core.WriteTd(db, block.Hash(), block.DeprecatedTd()); err != nil {
// 				return err
// 			}
// 			if err := core.WriteBody(db, block.Hash(), block.Body()); err != nil {
// 				return err
// 			}
// 			if err := core.WriteHeader(db, block.Header()); err != nil {
// 				return err
// 			}
// 			if err := db.Delete(it.Key()); err != nil {
// 				return err
// 			}
// 		}
// 		// Lastly, upgrade the head block, disabling the upgrade mechanism
// 		current := core.GetBlockByHashOld(db, head)

// 		if err := core.WriteTd(db, current.Hash(), current.DeprecatedTd()); err != nil {
// 			return err
// 		}
// 		if err := core.WriteBody(db, current.Hash(), current.Body()); err != nil {
// 			return err
// 		}
// 		if err := core.WriteHeader(db, current.Header()); err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// func addMipmapBloomBins(db ethdb.Database) (err error) {
// 	const mipmapVersion uint = 2

// 	// check if the version is set. We ignore data for now since there's
// 	// only one version so we can easily ignore it for now
// 	var data []byte
// 	data, _ = db.Get([]byte("setting-mipmap-version"))
// 	if len(data) > 0 {
// 		var version uint
// 		if err := rlp.DecodeBytes(data, &version); err == nil && version == mipmapVersion {
// 			return nil
// 		}
// 	}

// 	defer func() {
// 		if err == nil {
// 			var val []byte
// 			val, err = rlp.EncodeToBytes(mipmapVersion)
// 			if err == nil {
// 				err = db.Put([]byte("setting-mipmap-version"), val)
// 			}
// 			return
// 		}
// 	}()
// 	latestBlock := core.GetBlock(db, core.GetHeadBlockHash(db))
// 	if latestBlock == nil { // clean database
// 		return
// 	}

// 	tstart := time.Now()
// 	glog.V(logger.Info).Infoln("upgrading db log bloom bins")
// 	for i := uint64(0); i <= latestBlock.NumberU64(); i++ {
// 		hash := core.GetCanonicalHash(db, i)
// 		if (hash == common.Hash{}) {
// 			return fmt.Errorf("chain db corrupted. Could not find block %d.", i)
// 		}
// 		core.WriteMipmapBloom(db, i, core.GetBlockReceipts(db, hash))
// 	}
// 	glog.V(logger.Info).Infoln("upgrade completed in", time.Since(tstart))
// 	return nil
// }
