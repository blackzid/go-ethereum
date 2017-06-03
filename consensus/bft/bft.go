package bft

import (
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	errZeroBlockTime = errors.New("timestamp equals parent's")
)

type BFT struct {
	config     *params.ChainConfig // Consensus engine configuration parameters
	db         ethdb.Database      // Database to store and retrieve snapshot checkpoints
	eventMux   *event.TypeMux
	blockchain *core.BlockChain

	pm *ProtocolManager

	signer common.Address // Ethereum address of the signing key
}

func New(config *params.ChainConfig, db ethdb.Database) *BFT {
	conf := *config

	bft := &BFT{
		config: &conf,
		db:     db,
	}
	return bft
}

func (b *BFT) SetupProtocolManager(chainConfig *params.ChainConfig, networkId uint64, mux *event.TypeMux, txpool *core.TxPool, blockchain *core.BlockChain, chainDb ethdb.Database, bftDb ethdb.Database, validators []common.Address, privateKeyHex string, etherbase common.Address, allowEmpty bool) error {
	var err error
	if b.pm, err = NewProtocolManager(chainConfig, networkId, mux, txpool, blockchain, chainDb, bftDb, validators, privateKeyHex, etherbase, allowEmpty); err != nil {
		return err
	}
	return nil
}

func (b *BFT) Start() {
	b.pm.Start()
}

func (b *BFT) RunPeer(p *peer) {
	if err := b.pm.handle(p); err != nil {
		log.Debug("handle error: ", err)
	}
}

func (b *BFT) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (b *BFT) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return b.verifyHeader(chain, header, parent)
}

func (b *BFT) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for _, header := range headers {
			number := header.Number.Uint64()
			parent := chain.GetHeader(header.ParentHash, number-1)
			err := b.verifyHeader(chain, header, parent)
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (b *BFT) verifyHeader(chain consensus.ChainReader, header, parent *types.Header) error {
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	if header.Time.Cmp(parent.Time) <= 0 {
		return errZeroBlockTime
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}

	if err := b.pm.consensusManager.verifyVotes(header.Hash()); err != nil {
		return err
	}

	return nil
}

func (b *BFT) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (b *BFT) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

func (b *BFT) Prepare(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

func (b *BFT) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

func (b *BFT) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	log.Info("Sealing", "block", block)
	return block, nil
}

func (b *BFT) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "bft",
		Version:   "1.0",
		Service:   &API{chain: chain, bft: b},
		Public:    false,
	}}
}

func (b *BFT) Protocols() []p2p.Protocol {
	return b.pm.SubProtocols
}
