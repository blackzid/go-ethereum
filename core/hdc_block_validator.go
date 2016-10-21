package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/pow"
	"gopkg.in/fatih/set.v0"
)

type HDCBlockValidator struct {
	config *ChainConfig // Chain configuration options
	bc     *BlockChain  // Canonical block chain
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewHDCBlockValidator(config *ChainConfig, blockchain *BlockChain) *HDCBlockValidator {
	validator := &BlockValidator{
		config: config,
		bc:     blockchain,
	}
	return validator
}

func (v *HDCBlockValidator) ValidateBlock(block *types.Block) error {
	if v.bc.HasBlock(block.Hash()) {
		if _, err := state.New(block.Root(), v.bc.chainDb); err == nil {
			return &KnownBlockError{block.Number(), block.Hash()}
		}
	}
	parent := v.bc.GetBlock(block.ParentHash())
	if parent == nil {
		return ParentError(block.ParentHash())
	}
	if _, err := state.New(parent.Root(), v.bc.chainDb); err != nil {
		return ParentError(block.ParentHash())
	}

	header := block.Header()
	// validate the block header
	if err := HDCValidateHeader(v.config, header, parent.Header(), false); err != nil {
		return err
	}
	// verify the uncles are correctly rewarded
	if err := v.VerifyUncles(block, parent); err != nil {
		return err
	}

	// Verify UncleHash before running other uncle validations
	unclesSha := types.CalcUncleHash(block.Uncles())
	if unclesSha != header.UncleHash {
		return fmt.Errorf("invalid uncles root hash. received=%x calculated=%x", header.UncleHash, unclesSha)
	}

	// The transactions Trie's root (R = (Tr [[i, RLP(T1)], [i, RLP(T2)], ... [n, RLP(Tn)]]))
	// can be used by light clients to make sure they've received the correct Txs
	txSha := types.DeriveSha(block.Transactions())
	if txSha != header.TxHash {
		return fmt.Errorf("invalid transaction root hash. received=%x calculated=%x", header.TxHash, txSha)
	}

	return nil
}

func (v *HDCBlockValidator) ValidateState(block, parent *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas *big.Int) (err error) {
	header := block.Header()
	if block.GasUsed().Cmp(usedGas) != 0 {
		return ValidationError(fmt.Sprintf("gas used error (%v / %v)", block.GasUsed(), usedGas))
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("unable to replicate block's bloom=%x vs calculated bloom=%x", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts)
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash. received=%x calculated=%x", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(); header.Root != root {
		return fmt.Errorf("invalid merkle root: header=%x computed=%x", header.Root, root)
	}
	return nil
}

func (v *HDCBlockValidator) VerifyUncles(block, parent *types.Block) error {
	// validate that there at most 2 uncles included in this block
	if len(block.Uncles()) > 2 {
		return ValidationError("Block can only contain maximum 2 uncles (contained %v)", len(block.Uncles()))
	}

	uncles := set.New()
	ancestors := make(map[common.Hash]*types.Block)
	for _, ancestor := range v.bc.GetBlocksFromHash(block.ParentHash(), 7) {
		ancestors[ancestor.Hash()] = ancestor
		// Include ancestors uncles in the uncle set. Uncles must be unique.
		for _, uncle := range ancestor.Uncles() {
			uncles.Add(uncle.Hash())
		}
	}
	ancestors[block.Hash()] = block
	uncles.Add(block.Hash())

	for i, uncle := range block.Uncles() {
		hash := uncle.Hash()
		if uncles.Has(hash) {
			// Error not unique
			return UncleError("uncle[%d](%x) not unique", i, hash[:4])
		}
		uncles.Add(hash)

		if ancestors[hash] != nil {
			branch := fmt.Sprintf("  O - %x\n  |\n", block.Hash())
			for h := range ancestors {
				branch += fmt.Sprintf("  O - %x\n  |\n", h)
			}
			glog.Infoln(branch)
			return UncleError("uncle[%d](%x) is ancestor", i, hash[:4])
		}

		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == parent.Hash() {
			return UncleError("uncle[%d](%x)'s parent is not ancestor (%x)", i, hash[:4], uncle.ParentHash[0:4])
		}

		if err := HDcValidateHeader(v.config, uncle, ancestors[uncle.ParentHash].Header(), true); err != nil {
			return ValidationError(fmt.Sprintf("uncle[%d](%x) header invalid: %v", i, hash[:4], err))
		}
	}

	return nil
}

func (v *HDCBlockValidator) ValidateHeader(header, parent *types.Header, checkPow bool) error {
	// Short circuit if the parent is missing.
	if parent == nil {
		return ParentError(header.ParentHash)
	}
	// Short circuit if the header's already known or its parent missing
	if v.bc.HasHeader(header.Hash()) {
		return nil
	}
	return HDCValidateHeader(v.config, header, parent, false)
}

func HDCValidateHeader(config *ChainConfig, header *types.Header, parent *types.Header, uncle bool) error {
	if big.NewInt(int64(len(header.Extra))).Cmp(params.MaximumExtraDataSize) == 1 {
		return fmt.Errorf("Header extra data too long (%d)", len(header.Extra))
	}

	if uncle {
		if header.Time.Cmp(common.MaxBig) == 1 {
			return BlockTSTooBigErr
		}
	} else {
		if header.Time.Cmp(big.NewInt(time.Now().Unix())) == 1 {
			return BlockFutureErr
		}
	}
	if header.Time.Cmp(parent.Time) != 1 {
		return BlockEqualTSErr
	}

	num := new(big.Int).Set(parent.Number)
	num.Sub(header.Number, num)
	if num.Cmp(big.NewInt(1)) != 0 {
		return BlockNumberErr
	}

	return ValidateDAOHeaderExtraData(config, header)
}
