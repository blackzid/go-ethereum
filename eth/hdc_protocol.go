// HydraChain Wire Protocol

package eth

import (
	// "fmt"
	// "io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/rlp"
)

var HDCProtocolName = "hdc"

const (
	MaxGetproposalsCount = 10
)

// eth protocol message codes
const (
	// Protocol messages belonging to hdc
	// HDCStatusMsg         = 0x10
	// HDCTxMsg             = 0x11
	GetBlockProposalsMsg = 0x12
	BlockProposalsMsg    = 0x13
	NewBlockProposalMsg  = 0x14
	VotingInstructionMsg = 0x15
	VoteMsg              = 0x16
	ReadyMsg             = 0x17
)

type HDCStatusData struct {
	ProtocolVersion uint32
	NetworkId       uint32
	TD              *big.Int
	CurrentLockset  *types.LockSet
	GenesisBlock    common.Hash
}

// Requests a BlockProposals message detailing a number of blocks to be sent, each referred to
// by block number. Note: Don't expect that the peer necessarily give you all these blocks
// in a single message - you might have to re-request them.

type blockProposalsData struct {
	BlockProposals []*types.BlockProposal
}
type newBlockProposals struct {
	BlockProposal *types.BlockProposal
}
type votingInstructionData struct {
	VotingInstruction *types.VotingInstruction
}
type voteData struct {
	Vote *types.Vote
}

type readyData struct {
	Ready *types.Ready
}
