// HydraChain Wire Protocol

package eth

import (
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// Constants to match up protocol versions and messages
const (
	eth62 = 62
	eth63 = 63
)

// Official short name of the protocol used during capability negotiation.
var HDCProtocolName = "hdc"

const (
	NetworkId          = 1
	ProtocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message
)

// eth protocol message codes
const (
	// Protocol messages belonging to hdc
	HDCStatusMsg         = 0x10
	HDCTxMsg             = 0x11
	GetBlockProposalsMsg = 0x12
	BlockProposalsMsg    = 0x13
	NewBlockProposalMsg  = 0x14
	VotingInstructionMsg = 0x15
	VoteMsg              = 0x16
	ReadyMsg             = 0x17
)

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrExtraStatusMsg
	ErrSuspendedPeer
)

func (e errCode) String() string {
	return errorToString[int(e)]
}

// XXX change once legacy code is out
var errorToString = map[int]string{
	ErrMsgTooLarge:             "Message too long",
	ErrDecode:                  "Invalid message",
	ErrInvalidMsgCode:          "Invalid message code",
	ErrProtocolVersionMismatch: "Protocol version mismatch",
	ErrNetworkIdMismatch:       "NetworkId mismatch",
	ErrGenesisBlockMismatch:    "Genesis block mismatch",
	ErrNoStatusMsg:             "No status message",
	ErrExtraStatusMsg:          "Extra status message",
	ErrSuspendedPeer:           "Suspended peer",
}

type HDCStatusMsg struct {
	ProtocolVersion uint32
	NetworkId       uint32
	TD              *big.Int
	CurrentLockset  *LockSet
	GenesisBlock    common.Hash
}

// Requests a BlockProposals message detailing a number of blocks to be sent, each referred to
// by block number. Note: Don't expect that the peer necessarily give you all these blocks
// in a single message - you might have to re-request them.
type getBlockProposals struct {
	Number uint64 // Number of one particular block being announced
}
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
