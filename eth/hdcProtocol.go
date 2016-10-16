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
	// Protocol messages belonging to eth/62
	StatusMsg            = 0x00
	TxMsg                = 0x01
	GetBlockProposalsMsg = 0x02
	BlockProposalsMsg    = 0x03
	NewBlockProposalMsg  = 0x04
	VotingInstructionMsg = 0x05
	VoteMsg              = 0x06
	ReadyMsg             = 0x07
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
