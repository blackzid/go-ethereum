package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/logger"
	"github.com/ethereum/go-ethereum/logger/glog"
	"github.com/ethereum/go-ethereum/p2p"
)

func (p *peer) SendReadyMsg(r *types.Ready) error {
	p.broadcastFilter.Add(r.Hash())
	err := p2p.Send(p.rw, ReadyMsg, []interface{}{r})
	// fmt.Println("SendReady msg :", r)
	// fmt.Println("SendReady msg error:", err)
	return err
}
func (p *peer) SendNewBlockProposal(bp *types.BlockProposal) error {
	p.broadcastFilter.Add(bp.Hash())
	return p2p.Send(p.rw, NewBlockProposalMsg, []interface{}{bp})
}
func (p *peer) SendVotingInstruction(vi *types.VotingInstruction) error {
	p.broadcastFilter.Add(vi.Hash())
	return p2p.Send(p.rw, VotingInstructionMsg, &votingInstructionData{VotingInstruction: vi})
}
func (p *peer) SendVote(v *types.Vote) error {
	p.broadcastFilter.Add(v.Hash())
	return p2p.Send(p.rw, VoteMsg, &voteData{Vote: v})
}
func (p *peer) SendPrecommitVote(v *types.PrecommitVote) error {
	p.precommitFilter.Add(v.Hash())
	return p2p.Send(p.rw, PrecommitVoteMsg, &precommitVoteData{PrecommitVote: v})
}
func (p *peer) SendBlockProposals(bps []*types.BlockProposal) error {
	glog.V(logger.Info).Infof(" Sending  proposals", len(bps))
	for _, bp := range bps {
		p.broadcastFilter.Add(bp.Hash())
	}
	glog.V(logger.Info).Infof(" -----send")
	return p2p.Send(p.rw, BlockProposalsMsg, bps)
}
func (p *peer) RequestBlockProposals(blocknumbers []types.RequestProposalNumber) error {
	return p2p.Send(p.rw, GetBlockProposalsMsg, blocknumbers)
}

// func (p *peer) SendTransaction(r types.Ready) error {
// 	return p2p.Send(p.rw, ReadyMsg, []interface{}{r})
// }
func (ps *peerSet) PeersWithoutHash(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()
	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.broadcastFilter.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}

func (ps *peerSet) PeersWithoutPrecommit(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()
	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.precommitFilter.Has(hash) {
			list = append(list, p)
		}
	}
	return list
}
