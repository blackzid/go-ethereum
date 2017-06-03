// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package bft

import (
	// "math/rand"
	// "sync/atomic"
	"time"

	// "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/p2p/discover"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	minDesiredPeerCount = 5                // Amount of peers desired to start syncing

	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

type txsync struct {
	p   *peer
	txs []*types.Transaction
}

// syncTransactions starts sending all currently pending transactions to the given peer.
// func (pm *ProtocolManager) syncTransactions(p *peer) {
// 	var txs types.Transactions
// 	pending, _ := pm.txpool.Pending()
// 	for _, batch := range pending {
// 		txs = append(txs, batch...)
// 	}
// 	if len(txs) == 0 {
// 		return
// 	}
// 	select {
// 	case pm.txsyncCh <- &txsync{p, txs}:
// 	case <-pm.quitSync:
// 	}
// }

// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
// func (pm *ProtocolManager) txsyncLoop() {
// 	var (
// 		pending = make(map[discover.NodeID]*txsync)
// 		sending = false               // whether a send is active
// 		pack    = new(txsync)         // the pack that is being sent
// 		done    = make(chan error, 1) // result of the send
// 	)

// 	// send starts a sending a pack of transactions from the sync.
// 	send := func(s *txsync) {
// 		// Fill pack with transactions up to the target size.
// 		size := common.StorageSize(0)
// 		pack.p = s.p
// 		pack.txs = pack.txs[:0]
// 		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
// 			pack.txs = append(pack.txs, s.txs[i])
// 			size += s.txs[i].Size()
// 		}
// 		// Remove the transactions that will be sent.
// 		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
// 		if len(s.txs) == 0 {
// 			delete(pending, s.p.ID())
// 		}
// 		// Send the pack in the background.
// 		s.p.Log().Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
// 		sending = true
// 		go func() { done <- pack.p.SendTransactions(pack.txs) }()
// 	}

// 	// pick chooses the next pending sync.
// 	pick := func() *txsync {
// 		if len(pending) == 0 {
// 			return nil
// 		}
// 		n := rand.Intn(len(pending)) + 1
// 		for _, s := range pending {
// 			if n--; n == 0 {
// 				return s
// 			}
// 		}
// 		return nil
// 	}

// 	for {
// 		select {
// 		case s := <-pm.txsyncCh:
// 			pending[s.p.ID()] = s
// 			if !sending {
// 				send(s)
// 			}
// 		case err := <-done:
// 			sending = false
// 			// Stop tracking peers that cause send failures.
// 			if err != nil {
// 				pack.p.Log().Debug("Transaction send failed", "err", err)
// 				delete(pending, pack.p.ID())
// 			}
// 			// Schedule the next send.
// 			if s := pick(); s != nil {
// 				send(s)
// 			}
// 		case <-pm.quitSync:
// 			return
// 		}
// 	}
// }