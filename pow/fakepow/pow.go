package fakepow

import (
	"math/big"

	"github.com/ethereum/go-ethereum/pow"
)

type FakePoW struct {
	hash     *big.Int
	HashRate int64
	turbo    bool
}

func New() *FakePoW {
	return &FakePoW{turbo: false}
}

func (pow *FakePoW) GetHashrate() int64 {
	return 0
}

func (pow *FakePoW) Turbo(on bool) {
	pow.turbo = on
}
func (pow *FakePoW) Search(block pow.Block, stop <-chan struct{}, index int) (uint64, []byte) {
	return 0, nil
}
func (pow *FakePoW) Verify(block pow.Block) bool {
	return true
}
