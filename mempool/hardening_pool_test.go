// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Fail-on-pristine tests for the ledger-free half of the mempool hardening
// batch: F-060 (the fee-ordered eviction path could evict the very tx it had
// just inserted) and F-120 (eviction leaked two map entries per evicted tx).
package mempool

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// newHardeningTx builds a distinct transfer tx carrying the given fee. Every tx
// it returns serialises to the same size, so fee alone drives the fee rate.
func newHardeningTx(fee common.Fixed64) interfaces.Transaction {
	tx := functions.CreateTransaction(
		0,
		common2.TransferAsset,
		0,
		&payload.TransferAsset{},
		[]*common2.Attribute{{
			Usage: common2.Nonce,
			Data:  randomNonceData(),
		}},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
	tx.SetFee(fee)
	return tx
}

// TestF060AddTxNeverEvictsTheTxItJustInserted proves the admission guard now
// answers the question the eviction loop actually poses.
//
// Fail-on-pristine: pre-fix the guard only rejected a tx paying strictly less
// than the lowest entry, so an equal-fee-rate tx was inserted at the tail of a
// full list and then popped by the eviction loop - AddTx returned nil (the pool
// therefore put it in txnList) while the list no longer held it.
func TestF060AddTxNeverEvictsTheTxItJustInserted(t *testing.T) {
	var popped []common.Uint256
	onPopBack := func(h common.Uint256) { popped = append(popped, h) }

	txSize := newHardeningTx(100).GetSize()
	list := newTxFeeOrderedList(onPopBack, uint64(txSize*2))

	for i := 0; i < 2; i++ {
		assert.NoError(t, list.AddTx(newHardeningTx(100)))
	}
	assert.Equal(t, 2, list.GetSize())
	assert.Len(t, popped, 0)

	// Same fee rate as everything in the full list: it can displace nothing,
	// because eviction may only free entries paying strictly less.
	sameRate := newHardeningTx(100)
	err := list.AddTx(sameRate)
	assert.Equal(t, addingTxExcluded, err)
	assert.Len(t, popped, 0)
	assert.Equal(t, 2, list.GetSize())
	for _, item := range list.list {
		assert.NotEqual(t, sameRate.Hash(), item.Hash)
	}

	// A tx that really does pay more still displaces the cheapest entry - the
	// eviction path itself is intact.
	better := newHardeningTx(1000)
	assert.NoError(t, list.AddTx(better))
	assert.Len(t, popped, 1)
	assert.NotEqual(t, better.Hash(), popped[0])
	assert.Equal(t, 2, list.GetSize())
	assert.Equal(t, better.Hash(), list.list[0].Hash)
}

// TestF060CanAcceptRejectsOversizedTx guards the other end of the same
// invariant: a tx larger than the whole pool can never be admitted, and must
// not be inserted-then-popped.
func TestF060CanAcceptRejectsOversizedTx(t *testing.T) {
	var popped []common.Uint256
	list := newTxFeeOrderedList(func(h common.Uint256) {
		popped = append(popped, h)
	}, 1)

	tx := newHardeningTx(100)
	assert.Equal(t, addingTxExcluded, list.AddTx(tx))
	assert.Equal(t, 0, list.GetSize())
	assert.Len(t, popped, 0)
}
