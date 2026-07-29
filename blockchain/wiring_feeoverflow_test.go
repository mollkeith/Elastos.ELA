// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Block fee-accumulator overflow — at the PRODUCTION DISPATCH.
//
// THE EVIDENCE GAP THIS CLOSES. checkTxsContext accumulates the block`s total ELA fee two
// different ways, chosen by height:
//
//	>= StrictMoneyRangeHeight : GetTxFeeStrict + AddFixed64, and REJECT on overflow
//	<  StrictMoneyRangeHeight : totalTxFee += GetTxFee(...)  -- the legacy WRAPPING add
//
// Every existing test for this exercises the helpers (GetTxFeeStrict, GetTxFeeMapStrict,
// AddFixed64) directly. Mutation measured at HEAD: neutering the height branch in
// checkTxsContext, so the legacy wrapping accumulator runs at EVERY height, left the entire
// shipping gate green. totalTxFee is the input to coinbaseTotalReward — it sizes the block
// reward — so a wrapped accumulator is a supply-side defect, not a cosmetic one.
//
// This test drives the REAL (*BlockChain).checkTxsContext on the store harness in
// wiring_bip30_test.go. The transactions are stubs whose ContextCheck returns crafted
// references, which is the only practical way to put an overflowing fee total in front of
// the accumulator: GetTxFeeMapStrict bounds each single transaction`s input total by
// MoneyRange (1e17 sela), so overflowing the int64 accumulator takes 93 of them.
//
// FAIL-ON-PRISTINE: neuter `if block.Height >= b.chainParams.StrictMoneyRangeHeight` in
// checkTxsContext -> "FEE ACCUMULATOR OVERFLOW ACCEPTED".
//
// REPLAY SAFETY: the below-gate leg asserts the legacy wrapping accumulator is still what
// runs at 2,260,450, i.e. that no overflow rejection is introduced into retained history.
package blockchain

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

// feeTx is a transaction whose context check succeeds and whose references carry a
// MoneyRange-maximal ELA input against no outputs — the largest single-transaction fee the
// strict accumulator will accept.
type feeTx struct {
	interfaces.Transaction // nil embedded interface: any un-stubbed call panics visibly
	in                     *common2.Input
	ref                    common2.Output
}

func (f *feeTx) ContextCheck(interfaces.Parameters) (
	map[*common2.Input]common2.Output, elaerr.ELAError) {
	return map[*common2.Input]common2.Output{f.in: f.ref}, nil
}
func (f *feeTx) Outputs() []*common2.Output { return nil }

// Serialize is reached only on the error path of checkCoinbaseTransactionContext, which
// serializes the whole block for the log line. It must not panic there.
func (f *feeTx) Serialize(io.Writer) error { return nil }
func (f *feeTx) Fee() common.Fixed64       { return f.ref.Value }
func (f *feeTx) IsCRCProposalTx() bool     { return false }

// feeOverflowBlock returns a block at `height` carrying one clean coinbase plus `n`
// maximal-fee transactions.
func feeOverflowBlock(t *testing.T, b *BlockChain, height uint32, n int) *types.Block {
	t.Helper()
	blk := bip30Block(t, b, height, []byte{byte(height), byte(height >> 8)})
	for i := 0; i < n; i++ {
		in := &common2.Input{Previous: common2.OutPoint{Index: uint16(i)}}
		blk.Transactions = append(blk.Transactions, &feeTx{
			in:  in,
			ref: common2.Output{AssetID: core.ELAAssetID, Value: common.MaxELAMoney},
		})
	}
	blk.Header.Timestamp = uint32(time.Now().Unix())
	return blk
}

// feeOverflowTxCount is the smallest number of MoneyRange-maximal fees whose sum exceeds
// MaxInt64 — derived here rather than hard-coded so it tracks MaxELAMoney.
func feeOverflowTxCount() int {
	n := 0
	var acc common.Fixed64
	for {
		next, err := common.AddFixed64(acc, common.MaxELAMoney)
		n++
		if err != nil {
			return n
		}
		acc = next
	}
}

// TestWiringFeeAccumulatorOverflowRejectedAtGate is the fail-on-pristine test.
func TestWiringFeeAccumulatorOverflowRejectedAtGate(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)

	n := feeOverflowTxCount()
	if n < 2 {
		t.Fatalf("test vector broken: %d maximal fees cannot overflow the accumulator", n)
	}

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		err := b.checkTxsContext(feeOverflowBlock(t, b, h, n), nil)
		if err == nil {
			t.Fatalf("FEE ACCUMULATOR OVERFLOW ACCEPTED at height %d: %d transactions each "+
				"paying the MoneyRange maximum summed past MaxInt64 and checkTxsContext "+
				"returned nil — the strict accumulator branch is not reached", h, n)
		}
		if !strings.Contains(err.Error(), "overflow") {
			t.Fatalf("rejected for the WRONG reason at height %d: %v", h, err)
		}
	}

	// One transaction below the overflow point must NOT be rejected for overflow: the
	// guard must bound the accumulator, not reject large fees outright.
	err := b.checkTxsContext(feeOverflowBlock(t, b, wiringGate, n-1), nil)
	if err != nil && strings.Contains(err.Error(), "overflow") {
		t.Fatalf("FALSE OVERFLOW REJECT with %d maximal fees (the sum still fits): %v", n-1, err)
	}
}

// TestWiringFeeAccumulatorBelowGateStillWraps is the replay-safety half: at 2,260,450 —
// the forced-rollback target and last retained block — the legacy wrapping accumulator is
// still what runs, so no historical block gains a new rejection.
func TestWiringFeeAccumulatorBelowGateStillWraps(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)

	n := feeOverflowTxCount()
	err := b.checkTxsContext(feeOverflowBlock(t, b, wiringBelowGate, n), nil)
	if err != nil && strings.Contains(err.Error(), "overflow") {
		t.Fatalf("REPLAY BREAK below the gate: the overflow rejection reached retained "+
			"history at height %d: %v", wiringBelowGate, err)
	}
}
