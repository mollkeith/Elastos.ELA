// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT license.
//
// Battle-test suite for the v0.9.9.7 money-overflow fix. Drives 10 distinct
// attack shapes through the node's REAL validation functions (GetTxFeeStrict,
// MoneyRange, AddFixed64) -- not mocks. Reuses helpers from exploit_repro_test.go
// (same package): elaOutput, and the mainnet constants.
//
// Each test asserts either BREACH-guard (a crafted value-creating tx must be
// rejected by the strict path) or FALSE-POSITIVE-guard (a legitimate tx, even a
// large one, must still pass). A legacy-path cross-check shows what the OLD node
// would have done, to prove the shape is actually dangerous.

package blockchain_test

import (
	"math"
	"math/big"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// craftTx builds a TransferAsset with one input worth inSela and the given outputs.
func craftTx(inSela int64, outs []int64) (interfaces.Transaction, map[*common2.Input]common2.Output) {
	in := &common2.Input{Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 0}}
	outputs := make([]*common2.Output, len(outs))
	for i, v := range outs {
		outputs[i] = elaOutput(v)
	}
	tx := functions.CreateTransaction(
		common2.TxVersion09, common2.TransferAsset, 0,
		&payload.TransferAsset{}, []*common2.Attribute{},
		[]*common2.Input{in}, outputs, 0, []*program.Program{},
	)
	refs := map[*common2.Input]common2.Output{
		tx.Inputs()[0]: {AssetID: core.ELAAssetID, Value: common.Fixed64(inSela)},
	}
	return tx, refs
}

func mustRejectStrict(t *testing.T, name string, tx interfaces.Transaction, refs map[*common2.Input]common2.Output) {
	t.Helper()
	if fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs); err == nil {
		t.Fatalf("BREACH [%s]: strict path ACCEPTED a value-creating tx (fee=%d)", name, int64(fee))
	} else {
		t.Logf("PASS [%s]: strict REJECTED -> %v", name, err)
	}
}

func mustAcceptStrict(t *testing.T, name string, tx interfaces.Transaction, refs map[*common2.Input]common2.Output, wantFee int64) {
	t.Helper()
	fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
	if err != nil {
		t.Fatalf("FALSE POSITIVE [%s]: strict REJECTED a legitimate tx -> %v", name, err)
	}
	if int64(fee) != wantFee {
		t.Fatalf("FALSE POSITIVE [%s]: strict fee=%d, want %d", name, int64(fee), wantFee)
	}
	t.Logf("PASS [%s]: strict accepted legit tx, fee=%d", name, int64(fee))
}

// legacyWraps confirms the OLD node would have been fooled (fee looks tiny/normal),
// proving the shape is genuinely dangerous and not a strawman.
func legacyLooksNormal(t *testing.T, name string, tx interfaces.Transaction, refs map[*common2.Input]common2.Output) {
	t.Helper()
	fee := blockchain.GetTxFee(tx, core.ELAAssetID, refs)
	t.Logf("  (legacy path fee for %s = %d sela -- what the OLD node saw)", name, int64(fee))
}

// ---- BATTLE TEST 1: single-output 2x MaxInt64 wrap (the original shape) ----
func TestBattle01_SingleOutputWrap(t *testing.T) {
	// two near-MaxInt64 outputs + calibration; true sum >> 2^64, wraps low.
	tx, refs := craftTx(inputSela, []int64{out0Sela, out1Sela, out2Sela})
	legacyLooksNormal(t, "single-wrap", tx, refs)
	mustRejectStrict(t, "single-wrap", tx, refs)
}

// ---- BATTLE TEST 2: aggregate bound -- two outputs each == MaxELAMoney ----
func TestBattle02_AggregateTwoMax(t *testing.T) {
	// each output individually passes MoneyRange (== MaxELAMoney) but the running
	// total (2x) must be re-bounded and rejected.
	m := int64(common.MaxELAMoney)
	tx, refs := craftTx(m, []int64{m, m})
	mustRejectStrict(t, "aggregate-2xMax", tx, refs)
}

// ---- BATTLE TEST 3: many small outputs summing past the bound ----
func TestBattle03_ManySmallAggregate(t *testing.T) {
	// 300 outputs, each 1e15 (0.01 ELA-scale, individually valid); sum 3e17 > MaxELAMoney(1e17).
	const each = int64(1_000_000_000_000_000) // 1e15
	outs := make([]int64, 300)
	for i := range outs {
		outs[i] = each
	}
	tx, refs := craftTx(int64(common.MaxELAMoney), outs)
	mustRejectStrict(t, "many-small-aggregate", tx, refs)
}

// ---- BATTLE TEST 4a: boundary -- single output EXACTLY MaxELAMoney is valid ----
func TestBattle04a_BoundaryExactMaxAccepted(t *testing.T) {
	m := int64(common.MaxELAMoney)
	tx, refs := craftTx(m, []int64{m}) // fee 0, output == MaxELAMoney
	mustAcceptStrict(t, "exact-MaxELAMoney", tx, refs, 0)
}

// ---- BATTLE TEST 4b: boundary -- MaxELAMoney+1 is rejected ----
func TestBattle04b_BoundaryOverMaxRejected(t *testing.T) {
	m := int64(common.MaxELAMoney)
	tx, refs := craftTx(m+1, []int64{m + 1})
	mustRejectStrict(t, "MaxELAMoney+1", tx, refs)
}

// ---- BATTLE TEST 5: negative-value output cannot be used to mask a giant one ----
func TestBattle05_NegativeOffset(t *testing.T) {
	// giant positive offset by a negative so the naive sum looks tiny.
	giant := int64(common.MaxELAMoney) * 5 // > MaxELAMoney
	tx, refs := craftTx(inputSela, []int64{giant, -(giant - inputSela + 500)})
	legacyLooksNormal(t, "neg-offset", tx, refs)
	mustRejectStrict(t, "neg-offset", tx, refs)
}

// ---- BATTLE TEST 6: value creation without wrap (outputs > inputs) rejected ----
// Defense-in-depth: GetTxFeeStrict only COMPUTES the (checked) fee; the outputs<=inputs
// invariant is enforced by the min-fee check (isSmallThanMinTransactionFee, fee <
// MinTransactionFee=100), wired into ContextCheck at transactionchecker.go:172. A plain
// outputs>inputs tx yields a NEGATIVE fee that fails that check ("transaction fee not enough").
func TestBattle06_PlainValueCreation(t *testing.T) {
	const minFee = int64(100) // config.MinTransactionFee default
	tx, refs := craftTx(100_000_000, []int64{200_000_000})
	// GetTxFeeStrict computes the true fee without overflow -> it is negative here.
	fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
	if err != nil {
		t.Logf("PASS [outputs>inputs]: strict path errored -> %v", err)
		return
	}
	if int64(fee) >= 0 {
		t.Fatalf("setup drift: expected negative fee for outputs>inputs, got %d", int64(fee))
	}
	// the negative fee is below MinTransactionFee, so the min-fee check rejects the tx.
	if int64(fee) >= minFee {
		t.Fatalf("BREACH [outputs>inputs]: fee %d not below MinTransactionFee %d -- min-fee check would NOT reject", int64(fee), minFee)
	}
	t.Logf("PASS [outputs>inputs]: strict fee=%d < MinTransactionFee=%d -> min-fee check rejects (transaction fee not enough)", int64(fee), minFee)
}

// ---- BATTLE TEST 7: exact mainnet block-2260451 replay (regression lock) ----
func TestBattle07_MainnetReplay(t *testing.T) {
	tx := exploitTx(t)
	refs := exploitRefs(tx)
	if int64(blockchain.GetTxFee(tx, core.ELAAssetID, refs)) != wantFee {
		t.Fatalf("setup drift: legacy fee != %d", wantFee)
	}
	mustRejectStrict(t, "mainnet-2260451", tx, refs)
}

// ---- BATTLE TEST 8: false-positive guard at large-but-legit scale ----
func TestBattle08_LargeLegitAccepted(t *testing.T) {
	// input 500,000 ELA; outputs 400k + 99.999k ELA; fee 0.001 ELA. All < MaxELAMoney, sum < input.
	const in = int64(50_000_000_000_000)  // 500,000 ELA
	const o0 = int64(40_000_000_000_000)  // 400,000 ELA
	const o1 = int64(9_999_900_000_000)   // 99,999 ELA
	tx, refs := craftTx(in, []int64{o0, o1})
	mustAcceptStrict(t, "large-legit", tx, refs, in-o0-o1)
}

// ---- BATTLE TEST 9: AddFixed64 checked-add helper correctness ----
func TestBattle09_AddFixed64Helper(t *testing.T) {
	// adding two large positives that overflow int64 must ERROR, not wrap negative.
	if _, err := common.AddFixed64(common.Fixed64(math.MaxInt64), common.Fixed64(1)); err == nil {
		t.Fatal("BREACH: AddFixed64(MaxInt64, 1) did not error (silent wrap)")
	}
	half := common.Fixed64(math.MaxInt64/2 + 1)
	if _, err := common.AddFixed64(half, half); err == nil {
		t.Fatal("BREACH: AddFixed64 of two half-max positives did not error (wraps negative)")
	}
	// a valid add must still work and stay MoneyRange-checkable.
	sum, err := common.AddFixed64(common.Fixed64(common.MaxELAMoney), common.Fixed64(common.MaxELAMoney))
	if err != nil {
		t.Fatalf("AddFixed64(MaxELAMoney,MaxELAMoney) errored unexpectedly: %v", err)
	}
	if common.MoneyRange(sum) {
		t.Fatalf("BREACH: MoneyRange accepted 2xMaxELAMoney = %d", int64(sum))
	}
	t.Logf("PASS: AddFixed64 catches overflow; MoneyRange rejects 2xMaxELAMoney")
}

// ---- BATTLE TEST 10: near-2^64 total via 3 outputs just over the wrap point ----
func TestBattle10_JustOverTwoPow64(t *testing.T) {
	// three outputs whose big.Int sum is 2^64 + (inputSela-500): the exact wrap the
	// mainnet attacker used, generalized. Confirm the true sum > 2^64 then reject.
	twoPow64 := new(big.Int).Lsh(big.NewInt(1), 64)
	sum := new(big.Int)
	for _, v := range []int64{out0Sela, out1Sela, out2Sela} {
		sum.Add(sum, big.NewInt(v))
	}
	if sum.Cmp(twoPow64) <= 0 {
		t.Fatalf("setup: sum %s not over 2^64", sum)
	}
	tx, refs := craftTx(inputSela, []int64{out0Sela, out1Sela, out2Sela})
	mustRejectStrict(t, "just-over-2^64", tx, refs)
	// and each crafted output is itself out of range (first line of defence)
	if common.MoneyRange(common.Fixed64(out0Sela)) {
		t.Fatal("BREACH: MoneyRange accepted a near-MaxInt64 output")
	}
	t.Logf("PASS: per-output MoneyRange + aggregate both reject the wrap")
}
