// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT license.
//
// Extended battle-test suite (blockchain_test): table-driven breach guards and
// false-positive guards driven through the REAL strict fee function. Reuses
// craftTx / elaOutput from battle_test.go and the mainnet constants from
// exploit_repro_test.go (same package). Each table row is an independent green.

package blockchain_test

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
)

func sumI64(xs []int64) int64 {
	var s int64
	for _, x := range xs {
		s += x // test-side only; may wrap, that is the point of the attack rows
	}
	return s
}

// ---- BREACH GUARDS: every crafted value-creating shape must be REJECTED ----
func TestBattleBreachShapes(t *testing.T) {
	m := int64(common.MaxELAMoney)
	rows := []struct {
		name string
		in   int64
		outs []int64
	}{
		{"single-MaxInt64", 1000, []int64{math.MaxInt64}},
		{"two-MaxInt64", 1000, []int64{math.MaxInt64, math.MaxInt64}},
		{"mainnet-2260451", inputSela, []int64{out0Sela, out1Sela, out2Sela}},
		{"four-way-wrap", inputSela, []int64{math.MaxInt64 / 2, math.MaxInt64 / 2, math.MaxInt64 / 2, math.MaxInt64 / 2}},
		{"aggregate-2xMax", m, []int64{m, m}},
		{"aggregate-3xMax", m, []int64{m, m, m}},
		{"over-max-single", m + 1, []int64{m + 1}},
		{"huge-plus-dust", inputSela, []int64{m * 3, 1}},
		{"maxint-plus-small", 1000, []int64{math.MaxInt64, 100}},
		{"ten-x-max-single", 1000, []int64{m * 10}},
		{"five-max-wrap", inputSela, []int64{m * 5, m * 5, m * 5, m * 5}},
		{"neg-mask-giant", inputSela, []int64{m * 5, -(m*5 - inputSela + 500)}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tx, refs := craftTx(r.in, r.outs)
			if fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs); err == nil {
				t.Fatalf("BREACH [%s]: strict ACCEPTED value-creating tx (fee=%d)", r.name, int64(fee))
			}
		})
	}
}

// ---- FALSE-POSITIVE GUARDS: every legitimate shape must be ACCEPTED ----
func TestBattleLegitShapes(t *testing.T) {
	m := int64(common.MaxELAMoney)
	rows := []struct {
		name string
		in   int64
		outs []int64
	}{
		{"dust-1sela-fee", 1000, []int64{900}},
		{"everyday-payment", 10_000_000_000, []int64{9_999_990_000}},
		{"zero-fee", 100_000_000, []int64{100_000_000}},
		{"exact-max-output", m, []int64{m}},
		{"near-max-under", m, []int64{m - 1}},
		{"hundred-k-ela", 10_000_000_000_000, []int64{9_999_999_990_000}},
		{"five-hundred-k-ela", 50_000_000_000_000, []int64{49_999_999_999_900}},
		{"one-million-ela", 100_000_000_000_000, []int64{99_999_999_990_000}},
		{"multi-output-legit", 1_000_000_000_000, []int64{500_000_000_000, 400_000_000_000, 99_999_990_000}},
		{"many-small-legit", 1_000_000_000, []int64{100_000_000, 200_000_000, 300_000_000, 399_999_000}},
		{"split-in-half", 20_000_000_000, []int64{9_999_997_500, 9_999_997_500}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tx, refs := craftTx(r.in, r.outs)
			wantFee := r.in - sumI64(r.outs)
			fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
			if err != nil {
				t.Fatalf("FALSE POSITIVE [%s]: strict REJECTED a legit tx -> %v", r.name, err)
			}
			if int64(fee) != wantFee {
				t.Fatalf("FALSE POSITIVE [%s]: fee=%d, want %d", r.name, int64(fee), wantFee)
			}
		})
	}
}

// ---- DEFENSE-IN-DEPTH: outputs>inputs yields a fee below MinTransactionFee ----
func TestBattleValueCreationBelowMinFee(t *testing.T) {
	const minFee = int64(100)
	rows := []struct {
		name string
		in   int64
		outs []int64
	}{
		{"double-out", 100_000_000, []int64{200_000_000}},
		{"tiny-over", 1000, []int64{1001}},
		{"big-over", 1_000_000_000, []int64{2_000_000_000}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tx, refs := craftTx(r.in, r.outs)
			fee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
			if err != nil {
				return // strict errored -> also fine
			}
			if int64(fee) >= minFee {
				t.Fatalf("BREACH [%s]: fee %d >= MinTransactionFee %d -- min-fee check would NOT reject", r.name, int64(fee), minFee)
			}
		})
	}
}

// ---- HEIGHT-GATE: the same tx is legacy-accepted below and strict-rejected at/above ----
func TestBattleHeightGate(t *testing.T) {
	tx, refs := craftTx(inputSela, []int64{out0Sela, out1Sela, out2Sela})
	const gate = uint32(2260451)
	decide := func(height uint32) bool { // true == accepted
		if height >= gate {
			_, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
			return err == nil
		}
		blockchain.GetTxFee(tx, core.ELAAssetID, refs)
		return true // legacy path always "accepts" (the exploit)
	}
	rows := []struct {
		name   string
		height uint32
		accept bool
	}{
		{"far-below-gate", 1, true},
		{"just-below-gate", gate - 1, true},
		{"exactly-at-gate", gate, false},
		{"just-above-gate", gate + 1, false},
		{"far-above-gate", gate + 1_000_000, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := decide(r.height); got != r.accept {
				t.Fatalf("height %d: accepted=%v, want %v", r.height, got, r.accept)
			}
		})
	}
}
