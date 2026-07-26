// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Cross-chain money bound — per-ARM evidence.
//
// THE EVIDENCE GAP THIS CLOSES. zz_replay_test.go proves the composite: the real mainnet
// transaction from block 2,208,265 is accepted below the gate and rejected at and above it.
// But it asserts only THAT an error came back, never WHICH of the three gated arms produced
// it, and its single vector trips all three at once (TargetAmount = int64max-9999 is out of
// money range AND overflows the fee addition AND under-funds the output). Mutation measured
// at HEAD: neutering any ONE of the three arms leaves the entire shipping gate green,
// because a sibling arm still rejects that one vector.
//
// The arm that matters most is the LAST one. `output.Value < required` is the actual money
// bound — the check that a cross-chain redemption is backed by locked ELA. Delete it and a
// transaction declaring 1,000 ELA to the side chain against 0.00000001 ELA locked is
// accepted at every height at and above the gate, and the side chain honours the redemption.
// Nothing in the tree noticed.
//
// Each test below isolates ONE arm with a vector that the other two accept, drives the
// production dispatch (SpecialContextCheck, the same entry point block validation uses),
// and asserts the arm`s own rejection message. All vectors are the REAL 270-byte mainnet
// transaction with exactly one field changed, so every other check in
// checkTransferCrossChainAssetTransactionV1 is satisfied by construction.
//
// No new height literal: every case uses config.GetDefaultParams().StrictMoneyRangeHeight.
package transaction

import (
	"math"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"

	"github.com/stretchr/testify/assert"
)

// xcVector re-decodes the real mainnet cross-chain transaction and overwrites the two
// fields the gated bound reads: the declared TargetAmount and the locked output Value.
// Everything else — version, payload version, output type, the "X" cross-chain program
// hash prefix, the programs — stays exactly as it is on chain.
func xcVector(t *testing.T, target, locked common.Fixed64, height uint32,
	cfg *config.Configuration) error {
	t.Helper()
	txn := decodeRealTx(t)
	out := txn.Outputs()[0]
	p, ok := out.Payload.(*outputpayload.CrossChainOutput)
	if !ok {
		t.Fatalf("test vector broken: output payload is %T, not a CrossChainOutput", out.Payload)
	}
	p.TargetAmount = target
	out.Value = locked
	txn.SetParameters(&TransactionParameters{
		Transaction: txn, BlockHeight: height, Config: cfg,
	})
	elaErr, _ := txn.SpecialContextCheck()
	if elaErr == nil {
		return nil
	}
	return elaErr
}

// TestXChainUnbackedRedemptionIsRejected isolates the `output.Value < required` arm: the
// money bound itself. TargetAmount is a perfectly ordinary 1,000 ELA — inside MoneyRange,
// nowhere near overflowing the fee addition — so ONLY this arm can reject it.
//
// FAIL-ON-PRISTINE: neuter `if output.Value < required` in
// checkTransferCrossChainAssetTransactionV1 -> "UNBACKED REDEMPTION ACCEPTED".
func TestXChainUnbackedRedemptionIsRejected(t *testing.T) {
	cfg := config.GetDefaultParams()
	gate := cfg.StrictMoneyRangeHeight

	const target = common.Fixed64(1000 * 100000000) // 1,000 ELA declared to the side chain
	const locked = common.Fixed64(1)                // 0.00000001 ELA actually locked

	assert.True(t, common.MoneyRange(target), "vector must be inside MoneyRange")
	_, addErr := common.AddFixed64(cfg.MinCrossChainTxFee, target)
	assert.NoError(t, addErr, "vector must not overflow the fee addition")

	for _, h := range []uint32{gate, gate + 1, gate + 100000} {
		err := xcVector(t, target, locked, h, cfg)
		if err == nil {
			t.Fatalf("UNBACKED REDEMPTION ACCEPTED at height %d: %v ELA declared to the side "+
				"chain against %v sela locked — the gated money bound is not reached",
				h, target, locked)
		}
		if !strings.Contains(err.Error(), "invalid cross chain output amount") {
			t.Fatalf("rejected for the WRONG reason at height %d: %v", h, err)
		}
	}

	// Positive control: fully backed at the same heights must be ACCEPTED, otherwise the
	// assertions above would also be satisfied by a guard that rejects everything.
	backed := target + cfg.MinCrossChainTxFee
	for _, h := range []uint32{gate - 1, gate, gate + 1} {
		if err := xcVector(t, target, backed, h, cfg); err != nil {
			t.Fatalf("FALSE REJECT of a fully backed redemption at height %d: %v", h, err)
		}
	}
}

// TestXChainTargetAmountMoneyRangeIsRejected isolates the MoneyRange arm. The declared
// amount is above MaxELAMoney but far below the point where the fee addition overflows,
// and the output is over-funded, so neither sibling arm can reject it.
//
// FAIL-ON-PRISTINE: neuter `if !common.MoneyRange(p.TargetAmount)` -> "OUT-OF-RANGE
// TARGET ACCEPTED".
func TestXChainTargetAmountMoneyRangeIsRejected(t *testing.T) {
	cfg := config.GetDefaultParams()
	gate := cfg.StrictMoneyRangeHeight

	target := common.MaxELAMoney + 1 // one sela past the whole ever-creatable supply
	// Fully funded on purpose: below the gate the legacy expression
	// `output.Value < MinCrossChainTxFee + TargetAmount` must NOT reject it either, so
	// the below-gate leg proves the MoneyRange arm is what rejects above the gate.
	locked := target + cfg.MinCrossChainTxFee

	assert.False(t, common.MoneyRange(target), "vector must be outside MoneyRange")
	_, addErr := common.AddFixed64(cfg.MinCrossChainTxFee, target)
	assert.NoError(t, addErr, "vector must NOT overflow, or the overflow arm would reject it")

	for _, h := range []uint32{gate, gate + 1} {
		err := xcVector(t, target, locked, h, cfg)
		if err == nil {
			t.Fatalf("OUT-OF-RANGE TARGET ACCEPTED at height %d: TargetAmount %v exceeds "+
				"MaxELAMoney %v — the MoneyRange arm is not reached", h, target, common.MaxELAMoney)
		}
		if !strings.Contains(err.Error(), "out of money range") {
			t.Fatalf("rejected for the WRONG reason at height %d: %v", h, err)
		}
	}

	// Below the gate the SAME bytes must still be accepted: retained history replays
	// byte-identically, and this proves the arm reads the real gate.
	if err := xcVector(t, target, locked, gate-1, cfg); err != nil {
		t.Fatalf("REPLAY BREAK below the gate: %v", err)
	}
}

// TestXChainFeeAdditionOverflowIsRejected isolates the overflow arm. With the shipped
// MinCrossChainTxFee of 10,000 sela this arm is UNREACHABLE — MoneyRange runs first and
// caps TargetAmount at MaxELAMoney, and MaxELAMoney + 10,000 cannot overflow int64 — so no
// vector built from an attacker-chosen amount alone can distinguish it. What the arm
// genuinely defends is the addition itself against a MinCrossChainTxFee that is not small,
// which is a configuration value. This test therefore drives the production dispatch with
// exactly that: an in-range TargetAmount and a fee large enough to overflow the sum.
//
// FAIL-ON-PRISTINE: neuter `if err != nil` on the AddFixed64 result -> the wrapped
// negative `required` makes `output.Value < required` false and the transaction is
// ACCEPTED, which is precisely the mainnet 2,208,265 mechanism.
func TestXChainFeeAdditionOverflowIsRejected(t *testing.T) {
	base := config.GetDefaultParams()
	gate := base.StrictMoneyRangeHeight

	cfg := *base
	cfg.MinCrossChainTxFee = common.Fixed64(math.MaxInt64) // forces the sum to overflow

	target := common.MaxELAMoney // in range, so the MoneyRange arm passes
	assert.True(t, common.MoneyRange(target))
	_, addErr := common.AddFixed64(cfg.MinCrossChainTxFee, target)
	assert.Error(t, addErr, "vector must overflow the fee addition")

	err := xcVector(t, target, common.Fixed64(1), gate, &cfg)
	if err == nil {
		t.Fatal("OVERFLOWING FEE ADDITION ACCEPTED: the wrapped negative bound admits an " +
			"unbacked redemption — the overflow arm is not reached")
	}
	if !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("rejected for the WRONG reason: %v", err)
	}
}
