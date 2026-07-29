// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package blockchain

import (
	"math"
	"testing"

	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

// TestF013CoinbaseFrozenOutputRejected closes F-013: the coinbase (block tx index 0)
// is the one transaction that never runs checkFrozenAddresses — checkTxsContext only
// validates txs[1:] and the coinbase's own ContextCheck/SpecialContextCheck are DEAD on
// connect (the same reason F-089's BIP30 guard had to move into blockvalidator.go). So
// the "no sends TO a frozen address" half of the frozen-address rule was unenforced on
// the coinbase path: the merge-miner output (Outputs[1]) has no address constraint in
// checkCoinbaseTransactionContext, so a producer could pay the quarantined exploit
// address from the block reward and no validator would reject it.
//
// This drives the REAL enforcement point, b.checkCoinbaseTransactionContext, with an
// otherwise-valid DPoSV2 coinbase whose only defect is Outputs[1] paying a frozen
// address.
//
//	fixed / above gate : the frozen-paying coinbase is REJECTED ("frozen address").
//	honest / above gate : an honest miner address passes (no false reject).
//	below gate          : the SAME frozen-paying coinbase is ACCEPTED (check skipped),
//	                      so retained-history replay below the gate is byte-identical.
//
// Fail-on-pristine: with the checkCoinbaseFrozenOutputs call reverted, the above-gate
// frozen coinbase passes every other check and is ACCEPTED (NoError), so the
// assert.Error below fails — the wiring is demonstrably load-bearing.
func TestF013CoinbaseFrozenOutputRejected(t *testing.T) {
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = 2260451
	gate := params.StrictMoneyRangeHeight

	// A frozen address active from height 0 (the gate, not DisableStartHeight, is what
	// decides enforcement here). Distinct from the CR-assets / DPoSV2-reward hashes so the
	// constrained coinbase outputs are never themselves flagged.
	frozenPH := Uint168{0x21, 0xEF, 0xD0, 0x0F, 0xF0, 0x0D}
	params.FrozenAddresses = []config.FrozenAddress{{
		Address:            "EfduuvdDcAgif8njgXNJUfsBumQf9yYP72",
		DisableStartHeight: 0,
		ProgramHash:        &frozenPH,
	}}

	b := &BlockChain{
		chainParams: params,
		state:       &state.State{StateKeyFrame: &state.StateKeyFrame{}},
	}
	orig := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: &state.ArbitratorsMock{}}
	defer func() { DefaultLedger = orig }()

	// mkCoinbase builds an otherwise-valid BFT DPoSV2 coinbase (mock activeHeight is
	// 2000000, so any height > 2000001 takes that branch). Outputs[0]=CR assets,
	// Outputs[2]=DPoSV2 reward accumulate (both address-constrained), Outputs[1]=minerPH
	// (unconstrained — the only place a frozen address can slip in).
	crAddr := *params.CRConfiguration.CRAssetsProgramHash
	dposAddr := *params.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash
	mkCoinbase := func(height uint32, minerPH Uint168) (interfaces.Transaction, Fixed64) {
		total, err := b.coinbaseTotalReward(height, 0)
		assert.NoError(t, err)
		cr := Fixed64(math.Ceil(float64(total) * 0.3))
		arb := Fixed64(math.Ceil(float64(total) * 0.35))
		miner := total - cr - arb
		// lock = height: FV-19's relocated F-031 pin now runs inside
		// checkCoinbaseTransactionContext, so an honest stub coinbase must carry the
		// LockTime an honest producer sets.
		tx := &f011Tx{lock: height, outs: []*common2.Output{
			{Value: cr, ProgramHash: crAddr},
			{Value: miner, ProgramHash: minerPH},
			{Value: arb, ProgramHash: dposAddr},
		}}
		return tx, arb // arb is the dposReward the caller passes for Outputs[2]
	}

	honestPH := Uint168{0x21, 0xAB, 0xCD, 0xEF}

	// FIXED, above gate: the frozen-paying coinbase is rejected.
	cbFrozenAbove, dposA := mkCoinbase(gate+100, frozenPH)
	errAbove := b.checkCoinbaseTransactionContext(gate+100, cbFrozenAbove, 0, dposA)
	assert.Error(t, errAbove,
		"F-013: a coinbase paying a frozen address must be rejected at/above the gate")
	if errAbove != nil {
		assert.Contains(t, errAbove.Error(), "frozen address",
			"rejection must be the frozen-address rule, not an unrelated check")
	}

	// No false reject: above the gate an honest miner address passes.
	cbHonestAbove, dposH := mkCoinbase(gate+100, honestPH)
	assert.NoError(t, b.checkCoinbaseTransactionContext(gate+100, cbHonestAbove, 0, dposH),
		"an honest coinbase must not be rejected by the frozen-address rule")

	// Below gate: the SAME frozen-paying coinbase is accepted (check skipped) — the
	// byte-identical-replay guarantee for retained history below StrictMoneyRangeHeight.
	cbFrozenBelow, dposB := mkCoinbase(gate-1, frozenPH)
	assert.NoError(t, b.checkCoinbaseTransactionContext(gate-1, cbFrozenBelow, 0, dposB),
		"below the gate the coinbase frozen check must be skipped (byte-identical replay)")
}
