// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// XM-04 -- the DPoS reward STATE was left on the asset-blind fee basis.
//
// The F-011/F-086 fix moved the VALIDATOR onto the ELA-filtered fee at
// RevisedDPoSRewardHeight (blockchain.GetBlockDPOSRewardStrict) but
// Arbiters.getBlockDPOSReward kept summing tx.Fee() over every transaction in the block.
// That is the side that mints: accumulateReward -> accumulativeReward and
// clearingDPOSReward -> distributeDPOSReward -> arbitersRoundReward, i.e. claimable,
// spendable ELA. SumBlockTxFees is now the single definition shared with
// blockchain.GetBlockDPOSReward; this file pins its gate and its shape.
package state

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"

	"github.com/stretchr/testify/assert"
)

const (
	xmStrictGate  = uint32(2260451) // gate 1
	xmRevisedGate = uint32(2265000) // gate 2, RevisedDPoSRewardHeight
)

// xmFeeTx carries nothing but a fee. SumBlockTxFees and getBlockDPOSReward read Fee()
// and nothing else, so the embedded interface never has to be satisfied.
type xmFeeTx struct {
	interfaces.Transaction
	fee common.Fixed64
}

func (t *xmFeeTx) Fee() common.Fixed64 { return t.fee }

func xmBlock(height uint32, fees ...common.Fixed64) *types.Block {
	txs := make([]interfaces.Transaction, 0, len(fees))
	for _, f := range fees {
		txs = append(txs, &xmFeeTx{fee: f})
	}
	return &types.Block{
		Header:       common2.Header{Height: height},
		Transactions: txs,
	}
}

func xmArbiters() *Arbiters {
	cfg := *config.GetDefaultParams()
	cfg.StrictMoneyRangeHeight = xmStrictGate
	cfg.RevisedDPoSRewardHeight = xmRevisedGate
	return &Arbiters{ChainParams: &cfg}
}

// TestXM04SumBlockTxFeesBelowGateIsLegacyVerbatim -- retained history and the window
// before activation must be byte-identical: every transaction counted, coinbase included,
// wrapping addition.
func TestXM04SumBlockTxFeesBelowGateIsLegacyVerbatim(t *testing.T) {
	heights := []uint32{0, 1000000, 2260450, xmStrictGate, xmRevisedGate - 1}
	feeSets := [][]common.Fixed64{
		{0, 100, 200, 300},
		{500, 0, 0},
		{0},
		{7, -3, 11}, // legacy tolerated negatives; below the gate that must not change
	}

	for _, h := range heights {
		for _, fees := range feeSets {
			var want common.Fixed64
			for _, f := range fees {
				want += f
			}
			txs := xmBlock(h, fees...).Transactions
			assert.Equal(t, want, SumBlockTxFees(txs, h, xmRevisedGate),
				"below gate 2 the legacy sum must be reproduced exactly at height %d", h)
		}
	}
}

// TestXM04SumBlockTxFeesAboveGateExcludesCoinbase -- at and above the gate the total must
// have the SAME shape as blockchain checkTxsContext's: start at index 1.
// FAILS ON PRISTINE: getBlockDPOSReward summed every transaction including index 0.
func TestXM04SumBlockTxFeesAboveGateExcludesCoinbase(t *testing.T) {
	for _, h := range []uint32{xmRevisedGate, xmRevisedGate + 1, 3000000} {
		// index 0 carries a large fee; it must contribute nothing.
		txs := xmBlock(h, 9_999_999_999, 100, 200, 300).Transactions
		assert.Equal(t, common.Fixed64(600), SumBlockTxFees(txs, h, xmRevisedGate),
			"the coinbase leg must not enter the fee total at height %d", h)
	}
}

// TestXM04SumBlockTxFeesAboveGateIgnoresNonPositive -- a negative fee must never be able
// to move the reward base. XM-02 makes it unreachable; this is the belt.
func TestXM04SumBlockTxFeesAboveGateIgnoresNonPositive(t *testing.T) {
	h := xmRevisedGate + 10
	txs := xmBlock(h, 0, 100, -1_000_000, 200, 0, 300).Transactions
	assert.Equal(t, common.Fixed64(600), SumBlockTxFees(txs, h, xmRevisedGate))
}

// TestXM04SumBlockTxFeesAboveGateRejectsOverflow -- checked addition, not wrapping.
func TestXM04SumBlockTxFeesAboveGateRejectsOverflow(t *testing.T) {
	h := xmRevisedGate + 10
	huge := common.Fixed64(math.MaxInt64 - 10)
	txs := xmBlock(h, 0, huge, huge).Transactions
	got := SumBlockTxFees(txs, h, xmRevisedGate)
	assert.True(t, got >= 0, "the total must never wrap negative, got %d", int64(got))
	assert.True(t, common.MoneyRange(got), "the total must stay inside the money range")
}

// TestXM04GateBoundaryIsExact -- one block either side of RevisedDPoSRewardHeight.
func TestXM04GateBoundaryIsExact(t *testing.T) {
	fees := []common.Fixed64{500, 100, 200}
	below := xmBlock(xmRevisedGate-1, fees...).Transactions
	above := xmBlock(xmRevisedGate, fees...).Transactions

	assert.Equal(t, common.Fixed64(800), SumBlockTxFees(below, xmRevisedGate-1, xmRevisedGate),
		"one block below the gate the coinbase leg is still counted (legacy)")
	assert.Equal(t, common.Fixed64(300), SumBlockTxFees(above, xmRevisedGate, xmRevisedGate),
		"at the gate the coinbase leg is excluded")
}

// TestXM04GetBlockDPOSRewardUsesTheSharedDefinition drives the REAL production
// getBlockDPOSReward -- the function whose result becomes accumulativeReward and then
// claimable ELA -- and pins it to the shared basis.
// FAILS ON PRISTINE: pristine sums every transaction, so the coinbase leg inflates the
// arbiter reward.
func TestXM04GetBlockDPOSRewardUsesTheSharedDefinition(t *testing.T) {
	a := xmArbiters()

	for _, h := range []uint32{xmRevisedGate, xmRevisedGate + 1, 3000000} {
		block := xmBlock(h, 5_000_000, 100, 200, 300)
		want := common.Fixed64(math.Ceil(float64(common.Fixed64(600)+
			a.ChainParams.GetBlockReward(h)) * 0.35))
		assert.Equal(t, want, a.getBlockDPOSReward(block),
			"the arbiter reward at height %d must be derived from the shared fee basis", h)
	}

	// Below the gate the legacy result is preserved exactly.
	for _, h := range []uint32{2000000, 2260450, xmStrictGate, xmRevisedGate - 1} {
		block := xmBlock(h, 5_000_000, 100, 200, 300)
		want := common.Fixed64(math.Ceil(float64(common.Fixed64(5_000_600)+
			a.ChainParams.GetBlockReward(h)) * 0.35))
		assert.Equal(t, want, a.getBlockDPOSReward(block),
			"below the gate the legacy arbiter reward at height %d must be unchanged", h)
	}
}
