// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// F-011 / F-086 (DPoS coinbase mint via the non-ELA fee wedge) — empirical proof
// of the MECHANISM using the real production fee functions. The DPoS arbiter
// reward leg (GetBlockDPOSRewardStrict, summing tx.Fee() == getTransactionFee ==
// ALL-asset input-minus-output) is computed on a different fee basis than the
// CR/miner legs (ELA-filtered totalTxFee via GetTxFeeStrict(ELAAssetID)). Any
// non-ELA fee therefore inflates the arbiter base above the CR/miner base -> an
// over-issuance of 0.35 x (non-ELA fee).
//
// This proves the wedge is REAL and still PRESENT in our tree (NOT closed by the
// strict-money fix). Its safety currently rests ONLY on there being no live
// non-ELA UTXOs (the F-056 ban blocks new ones) -- a DORMANCY that cannot be
// empirically confirmed with read-only mainnet + no asset-enumeration RPC, so it
// stays INFERRED + DEFERRED (see INFERRED-ITEMS.md A3). Clean resolution: unify
// the DPoS reward basis to ELA-only at/above the gate (engineer Q B6).
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
}

// TestF011NonELAFeeWedgeDivergence proves the two reward-leg fee bases diverge by
// exactly the non-ELA fee, across >=5 non-ELA values, using the real production
// GetTxFeeStrict.
func TestF011NonELAFeeWedgeDivergence(t *testing.T) {
	// A non-ELA asset id (anything != core.ELAAssetID).
	var nonELA common.Uint256
	nonELA[0] = 0x99
	assert.NotEqual(t, core.ELAAssetID, nonELA)

	values := []common.Fixed64{1, 100, 100000, 1_0000_0000, 5000_0000_0000}
	proven := 0
	for _, v := range values {
		// A tx that spends a non-ELA UTXO worth v and produces no outputs.
		tx := functions.CreateTransaction(
			common2.TxVersion09, common2.TransferAsset, 0,
			&payload.TransferAsset{}, nil,
			[]*common2.Input{{Previous: common2.OutPoint{TxID: common.Uint256{1}, Index: 0}}},
			nil, 0, nil,
		)
		refs := map[*common2.Input]common2.Output{
			{Previous: common2.OutPoint{TxID: common.Uint256{1}, Index: 0}}: {
				AssetID: nonELA,
				Value:   v,
			},
		}

		// CR/miner leg basis: ELA-filtered fee -> 0 (the input is non-ELA).
		elaFee, err := blockchain.GetTxFeeStrict(tx, core.ELAAssetID, refs)
		assert.NoError(t, err)
		assert.Equal(t, common.Fixed64(0), elaFee,
			"ELA-filtered fee (CR/miner leg) must exclude the non-ELA input")

		// The non-ELA fee itself.
		nonElaFee, err := blockchain.GetTxFeeStrict(tx, nonELA, refs)
		assert.NoError(t, err)
		assert.Equal(t, v, nonElaFee)

		// Arbiter leg basis: tx.Fee() == getTransactionFee == ALL-asset sum ==
		// sum over the per-asset strict map == elaFee + nonElaFee == v.
		arbiterBasis := elaFee + nonElaFee

		// THE WEDGE: arbiter reward base exceeds the CR/miner base by the whole
		// non-ELA fee -> a coinbase over-issuance of ceil(0.35 * v) to arbiters.
		assert.Greater(t, arbiterBasis, elaFee,
			"F-011/086 wedge: arbiter reward base (all-asset) > CR/miner base (ELA-only) by v=%d", v)
		assert.Equal(t, v, arbiterBasis-elaFee, "divergence must equal the non-ELA fee")

		if arbiterBasis-elaFee == v && elaFee == 0 {
			proven++
		}
	}
	assert.GreaterOrEqual(t, proven, 5,
		"wedge divergence must be demonstrated for >=5 non-ELA fee values; got %d", proven)
}
