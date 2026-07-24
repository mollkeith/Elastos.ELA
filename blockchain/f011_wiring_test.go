// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package blockchain

import (
	"math"
	"testing"

	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	. "github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

// f011Tx is a minimal interfaces.Transaction exposing only Fee() and Outputs() — all that
// GetBlockDPOSReward and checkCoinbaseTransactionContext's DPoSV2 branch read. (package
// blockchain cannot import core/transaction — that package imports blockchain — so the
// functions registry is unusable from an internal test.)
type f011Tx struct {
	interfaces.Transaction
	fee  Fixed64
	outs []*common2.Output
	// lock models the coinbase LockTime. FV-19 relocated the F-031 pin onto
	// checkCoinbaseTransactionContext, which now reads it, so every stub coinbase handed
	// to that function must set lock = its block height exactly as pow/service.go does.
	lock uint32
}

func (f *f011Tx) Fee() Fixed64               { return f.fee }
func (f *f011Tx) Outputs() []*common2.Output { return f.outs }
func (f *f011Tx) LockTime() uint32           { return f.lock }

// TestF011CoinbaseWedgeRejectedOnELABasis closes the F-011 EVIDENCE GAP flagged by the
// Fable-review fork: the pre-existing f011 tests call GetBlockDPOSRewardStrict directly and
// still pass with the blockvalidator.go call site reverted, so nothing ever executed the
// CONSEQUENCE of the basis choice.
//
// This drives BOTH real branches of the fork at blockvalidator.go:~618 and then the real
// enforcement point:
//
//	pre-fix  : b.GetBlockDPOSReward(block)            -> sums tx.Fee() across ALL assets
//	fixed    : b.GetBlockDPOSRewardStrict(h, feeELA)  -> ELA-filtered basis (GetTxFeeStrict
//	                                                     with core.ELAAssetID)
//	then     : b.checkCoinbaseTransactionContext(...)  decides accept/reject
//
// The wedge (INFERRED-ITEMS A3): a coinbase with ELA-basis CR/miner legs but an Outputs[2]
// (arbiter leg) sized on the ALL-ASSET basis — ceil(0.35 x nonELAfee) of unbacked ELA per
// block. Fail-on-pristine: the SAME coinbase is ACCEPTED against the pre-fix basis and
// REJECTED against the fixed basis, so the basis is demonstrably what stops the mint.
func TestF011CoinbaseWedgeRejectedOnELABasis(t *testing.T) {
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = 2260451
	b := &BlockChain{chainParams: params, state: &state.State{StateKeyFrame: &state.StateKeyFrame{}}}

	orig := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: &state.ArbitratorsMock{}}
	defer func() { DefaultLedger = orig }()

	// The reward-rule gate (Q-B6: a FRESH height, not the incident gate). Height must be at or
	// above it so mainnet takes the fixed branch, and > mock GetDPoSV2ActiveHeight()+1
	// (2000000+1) so the DPoSV2 coinbase branch runs.
	assert.Equal(t, uint32(2265000), params.RevisedDPoSRewardHeight,
		"F-011 activates at RevisedDPoSRewardHeight; if this moves, re-derive the wedge height")
	const height = uint32(2265000)
	assert.GreaterOrEqual(t, height, params.RevisedDPoSRewardHeight)

	const elaFee = Fixed64(0)            // ELA-filtered basis: no ELA fee in this block
	const nonELAFee = Fixed64(100000000) // 1.0 of a NON-ELA asset's fee = the wedge

	// FEE SIDE (the source of the fixed basis): the real GetTxFeeStrict, keyed on
	// core.ELAAssetID exactly as checkTxsContext calls it, EXCLUDES a non-ELA fee. So the
	// totalTxFee the fixed branch is handed really is ELA-only, while the same tx carries a
	// non-ELA fee that the pre-fix tx.Fee() sum would count.
	var nonELAAsset Uint256
	nonELAAsset[0] = 0xEE
	feeTx := &f011Tx{outs: []*common2.Output{{AssetID: core.ELAAssetID, Value: 10}}}
	inELA, inOther := &common2.Input{}, &common2.Input{}
	refs := map[*common2.Input]common2.Output{
		inELA:   {AssetID: core.ELAAssetID, Value: 10},
		inOther: {AssetID: nonELAAsset, Value: nonELAFee},
	}
	feeELA, err := GetTxFeeStrict(feeTx, core.ELAAssetID, refs)
	assert.NoError(t, err)
	assert.Equal(t, elaFee, feeELA, "the ELA-filtered accumulator must exclude the non-ELA fee")
	feeMap, err := GetTxFeeMapStrict(feeTx, refs)
	assert.NoError(t, err)
	assert.Equal(t, nonELAFee, feeMap[nonELAAsset],
		"the non-ELA fee is real and non-zero — it is simply not ELA-backed")

	// PRE-FIX basis — the genuine else-branch function, on a block whose only fee is non-ELA.
	blk := &Block{
		Header:       common2.Header{Height: height},
		Transactions: []interfaces.Transaction{&f011Tx{}, &f011Tx{fee: nonELAFee}},
	}
	dposPreFix := b.GetBlockDPOSReward(blk)

	// FIXED basis — the genuine if-branch function, on the ELA-filtered fee total.
	dposFixed, err := b.GetBlockDPOSRewardStrict(height, elaFee)
	assert.NoError(t, err)

	// The divergence IS the unbacked mint: 35% of the non-ELA fee, per block.
	assert.Greater(t, dposPreFix, dposFixed)
	assert.Equal(t, Fixed64(math.Ceil(float64(nonELAFee)*0.35)), dposPreFix-dposFixed,
		"pre-fix arbiter leg is inflated by ceil(0.35 x non-ELA fee) with no ELA backing")
	t.Logf("[F-011] nonELAfee=%d  dposPreFix=%d  dposFixed=%d  unbacked mint/block=%d sela",
		nonELAFee, dposPreFix, dposFixed, dposPreFix-dposFixed)

	// MAINNET-EQUIVALENCE (why activating at 2265000 cannot split the fleet): when every fee
	// is ELA — measured true for all 2,260,597 blocks of mainnet history, and enforced forward
	// by F-056 rejecting RegisterAsset at/above StrictMoneyRangeHeight — the pre-fix and fixed
	// bases are the SAME number, so the switch is a no-op. (CalculateTxsFee skips the coinbase
	// and checkTxsContext sums from i=1, so the coinbase contributes 0 to both sides.)
	const elaOnlyFee = Fixed64(37000000)
	elaOnlyBlk := &Block{
		Header:       common2.Header{Height: height},
		Transactions: []interfaces.Transaction{&f011Tx{}, &f011Tx{fee: elaOnlyFee}},
	}
	elaOnlyFixed, err := b.GetBlockDPOSRewardStrict(height, elaOnlyFee)
	assert.NoError(t, err)
	assert.Equal(t, b.GetBlockDPOSReward(elaOnlyBlk), elaOnlyFixed,
		"ELA-only: pre-fix and fixed bases must agree — the 2265000 activation is a no-op")

	// CR/miner legs on the ELA basis (they always were); only the arbiter leg varies.
	totalELA, err := b.coinbaseTotalReward(height, elaFee)
	assert.NoError(t, err)
	cr := Fixed64(math.Ceil(float64(totalELA) * 0.3))
	arb := Fixed64(math.Ceil(float64(totalELA) * 0.35))
	miner := totalELA - cr - arb
	crAddr := *params.CRConfiguration.CRAssetsProgramHash
	dposAddr := *params.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash
	mk := func(dposLeg Fixed64) interfaces.Transaction {
		return &f011Tx{lock: height, outs: []*common2.Output{
			{Value: cr, ProgramHash: crAddr},
			{Value: miner},
			{Value: dposLeg, ProgramHash: dposAddr},
		}}
	}
	wedge := mk(dposPreFix) // inflated arbiter leg = the unbacked mint
	honest := mk(dposFixed)

	// FIXED basis: the wedge coinbase is REJECTED on the DPoS leg.
	errWedge := b.checkCoinbaseTransactionContext(height, wedge, elaFee, dposFixed)
	assert.Error(t, errWedge)
	if errWedge != nil {
		assert.Contains(t, errWedge.Error(), "last DPoS reward value not correct",
			"F-011: an all-asset-sized arbiter leg must be rejected against the ELA-filtered basis")
	}

	// No false reject: an honest ELA-basis coinbase passes.
	assert.NoError(t, b.checkCoinbaseTransactionContext(height, honest, elaFee, dposFixed),
		"an honest ELA-basis coinbase must not be rejected")

	// FAIL-ON-PRISTINE: against the pre-fix basis the SAME wedge coinbase is ACCEPTED —
	// the unbacked mint goes through. This assertion is what the fix makes false.
	assert.NoError(t, b.checkCoinbaseTransactionContext(height, wedge, elaFee, dposPreFix),
		"pre-fix (all-asset basis) the wedge coinbase is accepted — the mint the fix prevents")
}
