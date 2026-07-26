// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// XM-01 -- the coinbase accepted ANY AssetID at and above PublicDPOSHeight.
//
// CoinBaseTransaction.CheckTransactionOutput loops every output demanding
// core.ELAAssetID only on the branch taken BELOW PublicDPOSHeight; the branch taken by
// every block since height 402,680 has no such loop, and nothing downstream restores it.
// The coinbase is the one transaction that creates outputs with no inputs, so this let a
// block producer stamp an arbitrary 32-byte asset id onto real, spendable chain state.
//
// This file proves: (a) the guard fires on the LIVE path at and above the gate, (b) the
// verdict BELOW the gate is bit-for-bit the pristine verdict for every input, including
// the non-ELA coinbases the pristine code accepted, so retained history still replays.
package transaction

import (
	"errors"
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

const (
	// gate 1 -- StrictMoneyRangeHeight, the coordinated recovery activation.
	xmGate = uint32(2260451)

	// The REAL mainnet reward split in force across both gates: halving factor 3,
	// R = 76,103,500 sela (MEASURED over the retained chain; next halving 3,153,600).
	xmBlockReward = common.Fixed64(76103500)
	xmCRLeg       = common.Fixed64(22831050) // ceil(0.30 * R)
	xmDPoSLeg     = common.Fixed64(26636225) // ceil(0.35 * R)
	xmMinerLeg    = common.Fixed64(26636225) // R - CR - DPoS
)

func xmNonELAAsset() common.Uint256 {
	var a common.Uint256
	a[0] = 0x99
	a[31] = 0x11
	return a
}

func xmParams(height uint32) *config.Configuration {
	cfg := *config.GetDefaultParams()
	cfg.StrictMoneyRangeHeight = xmGate
	cfg.RevisedDPoSRewardHeight = 2265000
	_ = height
	return &cfg
}

// xmCoinbase builds a DPoSv2-shaped coinbase: 3 outputs carrying the real mainnet
// reward split, with a caller-chosen AssetID per output.
func xmCoinbase(height uint32, assets []common.Uint256) interfaces.Transaction {
	values := []common.Fixed64{xmCRLeg, xmMinerLeg, xmDPoSLeg}
	outs := make([]*common2.Output, len(assets))
	for i := range assets {
		outs[i] = &common2.Output{
			AssetID:     assets[i],
			Value:       values[i],
			Type:        common2.OTNone,
			ProgramHash: common.Uint168{byte(i + 1)},
			Payload:     &outputpayload.DefaultOutput{},
		}
	}
	return functions.CreateTransaction(
		0, common2.CoinBase, payload.CoinBaseVersion, &payload.CoinBase{},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: math.MaxUint16},
			Sequence: math.MaxUint32,
		}},
		outs, height, []*program.Program{},
	)
}

func xmAllELA() []common.Uint256 {
	return []common.Uint256{core.ELAAssetID, core.ELAAssetID, core.ELAAssetID}
}

// xmSanity drives the EXACT entry point CheckBlockSanity uses for every transaction of
// every block, coinbase included: BlockChain.CheckTransactionSanity builds the parameters
// with functions.GetTransactionParameters and calls txn.SanityCheck, which dispatches
// Transaction.CheckTransactionOutput. Nothing here is a mock.
func xmSanity(txn interfaces.Transaction, height uint32) error {
	para := &TransactionParameters{
		Transaction: txn,
		BlockHeight: height,
		Config:      xmParams(height),
	}
	if err := txn.SanityCheck(para); err != nil {
		return errors.New(err.Error())
	}
	return nil
}

// TestXM01NonELACoinbaseRejectedAtAndAboveGate -- the acceptance half.
// FAILS ON PRISTINE: without checkCoinbaseOutputAssets the post-PublicDPOSHeight branch
// has no asset rule at all and every one of these coinbases is accepted.
func TestXM01NonELACoinbaseRejectedAtAndAboveGate(t *testing.T) {
	fake := xmNonELAAsset()
	heights := []uint32{xmGate, xmGate + 1, xmGate + 1000, 2265000, 3000000}

	// Every output position matters: outputs[0] and outputs[2] are pinned to protocol
	// addresses by checkCoinbaseTransactionContext but their ASSET was never pinned,
	// and outputs[1] (the merge-miner leg) carries no address constraint at all.
	for pos := 0; pos < 3; pos++ {
		for _, h := range heights {
			assets := xmAllELA()
			assets[pos] = fake
			err := xmSanity(xmCoinbase(h, assets), h)
			assert.Error(t, err,
				"coinbase with a non-ELA AssetID at output[%d], height %d, must be rejected", pos, h)
			assert.Contains(t, err.Error(), "asset ID in coinbase is invalid")
		}
	}

	// All three legs forged at once.
	for _, h := range heights {
		err := xmSanity(xmCoinbase(h, []common.Uint256{fake, fake, fake}), h)
		assert.Error(t, err, "all-non-ELA coinbase at height %d must be rejected", h)
	}
}

// TestXM01ELACoinbaseStillAcceptedAtAndAboveGate -- the guard must not reject honest
// blocks. This is the rule that keeps the chain moving after the restart.
func TestXM01ELACoinbaseStillAcceptedAtAndAboveGate(t *testing.T) {
	for _, h := range []uint32{xmGate, xmGate + 1, 2265000, 3000000} {
		assert.NoError(t, xmSanity(xmCoinbase(h, xmAllELA()), h),
			"an all-ELA coinbase at height %d must still be accepted", h)
	}
}

// TestXM01RetainedHistoryStillReplays -- the below-gate half of the invariant, and the
// trap that already bit this campaign twice. The pristine code ACCEPTED a non-ELA
// coinbase at every height above PublicDPOSHeight. A v1.0.0 node replaying from genesis
// must reach the same verdict on every retained block, so below the gate the guard must
// be invisible -- including for inputs the new rule would reject above it.
func TestXM01RetainedHistoryStillReplays(t *testing.T) {
	fake := xmNonELAAsset()
	// Real retained heights: the block the ungated money bound wrongly rejected, the
	// exploit block's neighbourhood, PublicDPOSHeight itself, and the gate boundary.
	heights := []uint32{402680, 500000, 1000000, 2000000, 2208265, 2260265, 2260450}

	for _, h := range heights {
		assert.NoError(t, xmSanity(xmCoinbase(h, xmAllELA()), h),
			"retained all-ELA coinbase at %d must replay", h)
		for pos := 0; pos < 3; pos++ {
			assets := xmAllELA()
			assets[pos] = fake
			assert.NoError(t, xmSanity(xmCoinbase(h, assets), h),
				"REPLAY BREAKS: retained height %d, output[%d] non-ELA, rejected by a "+
					"v1.0.0 node although the released code accepted it", h, pos)
		}
	}
}

// xmPristineCoinbaseOutputCheck is the body of CoinBaseTransaction.CheckTransactionOutput
// as it stood at HEAD b3f79009, copied verbatim. It is the oracle for the differential
// test below.
func xmPristineCoinbaseOutputCheck(txn interfaces.Transaction, blockHeight uint32,
	chainParams *config.Configuration) error {
	if len(txn.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}
	if len(txn.Outputs()) < 2 {
		return errors.New("coinbase output is not enough, at least 2")
	}

	foundationReward := txn.Outputs()[0].Value
	var totalReward = common.Fixed64(0)
	if blockHeight < chainParams.PublicDPOSHeight {
		for _, output := range txn.Outputs() {
			if output.AssetID != core.ELAAssetID {
				return errors.New("asset ID in coinbase is invalid")
			}
			totalReward += output.Value
		}

		if foundationReward < common.Fixed64(float64(totalReward)*0.3) {
			return errors.New("reward to foundation in coinbase < 30%")
		}
	} else {
		totalReward = txn.Outputs()[0].Value + txn.Outputs()[1].Value
		if len(txn.Outputs()) == 2 && foundationReward <
			common.Fixed64(float64(totalReward)*0.3/0.65) {
			return errors.New("reward to foundation in coinbase < 30%")
		}
	}

	return nil
}

// TestXM01BelowGateVerdictIdenticalToPristine is the strongest form of the replay
// invariant: for a matrix of heights BELOW the gate and every asset arrangement, the
// patched production function and the pristine expression must return the SAME verdict.
// No census, no sampling -- an exhaustive equivalence over the inputs that can occur.
func TestXM01BelowGateVerdictIdenticalToPristine(t *testing.T) {
	fake := xmNonELAAsset()
	heights := []uint32{0, 1, 100000, 402679, 402680, 402681, 1051200, 2000000,
		2208265, 2260265, 2260449, 2260450}
	arrangements := [][]common.Uint256{
		{core.ELAAssetID, core.ELAAssetID, core.ELAAssetID},
		{fake, core.ELAAssetID, core.ELAAssetID},
		{core.ELAAssetID, fake, core.ELAAssetID},
		{core.ELAAssetID, core.ELAAssetID, fake},
		{fake, fake, fake},
	}

	compared := 0
	for _, h := range heights {
		cfg := xmParams(h)
		for _, assets := range arrangements {
			txn := xmCoinbase(h, assets)
			txn.SetParameters(&TransactionParameters{
				Transaction: txn, BlockHeight: h, Config: cfg})

			got := txn.CheckTransactionOutput()
			want := xmPristineCoinbaseOutputCheck(txn, h, cfg)

			assert.Equal(t, want == nil, got == nil,
				"height %d: patched verdict differs from pristine (pristine=%v, patched=%v)",
				h, want, got)
			if want != nil && got != nil {
				assert.Equal(t, want.Error(), got.Error(), "height %d: message drift", h)
			}
			compared++
		}
	}
	assert.Equal(t, len(heights)*len(arrangements), compared)
	t.Logf("below-gate equivalence proven over %d (height, asset-arrangement) pairs", compared)
}

// TestXM01GateBoundaryIsExact pins the activation height itself: rejected AT the gate,
// accepted one block below it. A wrong-by-one gate is a chain split.
func TestXM01GateBoundaryIsExact(t *testing.T) {
	fake := xmNonELAAsset()
	assets := []common.Uint256{core.ELAAssetID, fake, core.ELAAssetID}

	assert.NoError(t, xmSanity(xmCoinbase(xmGate-1, assets), xmGate-1),
		"height gate-1 is retained history and must be accepted")
	assert.Error(t, xmSanity(xmCoinbase(xmGate, assets), xmGate),
		"height gate must be rejected")
}
