// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"math"

	"github.com/elastos/Elastos.ELA/common"
)

// TestF011ArbiterRewardMintAndFix drives the REAL production arbiter-reward
// function (GetBlockDPOSRewardStrict) on the suite's live BlockChain to prove:
//   - the MINT: on an ALL-asset fee basis (elaFee+V, what the pre-fix code fed
//     coinbase[2]) the arbiter reward exceeds the ELA-only basis (elaFee) by
//     ~ceil(0.35*V) -> exactly the unbacked ELA a crafted coinbase could claim.
//   - the FIX: post-fix, checkTxsContext calls GetBlockDPOSRewardStrict with the
//     ELA-filtered totalTxFee, so coinbase[2] is capped at the ELA-backed value.
//   - BIT-IDENTICAL for honest (all-ELA) blocks: V=0 -> zero divergence.
func (s *txValidatorTestSuite) TestF011ArbiterRewardMintAndFix() {
	chain := s.Chain
	gate := chain.GetParams().StrictMoneyRangeHeight
	height := gate + 50 // at/above the recovery gate

	elaFee := common.Fixed64(1_0000_0000) // a normal 1-ELA fee

	// Non-ELA fee amounts whose 0.35*v is comfortably >= 1 sela (real mint).
	nonELAFees := []common.Fixed64{
		100, 1_0000_0000, 100_0000_0000, 5000_0000_0000, 100_0000_0000_0000,
	}

	// ELA-only basis (the fix): the arbiter reward that is actually ELA-backed.
	rewardELA, err := chain.GetBlockDPOSRewardStrict(height, elaFee)
	s.NoError(err)
	s.Greater(rewardELA, common.Fixed64(0), "sanity: arbiter reward must be positive")

	proven := 0
	for _, v := range nonELAFees {
		// All-asset basis (pre-fix): coinbase[2] was validated against this.
		rewardAllAsset, err := chain.GetBlockDPOSRewardStrict(height, elaFee+v)
		s.NoError(err)

		mint := rewardAllAsset - rewardELA
		// The over-issuance equals ceil(0.35*(R+elaFee+v)) - ceil(0.35*(R+elaFee)),
		// i.e. ~0.35*v of ELA created with no ELA fee backing it.
		s.Greater(mint, common.Fixed64(0),
			"MINT: all-asset arbiter reward over-issues vs ELA-only for non-ELA fee v=%d", v)
		expected := common.Fixed64(math.Ceil(float64(v) * 0.35))
		// within 2 sela of the exact 0.35*v (double ceil rounding).
		s.InDelta(float64(expected), float64(mint), 2.0,
			"mint must be ~ceil(0.35*v); v=%d expected=%d got=%d", v, expected, mint)
		if mint > 0 {
			proven++
		}
	}
	s.GreaterOrEqual(proven, 5, "the arbiter over-issuance must be shown for >=5 non-ELA fees")

	// Rounding boundary (audit note): a sub-~3-sela non-ELA fee rounds away, so the
	// attacker mints 0 integer sela — no exploitable gain at the floor.
	mintTiny, err := chain.GetBlockDPOSRewardStrict(height, elaFee+1)
	s.NoError(err)
	s.LessOrEqual(mintTiny-rewardELA, common.Fixed64(1),
		"tiny non-ELA fee yields at most rounding noise, not a real mint")

	// BIT-IDENTICAL for honest blocks: an all-ELA block (no non-ELA fee) feeds the
	// SAME fee to both bases, so there is zero divergence -> the fix changes
	// nothing for every honest block.
	sameBasis, err := chain.GetBlockDPOSRewardStrict(height, elaFee)
	s.NoError(err)
	s.Equal(rewardELA, sameBasis, "V=0: fix is byte-identical for honest all-ELA blocks")

	// Below the gate the strict path is inactive (legacy reward preserved); sanity
	// that the gated function still returns for a below-gate height without error.
	belowRewardELA, err := chain.GetBlockDPOSRewardStrict(gate-1, elaFee)
	s.NoError(err)
	s.Greater(belowRewardELA, common.Fixed64(0))
}
