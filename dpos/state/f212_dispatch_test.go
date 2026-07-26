// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

// F-212 — empty-arbiter-slot reward double-emit, at the PRODUCTION DISPATCH.
//
// THE EVIDENCE GAP THIS CLOSES. f212_test.go calls distributeWithNormalArbitratorsV3
// directly and asserts on its realDPOSReward return. Two things were therefore unproven:
//
//  1. `change`, the quantity that is actually MINTED to the CR and miner legs, is computed
//     one level up in distributeDPOSReward (`change = reward - realDPOSReward`). The helper
//     test never evaluates it, so it cannot show the double-emit is gone from the number
//     that reaches the coinbase.
//  2. distributeDPOSReward selects between FOUR distribution functions by height. The fix
//     was applied to V3 and V2, but only V3 had a test — mutation measured at HEAD:
//     neutering the V2 gate left the entire shipping gate green.
//
// These tests drive distributeDPOSReward — the function every reward path calls — once on
// the V3 leg and once on the V2 leg, and assert the invariant in terms of `change` itself:
// at and above RevisedDPoSRewardHeight, `change` must fall by EXACTLY the amount burned to
// the Destroy address, because that amount is no longer both burned AND re-minted. The
// burned amount is read out of the returned roundReward map rather than recomputed here, so
// the assertion does not restate the production reward formula.
//
// FAIL-ON-PRISTINE (measured): neuter either `if height >= a.ChainParams.RevisedDPoSRewardHeight`
// in dpos/state/arbitrators.go (the V3 leg or the V2 leg) -> "EMPTY-SLOT REWARD STILL
// DOUBLE-EMITTED" on the corresponding leg.
//
// No new height literal: the gate is config.Configuration.RevisedDPoSRewardHeight, set here
// to a per-test value the way f212_test.go already does.

// f212Arbiters builds the smallest Arbiters that reaches the empty-arbiter-slot loop:
// 3 arbiter slots configured, 1 elected, so 2 slots are empty and their block-confirm
// reward is burned to the Destroy address.
func f212Arbiters(t *testing.T, gate uint32, v2Leg bool) (*Arbiters, *common.Uint168) {
	t.Helper()
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pkBuf, err := pub.EncodePoint(true)
	assert.NoError(t, err)
	arb, err := NewOriginArbiter(pkBuf)
	assert.NoError(t, err)

	destroy := &common.Uint168{0xff}
	cfg := &config.Configuration{
		DestroyELAProgramHash:   destroy,
		RevisedDPoSRewardHeight: gate,
	}
	cfg.DPoSConfiguration.NormalArbitratorsCount = 3
	cfg.DPoSConfiguration.CRCArbiters = []string{}
	// Leg selection in distributeDPOSReward is by height against these two thresholds.
	if v2Leg {
		cfg.CRConfiguration.ChangeCommitteeNewCRHeight = gate + 1000000 // out of reach -> not V3
		cfg.CRConfiguration.CRClaimDPOSNodeStartHeight = 0              // -> V2
	} else {
		cfg.CRConfiguration.ChangeCommitteeNewCRHeight = 0 // -> V3
	}

	return &Arbiters{
		State:              &State{StateKeyFrame: &StateKeyFrame{}},
		ChainParams:        cfg,
		CurrentArbitrators: []ArbiterMember{arb},
		CurrentCandidates:  []ArbiterMember{},
		CurrentReward: RewardData{
			OwnerVotesInRound: map[common.Uint168]common.Fixed64{},
			TotalVotesInRound: 1,
		},
	}, destroy
}

// f212Change runs the REAL dispatch and returns (burned-to-Destroy, change).
func f212Change(t *testing.T, gate, height uint32, reward common.Fixed64,
	v2Leg bool) (common.Fixed64, common.Fixed64) {
	t.Helper()
	a, destroy := f212Arbiters(t, gate, v2Leg)
	roundReward, change, err := a.distributeDPOSReward(height, reward)
	assert.NoError(t, err)
	return roundReward[*destroy], change
}

func f212AssertLeg(t *testing.T, v2Leg bool, legName string) {
	t.Helper()
	const reward = common.Fixed64(100 * 1e8)
	const gate = uint32(2270000) // a fresh future height, above the frozen tip 2,260,595

	burnedBelow, changeBelow := f212Change(t, gate, gate-1, reward, v2Leg)
	burnedAbove, changeAbove := f212Change(t, gate, gate, reward, v2Leg)

	if burnedBelow == 0 {
		t.Fatalf("test vector broken on the %s leg: nothing was burned to the Destroy "+
			"address, so the empty-slot loop was never reached", legName)
	}
	assert.Equal(t, burnedBelow, burnedAbove,
		"%s leg: the BURN itself must be unchanged by the gate — only its accounting changes",
		legName)

	if changeBelow-changeAbove != burnedBelow {
		t.Fatalf("EMPTY-SLOT REWARD STILL DOUBLE-EMITTED on the %s leg: change fell by %v "+
			"across the gate but %v was burned to the Destroy address. change is what the "+
			"CR and miner legs mint, so any shortfall here is the burned reward being "+
			"emitted a second time. below=%v above=%v",
			legName, changeBelow-changeAbove, burnedBelow, changeBelow, changeAbove)
	}

	// The gate must be exact: gate-1 keeps the legacy (double-emitting) accounting so
	// retained history re-derives byte-identically.
	_, changeAtGatePlus := f212Change(t, gate, gate+1, reward, v2Leg)
	assert.Equal(t, changeAbove, changeAtGatePlus,
		"%s leg: the fixed accounting must hold above the gate too", legName)
}

// TestF212DispatchV3ChangeDropsByBurnedTotal drives distributeDPOSReward on the V3 leg.
func TestF212DispatchV3ChangeDropsByBurnedTotal(t *testing.T) {
	f212AssertLeg(t, false, "V3")
}

// TestF212DispatchV2ChangeDropsByBurnedTotal drives distributeDPOSReward on the V2 leg —
// the leg that shipped with the fix but with no test at all.
func TestF212DispatchV2ChangeDropsByBurnedTotal(t *testing.T) {
	f212AssertLeg(t, true, "V2")
}
