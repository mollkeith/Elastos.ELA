// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

// TestF212EmptySlotRewardNotDoubleCounted proves the F-212 fix (Q-B7). The empty-arbiter-
// slot loop in distributeWithNormalArbitratorsV3 burns individualBlockConfirmReward to the
// Destroy address but, pre-fix, did NOT add it to realDPOSReward — so the caller's
// `change = reward - realDPOSReward` over-states change by the destroyed total and re-mints
// it to the CR+miner legs (the empty-slot reward is emitted TWICE). The fix accounts the
// destroyed reward in realDPOSReward at/above RevisedDPoSRewardHeight. Drives the REAL V3
// distribution with 2 empty slots and asserts realDPOSReward grows by exactly the destroyed
// total above the gate (so `change` no longer double-counts). FAILS on pristine (above==below),
// PASSES on the fixed tree.
func TestF212EmptySlotRewardNotDoubleCounted(t *testing.T) {
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pkBuf, err := pub.EncodePoint(true)
	assert.NoError(t, err)
	arb, err := NewOriginArbiter(pkBuf)
	assert.NoError(t, err)

	const reward = common.Fixed64(100 * 1e8)
	const gate = uint32(2270000) // a fresh future height (> frozen tip 2260595)
	destroy := &common.Uint168{0xff}

	realReward := func(height uint32) common.Fixed64 {
		cfg := &config.Configuration{
			DestroyELAProgramHash:   destroy,
			RevisedDPoSRewardHeight: gate,
		}
		cfg.DPoSConfiguration.NormalArbitratorsCount = 3 // arbitersCount = 3 (+0 CRC)
		cfg.DPoSConfiguration.CRCArbiters = []string{}
		a := &Arbiters{
			State:              &State{StateKeyFrame: &StateKeyFrame{}}, // ConsensusAlgorithm=DPOS(0)
			ChainParams:        cfg,
			CurrentArbitrators: []ArbiterMember{arb}, // 1 elected -> 2 empty slots
			CurrentCandidates:  []ArbiterMember{},
			CurrentReward: RewardData{
				OwnerVotesInRound: map[common.Uint168]common.Fixed64{},
				TotalVotesInRound: 1, // avoid divide-by-zero in rewardPerVote
			},
		}
		_, real, err := a.distributeWithNormalArbitratorsV3(height, reward)
		assert.NoError(t, err)
		return real
	}

	ibcr := common.Fixed64(math.Floor(float64(reward) * 0.25 / 3)) // individualBlockConfirmReward
	const emptySlots = common.Fixed64(2)

	below := realReward(gate - 1) // pre-fix behaviour: empty-slot reward NOT accounted
	above := realReward(gate)     // fixed: empty-slot reward accounted

	assert.Equal(t, emptySlots*ibcr, above-below,
		"F-212: at/above the gate realDPOSReward must account the destroyed empty-slot rewards "+
			"(so change = reward - realDPOSReward no longer re-mints them). Pre-fix above==below (double-count).")
	// change is over-stated below the gate by exactly the destroyed total that gets re-minted.
	assert.Equal(t, emptySlots*ibcr, (reward-below)-(reward-above),
		"the CR+miner change is reduced by the destroyed empty-slot total above the gate")
}
