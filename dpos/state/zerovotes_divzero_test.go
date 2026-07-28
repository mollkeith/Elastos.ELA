// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

// Divide-by-zero in the DPoS round reward, on the THREE LIVE copies.
//
// THE EVIDENCE GAP THIS CLOSES. The shipped guard went onto
// distributeWithNormalArbitratorsV0 in dpos/state/heightversion.go, which
// distributeDPOSReward selects only below CRCommitteeStartHeight+2N. V0 therefore cannot
// run on a chain that has a CR committee: the guard landed on the one copy that is dead.
// V3, V2 and V1 in dpos/state/arbitrators.go are byte-identical siblings and all three
// still divided by float64(totalVotesInRound) with nothing testing it for zero. Their
// early returns check only len(CurrentArbitrators)==0 and the all-CRC case.
//
// WHY ONE TEST WOULD NOT DO. A single test pinned to one copy leaves the other two
// unproven, which is precisely the defect being fixed. There is one test per live copy and
// each calls its own function directly, so reverting the guard in exactly one of them fails
// exactly one test.
//
// WHAT GOES WRONG WITHOUT THE GUARD. totalVotesInRound is the snapshot sum of
// producer.Votes() over the non-CRC arbiters and candidates (snapshotVotesStates). A round
// whose elected producers all hold zero votes makes it 0 while the arbiter set is non-empty
// and not all-CRC, so the early returns do not fire. rewardPerVote becomes +Inf, every
// per-producer reward becomes Fixed64 of a NaN or a +Inf, and the Go spec leaves that
// conversion implementation-dependent. MEASURED, same source and same inputs:
//
//	amd64: floor(0*rpv)=NaN -> -9223372036854775808, floor(v*rpv)=+Inf -> -9223372036854775808
//	arm64: floor(0*rpv)=NaN ->                    0, floor(v*rpv)=+Inf ->  9223372036854775807
//
// So this is a consensus split, not just a bad number: CheckCoinbaseArbitratorsReward
// compares these values to the coinbase exactly. On amd64 it is also real spendable ELA
// going negative, and the `change < 0` backstop in distributeDPOSReward does NOT catch it,
// because a hugely negative realDPOSReward makes change = reward - realDPOSReward POSITIVE.
// Each test asserts on change too, so that miss is covered rather than assumed.
//
// FAIL-ON-PRISTINE. Restore `rewardPerVote := totalTopProducersReward /
// float64(totalVotesInRound)` in any one of the three and only that leg's test fails, with
// the negative reward printed.
//
// No new height literal: nothing here is height-gated, and the reward pot and the leg
// selection thresholds are per-test config values, not chain constants.

// zeroVoteRoundReward is the round-reward pot used by every case below. 100 ELA keeps
// totalTopProducersReward (75 ELA) and individualBlockConfirmReward (25 ELA) exact in
// float64, so the expected values are exact integers and the assertions are unambiguous.
const zeroVoteRoundReward = common.Fixed64(100 * 1e8)

// zeroVoteArbiters builds the smallest Arbiters that reaches the division: exactly one
// elected arbiter, of type Origin so it is NOT a CRC arbiter, zero candidates, and
// TotalVotesInRound == 0 with an empty OwnerVotesInRound so every producer's votes are 0.
//
// CRCArbiters is empty and NormalArbitratorsCount is 1, which does three things at once:
// len(CRCArbiters)==0 != len(CurrentArbitrators)==1 so the all-CRC early return does not
// fire; arbitersCount==1 so V3 and V2 have no empty arbiter slots and the F-212 empty-slot
// loop cannot run and cannot colour the result; and the arbiter falls to the non-CRC branch
// where individualProducerReward is computed from rewardPerVote, which is the code under
// test.
func zeroVoteArbiters(t *testing.T) *Arbiters {
	t.Helper()

	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pkBuf, err := pub.EncodePoint(true)
	assert.NoError(t, err)
	arb, err := NewOriginArbiter(pkBuf)
	assert.NoError(t, err)
	assert.NotEqual(t, CRC, arb.GetType(),
		"test vector broken: the arbiter must not be a CRC arbiter or the CRC branch is taken "+
			"and rewardPerVote is never used")

	cfg := &config.Configuration{
		DestroyELAProgramHash: &common.Uint168{0xff},
	}
	cfg.CRConfiguration.CRCProgramHash = &common.Uint168{0xfe}
	cfg.DPoSConfiguration.NormalArbitratorsCount = 1
	cfg.DPoSConfiguration.CRCArbiters = []string{}

	return &Arbiters{
		State:              &State{StateKeyFrame: &StateKeyFrame{}}, // ConsensusAlgorithm = DPOS, not POW
		ChainParams:        cfg,
		CurrentArbitrators: []ArbiterMember{arb},
		CurrentCandidates:  []ArbiterMember{},
		CurrentReward: RewardData{
			OwnerVotesInRound: map[common.Uint168]common.Fixed64{},
			TotalVotesInRound: 0, // THE CONDITION UNDER TEST
		},
	}
}

// zeroVoteExpectedReward is what a correct zero-vote round pays: no votes means no per-vote
// reward, so the single arbiter receives the block-confirm share and nothing else. Written
// the way the production code writes it (floor of the 25% share over the arbiter slots)
// rather than as a bare literal, so the test states the rule and not a magic number.
func zeroVoteExpectedReward() common.Fixed64 {
	return common.Fixed64(math.Floor(float64(zeroVoteRoundReward) * 0.25 / 1.0))
}

// assertNoDivZeroGarbage is the whole assertion set, applied identically to each live copy.
func assertNoDivZeroGarbage(t *testing.T, leg string,
	roundReward map[common.Uint168]common.Fixed64, realDPOSReward common.Fixed64) {
	t.Helper()

	const minInt64 = common.Fixed64(math.MinInt64)
	const maxInt64 = common.Fixed64(math.MaxInt64)
	reward := zeroVoteRoundReward

	if len(roundReward) == 0 {
		t.Fatalf("%s: test vector broken, the round reward map is empty so an early return "+
			"was taken and the division was never reached", leg)
	}

	for hash, v := range roundReward {
		if v == minInt64 || v == maxInt64 {
			t.Fatalf("%s: reward for %s is %d, the exact signature of Fixed64(NaN) or "+
				"Fixed64(+Inf). totalVotesInRound was 0 and the division was not guarded. "+
				"This value is architecture-dependent: amd64 gives MinInt64 where arm64 "+
				"gives 0 or MaxInt64 for the same expression, so two honest nodes would "+
				"disagree on this block.", leg, hash, int64(v))
		}
		if v < 0 {
			t.Fatalf("%s: NEGATIVE reward %d for %s. A zero totalVotesInRound divided by "+
				"zero, rewardPerVote became +Inf and Fixed64(NaN) is MinInt64 on amd64. "+
				"This is real spendable ELA in arbitersRoundReward and in the coinbase "+
				"comparison.", leg, int64(v), hash)
		}
		if v > reward {
			t.Fatalf("%s: reward %d for %s exceeds the entire round pot %d",
				leg, int64(v), hash, int64(reward))
		}
	}

	if realDPOSReward < 0 {
		t.Fatalf("%s: realDPOSReward is NEGATIVE (%d). It is summed from the per-producer "+
			"rewards, so the unguarded division has propagated into the value the caller "+
			"turns into coinbase change.", leg, int64(realDPOSReward))
	}
	if realDPOSReward > reward {
		t.Fatalf("%s: realDPOSReward %d exceeds the round pot %d",
			leg, int64(realDPOSReward), int64(reward))
	}

	// The change < 0 backstop in distributeDPOSReward is NOT what saves us here, and this
	// asserts that rather than trusting it: a hugely negative realDPOSReward makes change
	// POSITIVE and sails past the backstop straight into the coinbase.
	change := reward - realDPOSReward
	if change < 0 || change > reward {
		t.Fatalf("%s: change = reward - realDPOSReward is %d, outside [0, %d]. This is the "+
			"quantity minted to the CR and miner legs.", leg, int64(change), int64(reward))
	}

	want := zeroVoteExpectedReward()
	assert.Equal(t, want, realDPOSReward,
		"%s: a zero-vote round must pay the block-confirm share only, with no per-vote "+
			"component", leg)
}

// dispatchHeight is a height every leg below is configured to select. It is a test value,
// not a chain gate.
const dispatchHeight = uint32(1000)

// TestZeroVotesV3NoDivideByZero covers distributeWithNormalArbitratorsV3, the copy the
// dispatcher selects at every current height.
// ARCHITECTURE CAVEAT, found by adversarial review and recorded so nobody trusts a green
// run on the wrong machine. Fixed64(NaN) is 0 on arm64 but MinInt64 on amd64, so the
// UNGUARDED path already produces the guarded answer on arm64 and any assertion on these
// functions' OUTPUT passes on the broken build there. This test is diagnostic on amd64
// only, which is what `make release` pins (GOARCH=amd64) and what the fleet runs. A green
// result on an arm64 developer machine proves nothing about this defect.

func TestZeroVotesV3NoDivideByZero(t *testing.T) {
	a := zeroVoteArbiters(t)

	roundReward, realDPOSReward, err := a.distributeWithNormalArbitratorsV3(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V3", roundReward, realDPOSReward)

	// Same state through the real dispatcher, so the leg is proven reachable in production
	// and change is proven sane, not just the helper return.
	a = zeroVoteArbiters(t)
	a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight = 0 // height >= 0+2N selects V3
	roundReward, change, err := a.distributeDPOSReward(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V3 via distributeDPOSReward", roundReward, zeroVoteRoundReward-change)
}

// TestZeroVotesV2NoDivideByZero covers distributeWithNormalArbitratorsV2.
func TestZeroVotesV2NoDivideByZero(t *testing.T) {
	a := zeroVoteArbiters(t)

	roundReward, realDPOSReward, err := a.distributeWithNormalArbitratorsV2(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V2", roundReward, realDPOSReward)

	a = zeroVoteArbiters(t)
	a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight = dispatchHeight * 1000 // out of reach, not V3
	a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight = 0                     // selects V2
	roundReward, change, err := a.distributeDPOSReward(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V2 via distributeDPOSReward", roundReward, zeroVoteRoundReward-change)
}

// TestZeroVotesV1NoDivideByZero covers distributeWithNormalArbitratorsV1.
func TestZeroVotesV1NoDivideByZero(t *testing.T) {
	a := zeroVoteArbiters(t)

	roundReward, realDPOSReward, err := a.distributeWithNormalArbitratorsV1(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V1", roundReward, realDPOSReward)

	a = zeroVoteArbiters(t)
	a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight = dispatchHeight * 1000 // not V3
	a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight = dispatchHeight * 1000 // not V2
	a.ChainParams.CRConfiguration.CRCommitteeStartHeight = 0                         // selects V1
	roundReward, change, err := a.distributeDPOSReward(dispatchHeight, zeroVoteRoundReward)
	assert.NoError(t, err)
	assertNoDivZeroGarbage(t, "V1 via distributeDPOSReward", roundReward, zeroVoteRoundReward-change)
}
