// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"fmt"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// f168BuildState builds a minimal State that reaches the lastPosition branch of
// countArbitratorsInactivityV3 with the given per-producer workedInRound values.
// dutyIndex 0 is the last position when NormalArbitratorsCount=1 and no CRC
// arbiters (0 == 1+0-1). GetArbiters / getCurrentCRMembers are stubbed empty so
// only the workedInRound reset appends fire.
func f168BuildState(worked []bool) (*State, []*Producer) {
	s := &State{
		StateKeyFrame: &StateKeyFrame{
			PendingProducers:  map[string]*Producer{},
			ActivityProducers: map[string]*Producer{},
		},
		History:             utils.NewHistory(maxHistoryCapacity),
		ChainParams:         &config.Configuration{DPoSV2StartHeight: 0},
		GetArbiters:         func() []*ArbiterInfo { return nil },
		getCurrentCRMembers: func() []*crstate.CRMember { return nil },
	}
	s.ChainParams.DPoSConfiguration.NormalArbitratorsCount = 1
	s.ChainParams.DPoSConfiguration.CRCArbiters = []string{}
	s.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight = 0

	producers := make([]*Producer, len(worked))
	for i, w := range worked {
		p := &Producer{workedInRound: w}
		producers[i] = p
		s.PendingProducers[fmt.Sprintf("p%d", i)] = p
	}
	return s, producers
}

// f168Patterns returns >20 distinct worked-flag patterns (varying length and
// true/false mixes) so both the bug and the fix are exercised across many cases.
func f168Patterns() [][]bool {
	patterns := [][]bool{
		{false},
		{true},
		{false, false},
		{true, false},
		{false, true},
		{true, true},
		{false, false, false},
		{true, false, true},
		{false, true, false},
		{true, true, false},
		{false, false, true, false},
		{true, false, false, true},
		{false, true, true, false, false},
		{true, true, true, true, false},
		{false, false, false, false, false},
		{true, false, true, false, true, false},
		{false, true, false, true, false, true},
	}
	// Add alternating patterns of growing length to exceed 20 total.
	for n := 2; n <= 8; n++ {
		p := make([]bool, n)
		for i := range p {
			p[i] = i%2 == 0
		}
		patterns = append(patterns, p)
	}
	return patterns
}

// TestF168BugMechanism documents, durably, WHY the pristine rollback was wrong:
// resetting workedInRound to false on apply but rolling back to a hard-coded
// true loses a producer's original "did not work" state, whereas restoring the
// captured original round-trips correctly. This is a self-contained
// demonstration of the exact closure shapes (pristine vs fixed).
func TestF168BugMechanism(t *testing.T) {
	for _, worked := range f168Patterns() {
		// Pristine shape: apply=false, rollback=HARD-CODED true.
		pristine := make([]bool, len(worked))
		copy(pristine, worked)
		for i := range pristine {
			v := &pristine[i]
			apply := func() { *v = false }
			rollback := func() { *v = true } // BUG: constant, not the original
			apply()
			rollback()
		}
		// Fixed shape: apply=false, rollback=captured original.
		fixed := make([]bool, len(worked))
		copy(fixed, worked)
		for i := range fixed {
			v := &fixed[i]
			ori := *v
			apply := func() { *v = false }
			rollback := func() { *v = ori }
			apply()
			rollback()
		}
		for i, w := range worked {
			if !w {
				assert.True(t, pristine[i],
					"pristine bug: a non-working producer is wrongly restored to true")
			}
			assert.Equal(t, w, fixed[i],
				"fix: rollback must restore the ORIGINAL workedInRound (idx %d)", i)
		}
	}
}

// TestF168RollbackRestoresWorkedInRound exercises the REAL production path:
// countArbitratorsInactivityV3 appends the lastPosition reset closures, Commit
// applies them (all workedInRound -> false), and RollbackTo reverses them. The
// fix requires each producer's workedInRound to return to its ORIGINAL value.
// On pristine code this FAILS for every non-working producer (restored to true);
// with the fix it passes. Runs across >20 patterns.
func TestF168RollbackRestoresWorkedInRound(t *testing.T) {
	const height = uint32(100)
	patterns := f168Patterns()
	assert.GreaterOrEqual(t, len(patterns), 20, "need >=20 scenarios")

	for pi, worked := range patterns {
		s, producers := f168BuildState(worked)

		// Reach the lastPosition branch (dutyIndex 0). Sponsor is arbitrary.
		s.countArbitratorsInactivityV3(height, []byte{byte(pi + 1)}, 0)

		// Commit applies the reset: every producer's workedInRound -> false.
		s.History.Commit(height)
		for i, p := range producers {
			assert.False(t, p.workedInRound,
				"after commit workedInRound must be false (pattern %d idx %d)", pi, i)
		}

		// Rollback must restore each producer's ORIGINAL value.
		assert.NoError(t, s.History.RollbackTo(height-1))
		for i, p := range producers {
			assert.Equal(t, worked[i], p.workedInRound,
				"FIX: rollback must restore original workedInRound (pattern %d idx %d)", pi, i)
		}
	}
}

// TestF168NoReorgUnaffected is the related-tx/regression check: without a
// rollback, a normal apply leaves workedInRound reset to false for all producers
// (unchanged behavior). The fix only alters the rollback path.
func TestF168NoReorgUnaffected(t *testing.T) {
	const height = uint32(200)
	s, producers := f168BuildState([]bool{true, false, true, false})
	s.countArbitratorsInactivityV3(height, []byte{0x09}, 0)
	s.History.Commit(height)
	for i, p := range producers {
		assert.False(t, p.workedInRound,
			"normal round reset must set workedInRound false (idx %d)", i)
	}
}
