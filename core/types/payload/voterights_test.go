// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// legacyVoteRights is the exact pre-hardening formula, kept here as the reference
// for the behaviour-identity proof.
func legacyVoteRights(votes common.Fixed64, castHeight, lockUntil uint32) common.Fixed64 {
	weightF := math.Log10(float64(lockUntil-castHeight) / 7200 * 10)
	return common.Fixed64(float64(votes) * weightF)
}

func mkVote(votes common.Fixed64, castHeight, lockUntil uint32) *DetailedVoteInfo {
	return &DetailedVoteInfo{
		BlockHeight: castHeight,
		Info:        []VotesWithLockTime{{Votes: votes, LockTime: lockUntil}},
	}
}

// TestVoteRightsBehaviourIdenticalForValidVotes is the load-bearing test: for every
// vote that passes validation (duration in [7200,720000], positive in-range votes),
// the guarded VoteRights must equal the legacy formula BIT-FOR-BIT. If this fails,
// the change is a consensus change, not hardening.
func TestVoteRightsBehaviourIdenticalForValidVotes(t *testing.T) {
	votesVals := []common.Fixed64{1, 100000000, 2405641496, 100000000000, 2628776200000000} // up to ~26M ELA
	for _, vv := range votesVals {
		for _, dur := range []uint32{7200, 7201, 72000, 123456, 500000, 719999, 720000} {
			cast := uint32(1000000)
			got := mkVote(vv, cast, cast+dur).VoteRights()
			want := legacyVoteRights(vv, cast, cast+dur)
			if got != want {
				t.Fatalf("VoteRights(votes=%d dur=%d)=%d, legacy=%d — NOT behaviour-identical",
					vv, dur, got, want)
			}
		}
	}
}

// TestVoteRightsGuardsRejectMalformed covers the guarded (never-legitimate) inputs.
func TestVoteRightsGuardsRejectMalformed(t *testing.T) {
	cast := uint32(1000000)
	cases := []struct {
		name             string
		v                *DetailedVoteInfo
	}{
		{"lockUntil==cast (underflow)", mkVote(100000000, cast, cast)},
		{"lockUntil<cast (uint32 underflow)", mkVote(100000000, cast, cast-1)},
		{"duration below min lock", mkVote(100000000, cast, cast+7199)},
		{"duration==0", mkVote(100000000, cast, cast)},
		{"votes zero", mkVote(0, cast, cast+100000)},
		{"votes negative", mkVote(-1, cast, cast+100000)},
		{"votes above money range", mkVote(common.MaxELAMoney+1, cast, cast+100000)},
	}
	for _, c := range cases {
		if got := c.v.VoteRights(); got != 0 {
			t.Fatalf("%s: VoteRights=%d, want 0", c.name, got)
		}
	}
}

// TestVoteRightsDurationClampIsInputSide: duration above max lock is clamped to the
// max (exact integer), giving exactly the max-lock weight, not an unbounded value.
func TestVoteRightsDurationClampIsInputSide(t *testing.T) {
	cast := uint32(1000000)
	atMax := mkVote(100000000, cast, cast+DposV2MaxVoteLockDuration).VoteRights()
	overMax := mkVote(100000000, cast, cast+DposV2MaxVoteLockDuration+50000).VoteRights()
	if atMax != overMax {
		t.Fatalf("over-max duration must clamp to max-lock weight: atMax=%d overMax=%d", atMax, overMax)
	}
}
