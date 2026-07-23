// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"encoding/hex"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// TestF181CleanExpiredVoteRollbackRestoresEffected proves F-181 (Class E reorg
// revert-asymmetry) in cleanExpiredDposV2Votes (state.go processTransactions).
//
// The forward closure decides whether to DELETE the producer from
// DposV2EffectedProducers using voteRights captured OUTSIDE the closure at
// History.Append call time (the pre-block total, which INCLUDES the vote being
// cleaned). The pre-fix revert closure did NOT restore the captured pre-block
// membership: it re-derived it from GetTotalDPoSV2VoteRights() >= threshold and
// only ever ADDED the producer back, never restored an entry that had been
// present pre-block with a total below the threshold. So a producer that was in
// DposV2EffectedProducers before the block (a reachable state: the forward
// delete-branch itself leaves a producer in the set after its rights drop below
// threshold) is silently DROPPED on reorg.
//
// The fix captures the pre-block membership boolean and restores it verbatim in
// the revert closure (forward/accept path unchanged -> ungated, below-gate replay
// byte-identical). len(DposV2EffectedProducers) feeds isDposV2Active(), so this
// membership drift is consensus-relevant.
//
// Fail-on-pristine: the final assertion (producer restored to
// DposV2EffectedProducers after RollbackTo) FAILS on the pristine revert, which
// leaves the producer dropped; it PASSES with the captured-membership restore.
func TestF181CleanExpiredVoteRollbackRestoresEffected(t *testing.T) {
	const H = uint32(8000) // processing height; the vote's LockTime (7201) < H so it expires

	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   &config.Configuration{},
	}
	// Effective-votes threshold well ABOVE the producer's total vote rights so
	// the expiry forward closure takes the DELETE branch.
	s.ChainParams.DPoSV2EffectiveVotes = common.Fixed64(80000 * 1e8)

	ownerKey := []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	effectedKey := hex.EncodeToString(ownerKey)

	// A single DPoSV2 vote: 1000 ELA locked for exactly the minimum duration
	// (7200), giving weight log10(10)=1.0 -> rights = 1000 ELA, far below 80000.
	var stakeAddr common.Uint168
	vote := payload.VotesWithLockTime{
		Candidate: ownerKey,
		Votes:     common.Fixed64(1000 * 1e8),
		LockTime:  7201,
	}
	dvi := payload.DetailedVoteInfo{
		StakeProgramHash: stakeAddr,
		TransactionHash:  common.Uint256{0x11, 0x22, 0x33},
		BlockHeight:      1, // duration = 7201 - 1 = 7200 (>= min lock, weight 1.0)
		PayloadVersion:   0,
		VoteType:         0,
		Info:             []payload.VotesWithLockTime{vote},
	}
	referKey := dvi.ReferKey()

	p := &Producer{
		info:     payload.ProducerInfo{OwnerKey: ownerKey, StakeUntil: 100000}, // >= H: not cancelled this block
		state:    Active,
		identity: DPoSV2,
	}
	p.detailedDPoSV2Votes = map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
		stakeAddr: {referKey: dvi},
	}
	p.dposV2Votes = vote.Votes

	s.ActivityProducers[effectedKey] = p
	// Pre-block membership: producer IS in DposV2EffectedProducers.
	s.DposV2EffectedProducers[effectedKey] = p

	// Guard the fixture: rights are below the threshold, so the forward path deletes.
	if got := p.GetTotalDPoSV2VoteRights(); !(got < float64(s.ChainParams.DPoSV2EffectiveVotes)) {
		t.Fatalf("fixture invalid: total rights %.0f must be < threshold %d", got, s.ChainParams.DPoSV2EffectiveVotes)
	}

	// Connect the block: the expiry pass cleans the vote and (forward closure)
	// removes the producer from DposV2EffectedProducers.
	s.processTransactions(nil, H)
	s.History.Commit(H)

	if _, ok := s.DposV2EffectedProducers[effectedKey]; ok {
		t.Fatal("forward closure must remove the producer from DposV2EffectedProducers when its captured rights are below threshold")
	}
	if _, ok := p.detailedDPoSV2Votes[stakeAddr][referKey]; ok {
		t.Fatal("forward closure must delete the expired vote from detailedDPoSV2Votes")
	}

	// Reorg across the block.
	if err := s.History.RollbackTo(H - 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	// The vote map and counter are restored by both pristine and fixed code.
	if _, ok := p.detailedDPoSV2Votes[stakeAddr][referKey]; !ok {
		t.Fatal("rollback must restore the expired vote to detailedDPoSV2Votes")
	}
	assert.Equal(t, vote.Votes, p.dposV2Votes, "rollback must restore dposV2Votes")

	// Discriminating assertion: the producer must be back in DposV2EffectedProducers,
	// exactly as it was pre-block. Pristine leaves it dropped.
	restored, ok := s.DposV2EffectedProducers[effectedKey]
	assert.True(t, ok,
		"F-181: rollback must restore the pre-block DposV2EffectedProducers membership (pristine drops the producer)")
	assert.Same(t, p, restored,
		"F-181: restored DposV2EffectedProducers entry must alias the live producer")
}
