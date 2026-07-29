// Copyright (c) 2026 The Elastos DAO
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

// TestF209ExpiredVotesDropZeroUsedVoteEntry is the fail-on-pristine test for F-209.
//
// UsedDposV2Votes is credited when a stake address casts DPoSV2 votes and debited by
// cleanExpiredDposV2Votes (state.processTransactions) when those votes expire. Once
// the last vote of an address expires the total is back to zero, but pristine keeps
// the map entry forever: UsedDposV2Votes therefore accumulates one permanent entry
// per stake address that has EVER voted, held in RAM, written into every serialized
// dpos keyframe (StateKeyFrame.Serialize -> SerializeProgramHashAmountMap) and deep
// copied by copyProgramHashAmountSet on every snapshot.
//
// Dropping a zero entry is behaviour-identical: UsedDposV2Votes maps to Fixed64 and
// every reader takes the zero value of a missing key, so no acceptance decision can
// tell the two apart. The same delete-at-zero is already the established pattern for
// this map on the NFT paths in state.go.
//
// The post-commit assertion FAILS on pristine (the entry is present with value 0) and
// PASSES with the fix. The post-rollback assertions guard against over-deletion: the
// reorg revert must restore the pre-block value exactly.
func TestF209ExpiredVotesDropZeroUsedVoteEntry(t *testing.T) {
	const H = uint32(8000) // processing height; the vote's LockTime (7201) < H so it expires

	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   &config.Configuration{},
	}
	s.ChainParams.DPoSV2EffectiveVotes = common.Fixed64(80000 * 1e8)

	ownerKey := []byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	effectedKey := hex.EncodeToString(ownerKey)

	var stakeAddr common.Uint168
	vote := payload.VotesWithLockTime{
		Candidate: ownerKey,
		Votes:     common.Fixed64(1000 * 1e8),
		LockTime:  7201,
	}
	dvi := payload.DetailedVoteInfo{
		StakeProgramHash: stakeAddr,
		TransactionHash:  common.Uint256{0x11, 0x22, 0x33},
		BlockHeight:      1,
		PayloadVersion:   0,
		VoteType:         0,
		Info:             []payload.VotesWithLockTime{vote},
	}
	referKey := dvi.ReferKey()

	p := &Producer{
		info:     payload.ProducerInfo{OwnerKey: ownerKey, StakeUntil: 100000},
		state:    Active,
		identity: DPoSV2,
	}
	p.detailedDPoSV2Votes = map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
		stakeAddr: {referKey: dvi},
	}
	p.dposV2Votes = vote.Votes

	s.ActivityProducers[effectedKey] = p
	s.DposV2EffectedProducers[effectedKey] = p

	// Pre-block state: this stake address' whole used-vote budget is the single vote
	// that is about to expire, exactly as processVoting would have left it.
	s.UsedDposV2Votes[stakeAddr] = vote.Votes

	// Connect the block: the expiry pass debits the used-vote total to zero.
	s.processTransactions(nil, H)
	s.History.Commit(H)

	// Sanity: the vote really did expire on this path.
	assert.NotContains(t, p.detailedDPoSV2Votes[stakeAddr], referKey,
		"fixture invalid: the vote must have been cleaned as expired")

	// Discriminating assertion: pristine leaves UsedDposV2Votes[stakeAddr] present at 0.
	_, present := s.UsedDposV2Votes[stakeAddr]
	assert.False(t, present,
		"F-209: the used-vote entry must be removed once it reaches zero - pristine keeps a "+
			"permanent residual-zero entry for every stake address that ever voted "+
			"(value now %d, map size %d)",
		s.UsedDposV2Votes[stakeAddr], len(s.UsedDposV2Votes))
	assert.Equal(t, common.Fixed64(0), s.UsedDposV2Votes[stakeAddr],
		"a missing entry must read back as zero, so no reader can tell the difference")

	// Over-deletion guard: the reorg revert must restore the pre-block value exactly.
	assert.NoError(t, s.History.RollbackTo(H-1), "rollback must succeed")
	restored, ok := s.UsedDposV2Votes[stakeAddr]
	assert.True(t, ok, "F-209: rollback must recreate the used-vote entry")
	assert.Equal(t, vote.Votes, restored,
		"F-209: rollback must restore the exact pre-block used-vote total")
}
