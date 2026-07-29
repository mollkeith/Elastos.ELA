// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// TestFV27GetHistoryThenRollbackToRollsEachGroupOnce drives FV-27 through the two
// PRODUCTION State methods that compose it: State.GetHistory (the only production
// reference to History.SeekTo anywhere in the tree) and State.RollbackTo (widely
// called, from CheckPoint.OnRollbackTo down).
//
// GetHistory does not merely read: SeekTo executes the top groups' ROLLBACK closures
// against the LIVE state and leaves the groups retained with h.height untouched.
// State.RollbackTo then reversed every retained group above its target, including
// those, so their closures ran TWICE -- silent corruption of live DPoS producer and
// vote state.
//
// GetHistory has no production caller today, which is what keeps FV-27 Low: this is a
// landmine, not a live bug. It is fixed now precisely because nothing yet depends on
// the broken behaviour -- the moment a "producers/votes at height H" RPC is wired to
// GetHistory it becomes acceptance-affecting.
//
// FAIL-ON-PRISTINE: the counter lands on 0 instead of 2, because the groups the seek
// already reversed are rolled back a second time.
func TestFV27GetHistoryThenRollbackToRollsEachGroupOnce(t *testing.T) {
	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   &config.Configuration{},
	}

	// Non-idempotent closures: a delta, not an absolute assignment. The absolute-
	// assignment shape used by the shipped history tests cannot see this defect.
	v := 0
	for h := uint32(1); h <= 5; h++ {
		s.History.Append(h, func() { v++ }, func() { v-- })
		s.History.Commit(h)
	}
	assert.Equal(t, 5, v, "sanity: five committed groups")

	// PRODUCTION: a historical-state query seeks the live history backwards.
	kf, err := s.GetHistory(3)
	assert.NoError(t, err)
	assert.NotNil(t, kf)
	assert.Equal(t, 3, v, "sanity: GetHistory really rewound live state via SeekTo")

	// PRODUCTION: a reorg now rolls back to 2.
	assert.NoError(t, s.RollbackTo(2))

	assert.Equal(t, 2, v,
		"FV-27: groups already reversed by GetHistory's backward seek must not be "+
			"rolled back again by State.RollbackTo (pristine double-rolls and lands on 0)")
}
