// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// deltaHistory returns a History plus a counter and an Append helper whose closures
// are NON-IDEMPOTENT (a +/-1 delta rather than an absolute assignment).
//
// The closure SHAPE is load-bearing. The shipped history tests use idempotent
// absolute assignments (v = hh / v = hh-1), and under those a double rollback lands
// on the same value as a single one -- which is exactly why f131_test.go passes over
// the FV-27 defect. A delta counter is the shape that can see it.
func deltaHistory() (*History, *int, func(uint32)) {
	h := NewHistory(16)
	v := 0
	appendCommit := func(height uint32) {
		h.Append(height, func() { v++ }, func() { v-- })
		h.Commit(height)
	}
	return h, &v, appendCommit
}

// TestFV27BackwardSeekThenRollbackRollsEachGroupOnce is the fail-on-pristine proof
// of FV-27.
//
// SeekTo's backward branch executes the top `seekHeight-height` groups' rollback
// closures but RETAINS the groups and leaves h.height untouched. RollbackTo then
// reverses EVERY retained group above its target -- including the ones SeekTo
// already reversed -- so those closures run TWICE.
//
// FAIL-ON-PRISTINE: without the re-commit at the top of RollbackTo the counter ends
// at 0 instead of 2, because groups 4 and 5 are rolled back a second time.
func TestFV27BackwardSeekThenRollbackRollsEachGroupOnce(t *testing.T) {
	h, v, appendCommit := deltaHistory()
	for height := uint32(1); height <= 5; height++ {
		appendCommit(height)
	}
	assert.Equal(t, 5, *v, "sanity: five committed groups")
	assert.Equal(t, uint32(5), h.Height())

	// Backward seek to 3: groups 5 and 4 are reversed but RETAINED.
	assert.NoError(t, h.SeekTo(3))
	assert.Equal(t, 3, *v, "sanity: the backward seek reversed groups 5 and 4")
	assert.Equal(t, 5, len(h.Changes()), "sanity: SeekTo retains the groups it reversed")

	// Now roll back to 2. Groups 5, 4 and 3 must each be reversed EXACTLY ONCE.
	assert.NoError(t, h.RollbackTo(2))

	assert.Equal(t, 2, *v,
		"FV-27: groups already reversed by a backward SeekTo must not be rolled back "+
			"again (pristine double-rolls 5 and 4 and lands on 0)")
	assert.Equal(t, uint32(2), h.Height())
	assert.Equal(t, 2, len(h.Changes()))
}

// TestFV27NoSeekRollbackUnchanged is the negative control: with no prior seek the
// re-commit must be a strict no-op, so the ordinary rollback path is untouched.
func TestFV27NoSeekRollbackUnchanged(t *testing.T) {
	h, v, appendCommit := deltaHistory()
	for height := uint32(1); height <= 5; height++ {
		appendCommit(height)
	}
	assert.NoError(t, h.RollbackTo(2))
	assert.Equal(t, 2, *v, "no seek: each group above the target is reversed exactly once")
	assert.Equal(t, uint32(2), h.Height())
}

// TestFV05RollbackSeekToRunsTempChangeClosures is the fail-on-pristine proof of the
// FV-05 mechanism at the History level.
//
// A height-0 Append is a temporary PREVIEW whose only reversal mechanisms are the
// next Append and an explicit rollback. RollbackSeekTo dropped the closures on the
// floor (`h.tempChanges = nil`), which made the preview PERMANENT: no later Append
// can reach it any more. In production that preview is the emergency
// InactiveArbitrators marking -- producer moved to InactiveProducers, an
// EmergencyInactiveArbiters entry, and EmergencyInactivePenalty added to the
// producer's deposit penalty.
//
// FAIL-ON-PRISTINE: `applied` stays true after RollbackSeekTo AND after the next
// Append, because the closure was discarded rather than run.
func TestFV05RollbackSeekToRunsTempChangeClosures(t *testing.T) {
	h := NewHistory(16)
	applied := false

	h.Append(5, func() {}, func() {})
	h.Commit(5)

	// The height-0 preview.
	h.Append(0, func() { applied = true }, func() { applied = false })
	h.Commit(5) // Commit executes outstanding temp changes and returns early.
	assert.True(t, applied, "sanity: the preview really applied")
	assert.Equal(t, uint32(5), h.Height(),
		"sanity: Commit with outstanding tempChanges does NOT advance the height")

	h.RollbackSeekTo(4)

	assert.False(t, applied,
		"FV-05: RollbackSeekTo must RUN the outstanding preview's rollback closure "+
			"(pristine discards it, making the emergency marking permanent)")

	// And the preview must not be resurrected by later activity.
	h.Append(6, func() {}, func() {})
	h.Commit(6)
	assert.False(t, applied, "the reversed preview must stay reversed")
}

// TestFV05RollbackToAtCurrentHeightClearsPreview is the fail-on-pristine proof of
// the second FV-05 leg: the tempChanges reset sat AFTER the `height >= h.height`
// early return, and that early return is exactly the branch the block-connect
// failure path takes -- Commit does not advance h.height while a preview is
// outstanding, so rolling back to H-1 finds h.height already at H-1.
//
// FAIL-ON-PRISTINE: `applied` stays true, because RollbackTo returns before it ever
// looks at tempChanges.
func TestFV05RollbackToAtCurrentHeightClearsPreview(t *testing.T) {
	h := NewHistory(16)
	applied := false

	h.Append(5, func() {}, func() {})
	h.Commit(5)

	h.Append(0, func() { applied = true }, func() { applied = false })
	h.Commit(5)
	assert.True(t, applied, "sanity: the preview really applied")

	// The connectBlock failure path: roll back to the height the history is already at.
	assert.NoError(t, h.RollbackTo(h.Height()))

	assert.False(t, applied,
		"FV-05: a rollback to the current tip must still reverse an outstanding preview "+
			"(pristine returns early and leaves it applied)")
}
