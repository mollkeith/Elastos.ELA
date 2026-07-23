// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF131RollbackToResetsSeekHeight — F-131: RollbackTo set h.height but not h.seekHeight,
// so a stale seekHeight left by a prior SeekTo stayed > the rollback target. The next
// Commit computes `seek := h.height - h.seekHeight` in uint32, which UNDERFLOWS to a huge
// value and corrupts/panics the seek loop. The fix restores the seekHeight == height
// invariant on rollback, exactly as Commit and SeekTo already do.
//
// Fail-on-pristine: without the fix, the final Commit underflows and the tracked value is
// not the committed value (or the seek loop panics).
func TestF131RollbackToResetsSeekHeight(t *testing.T) {
	h := NewHistory(100)
	v := 0
	for height := uint32(1); height <= 5; height++ {
		hh := height
		h.Append(hh, func() { v = int(hh) }, func() { v = int(hh) - 1 })
		h.Commit(hh)
	}
	assert.Equal(t, 5, v)

	// View history at 3 (seekHeight := 3), then roll back below it to 2.
	h.SeekTo(3)
	if err := h.RollbackTo(2); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Next accepted block at height 3. Pre-fix, Commit computes seek = 2 - 3 (underflow).
	assert.NotPanics(t, func() {
		h.Append(3, func() { v = 300 }, func() { v = -300 })
		h.Commit(3)
	}, "F-131: Commit after rollback must not underflow the seek computation")

	assert.Equal(t, 300, v,
		"F-131: after rollback+commit the tracked value must be the committed value, "+
			"not corrupted by a stale seekHeight underflow")
	assert.Equal(t, uint32(3), h.Height())
}
