// Copyright (c) 2026 The Elastos DAO
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

	// After RollbackTo(2) the state is at height 2 (v==2). A subsequent SeekTo(1) computes
	// seek := seekHeight - 1. Pre-fix seekHeight is the stale 3 -> seek=2 -> it rolls back
	// TWO changes (over-rolls to v==0). With the fix seekHeight==2 -> seek=1 -> it rolls
	// back exactly one change to view height 1 (v==1).
	assert.Equal(t, 2, v, "after RollbackTo(2) the tracked value is 2")
	h.SeekTo(1)
	assert.Equal(t, 1, v,
		"F-131: SeekTo(1) after a rollback must roll back exactly one change (v==1); a stale "+
			"seekHeight over-rolls to 0")
}
