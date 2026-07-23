// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF093HistoryUndoToSameHeight pins the primitive F-093 needs: RollbackTo is
// strictly-greater-than, so a group committed AT the current height (which is how
// PreProcessSpecialTx binds its emergency ForceChange, at block.Height-1) can never
// be reversed by it. UndoTo can.
func TestF093HistoryUndoToSameHeight(t *testing.T) {
	h := NewHistory(10)
	value := 0

	h.Append(10, func() { value = 1 }, func() { value = 0 })
	h.Commit(10)
	assert.Equal(t, 1, value)

	sp := h.Savepoint()

	// A second group committed at the very same height -- the ForceChange shape.
	h.Append(10, func() { value = 2 }, func() { value = 1 })
	h.Commit(10)
	assert.Equal(t, 2, value)

	// The rollback the connect-failure path performs cannot see it.
	assert.NoError(t, h.RollbackTo(10))
	assert.Equal(t, 2, value, "RollbackTo(10) is strictly-greater-than by design")

	// UndoTo reverses it and restores the history position.
	h.UndoTo(sp)
	assert.Equal(t, 1, value)
	assert.Equal(t, uint32(10), h.Height())

	// The history is consistent afterwards: a normal block still commits/rolls back.
	h.Append(11, func() { value = 3 }, func() { value = 1 })
	h.Commit(11)
	assert.Equal(t, 3, value)
	assert.NoError(t, h.RollbackTo(10))
	assert.Equal(t, 1, value)
	assert.Equal(t, uint32(10), h.Height())
}

// TestF093HistoryUndoToIsIdempotent: undoing to a savepoint twice must not reverse
// changes that were already committed before the savepoint was taken.
func TestF093HistoryUndoToIsIdempotent(t *testing.T) {
	h := NewHistory(10)
	value := 0

	h.Append(5, func() { value = 1 }, func() { value = 0 })
	h.Commit(5)
	sp := h.Savepoint()

	h.Append(5, func() { value = 2 }, func() { value = 1 })
	h.Commit(5)

	h.UndoTo(sp)
	h.UndoTo(sp)
	h.UndoTo(sp)
	assert.Equal(t, 1, value)
	assert.Equal(t, uint32(5), h.Height())
}
