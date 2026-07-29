// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package utils

import "fmt"

// change holds a change and it's rollback function.
type change struct {
	// execute is the function makes state change.
	execute func()

	// rollback is the function rollbacks the change.
	rollback func()
}

// HeightChanges holds all changes on a particular height.
type HeightChanges struct {
	// height is the height the changes happened.
	height uint32

	// changes are the changes on the height.
	changes []change
}

// append add a change into changes
func (hc *HeightChanges) append(c func(), r func()) {
	hc.changes = append(hc.changes, change{execute: c, rollback: r})
}

// commit execute the changes on the height.
func (hc *HeightChanges) commit() {
	for _, change := range hc.changes {
		change.execute()
	}
}

// rollback cancel the changes on the height.
func (hc *HeightChanges) rollback() {
	for _, change := range hc.changes {
		change.rollback()
	}
}

// History is a helper to log all producers and votes changes for state, so we
// can handle block rollback by tracing the change history, no need to loop
// though all transactions since the beginning of DPOS consensus.
type History struct {
	// capacity is the max block changes stored by history.
	capacity int

	// height is the best height the history knows.
	height uint32

	// changes holds the changes by the height where the changes happens.
	changes []HeightChanges

	// cachedChanges holds the changes that not committed yet.
	cachedChanges *HeightChanges

	// tempChanges stores the temporary changes caused by illegal block evidence
	// .  The changes will be rollback when next block comes.
	tempChanges []change

	// seekHeight stores a seek height if seekTo method was called, when a new
	// block received, state will be seek to best height first.
	seekHeight uint32

	// commits counts every height-change group ever committed. It is monotonic and
	// is NOT disturbed by the capacity trim (which drops the OLDEST groups), so it
	// is a stable savepoint marker where len(changes) is not.
	commits uint64
}

// Savepoint marks a committed position of the history. Undoing back to a savepoint
// reverses groups committed AT the current history height too, which RollbackTo --
// strictly-greater-than by design -- can never do.
type Savepoint struct {
	commits    uint64
	height     uint32
	seekHeight uint32
}

// Height returns the best height the history knows.
func (h *History) Height() uint32 {
	return h.height
}

// Changes holds the changes by the height where the changes happens.
func (h *History) Changes() []HeightChanges {
	return h.changes
}

// Append add a change and it's rollback into history.
// Append does NOT execute the change: it only CACHES (execute, rollback). The execute
// (forward) closure runs solely at Commit; rollback runs at RollbackTo/SeekTo. So a value
// captured in the enclosing scope at Append-call time is the PRE-BLOCK committed state -- a
// same-block same-key change is NOT reflected. Capture-outside revert patterns must ensure
// no two same-block changes touch the same key, or capture inside the forward closure.
func (h *History) Append(height uint32, execute func(), rollback func()) {
	// if height==0 means this is a temporary change.
	if height == 0 {
		change := change{execute: execute, rollback: rollback}
		h.tempChanges = append(h.tempChanges, change)
		return
	}

	// rollback and reset tempChanges when next block comes.
	if len(h.tempChanges) > 0 {
		for _, change := range h.tempChanges {
			change.rollback()
		}
		h.tempChanges = nil
	}

	// if cached changes not created, create a new cache instance.
	if h.cachedChanges == nil {
		if h.height != 0 && height < h.height {
			errMsg := fmt.Errorf("state history failed, expect larger "+
				"than %d got %d", h.height-1, height)
			panic(errMsg)
		}
		h.cachedChanges = &HeightChanges{height: height}
	}

	// changes on one height must be committed or cleared together.
	if height != h.cachedChanges.height {
		panic("previous changes not committed or cleared, wrong usage")
	}

	// append change into cache.
	h.cachedChanges.append(execute, rollback)
}

// Commit saves the pending changes into state.
func (h *History) Commit(height uint32) {
	// if there are temporary changes, just Commit them and return.
	if len(h.tempChanges) > 0 {
		for _, change := range h.tempChanges {
			change.execute()
		}
		return
	}

	// if history on a seek height, seek state to best height first.
	seek := h.height - h.seekHeight
	length := len(h.changes)
	for i := length - int(seek); i >= 0 && i < length; i++ {
		h.changes[i].commit()
	}

	// same height changes is just one
	holdHeight := make(map[uint32]bool, 0)
	var lastHeight uint32
	lastHeightChangesCount := 0
	for i, change := range h.changes {
		if i == 0 {
			lastHeight = change.height
		}
		if change.height == lastHeight {
			lastHeightChangesCount++
		}
		_, ok := holdHeight[change.height]
		if !ok {
			holdHeight[change.height] = true
		}
	}
	// if changes overflows history's capacity, remove the oldest change.
	if len(holdHeight) >= h.capacity {
		h.changes = h.changes[lastHeightChangesCount:]
	}

	// if no cached changes, create an empty height change.
	if h.cachedChanges == nil {
		h.cachedChanges = &HeightChanges{height: height}
	}

	// Commit cached changes and update history height.
	h.cachedChanges.commit()
	h.height = height
	h.seekHeight = height

	// add change into history.
	h.changes = append(h.changes, *h.cachedChanges)
	h.commits++

	// reset cached changes.
	h.cachedChanges = nil
}

// Savepoint returns the current committed position of the history.
func (h *History) Savepoint() Savepoint {
	return Savepoint{
		commits:    h.commits,
		height:     h.height,
		seekHeight: h.seekHeight,
	}
}

// UndoTo rolls back and discards every height-change group committed after sp, then
// restores the height/seek height captured by sp. Groups are reversed newest-first,
// exactly as RollbackTo does. Unlike RollbackTo it can reverse a group committed at
// the CURRENT history height, which is what an aborted block connect needs: the
// emergency ForceChange of PreProcessSpecialTx is committed at block.Height-1, i.e.
// at the tip, so no RollbackTo target can ever undo it.
func (h *History) UndoTo(sp Savepoint) {
	for h.commits > sp.commits && len(h.changes) > 0 {
		last := len(h.changes) - 1
		h.changes[last].rollback()
		h.changes = h.changes[:last]
		h.commits--
	}
	// Only reachable if more groups were committed since sp than the whole retained
	// capacity; a savepoint is always consumed within one block, so it cannot happen.
	h.commits = sp.commits
	h.height = sp.height
	h.seekHeight = sp.seekHeight
}

// SeekTo changes state to a historical height in range of history capacity.
func (h *History) SeekTo(height uint32) error {
	// check whether history is enough to seek
	holdHeight := make(map[uint32]bool, 0)
	trueChange := 0
	for _, change := range h.changes {
		_, ok := holdHeight[change.height]
		if !ok {
			trueChange++
			holdHeight[change.height] = true
		}
	}

	// check whether history is enough to seek
	limitHeight := h.height - uint32(trueChange)
	if height < limitHeight {
		return fmt.Errorf("seek to %d overflow history capacity,"+
			" at most seek to %d", height, limitHeight)
	}

	// seek changes to the historical height.
	seek := int(h.seekHeight) - int(height)
	length := len(h.changes)
	if seek >= 0 {
		for i := length - 1; i >= length-seek; i-- {
			h.changes[i].rollback()
		}
	} else {
		for i := length + seek; i >= 0 && i < length; i++ {
			h.changes[i].commit()
		}
	}
	h.seekHeight = height

	return nil
}

// RollbackSeekToSeekTo changes state to a historical height in range of history capacity.
func (h *History) RollbackSeekTo(height uint32) {
	// check whether history is allowed for rollback.
	if height >= h.height {
		return
	}

	// FV-05: RUN the outstanding temporary changes' rollback closures before
	// discarding them, exactly as RollbackTo below already does. A tempChange is a
	// height-0 PREVIEW (Append: height == 0) whose only reversal mechanism is either
	// the next Append or an explicit rollback here; dropping the closures on the
	// floor -- the shipped `h.tempChanges = nil` -- made the preview PERMANENT and
	// unreachable by any later Append. For the emergency InactiveArbitrators preview
	// that means a producer stuck in InactiveProducers, an orphaned
	// EmergencyInactiveArbiters entry and a permanently added EmergencyInactivePenalty.
	//
	// GATE: none. RollbackSeekTo is reached only from CkpManager.RestoreTo ->
	// dpos/state CheckPoint.OnRollbackSeekTo (a restore/reorg path); linear forward
	// sync never calls it, so retained history derives byte-identically.
	if len(h.tempChanges) > 0 {
		for _, change := range h.tempChanges {
			change.rollback()
		}
		h.tempChanges = nil
	}

	// rollback from last history.
	for i := len(h.changes) - 1; i >= 0; i-- {
		if h.changes[i].height > height {
			h.changes = h.changes[:i]
		}
	}
	h.height = height

	return
}

// RollbackTo restores state to height, and remove all histories after height.
// If no enough histories to rollback return error.
func (h *History) RollbackTo(height uint32) error {
	// FV-05: reverse the outstanding height-0 preview BEFORE the no-op early return
	// below, not after it. Commit(height) returns early while tempChanges is
	// non-empty WITHOUT advancing h.height, so on the block-connect failure path the
	// history height is still H-1 when the rollback target is H-1 -- i.e.
	// `height >= h.height` is exactly the branch taken, and the shipped ordering left
	// the emergency preview outstanding. Reversing first makes the preview's lifetime
	// independent of which branch is taken.
	//
	// GATE: none. Only the ORDER in which a not-yet-committed preview is reversed
	// changes; the preview is reversed by the next Append either way, and no
	// committed state is touched, so retained history derives byte-identically.
	if len(h.tempChanges) > 0 {
		for _, change := range h.tempChanges {
			change.rollback()
		}
		h.tempChanges = nil
	}

	// check whether history is allowed for rollback.
	if height >= h.height {
		return nil
	}

	// FV-27: restore the canonical forward view before rolling anything back. A
	// BACKWARD SeekTo (SeekTo:243-248) executes the top `seekHeight - height` groups'
	// rollback closures but RETAINS the groups and leaves h.height untouched, so the
	// loop below -- which reverses every retained group above the target -- executed
	// those same closures a SECOND time. Re-committing the seek-reversed groups first
	// (the identical loop Commit:148-152 already uses to leave a seek) puts every
	// retained group back in its committed state, so each is rolled back exactly once.
	//
	// Non-idempotent closures (a counter delta) corrupt under the double roll; the
	// idempotent absolute assignments used by the existing history tests hide it.
	//
	// GATE: none, and inert in the shipped binary: the only production reference to
	// History.SeekTo is dpos/state/state.go State.GetHistory, which itself has no
	// production caller. This removes the landmine before anything depends on it.
	if h.seekHeight < h.height {
		seek := int(h.height - h.seekHeight)
		length := len(h.changes)
		for i := length - seek; i >= 0 && i < length; i++ {
			h.changes[i].commit()
		}
		h.seekHeight = h.height
	}

	// rollback from last history.
	for i := len(h.changes) - 1; i >= 0; i-- {
		if h.changes[i].height > height {
			h.changes[i].rollback()
			h.changes = h.changes[:i]
		}
	}
	h.height = height
	// F-131: keep the seek/commit invariant (seekHeight == current view height), exactly
	// as Commit and SeekTo do. Without this a stale seekHeight left by a prior SeekTo
	// stays > the rollback target, so the next Commit computes seek = h.height -
	// h.seekHeight and UNDERFLOWS (uint32). Reorg/history-consistency; forward state
	// unchanged (Commit always sets seekHeight==height on the accepted path).
	h.seekHeight = height

	return nil
}

// newHistory creates a new history instance.
func NewHistory(cap int) *History {
	return &History{
		capacity: cap,
		changes:  make([]HeightChanges, 0, cap),
	}
}
