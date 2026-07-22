// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// TestF093ForceChangeCommitHeight verifies the height-gated selection: below the
// recovery gate the legacy block.Height-1 binding is preserved (replay-safety),
// at/above the gate the ForceChange is recorded at block.Height so a confirm-fail
// / reorg rollback to block.Height-1 can undo it.
func TestF093ForceChangeCommitHeight(t *testing.T) {
	const gate = uint32(2260451)

	// Below gate -> legacy H-1.
	assert.Equal(t, uint32(999), forceChangeCommitHeight(1000, gate))
	assert.Equal(t, uint32(2260449), forceChangeCommitHeight(2260450, gate))

	// At/above gate -> H.
	assert.Equal(t, uint32(2260451), forceChangeCommitHeight(2260451, gate))
	assert.Equal(t, uint32(2260452), forceChangeCommitHeight(2260452, gate))
	assert.Equal(t, uint32(3000000), forceChangeCommitHeight(3000000, gate))

	// Disabled gate (unit tests / no Blockchain wired) -> legacy H-1.
	assert.Equal(t, uint32(2999999), forceChangeCommitHeight(3000000, ^uint32(0)))
}

// TestF093RollbackUndoesForceChange demonstrates, with the REAL utils.History
// the arbiters use, WHY the commit height matters. History.RollbackTo(h) only
// reverses changes strictly above h. A ForceChange committed at block.Height-1
// therefore STICKS after a confirm-fail rollback to block.Height-1 (the bug),
// while committing it at block.Height lets that same rollback undo it (the fix).
func TestF093RollbackUndoesForceChange(t *testing.T) {
	for _, blockH := range []uint32{2260451, 2260452, 3000000, 5000000} {
		// LEGACY: ForceChange at H-1; block then advances history to H. A rollback
		// to H-1 undoes only height>H-1, so the H-1 ForceChange survives.
		legacy := utils.NewHistory(maxHistoryCapacityForTest)
		legacyForced := false
		legacy.Append(blockH-1,
			func() { legacyForced = true }, func() { legacyForced = false })
		legacy.Commit(blockH - 1)
		legacy.Append(blockH, func() {}, func() {})
		legacy.Commit(blockH)
		assert.NoError(t, legacy.RollbackTo(blockH-1))
		assert.True(t, legacyForced,
			"legacy H-1 binding: ForceChange STICKS after RollbackTo(H-1) (bug), H=%d", blockH)

		// FIXED: ForceChange at H. Rollback to H-1 undoes height>H-1 -> undone.
		fixed := utils.NewHistory(maxHistoryCapacityForTest)
		fixedForced := false
		fixed.Append(blockH,
			func() { fixedForced = true }, func() { fixedForced = false })
		fixed.Commit(blockH)
		assert.NoError(t, fixed.RollbackTo(blockH-1))
		assert.False(t, fixedForced,
			"fixed H binding: ForceChange UNDONE by RollbackTo(H-1) (fix), H=%d", blockH)
	}
}

const maxHistoryCapacityForTest = 720
