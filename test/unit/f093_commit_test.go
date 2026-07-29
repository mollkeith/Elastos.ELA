// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF093CommittedForceChangeSurvivesRollbackTo is the over-reach guard for the
// F-093 fix. Once the carrying block has connected (connectBlock's success branch,
// the gossip entry points, and the InitCheckpoint replay all call
// CommitPendingSpecialTx), the emergency ForceChange is permanent and a later
// RollbackTo(block.Height-1) must leave it exactly where the pristine tree left it.
// Without this the fix would silently undo ACCEPTED force changes on every reorg.
func TestF093CommittedForceChangeSurvivesRollbackTo(t *testing.T) {
	tip := f093Chain(t)

	assert.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[0], abtList[1], tip+1), tip))
	forced := abt.Snapshot()
	assert.True(t, forced.ForceChanged)
	assert.Equal(t, 1, len(forced.InactiveTxs))

	// The block connected: the change is committed.
	abt.CommitPendingSpecialTx()

	assert.NoError(t, abt.RollbackTo(tip))
	after := abt.Snapshot()
	assert.True(t, after.ForceChanged,
		"a committed ForceChange must survive RollbackTo, as on the pristine tree")
	assert.Equal(t, 1, len(after.InactiveTxs))
	assert.True(t, f093ArbiterViewEqual(forced, after))
}

// TestF093UndoIsIdempotent: connectBlock's failure path can reach the undo twice
// (checkBlockWithConfirmation rolls the checkpoint manager back to block.Height-1
// and the deferred bracket then fires as well). The second undo must be a no-op.
func TestF093UndoIsIdempotent(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()

	assert.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[0], abtList[1], tip+1), tip))
	assert.NoError(t, abt.RollbackTo(tip))
	first := abt.Snapshot()

	abt.UndoPendingSpecialTx()
	abt.UndoPendingSpecialTx()

	assert.True(t, f093ArbiterViewEqual(before, abt.Snapshot()))
	assert.True(t, f093ArbiterViewEqual(first, abt.Snapshot()))
	assert.False(t, abt.Snapshot().ForceChanged)
}
