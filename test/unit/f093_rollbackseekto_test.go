// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestF093RollbackSeekToClearsPending is the fail-on-pristine proof of residual
// #2: Arbiters.RollbackSeekTo must reverse and clear any outstanding special-tx
// savepoint FIRST, exactly as Arbiters.RollbackTo already does.
//
// Two coupled defects on the pristine tree, both fixed by the single added
// a.undoPendingSpecialTx() at the top of RollbackSeekTo:
//
//  1. The uncommitted emergency ForceChange OUTLIVES the seek. utils.History's
//     RollbackSeekTo only TRUNCATES the change records above the target (it never
//     calls their rollback closures), so on the pristine tree the live arbiter
//     rotation stays applied after seeking below the force-change height -- the
//     emergency change the network never accepted survives a seek.
//
//  2. That truncation also strands the savepoint. History.commits is decremented
//     ONLY by UndoTo, never by RollbackSeekTo, so a later UndoPendingSpecialTx
//     runs `for h.commits > sp.commits` against a change list whose force-change
//     record was already truncated: it reverses the OTHER half of the savepoint
//     (the degradation marker) without reversing the rotation, leaving the state
//     internally INCONSISTENT (forceChanged=true but the processed-payload marker
//     gone). On the fixed tree RollbackSeekTo already reversed+cleared the
//     savepoint, so that later undo is a strict no-op.
func TestF093RollbackSeekToClearsPending(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()
	require.False(t, before.ForceChanged)

	// Open a special-tx savepoint and leave it uncommitted -- exactly the state an
	// N-001 gossip caller left behind on the pristine tree.
	require.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[0], abtList[1], tip+1), tip))
	forced := abt.Snapshot()
	require.True(t, forced.ForceChanged, "sanity: the real ForceChange ran")
	require.NotEqual(t, len(before.CurrentArbitrators),
		len(forced.CurrentArbitrators), "sanity: the arbiter set rotated")

	// Seek to a height BELOW the force-change height (VoteStartHeight < tip). A
	// seek that does work targets height < tip <= force-change height, so the
	// uncommitted emergency change should be reversed, just as RollbackTo does.
	abt.RollbackSeekTo(abt.ChainParams.VoteStartHeight)
	mid := abt.Snapshot()

	// Defect #1: the pending emergency ForceChange must not outlive the seek.
	assert.False(t, mid.ForceChanged,
		"#2: RollbackSeekTo must reverse the uncommitted emergency ForceChange, "+
			"not let it outlive the seek")
	assert.Equal(t, len(before.CurrentArbitrators), len(mid.CurrentArbitrators),
		"#2: the pre-emergency arbiter set must be restored by the seek")
	assert.Equal(t, 0, len(mid.InactiveTxs),
		"#2: the processed-payload marker must be reversed with the rotation")

	// Defect #2: with the savepoint already cleared, a later undo is a no-op; on
	// the pristine tree it over-pops (reverses the marker without the rotation).
	abt.UndoPendingSpecialTx()
	end := abt.Snapshot()
	assert.True(t, reflect.DeepEqual(mid, end),
		"#2: once RollbackSeekTo cleared the pending savepoint, a later "+
			"UndoPendingSpecialTx must change nothing")
}
