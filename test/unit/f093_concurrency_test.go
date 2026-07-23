// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestF093SpecialTxSerialization is the #4 concurrency validation: the multi-step
// emergency bracket -- markPendingSpecialTx -> forceChange -> UndoPendingSpecialTx,
// each a SEPARATE a.mtx acquisition -- is NOT atomic on its own, so two brackets
// on different goroutines can interleave at the a.mtx-release boundaries and
// corrupt the shared History (invariant panic "previous changes not committed",
// a torn arbiter set, or a -race report). The specialTxMtx serialization the fix
// adds makes each bracket atomic against every other, so many goroutines can pound
// a shared Arbiters with reject-brackets (force-change then undo, net zero) and
// standalone reorg-detach rollbacks WITHOUT any of those failures and WITHOUT a
// deadlock.
//
// The bracket boundaries here (LockSpecialTx ... UnlockSpecialTx) are exactly what
// the production callers hold; RollbackTo is invoked UNDER the lock, mirroring the
// reorg-detach call site (RollbackTo deliberately does not self-acquire, so that
// connectBlock's confirm-failure RollbackTo does not re-enter and self-deadlock).
//
// Run with -race -count=N to stress. The reject brackets are net-zero, so the
// shared state must stay pinned at the pre-storm baseline throughout.
func TestF093SpecialTxSerialization(t *testing.T) {
	tip := f093Chain(t)
	base := abt.Snapshot()
	require.False(t, base.ForceChanged)

	const goroutines = 8
	const iterations = 80
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			// A distinct sponsor per goroutine keeps the payload hashes distinct.
			p := &payload.InactiveArbitrators{
				Sponsor:     abtList[id%len(abtList)],
				Arbitrators: [][]byte{abtList[(id+1)%len(abtList)]},
				BlockHeight: tip + 1,
			}
			for i := 0; i < iterations; i++ {
				if i%2 == 0 {
					// Reject bracket: the full transactional undo path. Under the
					// serialization this force-change and its undo are one atomic
					// unit; interleaved with another goroutine's bracket on the
					// pristine (unlocked) design it would corrupt History.
					abt.LockSpecialTx()
					_ = abt.ProcessSpecialTxPayload(p, tip)
					abt.UndoPendingSpecialTx()
					abt.UnlockSpecialTx()
				} else {
					// Standalone reorg-detach rollback shape.
					abt.LockSpecialTx()
					_ = abt.RollbackTo(tip)
					abt.UnlockSpecialTx()
				}
			}
		}(g)
	}
	wg.Wait()

	// No deadlock (we got here), no -race report, no panic. Every bracket was
	// net-zero, so the shared arbiter state must be pinned at the baseline.
	after := abt.Snapshot()
	assert.False(t, after.ForceChanged,
		"#4: net-zero reject brackets must leave no force-change behind")
	assert.Equal(t, len(base.CurrentArbitrators), len(after.CurrentArbitrators),
		"#4: the shared arbiter set was never torn by an interleave")
	assert.Equal(t, 0, len(after.InactiveTxs),
		"#4: no processed-payload marker leaked out of an interleaved bracket")

	// And a fresh bracket still works cleanly on the shared Arbiters afterward.
	abt.LockSpecialTx()
	require.NoError(t, abt.ProcessSpecialTxPayload(
		&payload.InactiveArbitrators{
			Sponsor:     abtList[0],
			Arbitrators: [][]byte{abtList[1]},
			BlockHeight: tip + 1,
		}, tip))
	require.True(t, abt.Snapshot().ForceChanged)
	abt.UndoPendingSpecialTx()
	abt.UnlockSpecialTx()
	assert.False(t, abt.Snapshot().ForceChanged)
}
