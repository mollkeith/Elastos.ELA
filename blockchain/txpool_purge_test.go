// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/core/checkpoint"

	"github.com/stretchr/testify/assert"
)

// The mempool checkpoint written from ABOVE the rollback target must not survive
// the rewind.
//
// WHY THIS EXISTS. MEASURED on a real mainnet node on 2026-07-28: after a correct
// rewind from 2,260,595 to 2,260,450, cp_txPool/2260595.txpcp was STILL PRESENT.
// Nothing in ForceRollback removes it, and it is invisible to every existing gate
// because Manager.MaxHeight skips cp_txPool by design -- so both forced-rollback
// baseline checks skip it too. The file describes the transaction pool from inside
// the discarded range, restores directly into the LIVE pool via
// txPoolCheckpoint.Deserialize -> txPool.appendToTxPool, and pow.GenerateBlock
// builds the first block of the recovered chain from that pool.
//
// FAIL-ON-PRISTINE: delete the PurgeTxPoolCheckpointAboveTarget call from main.go
// (or the body of the function) and TestPurgeRemovesTxPoolAboveTarget fails,
// because the above-target file is still on disk. Proven by removing the
// production behaviour, not by assertion.

func excludedCheckpointKey(t *testing.T) string {
	t.Helper()
	for _, k := range checkpoint.RegisteredCheckpointKeys() {
		if !checkpoint.CountedInMaxHeight(k) {
			return k
		}
	}
	t.Fatal("precondition: no registered checkpoint is excluded from MaxHeight; " +
		"the purge derives its directory from that exclusion")
	return ""
}

func TestPurgeRemovesTxPoolAboveTarget(t *testing.T) {
	const target = uint32(2260450)
	root := t.TempDir()
	key := excludedCheckpointKey(t)
	dir := filepath.Join(root, key)
	assert.NoError(t, os.MkdirAll(dir, 0o755))

	// exactly the shape observed on the real node
	above := filepath.Join(dir, "2260595.txpcp")
	below := filepath.Join(dir, "26456.txpcp")
	atTgt := filepath.Join(dir, "2260450.txpcp")
	live := filepath.Join(dir, "default.txpcp")
	for _, p := range []string{above, below, atTgt, live} {
		assert.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
	}

	assert.NoError(t, PurgeTxPoolCheckpointAboveTarget(root, target))

	_, err := os.Stat(above)
	if !os.IsNotExist(err) {
		t.Fatalf("ABOVE-TARGET MEMPOOL CHECKPOINT SURVIVED the purge: %s still exists.\n"+
			"  This file describes the mempool from inside the discarded range and\n"+
			"  restores into the LIVE pool, which is where the first block of the\n"+
			"  recovered chain is assembled from.", above)
	}

	// everything at or below the target, and the live file, must be untouched
	for _, p := range []string{below, atTgt, live} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("purge removed a file it must not touch: %s (%v)", p, err)
		}
	}
}

// The purge must never touch derived-state checkpoints. Deleting one would destroy
// the pre-target snapshot the post-rewind rebuild starts from -- a far worse
// outcome than the residue it is cleaning up.
func TestPurgeNeverTouchesDerivedState(t *testing.T) {
	const target = uint32(2260450)
	root := t.TempDir()

	guarded := map[string]string{}
	for _, k := range checkpoint.RegisteredCheckpointKeys() {
		if !checkpoint.CountedInMaxHeight(k) {
			continue // that is the mempool one, legitimately purgeable
		}
		d := filepath.Join(root, k)
		assert.NoError(t, os.MkdirAll(d, 0o755))
		// deliberately ABOVE the target, to prove the purge still leaves it alone
		p := filepath.Join(d, "2260595.dat")
		assert.NoError(t, os.WriteFile(p, []byte("x"), 0o644))
		guarded[k] = p
	}
	if len(guarded) == 0 {
		t.Skip("no counted checkpoints registered")
	}

	assert.NoError(t, PurgeTxPoolCheckpointAboveTarget(root, target))

	for k, p := range guarded {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("purge DELETED a derived-state checkpoint (%s): %s. The rewind's "+
				"rebuild starts from exactly these snapshots.", k, p)
		}
	}
}

// A node that never wrote a mempool checkpoint has nothing to purge, and a missing
// directory must not be an error on the restart path.
func TestPurgeToleratesMissingDirectory(t *testing.T) {
	assert.NoError(t, PurgeTxPoolCheckpointAboveTarget(t.TempDir(), 2260450))
}
