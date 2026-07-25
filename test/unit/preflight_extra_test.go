// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"

	"github.com/stretchr/testify/assert"
)

// TestPreflightCountsTheScansEachBootWillRun pins the cost model.
//
// The estimate is only worth printing if the SCAN COUNT is the boot's real one:
// the armed boot pays three full store scans (pre-flight, the closing residue
// sweep, and the completion verification), a boot at or below the target pays one,
// and a boot that is settled above the target or refuses on capacity pays none. A
// number that is not tied to those branches is a number an operator would plan
// restart day around and be wrong.
func TestPreflightCountsTheScansEachBootWillRun(t *testing.T) {
	const target = uint32(5)

	cases := []struct {
		name  string
		setup func(t *testing.T) (string, *config.Configuration)
		scans int
	}{
		{
			name: "armed/three-scans",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				return dir, p
			},
			scans: 3,
		},
		{
			name: "at-the-target/one-scan",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				return dir, p
			},
			scans: 1,
		},
		{
			name: "moved-forward/no-scan",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				func() {
					chain, store := t1Open(t, dir, p, nil, nil)
					defer t1Close(store)
					for i := uint32(0); i < 3; i++ {
						ops2Mine(t, chain, 7777)
					}
				}()
				return dir, p
			},
			scans: 0,
		},
		{
			name: "beyond-the-window/no-scan",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+b1b5CapacityDepth)
				return dir, p
			},
			scans: 0,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir, params := c.setup(t)
			report := preflightOnce(t, dir, params)
			assert.Equal(t, c.scans, report.Estimate.FullStoreScans,
				"full store scans this boot will run")
			assert.Contains(t, report.Estimate.Basis, "MEASURED",
				"the estimate must say what it is derived from")
		})
	}
}

// TestPreflightSaysTheStoreCannotDistinguishAStaleRestore is the honest answer to
// the stale-tarball question, asserted rather than claimed.
//
// The two cells are the same store, so the tool must SAY so on every armed
// prediction, and must not pretend to a signal it does not have.
func TestPreflightSaysTheStoreCannotDistinguishAStaleRestore(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	report := preflightOnce(t, dir, params)
	assert.Equal(t, blockchain.PreflightWillRewind, report.Outcome)
	joined := strings.Join(report.Warnings, "\n")
	assert.Contains(t, joined, "THE STORE CANNOT TELL YOU",
		"an armed prediction must state that it cannot distinguish a node that "+
			"has not started from one restored from pre-fork data")
	assert.Contains(t, joined, "ela-data-latest.tgz",
		"the warning must name the actual thing operators do")
	assert.Contains(t, joined, report.Version,
		"the warning must name the binary whose version it is telling the "+
			"operator to confirm")
}

// TestPreflightFindsTheEvidenceOfAReplacedDataDirectory pins the ONE local signal
// that does distinguish the two, and pins its direction.
//
// The node's logs live in <node dir>/logs, a SIBLING of data/, so a tarball
// unpacked over data/ leaves them behind. A log that records a completed rewind
// under a store that holds the removed block again is evidence something put the
// block back. Its ABSENCE is not evidence of anything, and the test pins that too.
func TestPreflightFindsTheEvidenceOfAReplacedDataDirectory(t *testing.T) {
	const target = uint32(5)

	nodeDir := t.TempDir()
	dataDir := filepath.Join(nodeDir, "data")
	params := t1Params(target)
	t1BuildChain(t, dataDir, params, target+3)

	// No logs yet: the tool must NOT claim evidence.
	report := preflightOnce(t, dataDir, params)
	assert.NotContains(t, strings.Join(report.Warnings, "\n"),
		"EVIDENCE THAT THIS DATA DIRECTORY WAS REPLACED",
		"absence of logs must never be reported as evidence")

	// Now give the node the log a completed rewind writes.
	logDir := filepath.Join(nodeDir, "logs", "node")
	assert.NoError(t, os.MkdirAll(logDir, 0700))
	assert.NoError(t, os.WriteFile(filepath.Join(logDir, "2026-07-13_00.00.00.log"),
		[]byte("2026/07/13 00:00:01 [WRN] GID 1, FORCED ROLLBACK: block store "+
			"rewound to 5 in 1s; the rewind and the clearing of its in-progress "+
			"marker are both on disk\n"), 0600))

	report = preflightOnce(t, dataDir, params)
	joined := strings.Join(report.Warnings, "\n")
	assert.Contains(t, joined, "EVIDENCE THAT THIS DATA DIRECTORY WAS REPLACED",
		"a completed rewind in the logs under a store that holds the removed "+
			"block again is exactly the stale-restore signature")
	assert.Contains(t, joined, "block store rewound to 5",
		"the evidence must quote the line it found")
}

// TestPreflightReportsAnUncleanShutdownWithoutRepairingIt pins the one mutation
// that would otherwise happen inside a mere "look at the store": ffldb's
// reconcileDB TRUNCATES flat block files when the write cursor scanned off disk is
// ahead of the metadata.
func TestPreflightReportsAnUncleanShutdownWithoutRepairingIt(t *testing.T) {
	log.NewDiscardDefault(0)
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	// Simulate the unclean shutdown: block bytes on disk past the metadata cursor.
	fdb := filepath.Join(dir, "blocks", "000000000.fdb")
	f, err := os.OpenFile(fdb, os.O_WRONLY|os.O_APPEND, 0)
	assert.NoError(t, err)
	_, err = f.Write(make([]byte, 4096))
	assert.NoError(t, err)
	assert.NoError(t, f.Close())

	before := storeManifest(t, dir)
	report := preflightOnce(t, dir, params)
	after := storeManifest(t, dir)

	assert.Equal(t, before, after,
		"the pre-flight performed the unclean-shutdown repair instead of "+
			"reporting it:\n"+manifestDiff(before, after))
	assert.Contains(t, strings.Join(report.Warnings, "\n"), "UNCLEAN SHUTDOWN",
		"the operator must be told the node will truncate flat files on start")

	// And the ORDINARY open really would have done it, which is why this matters.
	store, oerr := blockchain.NewChainStore(dir, params)
	assert.NoError(t, oerr)
	t1Close(store)
	assert.NotEqual(t, before, storeManifest(t, dir),
		"harness is wrong: a read-write open was expected to repair the store")
}

// TestPreflightNeverCreatesALockFile pins the single byte the read-only path could
// otherwise write: goleveldb's read-only open CREATES the LOCK file when it is
// missing.
func TestPreflightNeverCreatesALockFile(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	params := t1Params(5)
	t1BuildChain(t, dir, params, 8)

	lockPath := filepath.Join(dir, "blocks", "metadata", "LOCK")
	assert.NoError(t, os.Remove(lockPath))

	before := storeManifest(t, dir)
	_, err := blockchain.NewReadOnlyChainStore(dir, params)
	assert.Error(t, err, "a leveldb directory with no LOCK must be refused")
	assert.Equal(t, before, storeManifest(t, dir),
		"the pre-flight created a LOCK file:\n"+manifestDiff(before, storeManifest(t, dir)))
	_, serr := os.Stat(lockPath)
	assert.True(t, os.IsNotExist(serr), "LOCK was created")
}

// TestPreflightRefusesTheStoresTheBootRefuses covers the two damaged shapes that
// are not in the nine-cell table: an interrupted rollback at or below the target,
// and above-target main-chain records the loaded index cannot reach.
func TestPreflightRefusesTheStoresTheBootRefuses(t *testing.T) {
	const target = uint32(5)

	t.Run("interrupted-rollback-at-the-target", func(t *testing.T) {
		dir := t.TempDir()
		params := t1Params(target)
		hashes := t1BuildChain(t, dir, params, target+3)
		// Every header row above the target eaten: the loaded tip falls back to the
		// target while the main-chain index still describes the discarded chain.
		t1EatHeaderRows(t, dir, params, hashes, target+1, target+3)

		report := preflightOnce(t, dir, params)
		assert.Equal(t, blockchain.PreflightWillRefuse, report.Outcome)
		assert.Contains(t, strings.Join(report.Blocking, "\n"),
			"INTERRUPTED", "the refusal must name the interrupted rollback")

		b := ops2BootOnce(t, dir, params)
		assert.Error(t, b.Refused, "the boot must actually refuse")
	})

	t.Run("unreachable-main-chain-records-above-the-target", func(t *testing.T) {
		dir := t.TempDir()
		params := t1Params(target)
		hashes := t1BuildChain(t, dir, params, target+3)
		// Eat only the TOP rows: the node still loads a tip above the target and
		// still arms, but the rewind can never visit target+2..target+3.
		t1EatHeaderRows(t, dir, params, hashes, target+2, target+3)

		report := preflightOnce(t, dir, params)
		assert.Equal(t, blockchain.PreflightWillRefuse, report.Outcome)
		assert.Contains(t, strings.Join(report.Blocking, "\n"),
			"partial-rollback residue",
			"the refusal must name the damage the rewind cannot reach")

		b := ops2BootOnce(t, dir, params)
		assert.Error(t, b.Refused, "the boot must actually refuse")
	})
}

// TestPreflightReportsTheGatesAfterThePin pins the identity section: the heights
// reported must be the RESOLVED ones, not what the operator's file asked for.
func TestPreflightReportsTheGatesAfterThePin(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	report := preflightOnce(t, dir, params)
	assert.Equal(t, params.ForcedRollbackHeight, report.Gates.ForcedRollbackHeight)
	assert.Equal(t, params.ForcedRollbackTrigger, report.Gates.ForcedRollbackTrigger)
	assert.Equal(t, params.StrictMoneyRangeHeight, report.Gates.StrictMoneyRangeHeight)
	assert.Equal(t, params.RevisedDPoSRewardHeight, report.Gates.RevisedDPoSRewardHeight)
	assert.Equal(t, uint32(target), report.Gates.ForcedRollbackHeight)
}

// TestPreflightExitCodesAreDistinct pins the command's scripted API: no two exit
// codes may mean the same thing, because node.sh and the operator script branch on
// them.
func TestPreflightExitCodesAreDistinct(t *testing.T) {
	codes := map[int]string{}
	for name, code := range map[string]int{
		"ready": 0, "usage": 1, "store-unreadable": 2,
		"node-running": 3, "will-refuse": 4, "internal": 5,
	} {
		if prev, dup := codes[code]; dup {
			t.Fatalf("exit code %d means both %q and %q", code, prev, name)
		}
		codes[code] = name
	}
	assert.Len(t, codes, 6, fmt.Sprint("expected six distinct exit codes, got ",
		len(codes)))
}
