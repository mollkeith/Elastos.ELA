// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
)

// TestReadOnlyDriverRefusesAStoreWithNoLockFile tests the ffldb driver DIRECTLY.
//
// It exists because the mutation battery found that the driver's own LOCK-file
// refusal is unreachable through NewReadOnlyChainStore -- the running-node probe
// opens the same file first and refuses on ENOENT -- so deleting the driver's
// check changed nothing any test could see. The check is still worth having (a
// caller that opens the driver directly gets it), and this is the level it has to
// be measured at.
//
// The byte at stake is real: goleveldb's read-only open CREATES the LOCK file when
// it is missing (storage.newFileLock retries with O_CREATE), which would be the one
// write on the whole read-only path.
func TestReadOnlyDriverRefusesAStoreWithNoLockFile(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	params := t1Params(5)
	t1BuildChain(t, dir, params, 8)

	blocksDir := filepath.Join(dir, "blocks")
	lockPath := filepath.Join(blocksDir, "metadata", "LOCK")
	assert.NoError(t, os.Remove(lockPath))

	db, err := database.Open("ffldb-ro", blocksDir, wire.MainNet)
	if err == nil {
		_ = db.Close()
	}
	assert.Error(t, err, "the read-only driver must refuse a leveldb directory "+
		"with no LOCK file rather than create one")
	_, serr := os.Stat(lockPath)
	assert.Truef(t, os.IsNotExist(serr),
		"the read-only open created %s", lockPath)
}

// TestReadOnlyDriverRefusesToCreate pins that the read-only driver has no create
// path at all.
func TestReadOnlyDriverRefusesToCreate(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	target := filepath.Join(dir, "brand-new")

	db, err := database.Create("ffldb-ro", target, wire.MainNet)
	if err == nil {
		_ = db.Close()
	}
	assert.Error(t, err, "the read-only driver must not create a database")
	_, serr := os.Stat(target)
	assert.True(t, os.IsNotExist(serr), "the read-only driver created a directory")
}

// TestPreflightNamesTheInterruptedRollbackSentinel pins WHICH refusal an
// interrupted rollback at or below the target produces.
//
// Two production checks can both catch this store -- CheckForcedRollbackResidue's
// census and VerifyForcedRollbackApplied's trigger probe -- and their messages
// differ in what they tell the operator to do. Asserting only that the report
// refuses is satisfied by either, so the mutation battery could delete the census
// branch without any test noticing. This names the one the boot actually reaches.
func TestPreflightNamesTheInterruptedRollbackSentinel(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+3)
	t1EatHeaderRows(t, dir, params, hashes, target+1, target+3)

	report := preflightOnce(t, dir, params)
	assert.Equal(t, blockchain.PreflightWillRefuse, report.Outcome)
	blocking := strings.Join(report.Blocking, "\n")
	assert.Contains(t, blocking,
		blockchain.ErrForcedRollbackStoreInconsistent.Error(),
		"the census refusal is the one the boot reaches first, and it is the one "+
			"whose remedy fits this store")
	assert.Contains(t, blocking, "best-state height",
		"the refusal must quote the persisted best-chain state it disagrees with")
}

// TestPreflightReportsAnInterruptedRewindItWillResume pins the marker.
//
// A node that was interrupted mid-rewind and is still armed RESUMES on the next
// start. The operator has to be told that, because the alternative reading -- "the
// rewind is starting over" -- is what makes people reach for a manual rollback or
// a resync they do not need.
func TestPreflightReportsAnInterruptedRewindItWillResume(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	func() {
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		stop := make(chan struct{})
		close(stop)
		if err := chain.ForceRollback(stop); err == nil {
			t.Fatal("harness is wrong: the rewind was not interrupted")
		}
	}()

	report := preflightOnce(t, dir, params)
	assert.Equal(t, blockchain.PreflightWillRewind, report.Outcome)
	assert.True(t, report.Store.MarkerPresent,
		"the durable in-progress marker must be reported")
	assert.Equal(t, target, report.Store.MarkerTarget)
	assert.Contains(t, strings.Join(report.Notes, "\n"), "RESUMES it",
		"the operator must be told this start continues the interrupted rewind")
}

// TestPreflightMeasuresTheWholeChainDataDirectory pins the unit the time estimate
// is scaled in.
//
// The 66-73 s baseline was measured on "a 25 GB store", meaning the whole chain
// data directory. Scaling by the blocks/ sub-directory alone -- which on the real
// mainnet store is 14.6 GiB of the 24.5 GiB -- understates the very store the
// number came from by 40%, and it does so silently.
func TestPreflightMeasuresTheWholeChainDataDirectory(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+3)

	var blocksOnly int64
	assert.NoError(t, filepath.Walk(filepath.Join(dir, "blocks"),
		func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			blocksOnly += info.Size()
			return nil
		}))

	report := preflightOnce(t, dir, params)
	assert.Greater(t, report.Store.SizeBytes, blocksOnly,
		"the reported store size must cover the whole chain data directory, not "+
			"just blocks/ -- the sibling leveldb 'chain' store is part of the 25 GB "+
			"the timing baseline was measured on")
}
