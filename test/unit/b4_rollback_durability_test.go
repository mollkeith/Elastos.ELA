// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- TRACK B4 fail-on-pristine proof that the forced rollback's
// DURABILITY claims are true, and that an operator cannot disarm his way back onto
// the pre-rollback chain.
//
// THE DEFECT, in two halves.
//
// ffldb answers every read through an in-memory dbCache and pushes it to leveldb
// only past 20 MiB or 300 s -- both hardcoded at database/ffldb/db.go openDB, with
// no flag, no config field and no environment variable behind them. So:
//
//   - B4-1: ForceRollback logged "persisted store verified clean above target N",
//     and ScanForcedRollbackStore called itself "a read-only census of what the
//     PERSISTED block store still holds", while both actually read RAM. Measured on
//     two nodes differing only in the flush interval, the production one reported a
//     clean store at the instant 320 above-target entries were still only cached.
//   - B4-2: an unclean exit inside that window discards the entire rewind. An
//     operator who acted on the completion line and unset --forcedrollbacktrigger
//     then restarted a node that took every early return on the forced-rollback boot
//     path and came up on the PRE-ROLLBACK chain, serving the exploit-analogue block,
//     with nothing anywhere recording it.
//
// HOW THE PROOF WORKS, without a kill signal and without a hook in production code.
// Every test builds a real chain, closes both stores so the pre-rollback state is
// unambiguously on disk, reopens the way main.go boots, drives the real production
// entry points, and then COPIES THE DATA DIRECTORY BYTE FOR BYTE while the node is
// still live. That copy is exactly what a machine that lost the process at that
// instant would hold: writes that only ever reached the dbCache live in the Go heap
// and were never written to any file, so they are absent from it by construction.
// Reopening the copy and censusing it is the census a restart would get.
//
// PRISTINE BEHAVIOUR of each assertion is stated at the assertion.
package unit

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/database"
)

// b4Snapshot copies a live data directory to a fresh one and returns its path.
//
// This is the whole instrument, and it is honest for one reason: the ffldb write
// cache is a pair of in-memory treaps, not a file. Anything still in it has not been
// written anywhere, so a file-level copy cannot contain it -- no fsync semantics, no
// page-cache subtleties, and nothing to arrange in production code. What the copy
// holds is what a restarted process would find.
func b4Snapshot(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "snapshot")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.Create(target)
		if cerr != nil {
			return cerr
		}
		defer out.Close()
		_, cperr := io.Copy(out, in)
		return cperr
	})
	if err != nil {
		t.Fatalf("snapshot the live data directory: %v", err)
	}
	return dst
}

// b4Disarmed returns params for the same network with the forced rollback UNSET --
// the configuration of an operator who has read the completion line and cleaned up.
func b4Disarmed(target uint32) *config.Configuration {
	params := t1Params(target)
	params.ForcedRollbackTrigger = ""
	params.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
	return params
}

// TestB4CompletionLineDescribesDiskNotTheWriteCache is the B4-1 proof.
//
// It runs the real rewind and then asks the DISK -- through the same production
// census the rewind itself uses to justify its "persisted store verified clean above
// target" line -- whether the rewind is there.
//
// FAILS ON PRISTINE: with the flush absent, not one byte of a 3-block rewind reaches
// leveldb, so the copy still holds the discarded blocks on the main chain, still
// header-rowed, still fetchable by hash, and still carries the in-progress marker
// the completion line implies was retired.
func TestB4CompletionLineDescribesDiskNotTheWriteCache(t *testing.T) {
	const target = uint32(3)
	const tip = target + 4
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, tip)

	// CONTROL. The copy instrument must be able to SEE the pre-rollback chain, or a
	// clean census after the rewind would prove nothing at all.
	{
		before := b4Snapshot(t, dir)
		chain, store := t1Open(t, before, params, nil, nil)
		scan, err := blockchain.ScanForcedRollbackStore(chain.GetDB().GetFFLDB(), target)
		if err != nil {
			t.Fatalf("control census: %v", err)
		}
		t1Close(store)
		if scan.Clean() {
			t.Fatalf("harness broken: the pre-rollback copy must show the discarded "+
				"blocks on disk, got %s", scan.Summary())
		}
		if len(scan.MainChainAbove) != int(tip-target) {
			t.Fatalf("harness broken: the pre-rollback copy must carry %d main-chain "+
				"entries above the target, got %s", tip-target, scan.Summary())
		}
	}

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	if armed, err := chain.ForcedRollbackArmed(); err != nil || !armed {
		t.Fatalf("harness broken: node must be armed (armed=%v err=%v)", armed, err)
	}
	if err := chain.ForceRollback(nil); err != nil {
		t.Fatalf("ForceRollback: %v", err)
	}

	// The instant the completion line is written. Copy the store as a machine that
	// lost the process right here would leave it.
	after := b4Snapshot(t, dir)
	restarted, rstore := t1Open(t, after, params, nil, nil)
	defer t1Close(rstore)

	scan, err := blockchain.ScanForcedRollbackStore(restarted.GetDB().GetFFLDB(), target)
	if err != nil {
		t.Fatalf("census the restarted store: %v", err)
	}
	if !scan.Clean() {
		t.Fatalf("B4-1 PRISTINE BEHAVIOUR REPRODUCED: ForceRollback logged that the "+
			"PERSISTED store was verified clean above target %d, but a process that "+
			"died at that instant leaves a store still holding the rewind's own "+
			"residue: %s | main-chain above: %d, stored above: %d, header rows above: "+
			"%d, best-state height %d", target, scan.Summary(),
			len(scan.MainChainAbove), len(scan.StoredAbove), len(scan.HeaderRowsAbove),
			scan.BestStateHeight)
	}

	// The strongest form of the same claim: the production post-condition that emits
	// the "persisted store verified clean" line must hold on the RESTARTED store.
	if err := restarted.VerifyForcedRollbackComplete(); err != nil {
		t.Fatalf("B4-1: the assertion behind the completion log line does not hold on "+
			"the store a restart would find: %v", err)
	}

	// And the completion line also implies the in-progress marker was retired. If the
	// clear is still in the write cache, a crash resurrects a marker for a rewind
	// that is finished, which the B4-2 refusal below would then act on.
	marker, merr := restarted.ReadForcedRollbackMarker()
	if merr != nil {
		t.Fatalf("read marker on the restarted store: %v", merr)
	}
	if marker != nil {
		t.Fatalf("B4-1: the rewind announced completion while the clearing of its "+
			"in-progress marker (target %d, start %d) was still only in the write cache",
			marker.Target, marker.Start)
	}

	// Over-deletion guard: the retained chain must survive the flush path untouched.
	if got := restarted.GetHeight(); got != target {
		t.Fatalf("the restarted store must load exactly the retained chain, tip %d want %d",
			got, target)
	}
}

// TestB4DisarmAfterCrashInTheFlushWindowIsRefused is the B4-2 proof.
//
// It reproduces the trap in the order the operator meets it: a rewind STARTS, the
// process dies before any of it is durable (modelled exactly, by interrupting at the
// first block boundary and copying the store -- at that point the rewind has written
// nothing destructive and everything it did write is still cached), and the operator
// then restarts with --forcedrollbacktrigger unset.
//
// FAILS ON PRISTINE twice over: the in-progress marker is not on disk at all (it was
// written through the same cache), and there is no boot check that would read it if
// it were. Deleting either production call site -- the flush in
// writeForcedRollbackMarker, or CheckAbandonedForcedRollback from startNode (covered
// structurally in wiring_callsites_test.go) -- puts the trap straight back.
func TestB4DisarmAfterCrashInTheFlushWindowIsRefused(t *testing.T) {
	const target = uint32(3)
	const tip = target + 4
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, tip)

	// CONTROL, and it is load-bearing: a store on which no rewind was ever started
	// must not be refused just because the operator has no rollback configured.
	{
		chain, store := t1Open(t, dir, b4Disarmed(target), nil, nil)
		if err := chain.CheckAbandonedForcedRollback(); err != nil {
			t.Fatalf("a node that never started a rewind must boot when disarmed: %v", err)
		}
		t1Close(store)
	}

	// Start the rewind and lose the process inside the flush window. Interrupting at
	// the first block boundary is the same store state as a SIGKILL there: the marker
	// has been written, nothing destructive has run, and under pristine code neither
	// the marker nor anything else has reached disk.
	chain, store := t1Open(t, dir, params, nil, nil)
	interrupt := make(chan struct{})
	close(interrupt)
	rbErr := chain.ForceRollback(interrupt)
	if !errors.Is(rbErr, blockchain.ErrForcedRollbackInterrupted) {
		t.Fatalf("harness broken: a pre-closed interrupt must stop the rewind at the "+
			"first block boundary, got %v", rbErr)
	}
	crashed := b4Snapshot(t, dir)
	t1Close(store)

	// Each boot below opens the SAME crashed store, and ffldb/leveldb hold an
	// exclusive file lock, so exactly one may be open at a time -- which is also how
	// the operator meets them: one restart after another.

	// (1) The durable fact the refusal rests on. PRISTINE: absent -- the marker lived
	// and died in the ffldb write cache, so the crash erased the only record that a
	// rewind had ever been started.
	//
	// (2) And no false refusal on the resume path: this node is still configured for
	// the same target, so it must be allowed to boot and finish the rewind.
	func() {
		armedChain, armedStore := t1Open(t, crashed, params, nil, nil)
		defer t1Close(armedStore)

		marker, merr := armedChain.ReadForcedRollbackMarker()
		if merr != nil {
			t.Fatalf("read marker: %v", merr)
		}
		if marker == nil {
			t.Fatal("B4-2 PRISTINE BEHAVIOUR REPRODUCED: the in-progress marker is " +
				"written through the same write cache as the rewind, so a crash inside " +
				"the flush window leaves NOTHING on disk saying a forced rollback was " +
				"ever started")
		}
		if marker.Target != target {
			t.Fatalf("marker target %d, want %d", marker.Target, target)
		}
		if err := armedChain.CheckAbandonedForcedRollback(); err != nil {
			t.Fatalf("a node still armed for the same target must boot and resume, got: %v",
				err)
		}
		if armed, aerr := armedChain.ForcedRollbackArmed(); aerr != nil || !armed {
			t.Fatalf("the crashed store must still be armed (armed=%v err=%v)", armed, aerr)
		}
	}()

	// (3) THE TRAP ITSELF. Same store, operator has unset the trigger. Pristine let
	// this node come up on the pre-rollback chain, serving the exploit-analogue block.
	func() {
		disarmedChain, disarmedStore := t1Open(t, crashed, b4Disarmed(target), nil, nil)
		defer t1Close(disarmedStore)

		if got := disarmedChain.GetHeight(); got != tip {
			t.Fatalf("harness broken: the disarmed node must load the PRE-ROLLBACK chain "+
				"(tip %d), got %d", tip, got)
		}
		abandoned := disarmedChain.CheckAbandonedForcedRollback()
		if abandoned == nil {
			t.Fatalf("B4-2 PRISTINE BEHAVIOUR REPRODUCED: a node whose store records an "+
				"unfinished forced rollback to target %d started silently at height %d -- "+
				"back on the chain the recovery removes, serving the block it removes",
				target, disarmedChain.GetHeight())
		}
		if !errors.Is(abandoned, blockchain.ErrForcedRollbackAbandoned) {
			t.Fatalf("wrong sentinel: %v", abandoned)
		}
		for _, want := range []string{"refuses to start", "re-arm", "resumable"} {
			if !strings.Contains(abandoned.Error(), want) {
				t.Fatalf("the refusal must be unambiguous and actionable; %q missing from: %v",
					want, abandoned)
			}
		}
	}()

	// (4) The other disarm shape: retargeting. A marker for one target while the node
	// is configured for another must not be silently ignored either.
	func() {
		retargeted := t1Params(target + 1)
		retargeted.ForcedRollbackTrigger = params.ForcedRollbackTrigger
		reChain, reStore := t1Open(t, crashed, retargeted, nil, nil)
		defer t1Close(reStore)

		if err := reChain.CheckAbandonedForcedRollback(); !errors.Is(err,
			blockchain.ErrForcedRollbackAbandoned) {
			t.Fatalf("a marker for target %d on a node configured for target %d must be "+
				"refused, got: %v", target, target+1, err)
		}
	}()
}

// TestB4ScanCensusesDiskNotTheWriteCache pins the contract of
// ScanForcedRollbackStore itself, independently of who calls it.
//
// The function's own documentation calls it a census of the PERSISTED block store,
// four callers phrase operator-facing decisions in those terms
// (VerifyForcedRollbackComplete's "persisted store verified clean above target",
// CheckForcedRollbackResidue's purge, PreflightForcedRollback's diagnosis and the
// offline `ela-cli purgeresidue`), and one of them clears the only durable evidence
// that a rewind was under way. So the claim has to be true of the bytes on disk, not
// of the writer's view through the ffldb cache.
//
// The test states it as an equality a restart can check: whatever the live census
// reports, a copy of the data directory taken immediately afterwards must report the
// same thing.
//
// FAILS ON PRISTINE: an above-target raw-store entry committed but not yet flushed is
// counted by the live census and absent from the copy -- the census describes RAM and
// says "PERSISTED". Deleting the FlushCache call inside ScanForcedRollbackStore
// reproduces exactly that.
func TestB4ScanCensusesDiskNotTheWriteCache(t *testing.T) {
	const tip = uint32(3)
	const target = tip // nothing above the target except what this test adds
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()

	// An above-target side block written straight into the raw by-hash store, which
	// is the shape of the one real mainnet residue. The commit puts its location
	// entry in the ffldb write cache; nothing has asked for it to reach leveldb.
	orphan := &types.Block{
		Header: common2.Header{
			Version: 0, Height: tip + 1, Previous: hashes[tip],
			Timestamp: 1600000000 + tip + 1, Bits: 0x1d03ffff,
		},
		Transactions: []interfaces.Transaction{residueCoinbase(tip + 1)},
	}
	orphanHash := orphan.Hash()
	buf := new(bytes.Buffer)
	if err := (&types.DposBlock{Block: orphan}).Serialize(buf); err != nil {
		t.Fatalf("serialize orphan: %v", err)
	}
	if err := fdb.Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(orphanHash, buf.Bytes())
	}); err != nil {
		t.Fatalf("store orphan: %v", err)
	}

	// THE CENSUS, through the production entry point, on the live store.
	live, err := blockchain.ScanForcedRollbackStore(fdb, target)
	if err != nil {
		t.Fatalf("live census: %v", err)
	}
	if len(live.StoredAbove) != 1 {
		t.Fatalf("harness broken: the live census must see the orphan, got %s",
			live.Summary())
	}

	// What a restart would find, at the instant the census returned.
	persisted := b4Snapshot(t, dir)
	restarted, rstore := t1Open(t, persisted, params, nil, nil)
	defer t1Close(rstore)
	onDisk, err := blockchain.ScanForcedRollbackStore(restarted.GetDB().GetFFLDB(), target)
	if err != nil {
		t.Fatalf("census the restarted store: %v", err)
	}

	if len(onDisk.StoredAbove) != len(live.StoredAbove) ||
		len(onDisk.HeaderRowsAbove) != len(live.HeaderRowsAbove) ||
		len(onDisk.MainChainAbove) != len(live.MainChainAbove) ||
		onDisk.BestStateHeight != live.BestStateHeight {
		t.Fatalf("B4-1 PRISTINE BEHAVIOUR REPRODUCED: ScanForcedRollbackStore reports a "+
			"census of the PERSISTED store, but a process that died the moment it "+
			"returned leaves a different store.\n  reported: %s\n  on disk:  %s",
			live.Summary(), onDisk.Summary())
	}
	if onDisk.StoredAbove[0].Hash != orphanHash {
		t.Fatalf("the persisted residue is a different block: %s want %s",
			onDisk.StoredAbove[0].Hash.String(), orphanHash.String())
	}
}
