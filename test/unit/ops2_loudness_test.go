// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- OPS2 item 1: a destructive rollback must never be silent.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 8e78ce3, this harness): with the node
// log level at errorLog (PrintLevel 3, an ordinary quieted production setting) a real
// forced rollback discarded every block above the target while writing ZERO bytes to
// stderr. The whole narrative of the operation -- "rewinding chain store from X to Y",
// the per-block progress, "block store rewound" -- goes through log.Warnf, and
// Logger.Outputf drops any record whose level is below the configured one. The
// operator watching the console sees a one-shot, irreversible rewind of a live chain
// happen in complete silence.
//
// The control subtest is what makes this a measurement rather than an assumption: at
// the same level a plain log.Warnf sentinel is confirmed ABSENT from the logger's own
// sink, so the test is proving level-independence rather than accidentally passing
// because the level was never quiet.
package unit

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// ops2QuietLevel is the node log level used throughout this file. It equals
// common/log's errorLog, i.e. PrintLevel 3: warnings are dropped, errors are kept.
const ops2QuietLevel = 3

// ops2ControlSentinel is emitted through plain log.Warnf inside every capture. Its
// ABSENCE from both streams is what proves the level under test really is quiet.
const ops2ControlSentinel = "OPS2-CONTROL-A-PLAIN-WARNING"

// ops2Captured holds everything the process wrote to the two console streams while a
// quieted logger was installed.
type ops2Captured struct {
	Stdout string
	Stderr string
}

// ops2CaptureConsole runs fn with os.Stdout and os.Stderr replaced by pipes and a
// FRESH logger installed at the given level, and returns what each stream received.
//
// The logger is created INSIDE the swap on purpose: common/log.NewLogger captures
// os.Stdout once, when the logger is built, so a logger created before the swap would
// keep writing to the real console and the control assertion below would be vacuous.
//
// Both pipes are drained by goroutines. A pipe holds ~64KB; output that outgrew that
// with nobody reading would block the node under test instead of failing the test.
func ops2CaptureConsole(t *testing.T, level uint8, fn func()) ops2Captured {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	realOut, realErr := os.Stdout, os.Stderr
	var outBuf, errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(&outBuf, outR) }()
	go func() { defer wg.Done(); io.Copy(&errBuf, errR) }()

	os.Stdout, os.Stderr = outW, errW
	log.NewDefault(t.TempDir(), level, 0, 0)

	func() {
		defer func() {
			os.Stdout, os.Stderr = realOut, realErr
			outW.Close()
			errW.Close()
			// Restore the loud default every other test in this package expects.
			log.NewDefault(test.NodeLogPath, 0, 0, 0)
		}()
		log.Warnf(ops2ControlSentinel)
		fn()
	}()

	wg.Wait()
	return ops2Captured{Stdout: outBuf.String(), Stderr: errBuf.String()}
}

// ops2RequireQuiet asserts the control sentinel really was dropped, which is what
// establishes that the level under test is quiet. Without it a passing loudness
// assertion could simply mean nothing was ever filtered.
func ops2RequireQuiet(t *testing.T, got ops2Captured) {
	t.Helper()
	if strings.Contains(got.Stdout, ops2ControlSentinel) ||
		strings.Contains(got.Stderr, ops2ControlSentinel) {
		t.Fatalf("control: a plain log.Warnf reached the console at this level, so the "+
			"harness is not measuring a quieted node at all\nstdout: %q\nstderr: %q",
			got.Stdout, got.Stderr)
	}
}

// TestOps2ForcedRollbackAnnouncesItselfOnAQuietedNode is the item-1 proof for the
// rewind itself.
//
// FAILS ON PRISTINE: every FORCED ROLLBACK line is a log.Warnf, which the errorLog
// level discards, so stderr is empty and the whole destructive operation is invisible.
func TestOps2ForcedRollbackAnnouncesItselfOnAQuietedNode(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	t1BuildChain(t, dir, params, target+10)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	armed, err := chain.ForcedRollbackArmed()
	if err != nil {
		t.Fatalf("ForcedRollbackArmed: %v", err)
	}
	if !armed {
		t.Fatal("harness is wrong: the rollback is not armed")
	}

	got := ops2CaptureConsole(t, ops2QuietLevel, func() {
		if rerr := chain.ForceRollback(nil); rerr != nil {
			t.Errorf("ForceRollback: %v", rerr)
		}
	})

	ops2RequireQuiet(t, got)

	// The operation actually happened: 10 blocks are gone.
	if h := chain.GetHeight(); h != target {
		t.Fatalf("rewind did not run: tip %d, want %d", h, target)
	}

	for _, want := range []string{
		"rewinding chain store from height",
		"blocks discarded",
		"block store rewound to",
		"persisted store verified clean",
	} {
		if !strings.Contains(got.Stderr, want) {
			t.Errorf("a 10-block destructive rewind ran without announcing %q on stderr.\n"+
				"stderr was:\n%s", want, got.Stderr)
		}
	}
}

// TestOps2BootTimePurgeAnnouncesItselfOnAQuietedNode covers the other destructive
// path in scope: the boot-time residue purge, which deletes blocks from the raw store
// on a node that is no longer armed. It reached the operator only through log.Warnf
// as well.
//
// FAILS ON PRISTINE for the same reason as the rewind test.
func TestOps2BootTimePurgeAnnouncesItselfOnAQuietedNode(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	hashes := t1BuildChain(t, dir, params, target+3)
	residueHash := hashes[target+2]

	// Read the raw bytes while the block still exists, rewind for real, then put those
	// exact bytes back with no index of any kind -- the retention-residue shape a store
	// rewound by a binary that did not purge the raw block store carries.
	var raw []byte
	func() {
		chain, store := t1Open(t, dir, params, nil, nil)
		defer t1Close(store)
		raw = b1b5ReadRaw(t, chain, residueHash)
		if err := chain.ForceRollback(nil); err != nil {
			t.Fatalf("ForceRollback: %v", err)
		}
	}()

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	b1b5RestoreRaw(t, chain, residueHash, raw)

	got := ops2CaptureConsole(t, ops2QuietLevel, func() {
		if cerr := chain.CheckForcedRollbackResidue(); cerr != nil {
			t.Errorf("CheckForcedRollbackResidue: %v", cerr)
		}
	})

	ops2RequireQuiet(t, got)
	if !strings.Contains(got.Stderr, "purged") {
		t.Errorf("a boot-time purge deleted blocks from the store and said nothing an "+
			"operator could see.\nstderr was:\n%s", got.Stderr)
	}
}
