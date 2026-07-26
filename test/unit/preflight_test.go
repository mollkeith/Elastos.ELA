// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- `ela-cli preflight`.
//
// The command makes one claim: what it PREDICTS is what the node will actually do.
// This file is the measurement of that claim, and it is deliberately not phrased as
// "the report says X". Every cell here runs the pre-flight over a store, then runs
// the PRODUCTION boot sequence (ops2BootOnce) over the same store, and requires the
// two to agree. A prediction that drifts from the boot path fails here even when it
// is internally consistent.
//
// The cells are the nine of TestOps2OnceOnlyTruthTable, reused deliberately: the
// pre-flight's whole job is to tell an operator which of those cells they are in.
package unit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"

	"github.com/stretchr/testify/assert"
)

// preflightOnce runs the whole command pipeline -- read-only open, index load,
// report -- over dir, and closes everything again.
func preflightOnce(t *testing.T, dir string, params *config.Configuration) *blockchain.PreflightReport {
	t.Helper()
	// ScanForcedRollbackStore logs through the package logger, which is nil until
	// something installs one. The command installs a discarding one for exactly
	// this reason; do the same here rather than creating log files under the test.
	log.NewDiscardDefault(0)

	store, err := blockchain.NewReadOnlyChainStore(dir, params)
	if err != nil {
		t.Fatalf("NewReadOnlyChainStore: %v", err)
	}
	defer store.Close()
	chain, err := blockchain.LoadChainForPreflight(store, params)
	if err != nil {
		t.Fatalf("LoadChainForPreflight: %v", err)
	}
	report, err := blockchain.BuildPreflightReport(chain, blockchain.PreflightOptions{
		Version: "test", DataDir: dir, NodeDir: filepath.Dir(dir),
	})
	if err != nil {
		t.Fatalf("BuildPreflightReport: %v", err)
	}
	return report
}

// TestPreflightPredictsEveryTruthTableCell is the whole point of the command.
func TestPreflightPredictsEveryTruthTableCell(t *testing.T) {
	const target = uint32(5)

	type row struct {
		name        string
		setup       func(t *testing.T) (string, *config.Configuration)
		wantOutcome blockchain.PreflightOutcome
		wantCell    string
		// wantHeadline is the statement this cell must make to the operator.
		wantHeadline string
		// wantTrigger is where the store must say the targeted block still is.
		// Reported from the persisted indexes, so a report that stopped reading
		// them fails here rather than passing on a plausible-looking headline.
		wantTriggerPresent, wantTriggerOnMainChain bool
		// wantMainChainAbove, when >= 0, is the census the boot's own scan must
		// have produced and the report must have carried over.
		wantMainChainAbove int
	}

	rows := []row{
		{
			name: "A/holds-the-removed-chain/armed-config",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				return dir, p
			},
			wantOutcome:        blockchain.PreflightWillRewind,
			wantCell:           "A-or-E/holds-the-chain-the-recovery-removes",
			wantHeadline:       "WILL REWIND on start",
			wantTriggerPresent: true, wantTriggerOnMainChain: true,
			wantMainChainAbove: 3,
		},
		{
			name: "B/already-rewound/sitting-at-target",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				return dir, p
			},
			wantOutcome:        blockchain.PreflightNothingToDo,
			wantCell:           "B-or-D/at-the-target",
			wantHeadline:       "Nothing to roll back",
			wantMainChainAbove: 0,
		},
		{
			name: "C/already-rewound/moved-forward-on-the-recovered-chain",
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
			wantOutcome:  blockchain.PreflightNothingToDo,
			wantCell:     "C/already-rewound/moved-forward-on-the-recovered-chain",
			wantHeadline: "ALREADY APPLIED",
		},
		{
			name: "D/fresh-node-below-the-target",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				ref := t.TempDir()
				refParams := t1Params(target)
				t1BuildChain(t, ref, refParams, target+3)
				t1BuildChain(t, dir, p, target-2)
				p.ForcedRollbackTrigger = refParams.ForcedRollbackTrigger
				return dir, p
			},
			wantOutcome:  blockchain.PreflightNothingToDo,
			wantCell:     "D/below-the-target",
			wantHeadline: "below the rollback target",
		},
		{
			name: "E/old-backup-restored-after-the-restart",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				ops2BootOnce(t, dir, p)
				t1BuildChain(t, dir, p, target+3)
				return dir, p
			},
			wantOutcome:        blockchain.PreflightWillRewind,
			wantCell:           "A-or-E/holds-the-chain-the-recovery-removes",
			wantHeadline:       "WILL REWIND on start",
			wantTriggerPresent: true, wantTriggerOnMainChain: true,
			wantMainChainAbove: 3,
		},
		{
			name: "F/holds-the-removed-chain/rollback-not-configured",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				p.ForcedRollbackTrigger = ""
				p.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
				return dir, p
			},
			wantOutcome:  blockchain.PreflightNothingToDo,
			wantCell:     "F/no-forced-rollback-configured",
			wantHeadline: "No forced rollback is configured for network",
		},
		{
			name: "G/holds-the-removed-chain/beyond-the-rewind-window",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+b1b5CapacityDepth)
				return dir, p
			},
			wantOutcome:        blockchain.PreflightWillRefuse,
			wantCell:           "G",
			wantHeadline:       "beyond the",
			wantTriggerPresent: true, wantTriggerOnMainChain: true,
		},
		{
			name: "H/healthy-store/trigger-names-the-wrong-block",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				hashes := t1BuildChain(t, dir, p, target+3)
				p.ForcedRollbackTrigger = hashes[target+3].ReversedString()
				return dir, p
			},
			wantOutcome:        blockchain.PreflightWillRefuse,
			wantCell:           "H",
			wantHeadline:       "One of the two configured values is wrong",
			wantTriggerPresent: true, wantTriggerOnMainChain: true,
			wantMainChainAbove: -1,
		},
		{
			name: "I/interrupted-rewind/operator-then-disarmed",
			setup: func(t *testing.T) (string, *config.Configuration) {
				dir := t.TempDir()
				p := t1Params(target)
				t1BuildChain(t, dir, p, target+3)
				func() {
					chain, store := t1Open(t, dir, p, nil, nil)
					defer t1Close(store)
					stop := make(chan struct{})
					close(stop)
					if err := chain.ForceRollback(stop); err == nil {
						t.Fatal("harness is wrong: the rewind was not interrupted")
					}
				}()
				disarmed := t1Params(target)
				disarmed.ForcedRollbackTrigger = ""
				disarmed.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
				return dir, disarmed
			},
			wantOutcome:  blockchain.PreflightWillRefuse,
			wantCell:     "I",
			wantHeadline: "REFUSE to start",
		},
	}

	// Rows that say nothing about the census opt out with -1; Go's zero value is
	// 0, which would silently mean "assert an empty census", so the opt-out is
	// applied here rather than left to each row.
	for i := range rows {
		switch rows[i].name {
		case "A/holds-the-removed-chain/armed-config",
			"B/already-rewound/sitting-at-target",
			"E/old-backup-restored-after-the-restart":
		default:
			rows[i].wantMainChainAbove = -1
		}
	}

	var table strings.Builder
	table.WriteString("\npre-flight prediction vs the production boot it predicts\n")
	fmt.Fprintf(&table, "%-52s %-22s %-8s %-8s %s\n", "cell", "predicted", "armed",
		"refused", "agreed")

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			dir, params := r.setup(t)

			// PREDICT first: the boot below is destructive.
			report := preflightOnce(t, dir, params)

			assert.Equal(t, r.wantOutcome, report.Outcome, "outcome")
			assert.Truef(t, strings.HasPrefix(report.Cell, r.wantCell),
				"cell = %q, want prefix %q", report.Cell, r.wantCell)
			assert.Containsf(t, report.Headline, r.wantHeadline,
				"the headline does not make this cell's statement; it said: %s",
				report.Headline)
			assert.NotEmpty(t, report.Version,
				"every report must name the binary it describes")
			assert.Equal(t, r.wantTriggerPresent, report.Store.TriggerPresent,
				"where the store says the targeted block is")
			assert.Equal(t, r.wantTriggerOnMainChain, report.Store.OnMainChain,
				"whether the targeted block is still main-chain indexed")
			if r.wantMainChainAbove >= 0 {
				assert.True(t, report.Store.Scanned,
					"this boot runs a full store census, so the report must carry it")
				assert.Equal(t, r.wantMainChainAbove, report.Store.MainChainAbove,
					"main-chain records above the target")
			}

			// Now actually boot, and require the prediction to have been right.
			b := ops2BootOnce(t, dir, params)
			agreed := true
			switch report.Outcome {
			case blockchain.PreflightWillRewind:
				if !b.Armed || b.Refused != nil {
					agreed = false
					t.Errorf("predicted a rewind; the boot was armed=%v refused=%v",
						b.Armed, b.Refused)
				}
			case blockchain.PreflightWillRefuse:
				if b.Refused == nil {
					agreed = false
					t.Errorf("predicted a refusal; the boot started (armed=%v tip=%d)",
						b.Armed, b.Tip)
				}
			case blockchain.PreflightNothingToDo:
				if b.Armed || b.Rewound || b.Refused != nil {
					agreed = false
					t.Errorf("predicted nothing to do; the boot was armed=%v "+
						"rewound=%v refused=%v", b.Armed, b.Rewound, b.Refused)
				}
			}
			fmt.Fprintf(&table, "%-52s %-22s %-8v %-8v %v\n", r.name,
				string(report.Outcome), b.Armed, b.Refused != nil, agreed)
		})
	}
	t.Log(table.String())
}

// storeManifest fingerprints every file under dir: path, mode, size, mtime to the
// nanosecond, and the sha256 of the contents.
func storeManifest(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		if info.IsDir() {
			lines = append(lines, fmt.Sprintf("d %s %o", rel, info.Mode().Perm()))
			return nil
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		h := sha256.New()
		if _, cerr := io.Copy(h, f); cerr != nil {
			return cerr
		}
		lines = append(lines, fmt.Sprintf("f %s %o %d %d %s", rel,
			info.Mode().Perm(), info.Size(), info.ModTime().UnixNano(),
			hex.EncodeToString(h.Sum(nil))))
		return nil
	})
	if err != nil {
		t.Fatalf("manifest %s: %v", dir, err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestPreflightWritesNothing is the guarantee the whole command rests on, taken
// byte by byte rather than asserted.
//
// It runs over EVERY truth-table shape, because the interesting write paths are
// exactly the ones a boot would take: the residue purge, the marker clear and the
// flat-file unclean-shutdown repair all live behind branches that only some stores
// reach.
func TestPreflightWritesNothing(t *testing.T) {
	const target = uint32(5)

	shapes := map[string]func(t *testing.T) (string, *config.Configuration){
		"armed": func(t *testing.T) (string, *config.Configuration) {
			dir := t.TempDir()
			p := t1Params(target)
			t1BuildChain(t, dir, p, target+3)
			return dir, p
		},
		"already-rewound": func(t *testing.T) (string, *config.Configuration) {
			dir := t.TempDir()
			p := t1Params(target)
			t1BuildChain(t, dir, p, target+3)
			ops2BootOnce(t, dir, p)
			return dir, p
		},
		"interrupted-then-disarmed": func(t *testing.T) (string, *config.Configuration) {
			dir := t.TempDir()
			p := t1Params(target)
			t1BuildChain(t, dir, p, target+3)
			func() {
				chain, store := t1Open(t, dir, p, nil, nil)
				defer t1Close(store)
				stop := make(chan struct{})
				close(stop)
				_ = chain.ForceRollback(stop)
			}()
			disarmed := t1Params(target)
			disarmed.ForcedRollbackTrigger = ""
			disarmed.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
			return dir, disarmed
		},
		"beyond-the-window": func(t *testing.T) (string, *config.Configuration) {
			dir := t.TempDir()
			p := t1Params(target)
			t1BuildChain(t, dir, p, target+b1b5CapacityDepth)
			return dir, p
		},
	}

	names := make([]string, 0, len(shapes))
	for name := range shapes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			dir, params := shapes[name](t)
			before := storeManifest(t, dir)
			_ = preflightOnce(t, dir, params)
			after := storeManifest(t, dir)
			if before != after {
				t.Fatalf("THE PRE-FLIGHT WROTE TO THE STORE.\n%s",
					manifestDiff(before, after))
			}
		})
	}
}

// manifestDiff reports the lines that changed, so a failure names the file.
func manifestDiff(before, after string) string {
	b := map[string]bool{}
	for _, l := range strings.Split(before, "\n") {
		b[l] = true
	}
	a := map[string]bool{}
	for _, l := range strings.Split(after, "\n") {
		a[l] = true
	}
	var out []string
	for l := range b {
		if !a[l] {
			out = append(out, "-"+l)
		}
	}
	for l := range a {
		if !b[l] {
			out = append(out, "+"+l)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// TestPreflightNeverCreatesChainState pins the one branch that could turn a
// pre-flight into a store initialisation: initChainState calls createChainState --
// which WRITES the genesis block -- on a database with no chain-state record.
func TestPreflightNeverCreatesChainState(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	params := t1Params(5)

	// Create an EMPTY block database by opening and closing it once, so the
	// directory exists and is a valid leveldb without any chain state.
	store, err := blockchain.NewChainStore(dir, params)
	assert.NoError(t, err)
	t1Close(store)

	before := storeManifest(t, dir)
	roStore, err := blockchain.NewReadOnlyChainStore(dir, params)
	assert.NoError(t, err)
	_, lerr := blockchain.LoadChainForPreflight(roStore, params)
	roStore.Close()

	assert.ErrorIs(t, lerr, blockchain.ErrChainStoreUninitialised,
		"an uninitialised store must be reported, never initialised")
	assert.Equal(t, before, storeManifest(t, dir),
		"the pre-flight initialised an empty store instead of reporting it")
}

// TestPreflightRefusesWhileTheNodeHoldsTheStore is the running-node case. The
// pre-flight must say so and stop, never force or break the lock.
func TestPreflightRefusesWhileTheNodeHoldsTheStore(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	params := t1Params(5)
	t1BuildChain(t, dir, params, 8)

	// Hold the store the way a running node does.
	held, err := blockchain.NewChainStore(dir, params)
	assert.NoError(t, err)

	locked, lerr := blockchain.ChainStoreLockedByRunningNode(dir)
	assert.NoError(t, lerr)
	assert.True(t, locked, "a held store must read as locked")

	_, oerr := blockchain.NewReadOnlyChainStore(dir, params)
	assert.ErrorIs(t, oerr, blockchain.ErrChainStoreLocked)

	// And the holder is undisturbed: it can still read and still close cleanly.
	assert.NotNil(t, held.GetFFLDB())
	t1Close(held)

	// Once released, the pre-flight opens normally.
	locked, lerr = blockchain.ChainStoreLockedByRunningNode(dir)
	assert.NoError(t, lerr)
	assert.False(t, locked)
	roStore, oerr := blockchain.NewReadOnlyChainStore(dir, params)
	assert.NoError(t, oerr)
	roStore.Close()
}

// TestReadOnlyStoreRefusesWrites pins the in-process half of the guarantee: even
// if a future caller asks the read-only database for a writable transaction, it
// cannot get one. Without this the flat block files are unprotected -- leveldb
// refuses the metadata commit, but StoreBlock has appended bytes by then.
func TestReadOnlyStoreRefusesWrites(t *testing.T) {
	log.NewDiscardDefault(0)
	dir := t.TempDir()
	params := t1Params(5)
	t1BuildChain(t, dir, params, 8)

	store, err := blockchain.NewReadOnlyChainStore(dir, params)
	assert.NoError(t, err)
	defer store.Close()

	before := storeManifest(t, dir)

	_, berr := store.GetFFLDB().Begin(true)
	assert.Error(t, berr, "a writable transaction must be refused")
	assert.Contains(t, berr.Error(), "READ-ONLY")

	uerr := store.GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(common.Uint256{1}, []byte("this must never land"))
	})
	assert.Error(t, uerr, "an Update must be refused before it can reach the "+
		"flat block files")

	assert.Equal(t, before, storeManifest(t, dir),
		"refusing a writable transaction still changed the store")
}
