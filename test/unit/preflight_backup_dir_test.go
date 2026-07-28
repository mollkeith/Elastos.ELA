// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- a backup directory must not stop a correct node from starting.
//
// PredictRestoredCheckpointMaxHeight walks every directory under
// <dataDir>/checkpoints and used to decide what counted with a single exact string
// compare against its own copy of the "cp_txPool" literal. The authoritative gate it
// predicts, checkpoint.Manager.MaxHeight, iterates the REGISTERED checkpoints, so the
// two were not looking at the same set.
//
// The gap is reachable by following the documented procedure. The restart script
// tells the operator to back the checkpoints up before starting, and cp_txPool's
// snapshot follows the chain tip: on mainnet it carries 2,260,593, above the
// 2,260,450 rewind target. A copy at cp_txPool.bak is not equal to "cp_txPool", so it
// was counted, the predicted max jumped over the target, and main.go's early gate
// exited a node whose real checkpoints were all strictly pre-target.
//
// These tests are measured against the production checkpoint.Manager, not against a
// constant: the number the walk produces has to BE the number MaxHeight produces.
package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	dposstate "github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/mempool"

	"github.com/stretchr/testify/assert"
)

// The real mainnet numbers, so the test fails for the reason the operator hits.
const (
	// bakRollbackTarget is config.MainNetParams.ForcedRollbackHeight.
	bakRollbackTarget = uint32(2260450)
	// bakSettledHeight is where the consensus snapshots sit, strictly pre-target.
	bakSettledHeight = uint32(2259577)
	// bakTxPoolHeight is what cp_txPool/default.txpcp carries. It follows the tip,
	// which is why MaxHeight excludes it and why a copy of it does so much damage.
	bakTxPoolHeight = uint32(2260593)
)

// bakExtensions is DataExtension() per registered checkpoint, keyed by the
// registered key so the manager below is built from checkpoint's own table.
var bakExtensions = map[string]string{
	"cp_cr":     ".ccp",
	"cp_dpos":   ".dcp",
	"cp_txPool": ".txpcp",
}

// bakManager builds a real Manager over dataDir holding exactly the checkpoints a
// node registers, restores it, and hands back the authoritative gate's input.
func bakManager(t *testing.T, dataDir string, target uint32) *checkpoint.Manager {
	t.Helper()
	m := checkpoint.NewManager(t1Params(target))
	m.SetDataPath(filepath.Join(dataDir, "checkpoints"))
	for _, k := range checkpoint.RegisteredCheckpointKeys() {
		ext, ok := bakExtensions[k]
		assert.True(t, ok, "unknown registered checkpoint key %q: add its "+
			"DataExtension to bakExtensions", k)
		m.Register(&fakeCheckpoint{key: k, ext: ext})
	}
	// A missing default file is normal on a fresh node and Restore reports it. The
	// heights that did load are what matters here, so log rather than fail.
	if err := m.Restore(); err != nil {
		t.Logf("Restore reported: %v", err)
	}
	return m
}

// bakByKey indexes a prediction by checkpoint key.
func bakByKey(points []blockchain.RestoredCheckpoint) map[string]blockchain.RestoredCheckpoint {
	out := map[string]blockchain.RestoredCheckpoint{}
	for _, p := range points {
		out[p.Key] = p
	}
	return out
}

// TestBackupCheckpointDirectoryIsNotCountedAsACheckpoint is the fail-on-pristine
// test. With the registered-key filter reverted the prediction is 2,260,593 while
// the real MaxHeight is 2,259,577, and the node is refused on a correct store.
func TestBackupCheckpointDirectoryIsNotCountedAsACheckpoint(t *testing.T) {
	dataDir := t.TempDir()

	// The node's own checkpoints, exactly as a correctly prepared store holds them.
	writeDefaultSnapshot(t, dataDir, "cp_cr", ".ccp", bakSettledHeight)
	writeDefaultSnapshot(t, dataDir, "cp_dpos", ".dcp", bakSettledHeight)
	writeDefaultSnapshot(t, dataDir, "cp_txPool", ".txpcp", bakTxPoolHeight)

	// Step 3 of the restart procedure: take a backup before starting. Three shapes
	// of the same operator action, all carrying a height above the rollback target.
	writeDefaultSnapshot(t, dataDir, "cp_txPool.bak", ".txpcp", bakTxPoolHeight)
	writeDefaultSnapshot(t, dataDir, "cp_txPool.old", ".txpcp", bakTxPoolHeight)
	writeDefaultSnapshot(t, dataDir, "cp_dpos.20260727", ".dcp", bakTxPoolHeight)

	m := bakManager(t, dataDir, bakRollbackTarget)
	predicted, points := blockchain.PredictRestoredCheckpointMaxHeight(dataDir)

	assert.Equal(t, m.MaxHeight(), predicted,
		"the predicted height must BE the production gate's input; a directory the "+
			"manager never registers cannot change what MaxHeight sees")
	assert.Equal(t, bakSettledHeight, predicted,
		"only the registered consensus checkpoints count")
	assert.Less(t, predicted, bakRollbackTarget,
		"main.go's early gate exits on `mh >= target`, so a backup directory that "+
			"pushes the prediction over the target refuses a correct node")

	byKey := bakByKey(points)
	for _, p := range points {
		assert.True(t, checkpoint.IsRegisteredCheckpointKey(p.Key),
			"only registered checkpoints may be reported, got %q", p.Key)
	}
	for _, backup := range []string{"cp_txPool.bak", "cp_txPool.old", "cp_dpos.20260727"} {
		_, reported := byKey[backup]
		assert.False(t, reported, "%s is an operator backup, not a checkpoint: "+
			"Manager.Restore builds every path from a registered checkpoint's own "+
			"Key() and never lists this directory, so a start never opens it", backup)
	}

	// The registered tx-pool checkpoint is still reported, and still not counted.
	assert.Equal(t, bakTxPoolHeight, byKey["cp_txPool"].Height)
	assert.False(t, byKey["cp_txPool"].CountedInMaxHeight)
	assert.True(t, byKey["cp_cr"].CountedInMaxHeight)
	assert.True(t, byKey["cp_dpos"].CountedInMaxHeight)
}

// TestBackupCheckpointDirectoryDoesNotTripTheEarlyMeshGate restates main.go:330,
// the comparison that calls printErrorAndExit before arbitrator.Start().
func TestBackupCheckpointDirectoryDoesNotTripTheEarlyMeshGate(t *testing.T) {
	dataDir := t.TempDir()
	writeCheckpointWithHeight(t, dataDir, "cp_cr", bakSettledHeight, ".ccp")
	writeCheckpointWithHeight(t, dataDir, "cp_dpos", bakSettledHeight, ".dcp")
	writeCheckpointWithHeight(t, dataDir, "cp_txPool.bak", bakTxPoolHeight, ".txpcp")

	mh, detail := blockchain.PredictRestoredCheckpointMaxHeight(dataDir)

	// main.go:330 is `if mh >= cfg.ForcedRollbackHeight { printErrorAndExit(...) }`.
	assert.False(t, mh >= bakRollbackTarget,
		"a node holding only pre-target consensus snapshots plus the backup the "+
			"restart procedure told the operator to take must START, not exit")
	t.Logf("backup present: predicted %d < target %d, reported %v",
		mh, bakRollbackTarget, detail)
}

// TestBackupCheckpointDirectoryDoesNotFlipThePreflightToRefuse drives the whole
// pre-flight over a real store, so the operator-facing VERDICT is covered too, not
// just the number. Small heights, because this builds a real chain.
func TestBackupCheckpointDirectoryDoesNotFlipThePreflightToRefuse(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	p := t1Params(target)
	t1BuildChain(t, dir, p, target+3)

	writeDefaultSnapshot(t, dir, "cp_dpos", ".dcp", target-1)
	writeDefaultSnapshot(t, dir, "cp_txPool", ".txpcp", target+3)
	// The backup, carrying the tip-tracking height, above the target.
	writeDefaultSnapshot(t, dir, "cp_txPool.bak", ".txpcp", target+3)

	report := preflightOnce(t, dir, p)

	assert.Equal(t, blockchain.PreflightWillRewind, report.Outcome,
		"the store is clean and pre-target; a backup directory must not turn the "+
			"verdict into a refusal")
	assert.Equal(t, target-1, report.Store.RestoredCheckpointMaxHeight)
	assert.Empty(t, report.Blocking)
	assert.Contains(t, strings.Join(report.Notes, "\n"),
		"WILL run on this start, and passes")
}

// TestRegisteredCheckpointKeysMatchWhatANodeRegisters is the drift tripwire. The
// walk and the gate now read one table; this is what keeps that table true.
func TestRegisteredCheckpointKeysMatchWhatANodeRegisters(t *testing.T) {
	params := config.DefaultParams
	m := checkpoint.NewManager(&params)

	// The real mempool constructor, one of the three registration sites.
	mempool.NewTxPool(&params, m)

	registered := map[string]bool{}
	// Reset walks m.checkpoints and calls the filter on each; returning false means
	// nothing is reset, so this is a read-only enumeration of the live registry.
	m.Reset(func(point checkpoint.ICheckPoint) bool {
		registered[point.Key()] = true
		return false
	})

	// state.NewArbitrators and state.NewCommittee are far heavier to stand up here,
	// but each registers a checkpoint whose Key() is a package constant, so read the
	// constant off the exported type.
	registered[(&dposstate.CheckPoint{}).Key()] = true
	registered[(&crstate.Checkpoint{}).Key()] = true

	for key := range registered {
		assert.True(t, checkpoint.IsRegisteredCheckpointKey(key),
			"%q is registered by a production constructor but is missing from "+
				"checkpoint.registeredCheckpointKeys, so the pre-flight walk would "+
				"ignore its directory and under-predict MaxHeight", key)
	}
	assert.ElementsMatch(t, checkpoint.RegisteredCheckpointKeys(), bakKeysOf(registered),
		"the table must name exactly the checkpoints a node registers")

	// A backup of any of them must not be mistaken for one.
	for _, key := range checkpoint.RegisteredCheckpointKeys() {
		assert.False(t, checkpoint.IsRegisteredCheckpointKey(key+".bak"))
		assert.False(t, checkpoint.IsRegisteredCheckpointKey(key+".old"))
		assert.False(t, checkpoint.CountedInMaxHeight(key+".bak"))
	}
	assert.False(t, checkpoint.CountedInMaxHeight("cp_txPool"),
		"cp_txPool is registered but excluded from MaxHeight")
	assert.True(t, checkpoint.CountedInMaxHeight("cp_cr"))
	assert.True(t, checkpoint.CountedInMaxHeight("cp_dpos"))
}

func bakKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestNoUnlistedCheckpointRegistrationSites is the other half of the tripwire. The
// test above can only check checkpoints it knows how to build; this one fails when a
// FOURTH registration site appears anywhere in production source, which is the
// moment registeredCheckpointKeys would silently go stale.
func TestNoUnlistedCheckpointRegistrationSites(t *testing.T) {
	root := repoRoot(t)
	// The known sites, one per registered key.
	expected := map[string]bool{
		"mempool/txpool.go":         true,
		"dpos/state/arbitrators.go": true,
		"cr/state/committee.go":     true,
	}

	found := map[string]bool{}
	walkGoSources(t, root, ".", func(path string) {
		relPath, rerr := filepath.Rel(root, path)
		if rerr != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)
		// The tree carries IDE scaffolding under dot-directories (.idea holds a
		// "Go File.go" template full of $VARIABLES). Nothing under a dot-directory
		// is part of the module, so nothing there can register a checkpoint.
		if strings.HasPrefix(relPath, ".") {
			return
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Register" {
				return true
			}
			if !strings.HasSuffix(types.ExprString(sel.X), "CkpManager") {
				return true
			}
			found[relPath] = true
			return true
		})
	})

	for site := range found {
		assert.True(t, expected[site], "%s registers a checkpoint and is not one of "+
			"the three known sites: add its key to "+
			"core/checkpoint.registeredCheckpointKeys, or the pre-flight walk will "+
			"ignore that checkpoint's directory", site)
	}
	for site := range expected {
		assert.True(t, found[site], "%s no longer registers a checkpoint, so "+
			"core/checkpoint.registeredCheckpointKeys is now stale", site)
	}
}
