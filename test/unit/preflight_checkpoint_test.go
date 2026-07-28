// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- the pre-flight's prediction of main.go's LAST refusal.
//
// main.go:436-449 compares checkpoint.Manager.MaxHeight() against the rollback
// target AFTER InitCheckpoint and refuses if a restored snapshot is not strictly
// pre-target. That check sits past everything the truth-table cells cover, and the
// pre-flight used to be silent about it: LoadChainForPreflight passes a nil
// ckpManager, so the report could not see the gate at all. A store whose snapshot
// had drifted to or past the target was therefore told "WILL REWIND on start", and
// then -- having actually performed and persisted the rewind -- refused to start.
//
// These tests measure the prediction against the PRODUCTION Manager rather than
// against itself: the same default snapshot files are restored by a real
// checkpoint.Manager and its real MaxHeight() must equal the predicted number.
package unit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"

	"github.com/stretchr/testify/assert"
)

// fakeCheckpoint is the smallest ICheckPoint that is FAITHFUL in the one respect
// this prediction depends on: Height is the first field on the wire, exactly as
// cr/state/checkpoint.go:185 and dpos/state/checkpoint.go:240 write it.
type fakeCheckpoint struct {
	key    string
	ext    string
	height uint32
}

func (c *fakeCheckpoint) Serialize(w io.Writer) error {
	return common.WriteUint32(w, c.height)
}

func (c *fakeCheckpoint) Deserialize(r io.Reader) error {
	h, err := common.ReadUint32(r)
	if err != nil {
		return err
	}
	c.height = h
	return nil
}

func (c *fakeCheckpoint) OnBlockSaved(*types.DposBlock) {}
func (c *fakeCheckpoint) OnRollbackTo(uint32) error     { return nil }
func (c *fakeCheckpoint) OnRollbackSeekTo(uint32)       {}
func (c *fakeCheckpoint) Key() string                   { return c.key }
func (c *fakeCheckpoint) Snapshot() checkpoint.ICheckPoint {
	cp := *c
	return &cp
}
func (c *fakeCheckpoint) GetHeight() uint32             { return c.height }
func (c *fakeCheckpoint) SetHeight(h uint32)            { c.height = h }
func (c *fakeCheckpoint) SavePeriod() uint32            { return 1 }
func (c *fakeCheckpoint) SaveStartHeight() uint32       { return 0 }
func (c *fakeCheckpoint) EffectivePeriod() uint32       { return 1 }
func (c *fakeCheckpoint) DataExtension() string         { return c.ext }
func (c *fakeCheckpoint) LogError(error)                {}
func (c *fakeCheckpoint) Priority() checkpoint.Priority { return checkpoint.Medium }
func (c *fakeCheckpoint) OnInit()                       {}
func (c *fakeCheckpoint) StartHeight() uint32           { return 0 }
func (c *fakeCheckpoint) OnReset() error                { return nil }
func (c *fakeCheckpoint) Generator() func(buf []byte) checkpoint.ICheckPoint {
	return func(buf []byte) checkpoint.ICheckPoint {
		cp := &fakeCheckpoint{key: c.key, ext: c.ext}
		_ = cp.Deserialize(bytes.NewReader(buf))
		return cp
	}
}

// writeDefaultSnapshot lays down "<dataDir>/checkpoints/<key>/default<ext>" with the
// given height in its header -- the only file Manager.Restore loads for a key.
func writeDefaultSnapshot(t *testing.T, dataDir, key, ext string, height uint32) {
	t.Helper()
	dir := filepath.Join(dataDir, "checkpoints", key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	buf := new(bytes.Buffer)
	if err := common.WriteUint32(buf, height); err != nil {
		t.Fatalf("WriteUint32: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "default"+ext), buf.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// TestPredictedCheckpointHeightEqualsManagerMaxHeight is the load-bearing test: the
// number the pre-flight prints must be the number the boot's gate compares. It is
// measured against the real checkpoint.Manager, not asserted against a constant.
func TestPredictedCheckpointHeightEqualsManagerMaxHeight(t *testing.T) {
	dataDir := t.TempDir()
	writeDefaultSnapshot(t, dataDir, "cp_cr", ".ccp", 100)
	writeDefaultSnapshot(t, dataDir, "cp_dpos", ".dcp", 250)
	// Above both, and MaxHeight must ignore it (core/checkpoint/manager.go:315).
	writeDefaultSnapshot(t, dataDir, "cp_txPool", ".txpcp", 999)

	params := t1Params(5)
	m := checkpoint.NewManager(params)
	m.SetDataPath(filepath.Join(dataDir, "checkpoints"))
	m.Register(&fakeCheckpoint{key: "cp_cr", ext: ".ccp"})
	m.Register(&fakeCheckpoint{key: "cp_dpos", ext: ".dcp"})
	m.Register(&fakeCheckpoint{key: "cp_txPool", ext: ".txpcp"})
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	predicted, points := blockchain.PredictRestoredCheckpointMaxHeight(dataDir)
	assert.Equal(t, m.MaxHeight(), predicted,
		"the predicted height must BE the production gate's input")
	assert.Equal(t, uint32(250), predicted, "max over the counted checkpoints")

	byKey := map[string]blockchain.RestoredCheckpoint{}
	for _, p := range points {
		byKey[p.Key] = p
	}
	assert.Equal(t, uint32(100), byKey["cp_cr"].Height)
	assert.Equal(t, uint32(250), byKey["cp_dpos"].Height)
	assert.Equal(t, uint32(999), byKey["cp_txPool"].Height)
	assert.True(t, byKey["cp_cr"].CountedInMaxHeight)
	assert.False(t, byKey["cp_txPool"].CountedInMaxHeight,
		"cp_txPool must be excluded exactly as MaxHeight excludes it")
}

// TestPredictedCheckpointHeightHandlesUnreadableSnapshots: an absent or truncated
// default file restores no height, which is what the live checkpoint keeps too
// (loadCheckpointFile puts the pre-load height back on a failed Deserialize).
func TestPredictedCheckpointHeightHandlesUnreadableSnapshots(t *testing.T) {
	dataDir := t.TempDir()
	writeDefaultSnapshot(t, dataDir, "cp_dpos", ".dcp", 300)
	// A key with a directory but no default snapshot.
	if err := os.MkdirAll(filepath.Join(dataDir, "checkpoints", "cp_cr"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// A REGISTERED key whose default snapshot is shorter than its height header.
	// It has to be a registered key to be read at all: the walk covers exactly the
	// checkpoints Manager.Restore covers, and Restore derives every path from a
	// registered checkpoint's own Key() rather than from the directory listing.
	shortDir := filepath.Join(dataDir, "checkpoints", "cp_txPool")
	if err := os.MkdirAll(shortDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shortDir, "default.txpcp"), []byte{1, 2}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// A directory that is not a registered key at all. Nothing registers "cp_short",
	// so no start ever opens it and it must not appear in the prediction. This used
	// to be counted as a real checkpoint, which is the same defect that let an
	// operator's cp_txPool.bak refuse a correct node.
	strayDir := filepath.Join(dataDir, "checkpoints", "cp_short")
	if err := os.MkdirAll(strayDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(strayDir, "default.scp"), []byte{1, 2}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	predicted, points := blockchain.PredictRestoredCheckpointMaxHeight(dataDir)
	assert.Equal(t, uint32(300), predicted,
		"only the readable snapshot contributes a height")
	byKey := map[string]blockchain.RestoredCheckpoint{}
	for _, p := range points {
		byKey[p.Key] = p
	}
	assert.NotEmpty(t, byKey["cp_cr"].Err, "a missing snapshot must be reported")
	assert.Zero(t, byKey["cp_cr"].Height)
	assert.NotEmpty(t, byKey["cp_txPool"].Err, "a truncated snapshot must be reported")
	assert.Zero(t, byKey["cp_txPool"].Height)
	_, stray := byKey["cp_short"]
	assert.False(t, stray, "a directory that is not a registered checkpoint key is "+
		"never restored, so it must not be reported as a checkpoint")

	// No checkpoints directory at all: no prediction, no crash.
	empty, none := blockchain.PredictRestoredCheckpointMaxHeight(t.TempDir())
	assert.Zero(t, empty)
	assert.Empty(t, none)
}

// TestPreflightPredictsThePostRestoreRefusal is the regression this whole file
// exists for. Same store, same armed configuration, only the snapshot height
// differs -- and the prediction must change with it.
func TestPreflightPredictsThePostRestoreRefusal(t *testing.T) {
	const target = uint32(5)

	t.Run("stale snapshot at-or-above the target: rewinds, then refuses", func(t *testing.T) {
		dir := t.TempDir()
		p := t1Params(target)
		t1BuildChain(t, dir, p, target+3)
		writeDefaultSnapshot(t, dir, "cp_dpos", ".dcp", target+1)

		report := preflightOnce(t, dir, p)

		assert.Equal(t, blockchain.PreflightWillRefuse, report.Outcome,
			"a snapshot at or above the target must be predicted as a refusal")
		assert.Equal(t, uint32(target+1), report.Store.RestoredCheckpointMaxHeight)
		assert.True(t, report.Store.CheckpointGateEvaluated)
		assert.Contains(t, strings.Join(report.Blocking, "\n"),
			"is >= rewound target",
			"the blocker must be the node's own message")
		// The rewind is not cancelled by the later refusal; hiding that would send
		// the operator into a store that has already changed under them.
		assert.Contains(t, report.Headline, "WILL REWIND")
		assert.Contains(t, report.Headline, "REFUSE")
	})

	t.Run("snapshot below the target: prediction is unchanged", func(t *testing.T) {
		dir := t.TempDir()
		p := t1Params(target)
		t1BuildChain(t, dir, p, target+3)
		writeDefaultSnapshot(t, dir, "cp_dpos", ".dcp", target-1)

		report := preflightOnce(t, dir, p)

		assert.Equal(t, blockchain.PreflightWillRewind, report.Outcome)
		assert.Equal(t, uint32(target-1), report.Store.RestoredCheckpointMaxHeight)
		assert.True(t, report.Store.CheckpointGateEvaluated,
			"a rewinding boot always reaches the gate")
		assert.Contains(t, strings.Join(report.Notes, "\n"),
			"WILL run on this start, and passes",
			"the tool must say it looked, not stay silent")
	})

	t.Run("no snapshot: the tool says derived state is rebuilt by replay", func(t *testing.T) {
		dir := t.TempDir()
		p := t1Params(target)
		t1BuildChain(t, dir, p, target+3)

		report := preflightOnce(t, dir, p)

		assert.Equal(t, blockchain.PreflightWillRewind, report.Outcome)
		assert.Zero(t, report.Store.RestoredCheckpointMaxHeight)
		assert.Contains(t, strings.Join(report.Notes, "\n"),
			"rebuilds it by replaying the chain")
	})
}

// TestPreflightStatesTheCheckpointPredictionLimit: the prediction reads a header and
// does not deserialise the body, so it is an upper bound. An operator-facing tool
// that mispredicts quietly is worse than none, so the bound is in the OUTPUT.
func TestPreflightStatesTheCheckpointPredictionLimit(t *testing.T) {
	const target = uint32(5)
	dir := t.TempDir()
	p := t1Params(target)
	t1BuildChain(t, dir, p, target+3)
	writeDefaultSnapshot(t, dir, "cp_dpos", ".dcp", target-1)

	report := preflightOnce(t, dir, p)
	notes := strings.Join(report.Notes, "\n")
	assert.Contains(t, notes, "UPPER bound")
	assert.Contains(t, notes, "does NOT deserialise")
	assert.Contains(t, notes, "does NOT run InitCheckpoint")
}
