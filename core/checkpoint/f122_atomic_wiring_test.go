// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TEST — F-122 atomic checkpoint write.
//
// The blocker: swapping writeFileAtomic for a plain os.WriteFile at the saveCheckpoint
// call site left the suite green at HEAD ("ok, rc=0"). Nothing asserted that the save
// path REPLACES the destination rather than writing it in place — which is the entire
// point of the fix: an in-place write with no fsync leaves a SHORT checkpoint file behind
// on a crash, and replaceCheckpoints only tests existence before promoting it to
// default.<ext>, which then feeds the F-121 restore path on the next start.
//
// This test drives the REAL (*fileChannels).saveCheckpoint over a destination that
// already holds stale content, and asserts the observable signature of an atomic replace:
// the destination is a NEWLY CREATED file (0600, the mode writeFileAtomic creates its
// temp file with) rather than the pre-existing one rewritten in place (which keeps its
// original 0644), it holds the complete new content, and no .tmp residue is left behind.
package checkpoint

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/require"
)

func TestF122SaveCheckpointReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Configuration{
		CheckPointConfiguration: config.CheckPointConfiguration{
			DataPath:      dir,
			EnableHistory: true, // skip the clean-up leg; only the write is under test
		}}
	c := &fileChannels{cfg: &cfg.CheckPointConfiguration}

	pt := &checkpoint{data: new(uint64)}
	*pt.data = 0xDEADBEEF

	// A destination that already exists, world-readable, holding a torn/stale body —
	// the state a previous save leaves on disk.
	cpDir := getCheckpointDirectory(dir, pt)
	require.NoError(t, os.MkdirAll(cpDir, 0700))
	path := getFilePath(dir, pt)
	require.NoError(t, os.WriteFile(path, []byte("STALE TORN CHECKPOINT"), 0644))
	before, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0644), before.Mode().Perm(), "precondition: destination is 0644")

	reply := make(chan bool, 1)
	require.NoError(t, c.saveCheckpoint(&fileMsg{checkpoint: pt, reply: reply}))
	require.True(t, <-reply, "the save must report success")

	// 1. The destination holds exactly the serialized checkpoint, not the stale body.
	want := new(bytes.Buffer)
	require.NoError(t, pt.Serialize(want))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, want.Bytes(), got, "the destination must hold the complete new checkpoint")

	// 2. ATOMIC REPLACE: the destination is a file that was created fresh and renamed
	// over the old one (0600), NOT the pre-existing file rewritten in place (which would
	// still be 0644). This is the discriminator against a plain os.WriteFile.
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.Equalf(t, os.FileMode(0600), after.Mode().Perm(),
		"F-122 WIRING SEVERED: the checkpoint destination kept its pre-existing mode %v, so it "+
			"was written IN PLACE instead of being atomically replaced — a crash mid-write "+
			"leaves a short checkpoint that replaceCheckpoints will still promote",
		after.Mode().Perm())

	// 3. No temp residue.
	entries, err := filepath.Glob(filepath.Join(cpDir, "*.tmp"))
	require.NoError(t, err)
	require.Empty(t, entries, "the atomic write must leave no .tmp residue behind")
}
