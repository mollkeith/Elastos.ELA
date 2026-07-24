// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package checkpoint

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/stretchr/testify/require"
)

// failingCheckpoint is the in-package test checkpoint with a switch that makes
// Serialize fail, so the save path can be exercised the way a full disk or a
// broken keyframe would exercise it.
type failingCheckpoint struct {
	checkpoint
	failSerialize bool
}

func (f *failingCheckpoint) Serialize(w io.Writer) error {
	if f.failSerialize {
		return errors.New("serialize failed")
	}
	return f.checkpoint.Serialize(w)
}

// writeTruncatedDefault lays down a default checkpoint file that carries a height
// and then stops -- exactly what a torn write or a save that died after truncating
// its destination leaves behind.
func writeTruncatedDefault(t *testing.T, dir string, pt ICheckPoint, height uint32) {
	t.Helper()
	require.NoError(t, os.MkdirAll(getCheckpointDirectory(dir, pt), 0700))
	buf := new(bytes.Buffer)
	require.NoError(t, common.WriteUint32(buf, height))
	require.NoError(t, os.WriteFile(getDefaultPath(dir, pt), buf.Bytes(), 0600))
}

// TestF121_FailedRestoreMustNotPoisonHeight is the F-121 harm in one shot: a
// checkpoint file that deserializes halfway used to leave the LIVE checkpoint
// holding the height it read out of the bad file. Restore() skips OnInit() for a
// failed load, so the state behind that height is never recovered -- yet
// SafeHeight() still reports it, and InitCheckpoint's replay then starts above
// every block that would have rebuilt the state.
func TestF121_FailedRestoreMustNotPoisonHeight(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Configuration{
		CheckPointConfiguration: config.CheckPointConfiguration{
			DataPath: dir,
		}}
	m := NewManager(cfg)
	pt := &checkpoint{data: new(uint64)}
	m.Register(pt)
	defer m.Close()

	const poison = uint32(900000)
	writeTruncatedDefault(t, dir, pt, poison)

	err := m.Restore()

	// F-123: the failure must reach the caller instead of being overwritten by a
	// later success (or by the named return's zero value).
	require.Error(t, err, "Restore must report a checkpoint it could not load")

	// F-121: the live checkpoint must be untouched by the failed load.
	require.Equal(t, uint32(0), pt.GetHeight(),
		"a failed Deserialize must not leave the live checkpoint at the corrupt file's height")

	// The harm the poisoned height causes: the replay window collapses, so the node
	// would come up at full height with state that was never rebuilt.
	require.Equal(t, uint32(0), m.SafeHeight(),
		"SafeHeight must still demand a full replay after a failed restore")
}

// TestF123_RestoreReportsAFailureEvenWhenALaterCheckpointSucceeds pins the exact
// shipped mechanic: the failure was assigned to the NAMED return and the next
// iteration's success overwrote it with nil.
func TestF123_RestoreReportsAFailureEvenWhenALaterCheckpointSucceeds(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Configuration{
		CheckPointConfiguration: config.CheckPointConfiguration{
			DataPath: dir,
		}}
	m := NewManager(cfg)
	defer m.Close()

	// VeryHigh is ordered first and fails; Low is ordered last and succeeds.
	broken := &keyedCheckpoint{checkpoint: checkpoint{data: new(uint64),
		priority: VeryHigh}, key: "broken"}
	good := &keyedCheckpoint{checkpoint: checkpoint{data: new(uint64),
		priority: Low}, key: "good"}
	m.Register(broken)
	m.Register(good)

	writeTruncatedDefault(t, dir, broken, 900000)

	// A complete, loadable file for the checkpoint that restores fine.
	require.NoError(t, os.MkdirAll(getCheckpointDirectory(dir, good), 0700))
	whole := new(bytes.Buffer)
	require.NoError(t, common.WriteUint32(whole, 4242))
	require.NoError(t, common.WriteUint64(whole, 7))
	require.NoError(t, os.WriteFile(getDefaultPath(dir, good), whole.Bytes(), 0600))

	err := m.Restore()
	require.Error(t, err,
		"a later successful checkpoint must not turn a failed restore into success")
	require.Contains(t, err.Error(), "broken")

	// The healthy one still had to be restored: the loop must not abort.
	require.Equal(t, uint32(4242), good.GetHeight())
	require.Equal(t, uint32(0), broken.GetHeight())
}

// keyedCheckpoint gives each test checkpoint its own manager key and directory.
type keyedCheckpoint struct {
	checkpoint
	key string
}

func (k *keyedCheckpoint) Key() string { return k.key }

// TestF122_FailedSaveKeepsThePreviousCheckpointAndRepliesFalse covers both halves
// of F-122: the destination was truncated in place before the checkpoint had even
// been serialized, and the reply reported success regardless.
func TestF122_FailedSaveKeepsThePreviousCheckpointAndRepliesFalse(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Configuration{
		CheckPointConfiguration: config.CheckPointConfiguration{
			EnableHistory: true,
			DataPath:      dir,
		}}
	channels := NewFileChannels(cfg)
	defer channels.Exit()

	data := uint64(7)
	pt := &failingCheckpoint{checkpoint: checkpoint{data: &data, height: 10}}

	reply := make(chan bool)
	channels.Save(pt, reply)
	require.True(t, <-reply, "a healthy save must report success")

	saved, err := os.ReadFile(getFilePath(dir, pt))
	require.NoError(t, err)
	require.NotEmpty(t, saved)

	// Now the same save fails at Serialize time.
	pt.failSerialize = true
	reply = make(chan bool)
	channels.Save(pt, reply)
	require.False(t, <-reply, "a save that failed must not reply success")

	after, err := os.ReadFile(getFilePath(dir, pt))
	require.NoError(t, err,
		"a failed save must not remove the checkpoint that was already on disk")
	require.Equal(t, saved, after,
		"a failed save must not truncate the checkpoint that was already on disk")

	// No temp file may be left behind for cleanCheckpoints or replaceCheckpoints to
	// trip over.
	_, err = os.Stat(getFilePath(dir, pt) + ".tmp")
	require.True(t, os.IsNotExist(err), "the temp file must be removed on failure")
}

// TestF122_SaveIsAtomic checks the durability property itself: the final path is
// only ever created by a rename, never written through.
func TestF122_SaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(dir, 0700))

	path := dir + "/atomic.pt"
	require.NoError(t, writeFileAtomic(path, []byte("first")))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("first"), got)

	require.NoError(t, writeFileAtomic(path, []byte("second-and-longer")))
	got, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("second-and-longer"), got)

	_, err = os.Stat(path + ".tmp")
	require.True(t, os.IsNotExist(err))
}
