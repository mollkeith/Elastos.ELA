// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
)

// checkpointDirName mirrors main.go's checkpointPath (main.go:57), the directory
// under the chain data dir that main.go hands to Manager.SetDataPath (main.go:119).
const checkpointDirName = "checkpoints"

// txPoolCheckpointKey is the one checkpoint Manager.MaxHeight skips
// (core/checkpoint/manager.go:315). Mirrored here so the prediction covers exactly
// the same set as the gate it predicts.
const txPoolCheckpointKey = "cp_txPool"

// defaultCheckpointPrefix is checkpoint.DefaultCheckpoint. Manager.Restore loads
// getDefaultPath -> "<dataDir>/checkpoints/<key>/default<ext>", never a
// height-named file, so those are the only files whose heights can be restored.
const defaultCheckpointPrefix = "default."

// RestoredCheckpoint is one checkpoint's predicted post-restore height.
type RestoredCheckpoint struct {
	// Key is the checkpoint directory name, e.g. "cp_cr" or "cp_dpos".
	Key string `json:"key"`
	// File is the default snapshot Manager.Restore would load, or "" if absent.
	File string `json:"file,omitempty"`
	// Height is the height field in that file's header. Zero when the file is
	// absent or unreadable -- which is also what the live checkpoint keeps in
	// that case, because loadCheckpointFile puts the pre-load height back on a
	// failed Deserialize (core/checkpoint/manager.go:504-517).
	Height uint32 `json:"height"`
	// CountedInMaxHeight is false for cp_txPool, which MaxHeight skips.
	CountedInMaxHeight bool `json:"counted_in_max_height"`
	// Err explains an absent or unreadable snapshot.
	Err string `json:"error,omitempty"`
}

// PredictRestoredCheckpointMaxHeight predicts checkpoint.Manager.MaxHeight() as it
// will read AFTER a boot's InitCheckpoint, without restoring anything.
//
// Why this can be done from four bytes: Manager.Restore loads only the per-key
// "default" snapshot, and every consensus checkpoint serialises Height as its FIRST
// field with common.WriteUint32 -- cr/state/checkpoint.go:185 and
// dpos/state/checkpoint.go:240. MaxHeight then takes the max over all keys except
// cp_txPool. So the header word of each default file IS the height the gate at
// main.go:436-449 will compare, and reading it costs four bytes per checkpoint
// instead of deserialising ~130 MiB of CR and DPoS state.
//
// LIMIT, stated here and in the rendered report: this reads the header, it does not
// deserialise the body. A snapshot whose header is intact but whose body is corrupt
// fails Deserialize, and loadCheckpointFile then restores the pre-load height, so
// the node's real MaxHeight would be LOWER than predicted here. The prediction is
// therefore an UPPER bound: it can over-predict the refusal, never miss one.
//
// It opens every file O_RDONLY and writes nothing.
func PredictRestoredCheckpointMaxHeight(dataDir string) (uint32, []RestoredCheckpoint) {
	root := filepath.Join(dataDir, checkpointDirName)
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, nil
	}

	var out []RestoredCheckpoint
	var max uint32
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rc := RestoredCheckpoint{
			Key:                e.Name(),
			CountedInMaxHeight: e.Name() != txPoolCheckpointKey,
		}
		path, err := findDefaultCheckpointFile(filepath.Join(root, e.Name()))
		if err != nil {
			rc.Err = err.Error()
			out = append(out, rc)
			continue
		}
		rc.File = filepath.Base(path)
		h, err := readCheckpointHeaderHeight(path)
		if err != nil {
			rc.Err = err.Error()
			out = append(out, rc)
			continue
		}
		rc.Height = h
		if rc.CountedInMaxHeight && h > max {
			max = h
		}
		out = append(out, rc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return max, out
}

// findDefaultCheckpointFile locates "default<ext>" without hard-coding the
// per-checkpoint extension, which lives on the ICheckPoint implementations.
func findDefaultCheckpointFile(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, defaultCheckpointPrefix+"*"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no default snapshot in %s; this checkpoint will be "+
			"rebuilt by replay and restores no height", dir)
	}
	sort.Strings(matches)
	return matches[0], nil
}

// readCheckpointHeaderHeight reads the leading uint32 with the production decoder.
func readCheckpointHeaderHeight(path string) (uint32, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var hdr [4]byte
	n, err := f.ReadAt(hdr[:], 0)
	if n != len(hdr) {
		if err == nil {
			err = fmt.Errorf("short read")
		}
		return 0, fmt.Errorf("cannot read the height header: %v", err)
	}
	return common.ReadUint32(bytes.NewReader(hdr[:]))
}

// checkpointGateEvaluated restates main.go:436-439 -- the condition under which the
// boot compares CkpManager.MaxHeight() against the rollback target at all.
//
// willRewind stands in for main.go's forcedRollbackApplied: a boot that rewinds sets
// it, and after the rewind the tip IS the target, so the first disjunct holds.
func checkpointGateEvaluated(params *config.Configuration, tip uint32,
	willRewind bool) bool {
	if willRewind {
		return true
	}
	return params.ForcedRollbackTrigger != "" &&
		params.ForcedRollbackHeight != 0 &&
		params.ForcedRollbackHeight != config.DisabledForcedRollbackHeight &&
		tip <= params.ForcedRollbackHeight
}

// applyCheckpointGate is main.go's step AFTER InitCheckpoint (main.go:404-449),
// which predict() deliberately does not cover: predict walks the forced-rollback
// boot sequence, and this gate runs later, on restored checkpoint state.
//
// Before this existed the tool was silent about the gate, so a node whose snapshot
// had drifted to or past the target was told "WILL REWIND on start" and then, having
// actually performed the rewind, refused to start. An operator-facing tool that
// mispredicts that quietly is worse than none, so the report now either predicts the
// refusal or says in its own output that it looked and the gate does not apply.
func (r *PreflightReport) applyCheckpointGate(params *config.Configuration) {
	// A node that already refuses exits long before InitCheckpoint, so there is
	// nothing to predict and nothing to say.
	if r.Outcome == PreflightWillRefuse {
		return
	}

	max, points := PredictRestoredCheckpointMaxHeight(r.Store.DataDir)
	r.Store.RestoredCheckpoints = points
	r.Store.RestoredCheckpointMaxHeight = max

	target := params.ForcedRollbackHeight
	willRewind := r.Outcome == PreflightWillRewind
	r.Store.CheckpointGateEvaluated = checkpointGateEvaluated(params, r.Store.Tip, willRewind)

	// The header-only read cannot see a body that fails to deserialise, so say so
	// wherever the number is used for anything.
	if len(points) > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("Predicted restored checkpoint height "+
			"is %d, read from the height header of the default snapshot file(s) that "+
			"a start would restore. The pre-flight does NOT deserialise those files "+
			"and does NOT run InitCheckpoint, so this is an UPPER bound: a snapshot "+
			"with an intact header but a corrupt body fails to load and the node's "+
			"real restored height would be lower.", max))
	} else {
		r.Notes = append(r.Notes, "No default checkpoint snapshot was found under "+
			filepath.Join(r.Store.DataDir, checkpointDirName)+", so a start restores "+
			"no derived state and rebuilds it by replaying the chain. That replay is "+
			"NOT included in the estimate above.")
	}

	if !r.Store.CheckpointGateEvaluated {
		r.Notes = append(r.Notes, "The start-up check that refuses on a restored "+
			"checkpoint at or above the rollback target does not apply to this start "+
			"(the node is not rewinding and its tip is above the target), so the "+
			"height above cannot stop it.")
		return
	}

	if max < target {
		r.Notes = append(r.Notes, fmt.Sprintf("The start-up check that refuses on a "+
			"restored checkpoint at or above the rollback target WILL run on this "+
			"start, and passes on the heights read here (%d < %d).", max, target))
		return
	}

	// Production message, main.go:442-445, with the predicted height in place of the
	// restored one.
	blocker := fmt.Sprintf("forced rollback: a restored checkpoint height %d is >= "+
		"rewound target %d; the snapshot is not strictly pre-target, derived state "+
		"may be exploit-era -- refusing to start", max, target)

	if willRewind {
		// The rewind still happens and is persisted; the refusal comes after it.
		// Saying only "will refuse" would hide work the operator cannot undo.
		r.Headline = fmt.Sprintf("This node WILL REWIND on start and will then "+
			"REFUSE to start: the rewind from tip %d to %d runs and is persisted, "+
			"but the checkpoint snapshot it restores afterwards is at height %d, "+
			"which is at or above the target %d. Move or delete the stale default "+
			"snapshot(s) so the node rebuilds derived state by replay.",
			r.Store.Tip, target, max, target)
		r.Outcome = PreflightWillRefuse
		r.Blocking = append(r.Blocking, blocker)
		return
	}

	r.refuse(r.Cell, fmt.Errorf("%s", blocker), fmt.Sprintf("This node will REFUSE "+
		"to start: the checkpoint snapshot it restores is at height %d, at or above "+
		"the rollback target %d, so its derived state may be exploit-era. Move or "+
		"delete the stale default snapshot(s) so the node rebuilds derived state by "+
		"replay.", max, target))
}
