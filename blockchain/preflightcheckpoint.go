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
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
)

// checkpointDirName mirrors main.go's checkpointPath (main.go:57), the directory
// under the chain data dir that main.go hands to Manager.SetDataPath (main.go:119).
const checkpointDirName = "checkpoints"

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
	// CountedInMaxHeight is false for cp_txPool, the one REGISTERED checkpoint
	// MaxHeight skips. Every entry in the slice is a registered checkpoint, so this
	// is false for cp_txPool and true for everything else that appears.
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
// dpos/state/checkpoint.go:240. MaxHeight then takes the max over the REGISTERED
// checkpoints except cp_txPool. So the header word of each default file IS the
// height the gate at main.go:436-449 will compare, and reading it costs four bytes
// per checkpoint instead of deserialising ~130 MiB of CR and DPoS state.
//
// Which directories count is checkpoint.IsRegisteredCheckpointKey and
// checkpoint.CountedInMaxHeight, the same table MaxHeight's own skip rule reads.
// This walk must not grow a private notion of which names matter: see the comment
// on the filter in the loop for the failure that caused.
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
		// Consider only the keys a node actually REGISTERS. Manager.Restore walks
		// its registered checkpoints and derives each path from that checkpoint's
		// own Key() (core/checkpoint/manager.go, Restore and
		// getCheckpointDirectory); it never lists this directory. So a directory
		// whose name is not a registered key is never opened by a start and cannot
		// contribute to the height being predicted here.
		//
		// This used to be `e.Name() != txPoolCheckpointKey` against a private copy
		// of the "cp_txPool" literal, which is an exact string compare, so every
		// other directory was treated as a real checkpoint. An operator who copies
		// or renames the tx-pool checkpoint to cp_txPool.bak or cp_txPool.old got a
		// directory that is not equal to "cp_txPool" and was therefore COUNTED --
		// and cp_txPool's snapshot tracks the chain tip (2,260,593 on mainnet,
		// above the 2,260,450 rewind target), so the predicted max jumped over the
		// target. The restart procedure's own backup step produced that directory,
		// so following the documented procedure made main.go:330 refuse to start a
		// completely correct node.
		if !checkpoint.IsRegisteredCheckpointKey(e.Name()) {
			continue
		}
		rc := RestoredCheckpoint{
			Key:                e.Name(),
			CountedInMaxHeight: checkpoint.CountedInMaxHeight(e.Name()),
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

// PurgeTxPoolCheckpointAboveTarget removes any cp_txPool checkpoint whose recorded
// height is ABOVE the forced-rollback target, after the rewind has completed.
//
// cp_txPool is the one registered checkpoint that Manager.MaxHeight deliberately
// skips (core/checkpoint/manager.go), and both forced-rollback baseline gates
// therefore skip it by name; see CountedInMaxHeight above. That exclusion is correct
// arithmetic for the height gate, but it also means no other check can observe a
// cp_txPool file left above the target, and ForceRollback does not remove it either,
// so it survives the rewind: on a mainnet node rewound from 2,260,595 to 2,260,450,
// cp_txPool/2260595.txpcp was still present afterwards.
//
// It matters because cp_txPool has SavePeriod == EffectivePeriod == 1, so it is
// rewritten every block; on a frozen node it describes the mempool from inside the
// discarded range. txPoolCheckpoint.Deserialize calls txPool.appendToTxPool, the same
// entry point the live pool uses, so the file restores directly into the live pool,
// and pow.GenerateBlock assembles the first block of the recovered chain from that
// pool. Per-transaction re-validation does run, StrictMoneyRangeHeight included, so a
// harmful entry is unlikely to survive it; removing the file removes the question.
//
// Scope: only files strictly above the target are removed, and only from the
// cp_txPool directory. The `default` file is left alone, since it carries no height in
// its name and the checkpoint manager rewrites it from live state on the next save.
// Derived-state checkpoints (cp_dpos, cp_cr) are never touched here: the rewind's own
// post-rebuild baseline assertion already requires those to be below the target, and
// deleting one would destroy the snapshot the rebuild starts from.
//
// A missing directory is not an error: a node that never ran a mempool checkpoint has
// nothing to purge.
func PurgeTxPoolCheckpointAboveTarget(checkpointRoot string, target uint32) error {
	// Derive the directory from the SAME registration table MaxHeight consults,
	// rather than a local literal: the excluded key is by definition the one
	// registered checkpoint that MaxHeight does not count. If that table ever
	// gains or renames an excluded key this follows it automatically.
	var key string
	for _, k := range checkpoint.RegisteredCheckpointKeys() {
		if !checkpoint.CountedInMaxHeight(k) {
			key = k
			break
		}
	}
	if key == "" {
		return nil
	}
	dir := filepath.Join(checkpointRoot, key)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("forced rollback: read %s: %w", dir, err)
	}

	removed := make([]string, 0, 2)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Height-named files only. The manager writes "<height><ext>"; the live
		// file is "default<ext>" and carries no height, so it is skipped by the
		// same parse that selects the others.
		base := name
		if i := len(base) - len(filepath.Ext(base)); i >= 0 {
			base = base[:i]
		}
		var h uint64
		if _, perr := fmt.Sscanf(base, "%d", &h); perr != nil {
			continue
		}
		if uint32(h) <= target {
			continue
		}
		p := filepath.Join(dir, name)
		if rerr := os.Remove(p); rerr != nil {
			return fmt.Errorf("forced rollback: remove stale mempool checkpoint %s: %w", p, rerr)
		}
		removed = append(removed, name)
	}

	if len(removed) > 0 {
		sort.Strings(removed)
		log.Operatorf("FORCED ROLLBACK: purged %d mempool checkpoint(s) written above the "+
			"rollback target %d: %v. These describe the transaction pool from inside the "+
			"discarded range and would otherwise restore into the live pool on the next "+
			"start, which is where the first block of the recovered chain is built from.",
			len(removed), target, removed)
	}
	return nil
}
