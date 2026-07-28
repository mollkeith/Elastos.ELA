// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"fmt"
)

// This file holds the PURE-READ halves of the two boot-path checks that act on
// what they find.
//
// A pre-flight has to answer "what will this node do when it starts" without
// doing any of it. The obvious way to get that answer -- call
// VerifyForcedRollbackApplied and CheckForcedRollbackResidue and see what they
// return -- is not available: both PURGE. The other obvious way, restating their
// conditions in a second place, is worse: a pre-flight whose prediction is a COPY
// of the boot path's decision is exactly as good as the copy is fresh, and the
// first time the two drift the tool is confidently wrong on restart day.
//
// So the decision is extracted, once, into a function that only reads, and the
// boot path acts on its result. There is no second copy to drift.

// forcedRollbackExceedsCapacity reports whether rewinding from `start` down to
// `target` is deeper than the incremental window ForceRollback will accept.
//
// It exists so that the pre-flight's "this node will REFUSE to start" prediction
// for the capacity band is the boot path's own predicate rather than a restatement
// of it. Both ForceRollback (which refuses) and PreflightForcedRollback (which
// steps aside for that refusal) call it.
func forcedRollbackExceedsCapacity(start, target uint32) bool {
	return start > target && start-target >= maxHistoryCapacity
}

// ForcedRollbackApplyState is what DiagnoseForcedRollbackApplied found.
type ForcedRollbackApplyState int

const (
	// ApplyNotConfigured -- no forced rollback is active on this network.
	ApplyNotConfigured ForcedRollbackApplyState = iota
	// ApplySettled -- the trigger block is absent from all three persisted
	// indexes. Nothing to do.
	ApplySettled
	// ApplyTriggerHeightMismatch -- the configured trigger names a block at a
	// height other than target+1. The node REFUSES to start.
	ApplyTriggerHeightMismatch
	// ApplyTriggerOnMainChain -- the trigger is still main-chain indexed, so its
	// UTXO/derived-state processors were never reverted. The node REFUSES to start.
	ApplyTriggerOnMainChain
	// ApplyRetentionResidue -- the trigger is off the main chain but still in the
	// raw block store and/or carries an orphaned header row. The node purges those
	// two keys and continues.
	ApplyRetentionResidue
)

// ForcedRollbackApplyDiagnosis is the read-only result of the boot-time
// post-condition, before any of its actions are taken.
type ForcedRollbackApplyDiagnosis struct {
	State ForcedRollbackApplyState
	// Loc is where the trigger block still lives, or nil.
	Loc *ForcedRollbackTriggerLocation
	// Tip is the loaded block-index tip, Target the configured rollback height.
	Tip, Target uint32
	// TriggerHeight is the height the store says the trigger occupies, valid when
	// TriggerHeightKnown.
	TriggerHeight      uint32
	TriggerHeightKnown bool
	// Err is EXACTLY the error VerifyForcedRollbackApplied returns for the two
	// refusal states, and nil otherwise. The pre-flight prints it verbatim, so an
	// operator reads the same words before the boot that the boot would print.
	Err error
}

// DiagnoseForcedRollbackApplied probes the persisted store and classifies it,
// WITHOUT purging anything.
func (b *BlockChain) DiagnoseForcedRollbackApplied() (
	*ForcedRollbackApplyDiagnosis, error) {
	if !b.forcedRollbackConfigured() {
		return &ForcedRollbackApplyDiagnosis{State: ApplyNotConfigured}, nil
	}
	loc, err := b.LocateForcedRollbackTrigger()
	if err != nil {
		return nil, err
	}

	d := &ForcedRollbackApplyDiagnosis{
		Loc:    loc,
		Target: b.chainParams.ForcedRollbackHeight,
	}
	if len(b.Nodes) > 0 {
		d.Tip = uint32(len(b.Nodes) - 1)
	}

	if loc == nil || !loc.Present() {
		d.State = ApplySettled
		return d, nil
	}

	d.TriggerHeight, d.TriggerHeightKnown = b.forcedRollbackTriggerHeight(loc)

	// The trigger block is HERE, but is it the block this rollback is about? Every
	// branch below assumes the configured trigger names the block at target+1 and
	// nothing has ever checked that it does. When it does not, the disagreement is
	// between two configured values, not inside the database, and the answers below
	// (refuse with "restore a backup or wipe and resync", or purge the named block
	// from the store) are both destructive answers to a typo. Diagnose it first.
	if h := d.TriggerHeight; d.TriggerHeightKnown && h != d.Target+1 {
		d.State = ApplyTriggerHeightMismatch
		d.Err = fmt.Errorf("forced rollback: CONFIGURATION ERROR -- the configured "+
			"trigger %s names the block at height %d, but the forced rollback is "+
			"defined as the removal of the block at height %d (target %d + 1). The "+
			"block store is not damaged: the two values that disagree are both "+
			"configuration, and one of them is wrong. Refusing to start rather than "+
			"acting on a rollback this node cannot make sense of. Remedy: set "+
			"ForcedRollbackTrigger / --forcedrollbacktrigger to the hash of the block "+
			"at height %d, or set ForcedRollbackHeight / --forcedrollbackheight to one "+
			"below %d, then restart. Neither restoring a backup nor resyncing from "+
			"scratch helps here, and both are hours of work: a resynced node reads the "+
			"same configuration and stops in the same place",
			b.chainParams.ForcedRollbackTrigger, h, d.Target+1, d.Target, d.Target+1, h)
		return d, nil
	}

	if loc.OnMainChain {
		cause := "an INTERRUPTED rewind that never committed this block's rollback " +
			"transaction"
		if d.Tip > d.Target {
			cause = "a rewind that was DECLINED or never ran -- this node is still on " +
				"the chain the recovery removes"
		}
		d.State = ApplyTriggerOnMainChain
		d.Err = fmt.Errorf("%w: block %s is still recorded on the MAIN CHAIN at height "+
			"%d (loaded tip %d, rollback target %d). Signature of %s. Its UTXO and "+
			"derived-state processors have not been reverted, so this node would join "+
			"the recovered network on the exploit chain and stall it -- refusing to "+
			"start. %s Rewinding manually first also works: stop the node and, from "+
			"its working directory, run `ela-cli rollback --height %d --datadir <your "+
			"data dir>` (the --height FLAG is required; a bare positional height "+
			"prints help and does nothing), then restart.",
			ErrForcedRollbackNotApplied, loc.Hash.String(), loc.MainChainHeight, d.Tip,
			d.Target, cause, forcedRollbackRemedy, d.Target)
		return d, nil
	}

	d.State = ApplyRetentionResidue
	return d, nil
}

// ForcedRollbackResidueState is what DiagnoseForcedRollbackResidue found on a node
// sitting AT OR BELOW the target.
type ForcedRollbackResidueState int

const (
	// ResidueNotApplicable -- no forced rollback configured, no block index, or a
	// tip above the target (the node legitimately holds those blocks).
	ResidueNotApplicable ForcedRollbackResidueState = iota
	// ResidueInterrupted -- main-chain records above the target, or a persisted
	// best-chain state above it, while the loaded tip is not. The node REFUSES.
	ResidueInterrupted
	// ResidueRetentionOnly -- raw-store entries and/or orphaned header rows above
	// the target. The node purges them and continues.
	ResidueRetentionOnly
	// ResidueClean -- nothing above the target.
	ResidueClean
)

// ForcedRollbackResidueDiagnosis is the read-only result of the at-or-below-target
// safety net, before it purges anything.
type ForcedRollbackResidueDiagnosis struct {
	State       ForcedRollbackResidueState
	Scan        *ForcedRollbackStoreScan
	Tip, Target uint32
	// Marker/MarkerErr are the durable in-progress marker as CheckForcedRollbackResidue
	// reads it. MarkerErr is carried rather than returned because the production
	// check deliberately ignores it (`merr == nil && marker != nil`).
	Marker    *ForcedRollbackMarker
	MarkerErr error
	// Err is EXACTLY the error CheckForcedRollbackResidue returns for
	// ResidueInterrupted, and nil otherwise.
	Err error
}

// DiagnoseForcedRollbackResidue scans the store for a node at or below the
// rollback target, without purging anything and without clearing any marker.
func (b *BlockChain) DiagnoseForcedRollbackResidue() (
	*ForcedRollbackResidueDiagnosis, error) {
	d := &ForcedRollbackResidueDiagnosis{Target: b.chainParams.ForcedRollbackHeight}
	// Intrinsic guard, so the scan can never be provoked on a network where forced
	// rollback is inactive (the disabled sentinel is math.MaxUint32, which would
	// otherwise satisfy every `tip <= target` test and pay for a full store walk).
	if !b.forcedRollbackConfigured() {
		return d, nil
	}
	if len(b.Nodes) == 0 {
		return d, nil
	}
	d.Tip = uint32(len(b.Nodes) - 1)
	if d.Tip > d.Target {
		// The node legitimately holds blocks above the target (it is on a different
		// chain, or has already resynced forward). Nothing to assert.
		return d, nil
	}

	scan, err := ScanForcedRollbackStore(b.db.GetFFLDB(), d.Target)
	if err != nil {
		return nil, fmt.Errorf("forced rollback: scan store: %w", err)
	}
	d.Scan = scan
	d.Marker, d.MarkerErr = b.ReadForcedRollbackMarker()

	if len(scan.MainChainAbove) > 0 || scan.BestStateHeight > d.Target {
		d.State = ResidueInterrupted
		d.Err = interruptedRollbackError(scan, d.Tip)
		return d, nil
	}
	if len(scan.StoredAbove) > 0 || len(scan.HeaderRowsAbove) > 0 {
		d.State = ResidueRetentionOnly
		return d, nil
	}
	d.State = ResidueClean
	return d, nil
}
