// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"errors"
	"fmt"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"
)

// This file separates ARMED from APPLIED.
//
// `ForcedRollbackArmed` answers "does this node hold the chain the rollback
// targets". Nothing about it says the rewind happened, yet the boot path used its
// result as if it did: one branch DECLINED a capacity-exceeded rollback and kept
// booting, and a later assertion read the same flag as "the rollback happened".
// Measured in the 48-node rehearsal: every node declined, then every node refused to
// start (alive 0/48). The second, worse face is silent -- when the restored
// checkpoint happens to land below the target the assertion PASSES, and the node
// comes up UN-ROLLED-BACK on the exploit chain, which is exactly the straggler that
// stalls the recovered chain when it holds an on-duty arbiter seat.
//
// The fix is that "applied" is now a statement about BYTES ON DISK
// (VerifyForcedRollbackApplied: the trigger block is gone from every persisted
// index), and a node that cannot establish it does not start. Together with the
// pre-flight scan below, no configured node can silently end up above the target
// while still holding the exploit block.

// ErrForcedRollbackNotApplied reports that the block the forced rollback targets is
// still present in the PERSISTED store after the boot path had its chance to rewind.
// The node is, by definition, still on the chain the recovery removes.
var ErrForcedRollbackNotApplied = errors.New(
	"forced rollback: the targeted block is still in the persisted store, so the rollback was NOT applied")

// ErrForcedRollbackStoreDamaged reports partial-rollback residue that the rewind
// STRUCTURALLY cannot reach: blocks the block database still records as main chain
// above the target, but which are absent from the in-RAM index the rewind walks. No
// purge repairs it, because those blocks' RollbackBlock transactions -- which also
// revert the UTXO and derived-state processors -- never ran and never will.
var ErrForcedRollbackStoreDamaged = errors.New(
	"forced rollback: the block store carries partial-rollback residue the rewind cannot reach")

// forcedRollbackRemedy is the operator remedy shared by every unrepairable
// forced-rollback diagnosis. It deliberately does NOT name `ela-cli purgeresidue`:
// that command removes retention residue only, and running it here would delete the
// last evidence of the damage while leaving the un-reverted derived state in place.
const forcedRollbackRemedy = "Remedy: this is not repairable in place. Restore a " +
	"pre-rollback backup of the data directory and restart under this binary (its " +
	"rewind is resumable, so an interrupted run continues rather than ratcheting), " +
	"or wipe the data directory and resync from the network under this binary."

// ErrForcedRollbackAbandoned reports a store that carries a DURABLE in-progress
// forced-rollback marker which this node is not configured to finish -- the operator
// has unset (or retargeted) --forcedrollbacktrigger while a rewind was under way.
var ErrForcedRollbackAbandoned = errors.New(
	"forced rollback: the store carries an in-progress rollback this node is not configured to finish")

// CheckAbandonedForcedRollback closes the disarm trap, and it is the one check in
// this file that must run on every boot of every node whether or not a forced
// rollback is configured.
//
// The trap: ffldb buffers committed writes in RAM for up to 20 MiB / 300 s. Without
// the flushes that sit alongside this check, a rewind can complete, verify itself,
// clear its marker and log "block store rewound" with not one byte of any of it on
// disk. An unclean exit inside that window silently discards the whole rewind. If the
// operator has by then acted on the completion line and disarmed the trigger, the
// next boot takes every early return in this file, since forcedRollbackConfigured is
// false and LocateForcedRollbackTrigger, VerifyForcedRollbackApplied and
// CheckForcedRollbackResidue all decline, and the node comes up on the pre-rollback
// chain, serving the exploit block, with nothing anywhere saying so.
//
// The remedy has two halves and needs both. The flushes make the marker durable
// before the first destructive step and the marker's clearing durable before the
// completion line, so "a rewind started here and did not report finishing" is a fact
// that survives the crash. This check is what reads that fact on a boot the operator
// has disarmed, and refuses.
//
// It is deliberately not gated on configuration: gating it reopens the trap. It costs
// one metadata point lookup on a node that has never run a rollback, and it is silent
// when a marker exists but this node is configured for that same target, because that
// node is resuming and the armed path owns it.
//
// Limits, stated so nothing here reads as more than it is. It can only refuse on
// evidence this binary's rewind wrote: a store rewound by an earlier binary, or
// offline by `ela-cli rollback`, carries no marker and is invisible to it. Neither
// has the flush-window trap this closes, since the earlier rewind ratchets instead,
// which VerifyForcedRollbackApplied catches, and the offline command flushes on
// close, but a node whose data directory was assembled some other way is outside what
// this can see, and the runbook control (disarm only after a clean shutdown plus an
// offline residue scan reading zero) is what covers that case.
func (b *BlockChain) CheckAbandonedForcedRollback() error {
	marker, err := b.ReadForcedRollbackMarker()
	if err != nil {
		return err
	}
	if marker == nil {
		return nil
	}
	if b.forcedRollbackConfigured() &&
		b.chainParams.ForcedRollbackHeight == marker.Target {
		// Configured to finish exactly this rewind: the armed path, the residue
		// check and VerifyForcedRollbackApplied take it from here.
		return nil
	}

	configured := "this node has NO forced rollback configured"
	if b.chainParams.ForcedRollbackTrigger != "" &&
		b.chainParams.ForcedRollbackHeight != config.DisabledForcedRollbackHeight {
		configured = fmt.Sprintf("this node is configured for target %d instead",
			b.chainParams.ForcedRollbackHeight)
	}
	var tip uint32
	if len(b.Nodes) > 0 {
		tip = uint32(len(b.Nodes) - 1)
	}
	return fmt.Errorf("%w: the block database records a forced rollback to target %d "+
		"as STARTED (from height %d) and never finished, but %s (loaded tip %d). The "+
		"marker is written and flushed to disk before the first destructive step and "+
		"retired only after the completed rewind is on disk, so its survival means the "+
		"rewind did not provably complete -- most often an unclean exit inside the "+
		"database flush window, which silently reverts the whole rewind and leaves this "+
		"node back on the chain the recovery removes. Starting disarmed here is exactly "+
		"how a node rejoins on that chain unnoticed, so this node refuses to start. "+
		"Remedy: re-arm --forcedrollbacktrigger/--forcedrollbackheight for target %d and "+
		"restart -- the rewind is resumable and idempotent, and it clears the marker "+
		"once it is durably complete. Only if you intend this node to stay off the "+
		"recovered network should you instead wipe the data directory and resync",
		ErrForcedRollbackAbandoned, marker.Target, marker.Start, configured, tip,
		marker.Target)
}

// forcedRollbackConfigured reports whether a forced rollback is active on this
// network. The disabled sentinel is math.MaxUint32, which would otherwise satisfy
// every `tip <= target` test and pay for a full store walk on every boot.
func (b *BlockChain) forcedRollbackConfigured() bool {
	return b.chainParams.ForcedRollbackTrigger != "" &&
		b.chainParams.ForcedRollbackHeight != 0 &&
		b.chainParams.ForcedRollbackHeight != config.DisabledForcedRollbackHeight
}

// forcedRollbackTriggerHash parses the configured trigger. The config value is in
// DISPLAY (explorer/RPC) byte order so an operator can verify it against a block
// explorer; block hashes are stored internally reversed. Parsing it the other way
// round silently disarms everything in this file.
func (b *BlockChain) forcedRollbackTriggerHash() (*common.Uint256, error) {
	h, err := common.Uint256FromReversedHexString(b.chainParams.ForcedRollbackTrigger)
	if err != nil {
		return nil, fmt.Errorf("forced rollback: bad trigger hash %q: %w",
			b.chainParams.ForcedRollbackTrigger, err)
	}
	return h, nil
}

// ForcedRollbackTriggerLocation records where the targeted block still lives in the
// PERSISTED store. Every field is read from the database, never from b.Nodes, which
// is what makes it a real post-condition: b.Nodes is truncated by the rewind loop
// itself, so any assertion phrased over it restates the loop's own exit condition.
type ForcedRollbackTriggerLocation struct {
	// Hash is the trigger block hash in internal byte order.
	Hash common.Uint256
	// OnMainChain is true while the main-chain hash->height index still resolves
	// the trigger. RollbackBlock deletes that entry in the SAME atomic transaction
	// as the UTXO/derived-state rollback processors, so its presence proves those
	// processors have not run.
	OnMainChain bool
	// MainChainHeight is the height that index reports, valid when OnMainChain.
	MainChainHeight uint32
	// HeaderRow is true while the block-header index -- the index startup rebuilds
	// b.Nodes from -- still carries a row for the trigger at target+1.
	HeaderRow bool
	// InBlockStore is true while the raw by-hash store still serves the block over
	// P2P getdata / RPC getblock (residue #2).
	InBlockStore bool
}

// Present reports whether the trigger block survives anywhere in the store.
func (l *ForcedRollbackTriggerLocation) Present() bool {
	return l.OnMainChain || l.HeaderRow || l.InBlockStore
}

// String renders the location for an operator-facing message.
func (l *ForcedRollbackTriggerLocation) String() string {
	return fmt.Sprintf("main-chain=%v(height %d) header-row=%v block-store=%v",
		l.OnMainChain, l.MainChainHeight, l.HeaderRow, l.InBlockStore)
}

// LocateForcedRollbackTrigger probes the persisted store for the targeted block.
//
// It is three point lookups, not a bucket walk, so it is affordable on every boot of
// a 25GB mainnet store. It returns nil when forced rollback is not configured.
func (b *BlockChain) LocateForcedRollbackTrigger() (*ForcedRollbackTriggerLocation, error) {
	if !b.forcedRollbackConfigured() {
		return nil, nil
	}
	hash, err := b.forcedRollbackTriggerHash()
	if err != nil {
		return nil, err
	}
	loc := &ForcedRollbackTriggerLocation{Hash: *hash}
	err = b.db.GetFFLDB().View(func(dbTx database.Tx) error {
		if height, herr := dbFetchHeightByHash(dbTx, hash); herr == nil {
			loc.OnMainChain = true
			loc.MainChainHeight = height
		}
		meta := dbTx.Metadata()
		hdrIdx := meta.Bucket(blockIndexBucketName)
		if hdrIdx == nil {
			return fmt.Errorf("forced rollback: bucket %q missing", blockIndexBucketName)
		}
		loc.HeaderRow = hdrIdx.Get(
			blockIndexKey(hash, b.chainParams.ForcedRollbackHeight+1)) != nil
		blkIdx := meta.Bucket(blockLocIndexBucketName)
		if blkIdx == nil {
			return fmt.Errorf("forced rollback: bucket %q missing", blockLocIndexBucketName)
		}
		loc.InBlockStore = blkIdx.Get(hash[:]) != nil
		return nil
	})
	if err != nil {
		return nil, err
	}
	return loc, nil
}

// forcedRollbackTriggerHeight resolves, from the PERSISTED store, the height the
// configured trigger block actually occupies. ok is false when the store cannot say,
// in which case no claim is made and the caller carries on unchanged.
//
// The header-index probe in LocateForcedRollbackTrigger is keyed on (hash, target+1),
// so a hit there IS target+1 by construction; the other two sources are read from the
// store itself.
func (b *BlockChain) forcedRollbackTriggerHeight(
	loc *ForcedRollbackTriggerLocation) (uint32, bool) {
	if loc == nil {
		return 0, false
	}
	if loc.OnMainChain {
		return loc.MainChainHeight, true
	}
	if loc.HeaderRow {
		return b.chainParams.ForcedRollbackHeight + 1, true
	}
	if loc.InBlockStore {
		if hdr, err := b.db.GetFFLDB().GetHeader(loc.Hash); err == nil && hdr != nil {
			return hdr.Height, true
		}
	}
	return 0, false
}

// announceForcedRollbackSettled turns ONCE-ONLY from a property of the code into a
// statement an operator can read off the console.
//
// The once-only property itself needs no new machinery and none is added here. Arming
// requires the block at ForcedRollbackHeight+1 to hash to the configured trigger, and
// the rewind is precisely the operation that removes that block, so the predicate that
// authorises the rewind is falsified BY the rewind; once the chain re-mines a
// different block at that height it is falsified twice over. What was missing is that
// a node in that state took every early return in this file and said NOTHING, leaving
// the operator to infer safety from an absence of output -- which is also what a
// binary that never ran the check looks like.
//
// The claim made here is deliberately exactly what the store supports: the CONFIGURED
// trigger is absent from all three persisted indexes, and (above the target) a named,
// different block occupies target+1. It does not claim the trigger is the right one --
// on mainnet that is guaranteed by the pin, not by this function.
func (b *BlockChain) announceForcedRollbackSettled(tip uint32) {
	target := b.chainParams.ForcedRollbackHeight
	if tip <= target {
		log.Operatorf("FORCED ROLLBACK: nothing to roll back on this node -- its tip is "+
			"%d, at or below the target %d, and the trigger block %s is absent from the "+
			"main-chain index, the block-header index and the raw block store. The "+
			"rewind will not run on this boot.",
			tip, target, b.chainParams.ForcedRollbackTrigger)
		return
	}
	occupant := "<unreadable>"
	if h, err := b.GetBlockHash(target + 1); err == nil {
		occupant = h.ReversedString()
	}
	log.Operatorf("FORCED ROLLBACK: ALREADY APPLIED -- and it will not run again. "+
		"Evidence from this node's store: the trigger block %s is absent from the "+
		"main-chain index, the block-header index and the raw block store, height %d "+
		"is now held by block %s instead, and the tip is %d. The rewind arms only "+
		"while the block at height %d hashes to the trigger, so it cannot arm on this "+
		"store; only restoring a pre-rollback copy of the data directory could put "+
		"that block back.",
		b.chainParams.ForcedRollbackTrigger, target+1, occupant, tip, target+1)
}

// VerifyForcedRollbackApplied is the boot-time post-condition. The armed flag says
// what was requested, not what was applied, so it must not be read as if it meant
// applied.
//
// It must be called on every boot where a forced rollback is configured, including
// the boots where nothing was armed, because "armed" is exactly the fact that stops
// being true the moment the rewind is declined or half-done, and it is the boots
// after that which matter.
//
// The severities are not the same:
//
//   - the trigger is still main-chain indexed. Either this node is un-rolled-back on
//     the exploit chain (a declined or skipped rewind), or a rewind was interrupted
//     before the block's rollback transaction committed. In both cases the UTXO and
//     derived-state processors for that block have not been reverted. The node must
//     not join the recovered network: refuse to start.
//   - the trigger survives only as a raw-store entry and/or an orphaned header row.
//     That is retention residue: the chain is consistent, but the node still serves
//     the exploit block by hash, which has been reproduced on a live node. Both
//     records are provably above the target, so remove exactly those two keys and
//     continue.
func (b *BlockChain) VerifyForcedRollbackApplied() error {
	d, err := b.DiagnoseForcedRollbackApplied()
	if err != nil {
		return err
	}
	switch d.State {
	case ApplyNotConfigured:
		return nil
	case ApplySettled:
		// The rollback is settled on this store. Say so, with the evidence: a silent
		// nil is indistinguishable from a binary that never looked.
		b.announceForcedRollbackSettled(d.Tip)
		return nil
	case ApplyTriggerHeightMismatch, ApplyTriggerOnMainChain:
		return d.Err
	}

	loc, target := d.Loc, d.Target

	// Retention residue only. Both keys are keyed on the trigger, whose height is
	// target+1 by construction, so a targeted removal can never touch retained
	// history and does not need the full store walk.
	log.Operatorf("FORCED ROLLBACK: the rolled-back block %s is off the main chain but "+
		"still %s; purging so this node cannot serve it by hash",
		loc.Hash.String(), loc.String())
	hash := loc.Hash
	if loc.HeaderRow {
		if err := b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
			return dbRemoveBlockNodeKey(dbTx, &hash, target+1)
		}); err != nil {
			return fmt.Errorf("forced rollback: remove residual header row for %s: %w",
				hash.String(), err)
		}
	}
	if loc.InBlockStore {
		if err := b.db.GetFFLDB().DeleteBlockFromStore(hash); err != nil {
			return fmt.Errorf("forced rollback: purge residual block %s: %w",
				hash.String(), err)
		}
	}

	// The purge is a claim about disk and the re-probe below reads through the ffldb
	// write cache, which would report the purge either way. Make it true first.
	if ferr := b.flushStore("the targeted trigger-block purge"); ferr != nil {
		return ferr
	}

	// Re-probe: the purge is only worth anything if it actually took.
	after, err := b.LocateForcedRollbackTrigger()
	if err != nil {
		return err
	}
	if after != nil && after.Present() {
		return fmt.Errorf("%w: block %s survived the targeted purge (%s)",
			ErrForcedRollbackNotApplied, hash.String(), after.String())
	}
	log.Operatorf("FORCED ROLLBACK: verified -- block %s is absent from the main-chain "+
		"index, the block-header index and the raw block store", hash.String())
	return nil
}

// PreflightForcedRollback is the pre-flight store scan on the ARMED path.
//
// Without it the armed path goes straight into the rewind, so a store already
// damaged by an earlier interrupted rollback, which is the state the header-row-first
// per-block ordering leaves behind, is only discovered mid-rewind.
//
// What that looks like (test/unit/b1b5_rollback_outcome_test.go, subtest
// `pristine-sequence-fails-opaquely`): the rewind aborts on an internal
// transaction-index assertion, "dbIndexDisconnectBlock must be called with the block
// at the current index tip", quoting two raw hashes. It fails closed, which is
// right, but with no sentinel to classify it and no remedy to act on.
//
// A second hazard is structural rather than measured: had the rewind reached its
// closing sweep, PurgeForcedRollbackResidue would have deleted the stale main-chain
// index entries of the blocks the rewind could never reach, leaving a store that
// looks clean while those blocks' UTXO and derived-state effects are still applied.
// Diagnosing before anything runs forecloses both.
//
// It runs before anything destructive and diagnoses the two states the rewind cannot
// fix, naming a remedy for each:
//
//   - main-chain records above the target that the in-RAM index does not carry, or a
//     persisted best-chain state above the loaded tip. The rewind walks b.Nodes, so
//     it structurally cannot reach those blocks.
//   - a block the rewind MUST visit whose body is no longer in the store, so its
//     rollback processors cannot be built at all.
//
// Retention-only residue (off-chain raw entries, orphaned header rows) is reported
// but is not an error: ForceRollback's closing sweep removes it.
//
// Caller must have verified ForcedRollbackArmed first.
func (b *BlockChain) PreflightForcedRollback() error {
	// The census and the classification live in DiagnoseForcedRollbackPreflight, so
	// that `ela-cli preflight` predicts this boot with the code that decides it
	// rather than with a copy of its conditions, and can report the scan this
	// scan already paid for instead of running a second one.
	d, err := b.DiagnoseForcedRollbackPreflight()
	if err != nil {
		return err
	}
	switch d.State {
	case RewindPreflightNotApplicable:
		return nil
	case RewindPreflightCapacitySkipped:
		// ForceRollback refuses on capacity before it touches anything, and that
		// refusal IS this node's diagnosis. Stopping here also bounds the
		// reachability set by maxHistoryCapacity rather than by an unbounded
		// tip-target: a node that ran far past the target must not be asked to
		// build a set proportional to how far it ran.
		log.Operatorf("FORCED ROLLBACK: pre-flight skipped -- depth %d already exceeds the "+
			"incremental rewind window %d, so the rewind refuses before doing anything "+
			"and this node will not start", d.Depth, maxHistoryCapacity)
		return nil
	case RewindPreflightDamaged:
		return d.Err
	}

	log.Operatorf("FORCED ROLLBACK: pre-flight OK -- %s; %d block(s) to rewind, every one "+
		"reachable from the loaded block index and complete in the store; anything "+
		"left over is retention residue and is swept by the rewind",
		d.Scan.Summary(), d.Depth)
	return nil
}

// ForcedRollbackPreflightState is what DiagnoseForcedRollbackPreflight found.
type ForcedRollbackPreflightState int

const (
	// RewindPreflightNotApplicable -- no rollback configured, or the tip is
	// already at or below the target.
	RewindPreflightNotApplicable ForcedRollbackPreflightState = iota
	// RewindPreflightCapacitySkipped -- the depth already exceeds the incremental
	// window, so ForceRollback refuses and nothing below is worth computing.
	RewindPreflightCapacitySkipped
	// RewindPreflightDamaged -- the store carries damage the rewind cannot repair.
	RewindPreflightDamaged
	// RewindPreflightOK -- every block the rewind must visit is reachable and
	// complete.
	RewindPreflightOK
)

// ForcedRollbackPreflightDiagnosis is the read-only result of the armed path's
// pre-flight scan.
type ForcedRollbackPreflightDiagnosis struct {
	State ForcedRollbackPreflightState
	// Scan is the store scan result, nil when no scan was taken.
	Scan               *ForcedRollbackStoreScan
	Tip, Target, Depth uint32
	// Orphaned are main-chain records above the target the loaded index cannot
	// reach; Bodyless are blocks the rewind must visit whose body is gone.
	Orphaned, Bodyless []ResidueRef
	// Err is EXACTLY the error PreflightForcedRollback returns when damaged.
	Err error
}

// DiagnoseForcedRollbackPreflight scans the store for the armed path without
// touching anything. Caller must have verified ForcedRollbackArmed first.
func (b *BlockChain) DiagnoseForcedRollbackPreflight() (
	*ForcedRollbackPreflightDiagnosis, error) {
	d := &ForcedRollbackPreflightDiagnosis{Target: b.chainParams.ForcedRollbackHeight}
	if !b.forcedRollbackConfigured() {
		return d, nil
	}
	target := d.Target
	if len(b.Nodes) == 0 {
		return nil, errors.New("forced rollback pre-flight: the block index is empty")
	}
	tip := uint32(len(b.Nodes) - 1)
	d.Tip = tip
	if tip <= target {
		return d, nil
	}
	d.Depth = tip - target
	if forcedRollbackExceedsCapacity(tip, target) {
		d.State = RewindPreflightCapacitySkipped
		return d, nil
	}

	scan, err := ScanForcedRollbackStore(b.db.GetFFLDB(), target)
	if err != nil {
		return nil, fmt.Errorf("forced rollback pre-flight: scan store: %w", err)
	}
	d.Scan = scan

	// reachable is exactly the set the rewind loop will visit: b.Nodes above target.
	reachable := make(map[common.Uint256]struct{}, tip-target)
	for h := target + 1; h <= tip; h++ {
		reachable[*b.Nodes[h].Hash] = struct{}{}
	}

	for _, ref := range scan.MainChainAbove {
		if _, ok := reachable[ref.Hash]; !ok {
			d.Orphaned = append(d.Orphaned, ref)
		}
	}
	if len(d.Orphaned) > 0 || scan.BestStateHeight > tip {
		d.State = RewindPreflightDamaged
		d.Err = fmt.Errorf("%w: the block database records %d block(s) above the "+
			"forced-rollback target %d as MAIN CHAIN that the loaded block index does "+
			"not carry (best-state height %d, loaded tip %d), so the rewind can never "+
			"visit them and their UTXO/derived-state effects can never be reverted. "+
			"This is the store an earlier rollback under the shipped ordering left "+
			"behind. %s Unreachable: %s",
			ErrForcedRollbackStoreDamaged, len(d.Orphaned), target, scan.BestStateHeight,
			tip, forcedRollbackRemedy, refsString(d.Orphaned))
		return d, nil
	}

	// Every block the rewind must visit needs its body: RollbackBlock is built from
	// the deserialized block, so a missing raw entry under a live main-chain index
	// aborts the rewind mid-flight instead of before it starts.
	for h := target + 1; h <= tip; h++ {
		node := b.Nodes[h]
		phase, perr := b.forcedRollbackPhase(node.Hash)
		if perr != nil {
			return nil, fmt.Errorf("forced rollback pre-flight: probe %d: %w", h, perr)
		}
		if phase.onMainChain && !phase.inStore {
			d.Bodyless = append(d.Bodyless, ResidueRef{Hash: *node.Hash, Height: h})
		}
	}
	if len(d.Bodyless) > 0 {
		d.State = RewindPreflightDamaged
		d.Err = fmt.Errorf("%w: %d block(s) above the target %d are still main-chain "+
			"indexed but no longer in the block store, so their rollback transactions "+
			"cannot be built. %s Missing bodies: %s",
			ErrForcedRollbackStoreDamaged, len(d.Bodyless), target, forcedRollbackRemedy,
			refsString(d.Bodyless))
		return d, nil
	}

	d.State = RewindPreflightOK
	return d, nil
}
