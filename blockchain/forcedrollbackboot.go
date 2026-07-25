// Copyright (c) 2017-2020 The Elastos Foundation
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

// VerifyForcedRollbackApplied is the boot-time post-condition that replaces reading
// the ARMED flag as if it meant APPLIED.
//
// It must be called on every boot where a forced rollback is configured -- including
// the boots where nothing was armed -- because "armed" is exactly the fact that stops
// being true the moment the rewind is declined or half-done, and it is the boots
// after that which matter.
//
// The severities are not the same:
//
//   - the trigger is still MAIN-CHAIN INDEXED. Either this node is un-rolled-back on
//     the exploit chain (a declined or skipped rewind), or a rewind was interrupted
//     before the block's rollback transaction committed. In both cases the
//     UTXO/derived-state processors for that block have not been reverted. The node
//     must NOT join the recovered network: refuse to start.
//   - the trigger survives only as a raw-store entry and/or an orphaned header row.
//     That is retention residue: the chain is consistent, but the node still SERVES
//     the exploit block by hash (PROVEN live). Both records are provably above the
//     target, so remove exactly those two keys and continue.
func (b *BlockChain) VerifyForcedRollbackApplied() error {
	if !b.forcedRollbackConfigured() {
		return nil
	}
	loc, err := b.LocateForcedRollbackTrigger()
	if err != nil {
		return err
	}
	if loc == nil || !loc.Present() {
		return nil
	}

	target := b.chainParams.ForcedRollbackHeight
	var tip uint32
	if len(b.Nodes) > 0 {
		tip = uint32(len(b.Nodes) - 1)
	}

	if loc.OnMainChain {
		cause := "an INTERRUPTED rewind that never committed this block's rollback " +
			"transaction"
		if tip > target {
			cause = "a rewind that was DECLINED or never ran -- this node is still on " +
				"the chain the recovery removes"
		}
		return fmt.Errorf("%w: block %s is still recorded on the MAIN CHAIN at height "+
			"%d (loaded tip %d, rollback target %d). Signature of %s. Its UTXO and "+
			"derived-state processors have not been reverted, so this node would join "+
			"the recovered network on the exploit chain and stall it -- refusing to "+
			"start. %s Rewinding manually first also works: stop the node and, from "+
			"its working directory, run `ela-cli rollback --height %d --datadir <your "+
			"data dir>` (the --height FLAG is required; a bare positional height "+
			"prints help and does nothing), then restart.",
			ErrForcedRollbackNotApplied, loc.Hash.String(), loc.MainChainHeight, tip,
			target, cause, forcedRollbackRemedy, target)
	}

	// Retention residue only. Both keys are keyed on the trigger, whose height is
	// target+1 by construction, so a targeted removal can never touch retained
	// history and does not need the full store walk.
	log.Warnf("FORCED ROLLBACK: the rolled-back block %s is off the main chain but "+
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

	// Re-probe: the purge is only worth anything if it actually took.
	after, err := b.LocateForcedRollbackTrigger()
	if err != nil {
		return err
	}
	if after != nil && after.Present() {
		return fmt.Errorf("%w: block %s survived the targeted purge (%s)",
			ErrForcedRollbackNotApplied, hash.String(), after.String())
	}
	log.Warnf("FORCED ROLLBACK: verified -- block %s is absent from the main-chain "+
		"index, the block-header index and the raw block store", hash.String())
	return nil
}

// PreflightForcedRollback is the pre-flight store scan on the ARMED path.
//
// Until now the armed path went straight into the rewind, so a store already damaged
// by an earlier interrupted rollback -- the state the SHIPPED per-block ordering
// leaves behind -- was only discovered mid-rewind.
//
// MEASURED (test/unit/b1b5_rollback_outcome_test.go, subtest
// `pristine-sequence-fails-opaquely`): the rewind aborts on an internal
// transaction-index assertion, "dbIndexDisconnectBlock must be called with the block
// at the current index tip", quoting two raw hashes. It fails CLOSED, which is
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
	if !b.forcedRollbackConfigured() {
		return nil
	}
	target := b.chainParams.ForcedRollbackHeight
	if len(b.Nodes) == 0 {
		return errors.New("forced rollback pre-flight: the block index is empty")
	}
	tip := uint32(len(b.Nodes) - 1)
	if tip <= target {
		return nil
	}
	if depth := tip - target; depth >= maxHistoryCapacity {
		// ForceRollback refuses on capacity before it touches anything, and that
		// refusal IS this node's diagnosis. Returning here also bounds everything
		// below by maxHistoryCapacity rather than by an unbounded tip-target: a node
		// that ran far past the target must not be asked to build a reachability set
		// proportional to how far it ran.
		log.Warnf("FORCED ROLLBACK: pre-flight skipped -- depth %d already exceeds the "+
			"incremental rewind window %d, so the rewind refuses before doing anything "+
			"and this node will not start", depth, maxHistoryCapacity)
		return nil
	}

	scan, err := ScanForcedRollbackStore(b.db.GetFFLDB(), target)
	if err != nil {
		return fmt.Errorf("forced rollback pre-flight: scan store: %w", err)
	}

	// reachable is exactly the set the rewind loop will visit: b.Nodes above target.
	reachable := make(map[common.Uint256]struct{}, tip-target)
	for h := target + 1; h <= tip; h++ {
		reachable[*b.Nodes[h].Hash] = struct{}{}
	}

	var orphaned []ResidueRef
	for _, ref := range scan.MainChainAbove {
		if _, ok := reachable[ref.Hash]; !ok {
			orphaned = append(orphaned, ref)
		}
	}
	if len(orphaned) > 0 || scan.BestStateHeight > tip {
		return fmt.Errorf("%w: the block database records %d block(s) above the "+
			"forced-rollback target %d as MAIN CHAIN that the loaded block index does "+
			"not carry (best-state height %d, loaded tip %d), so the rewind can never "+
			"visit them and their UTXO/derived-state effects can never be reverted. "+
			"This is the store an earlier rollback under the shipped ordering left "+
			"behind. %s Unreachable: %s",
			ErrForcedRollbackStoreDamaged, len(orphaned), target, scan.BestStateHeight,
			tip, forcedRollbackRemedy, refsString(orphaned))
	}

	// Every block the rewind must visit needs its body: RollbackBlock is built from
	// the deserialized block, so a missing raw entry under a live main-chain index
	// aborts the rewind mid-flight instead of before it starts.
	var bodyless []ResidueRef
	for h := target + 1; h <= tip; h++ {
		node := b.Nodes[h]
		phase, perr := b.forcedRollbackPhase(node.Hash)
		if perr != nil {
			return fmt.Errorf("forced rollback pre-flight: probe %d: %w", h, perr)
		}
		if phase.onMainChain && !phase.inStore {
			bodyless = append(bodyless, ResidueRef{Hash: *node.Hash, Height: h})
		}
	}
	if len(bodyless) > 0 {
		return fmt.Errorf("%w: %d block(s) above the target %d are still main-chain "+
			"indexed but no longer in the block store, so their rollback transactions "+
			"cannot be built. %s Missing bodies: %s",
			ErrForcedRollbackStoreDamaged, len(bodyless), target, forcedRollbackRemedy,
			refsString(bodyless))
	}

	log.Warnf("FORCED ROLLBACK: pre-flight OK -- %s; %d block(s) to rewind, every one "+
		"reachable from the loaded block index and complete in the store; anything "+
		"left over is retention residue and is swept by the rewind",
		scan.Summary(), tip-target)
	return nil
}
