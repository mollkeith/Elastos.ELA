// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"
)

// ForcedRollbackArmed reports whether this node holds the chain the forced
// rollback targets.
//
// It requires BOTH that the local tip is above the rollback height AND that the
// block immediately above that height hashes to the configured trigger. The hash
// condition is what makes the operation safe:
//
//   - it fires only on a node that actually holds the bad chain,
//   - it is idempotent, because after the rewind that block no longer exists,
//   - it is a no-op for a freshly syncing node, which never accepts the block in
//     the first place once strict validation is active above the rollback height.
//
// It is ALSO the resume predicate. Because the per-block rewind now removes a
// block's header-index row LAST (see rollbackOneBlock), an interrupted rewind
// leaves every not-yet-finished block still in b.Nodes, so this predicate is still
// true on the next boot and the rewind picks up exactly where it stopped. Under
// the shipped ordering the header row was removed FIRST, so each interruption
// silently shrank b.Nodes by one block without rolling it back, and after
// (tip-target) restarts this predicate went false with none of the discarded
// blocks actually rolled back.
func (b *BlockChain) ForcedRollbackArmed() (bool, error) {
	target := b.chainParams.ForcedRollbackHeight
	trigger := b.chainParams.ForcedRollbackTrigger
	if trigger == "" || target == 0 {
		return false, nil
	}
	if uint32(len(b.Nodes)-1) <= target {
		return false, nil
	}

	// The config trigger is written in DISPLAY (explorer/RPC) byte order so an
	// operator can verify it against a block explorer. Block hashes are stored
	// internally in the reversed order, so parse the trigger reversed before
	// comparing. Using the non-reversed parse here silently disarms the rollback
	// (armed=false) and leaves the node on the corrupt chain.
	triggerHash, err := common.Uint256FromReversedHexString(trigger)
	if err != nil {
		return false, fmt.Errorf("forced rollback: bad trigger hash %q: %w", trigger, err)
	}
	// Deliberately does not log: this is a pure predicate, and it runs before
	// logging is guaranteed to be initialised. The caller reports the outcome.
	return b.Nodes[target+1].Hash.IsEqual(*triggerHash), nil
}

// ForceRollback rewinds the chain to the configured ForcedRollbackHeight.
//
// Architecture (option "d"): it rewinds the block store to the target and stops.
// It deliberately does NOT reprocess the rolled-back blocks (2260451..tip) through
// the derived-state accumulation path. The caller's later InitCheckpoint restores a
// checkpoint snapshot (which, by the save invariant, always lags the tip by
// EffectivePeriod=720 and is therefore strictly below this target and pre-exploit)
// and replays forward ONLY up to the rewound tip. Consequence, and the reason this
// architecture is preferred over "build-forward-then-unwind": the attacker's
// exploit-era transactions are never re-run through the unchecked vote/stake
// accumulation path on any node at startup. This is unconditionally safe rather than
// contingent on "no exploit-era stake/vote existed".
//
// Correctness is a theorem, not an accident of the current tip: default_snapshot <=
// tip-720 (save invariant) and depth<720 (the guard below) => the restored baseline
// is < target <= exploit_block on every conforming node; replay always re-derives to
// the rewound tip. main.go asserts SafeHeight() < ForcedRollbackHeight after
// InitCheckpoint, which fails the node loudly if an anomalous snapshot (e.g.
// hand-edited) ever sat at/above the target.
//
// UNPROVEN: derived-state CONTENT correctness after rebuild is validated only by the
// testnet reproduction (compare the arbiter/CR set at the target against a node
// freshly synced to that height). Treat that as a hard gate before production.
//
// Caller must have verified ForcedRollbackArmed first.

// ErrForcedRollbackExceedsCapacity is returned when this node's tip is more than
// the incremental-rewind window (maxHistoryCapacity) past the rollback target, so
// the auto-rollback cannot proceed without violating the pre-target-checkpoint
// baseline. It is operator-actionable, NOT fatal.
var ErrForcedRollbackExceedsCapacity = errors.New("forced rollback depth exceeds history capacity")

// ErrForcedRollbackInterrupted is returned when the operator interrupts the rewind.
// It is NOT a corruption report: the rewind is resumable by construction, so the
// remedy is simply to restart the node and let it continue.
var ErrForcedRollbackInterrupted = errors.New("forced rollback interrupted by operator")

// forcedRollbackMarkerKeyName is the ffldb metadata key holding the durable
// "a forced rollback is in progress" marker.
//
// The marker is a DIAGNOSTIC, not the correctness mechanism. Correctness rests on
// the per-block ordering (a block's header-index row is deleted only after all of
// its destructive work is durably committed) and on the phase probe, both of which
// work on a store written by the SHIPPED binary, which never wrote a marker. The
// marker's job is to make an interrupted rewind self-describing in the logs and to
// let the node say "resuming" rather than silently starting over.
var forcedRollbackMarkerKeyName = []byte("forcedrollbackinprogress")

// forcedRollbackMarkerVersion prefixes the marker so its layout can change.
const forcedRollbackMarkerVersion byte = 1

// forcedRollbackMarkerLen is version(1) + target(4) + start(4).
const forcedRollbackMarkerLen = 9

// ForcedRollbackMarker is the durable record of an in-progress forced rollback.
type ForcedRollbackMarker struct {
	// Target is the height the rewind is heading for.
	Target uint32
	// Start is the tip height the rewind began from, so progress can be reported
	// across restarts.
	Start uint32
}

// ReadForcedRollbackMarker returns the durable in-progress marker, or nil.
func (b *BlockChain) ReadForcedRollbackMarker() (*ForcedRollbackMarker, error) {
	var marker *ForcedRollbackMarker
	err := b.db.GetFFLDB().View(func(dbTx database.Tx) error {
		raw := dbTx.Metadata().Get(forcedRollbackMarkerKeyName)
		if raw == nil {
			return nil
		}
		if len(raw) != forcedRollbackMarkerLen || raw[0] != forcedRollbackMarkerVersion {
			return fmt.Errorf("forced rollback: unreadable in-progress marker "+
				"(%d bytes, version %d)", len(raw), raw[0])
		}
		marker = &ForcedRollbackMarker{
			Target: byteOrder.Uint32(raw[1:5]),
			Start:  byteOrder.Uint32(raw[5:9]),
		}
		return nil
	})
	return marker, err
}

// writeForcedRollbackMarker records that a rewind is under way.
func (b *BlockChain) writeForcedRollbackMarker(target, start uint32) error {
	raw := make([]byte, forcedRollbackMarkerLen)
	raw[0] = forcedRollbackMarkerVersion
	byteOrder.PutUint32(raw[1:5], target)
	byteOrder.PutUint32(raw[5:9], start)
	return b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Put(forcedRollbackMarkerKeyName, raw)
	})
}

// ClearForcedRollbackMarker removes the in-progress marker. It is exported because
// the boot path clears it once the PERSISTED store has been verified clean, which
// is the only point at which "in progress" is provably false.
func (b *BlockChain) ClearForcedRollbackMarker() error {
	return b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Delete(forcedRollbackMarkerKeyName)
	})
}

// forcedRollbackProgressSteps is how many progress lines a full rewind emits. The
// real mainnet rewind is 145 blocks over a 25GB store and the shipped code logged
// every 100th height, i.e. about two lines for the whole operation -- the shape
// that invites an operator to assume the node has hung and press Ctrl-C.
const forcedRollbackProgressSteps = 20

// blockRollbackPhase describes how much of one block's rewind is already durable,
// read from the database itself rather than from any marker. It is what makes the
// rewind exactly-once under repeated interruption: the shipped code re-ran every
// step unconditionally, and re-running RollbackBlock re-applies the per-transaction
// rollback processors, which are not idempotent.
type blockRollbackPhase struct {
	// onMainChain is true while the block still has a hash->height main-chain
	// index entry, which RollbackBlock deletes in the SAME atomic transaction as
	// the UTXO/state rollback processors. Its presence therefore proves the
	// rollback transaction has not committed; its absence proves it has.
	onMainChain bool
	// inStore is true while the block is still fetchable by hash.
	inStore bool
}

// forcedRollbackPhase probes the persisted store for one block's rewind phase.
func (b *BlockChain) forcedRollbackPhase(hash *common.Uint256) (blockRollbackPhase, error) {
	var phase blockRollbackPhase
	err := b.db.GetFFLDB().View(func(dbTx database.Tx) error {
		if _, herr := dbFetchHeightByHash(dbTx, hash); herr == nil {
			phase.onMainChain = true
		}
		idx := dbTx.Metadata().Bucket(blockLocIndexBucketName)
		if idx == nil {
			return fmt.Errorf("forced rollback: bucket %q missing",
				blockLocIndexBucketName)
		}
		phase.inStore = idx.Get(hash[:]) != nil
		return nil
	})
	return phase, err
}

// rollbackOneBlock durably discards exactly one block from the tip.
//
// ORDERING IS THE FIX. The shipped sequence was three separate database
// transactions in the order
//
//	T1 DBRemoveBlockNode  ->  T2 RollbackBlock  ->  T3 DBRemoveBlockFromStore
//
// and T1 destroys the block-header-index row that b.Nodes is rebuilt from at
// startup (chainio.go initChainState), while b.Nodes drives BOTH the arming
// predicate and the rewind loop's bound. An interruption or a T2 error between T1
// and T2 therefore made that block permanently un-rollbackable, and because
// main.go exits on the error, each operator restart ate one more header row until
// the node booted silently at exactly the target with none of the discarded blocks
// rolled back -- on mainnet that residue includes block 2,260,451, the exploit
// block. PROVEN on a live ffldb harness.
//
// The sequence is now
//
//	RollbackBlock  ->  DBRemoveBlockFromStore  ->  DBRemoveBlockNode
//
// so the header row survives until every destructive step for that block is
// durably committed. It is therefore itself the durable resume marker: whatever
// point an interruption lands on, the block is still in b.Nodes on the next boot,
// the node is still armed, and the rewind re-attempts it.
//
// Re-attempting is exactly-once because each step is skipped when the store shows
// it already committed. That matters most for RollbackBlock, which runs the
// per-transaction rollback processors inside the same atomic transaction that
// deletes the main-chain index entry -- so "still main-chain indexed" is a sound,
// self-describing proof that those processors have not run.
//
// Two constraints pin the middle step's position and are preserved:
// DBRemoveBlockFromStore cannot move BEFORE RollbackBlock, because
// ChainStore.handleRollbackBlockTask re-fetches the block by hash as a
// precondition; and it must happen at all, because RollbackBlock leaves the raw
// by-hash entry behind (residue #2) and a rolled-back node would otherwise keep
// serving the discarded blocks over P2P getdata / RPC getblock.
func (b *BlockChain) rollbackOneBlock(node, prevNode *BlockNode) error {
	fflDB := b.db.GetFFLDB()

	phase, err := b.forcedRollbackPhase(node.Hash)
	if err != nil {
		return fmt.Errorf("forced rollback: probe phase at %d: %w", node.Height, err)
	}

	// STEP 1 -- the rollback transaction (block state, main-chain index and the
	// per-transaction rollback processors, all atomically).
	if phase.onMainChain {
		if !phase.inStore {
			// Unreachable through this function's own ordering (the store entry is
			// removed only after the rollback commits, which clears onMainChain).
			// It can only mean the raw entry was removed by something else, and
			// without the block body the rollback processors cannot be built.
			return fmt.Errorf("forced rollback: block %s at height %d is still "+
				"main-chain indexed but no longer in the block store, so its "+
				"rollback cannot be built; restore a pre-rollback backup or wipe "+
				"and resync", node.Hash.String(), node.Height)
		}
		dposBlock, gerr := fflDB.GetBlock(*node.Hash)
		if gerr != nil {
			return fmt.Errorf("forced rollback: get block at %d: %w", node.Height, gerr)
		}
		if rerr := b.db.RollbackBlock(dposBlock.Block, node, dposBlock.Confirm,
			CalcPastMedianTime(prevNode)); rerr != nil {
			return fmt.Errorf("forced rollback: RollbackBlock %d: %w", node.Height, rerr)
		}
	} else {
		log.Warnf("FORCED ROLLBACK: resuming -- block %d was already rolled back by "+
			"an earlier, interrupted run; skipping its rollback transaction",
			node.Height)
	}

	// STEP 2 -- residue #2 purge. RollbackBlock clears the block-header index, the
	// main-chain height indexes and the tx-index siblings, but leaves the raw
	// by-hash block store (ffldb-blockidx) behind: a rolled-back node still
	// deserialized and SERVED the discarded blocks by hash over P2P getdata / RPC
	// getblock, and reported them present via HasBlock / IsBlockInStore.
	if phase.inStore {
		if perr := fflDB.Update(func(dbTx database.Tx) error {
			return DBRemoveBlockFromStore(dbTx, node.Hash)
		}); perr != nil {
			return fmt.Errorf("forced rollback: purge block store at %d: %w",
				node.Height, perr)
		}
		// A fetch above may have populated the in-RAM block LRU with this
		// now-purged hash; evict it so an in-process serve cannot return it.
		fflDB.EvictBlockCache(*node.Hash)
	}

	// STEP 3 -- and only now the header-index row, which is what makes every step
	// above re-attemptable across an interruption. Keyed by hash+height directly
	// rather than by a re-parsed header, because after step 2 the block body is no
	// longer fetchable; blockIndexKey uses exactly these two values, and the
	// BlockNode carries both. Unlike disconnectBlock2, the error is checked -- a
	// swallowed failure on a one-shot consensus rewind is unacceptable.
	if err := fflDB.Update(func(dbTx database.Tx) error {
		return dbRemoveBlockNodeKey(dbTx, node.Hash, node.Height)
	}); err != nil {
		return fmt.Errorf("forced rollback: DBRemoveBlockNode at %d: %w",
			node.Height, err)
	}
	return nil
}

// ForceRollback rewinds the chain store to the configured ForcedRollbackHeight.
//
// interrupt may be nil. When it is signalled the rewind stops at a block boundary
// and returns ErrForcedRollbackInterrupted; because each block's rewind is
// crash-atomic in effect (see rollbackOneBlock), restarting resumes it.
func (b *BlockChain) ForceRollback(interrupt <-chan struct{}) error {
	target := b.chainParams.ForcedRollbackHeight
	if len(b.Nodes) == 0 {
		return errors.New("forced rollback: the block index is empty")
	}
	start := uint32(len(b.Nodes) - 1)
	if start <= target {
		// Nothing to rewind. Guarded explicitly because `start - target` is unsigned
		// and would otherwise wrap into an enormous depth.
		return nil
	}
	depth := start - target

	if depth >= maxHistoryCapacity {
		return fmt.Errorf("forced rollback depth %d exceeds history capacity %d; "+
			"refusing to rewind incrementally -- run `ela-cli rollback %d` below the target "+
			"then restart, or unset --forcedrollbacktrigger to disarm: %w",
			depth, maxHistoryCapacity, target, ErrForcedRollbackExceedsCapacity)
	}

	// The marker is written BEFORE anything destructive, so an interrupted run is
	// self-describing on the next boot. A marker from an earlier, interrupted run
	// is expected here; only a marker for a DIFFERENT target is a red flag.
	if marker, merr := b.ReadForcedRollbackMarker(); merr != nil {
		return merr
	} else if marker != nil {
		if marker.Target != target {
			return fmt.Errorf("forced rollback: the store carries an in-progress "+
				"marker for target %d (started at %d) but this node is configured "+
				"for target %d; refusing to mix two rollbacks -- restore a backup "+
				"or wipe and resync", marker.Target, marker.Start, target)
		}
		log.Warnf("FORCED ROLLBACK: RESUMING an interrupted rewind -- original start "+
			"height %d, target %d, %d block(s) still to discard",
			marker.Start, marker.Target, depth)
	} else if werr := b.writeForcedRollbackMarker(target, start); werr != nil {
		return fmt.Errorf("forced rollback: write in-progress marker: %w", werr)
	}

	log.Warnf("FORCED ROLLBACK: rewinding chain store from height %d to %d (%d blocks). "+
		"This is a one-shot consensus rewind over the whole block store and may take "+
		"a long time on a large database. It is RESUMABLE: if it is interrupted, "+
		"restart the node and it continues from where it stopped.", start, target, depth)

	b.UTXOCache.CleanCache()

	logEvery := depth / forcedRollbackProgressSteps
	if logEvery == 0 {
		logEvery = 1
	}
	began := time.Now()

	for uint32(len(b.Nodes)-1) > target {
		// Interrupt at a BLOCK BOUNDARY only, so the store is never left mid-block
		// by a deliberate stop.
		select {
		case <-interrupt:
			done := start - uint32(len(b.Nodes)-1)
			return fmt.Errorf("%w after %d of %d block(s); the rewind is resumable -- "+
				"restart the node to continue (do NOT roll back or resync manually)",
				ErrForcedRollbackInterrupted, done, depth)
		default:
		}

		i := len(b.Nodes) - 1
		node := b.Nodes[i]
		prevNode := b.Nodes[i-1]

		if err := b.rollbackOneBlock(node, prevNode); err != nil {
			return err
		}

		// Reconcile the in-RAM index so no stale InMainChain=true node for a rewound
		// hash survives for this process's lifetime (disconnectBlock2 omitted this).
		b.index.RemoveNode(node)
		b.Nodes = b.Nodes[:i]
		b.BestChain = prevNode
		b.SetTip(prevNode)
		b.MedianTimePast = CalcPastMedianTime(prevNode)

		done := start - uint32(i-1)
		if done%uint32(logEvery) == 0 || uint32(i) == target+1 || done == 1 {
			log.Warnf("FORCED ROLLBACK: %d/%d blocks discarded (%d%%), store tip now %d, "+
				"elapsed %s", done, depth, done*100/depth, i-1,
				time.Since(began).Truncate(time.Second))
		}
	}

	// The per-iteration purge above walks only the accepted main chain (b.Nodes), so
	// it reaches every discarded block that was ON the best chain -- including the
	// exploit block. But a block can be StoreBlock'd above the target WITHOUT ever
	// joining the main chain: an orphan / side block (e.g. a child of the discarded
	// tip). Such blocks are absent from b.Nodes, so the loop structurally cannot reach
	// them, yet they remain fetchable by hash (ffldb-blockidx) and would be served just
	// like the main-chain residue. Sweep them with the SAME complete scan the offline
	// cleaner uses, so the in-line purge reaches exact clean-forward-sync parity on the
	// raw block store rather than being off by the orphan count. DeleteBlockFromStore
	// also evicts the RAM cache, so this is safe on the running node.
	if swept, serr := PurgeForcedRollbackResidue(b.db.GetFFLDB(), target); serr != nil {
		return fmt.Errorf("forced rollback: sweep above-target orphan residue: %w", serr)
	} else if swept > 0 {
		log.Warnf("FORCED ROLLBACK: swept %d above-target orphan/side block(s) that were "+
			"stored but never on the main chain", swept)
	}

	// The rewind is complete only once the PERSISTED store agrees. This is the
	// assertion main.go's height check could not make: chain.GetHeight() is
	// len(b.Nodes)-1, so comparing it against the target restates the loop's own
	// exit condition and can never fail.
	if verr := b.VerifyForcedRollbackComplete(); verr != nil {
		return verr
	}
	if cerr := b.ClearForcedRollbackMarker(); cerr != nil {
		return fmt.Errorf("forced rollback: clear in-progress marker: %w", cerr)
	}

	log.Warnf("FORCED ROLLBACK: block store rewound to %d in %s; derived state will be "+
		"rebuilt by InitCheckpoint from a pre-target snapshot (asserted < target)",
		len(b.Nodes)-1, time.Since(began).Truncate(time.Second))
	return nil
}

// VerifyForcedRollbackComplete asserts, against the PERSISTED store, that nothing
// above the rollback target survives in any index: no main-chain entry, no
// header-index row, no raw by-hash entry, and a best-chain state no higher than the
// target. It is the post-rewind safety net.
func (b *BlockChain) VerifyForcedRollbackComplete() error {
	target := b.chainParams.ForcedRollbackHeight
	scan, err := ScanForcedRollbackStore(b.db.GetFFLDB(), target)
	if err != nil {
		return fmt.Errorf("forced rollback: verify store: %w", err)
	}
	tip := uint32(len(b.Nodes) - 1)
	if tip != target {
		return fmt.Errorf("forced rollback: loaded chain tip is %d, expected exactly %d",
			tip, target)
	}
	if !scan.Clean() {
		return fmt.Errorf("%w: the rewind reported success but the persisted store "+
			"still holds data above the target (%s). main-chain: %s | stored: %s | "+
			"header rows: %s", ErrForcedRollbackStoreInconsistent, scan.Summary(),
			refsString(scan.MainChainAbove), refsString(scan.StoredAbove),
			refsString(scan.HeaderRowsAbove))
	}
	log.Warnf("FORCED ROLLBACK: persisted store verified clean above target %d "+
		"(best-state height %d)", target, scan.BestStateHeight)
	return nil
}

// CheckForcedRollbackResidue is the safety net for the boot where the rollback is
// NOT armed but the node sits at or below the target -- which is precisely the boot
// a ratcheted node comes up on, and precisely the boot both shipped safety nets
// skipped (one was tautological, the other was guarded by `if forcedRollbackFired`).
//
// It separates the two severities the store can show:
//
//   - main-chain records above the target, or a best-chain state above the target,
//     while the loaded tip is not: an interrupted rollback whose UTXO/derived-state
//     processors never ran. Unrepairable -> refuse to start.
//   - raw-store entries or orphaned header rows only: retention residue, which is
//     safely removable -> purge and continue. This is also the case for a node that
//     rolled back correctly under a binary that did not purge the block store, which
//     until now only the offline `ela-cli purgeresidue` command could reach.
//
// It must only be called when a forced rollback is configured for this network.
func (b *BlockChain) CheckForcedRollbackResidue() error {
	target := b.chainParams.ForcedRollbackHeight
	// Intrinsic guard, so the scan can never be provoked on a network where forced
	// rollback is inactive (the disabled sentinel is math.MaxUint32, which would
	// otherwise satisfy every `tip <= target` test and pay for a full store walk).
	if b.chainParams.ForcedRollbackTrigger == "" || target == 0 ||
		target == config.DisabledForcedRollbackHeight {
		return nil
	}
	if len(b.Nodes) == 0 {
		return nil
	}
	tip := uint32(len(b.Nodes) - 1)
	if tip > target {
		// The node legitimately holds blocks above the target (it is on a different
		// chain, or has already resynced forward). Nothing to assert.
		return nil
	}

	scan, err := ScanForcedRollbackStore(b.db.GetFFLDB(), target)
	if err != nil {
		return fmt.Errorf("forced rollback: scan store: %w", err)
	}
	if len(scan.MainChainAbove) > 0 || scan.BestStateHeight > target {
		return interruptedRollbackError(scan, tip)
	}
	if len(scan.StoredAbove) > 0 || len(scan.HeaderRowsAbove) > 0 {
		log.Warnf("FORCED ROLLBACK: node is at height %d (target %d) but the store still "+
			"holds %d discarded block(s) and %d orphaned header row(s) above the target; "+
			"purging (retention residue only -- the main chain is consistent)",
			tip, target, len(scan.StoredAbove), len(scan.HeaderRowsAbove))
		purged, perr := PurgeForcedRollbackResidue(b.db.GetFFLDB(), target)
		if perr != nil {
			return fmt.Errorf("forced rollback: purge residue at boot: %w", perr)
		}
		log.Warnf("FORCED ROLLBACK: purged %d residual block(s) above target %d",
			purged, target)
	}
	if marker, merr := b.ReadForcedRollbackMarker(); merr == nil && marker != nil {
		log.Warnf("FORCED ROLLBACK: clearing a stale in-progress marker (target %d, "+
			"start %d); the persisted store is verified clean above the target",
			marker.Target, marker.Start)
		if cerr := b.ClearForcedRollbackMarker(); cerr != nil {
			return fmt.Errorf("forced rollback: clear stale marker: %w", cerr)
		}
	}
	return nil
}
