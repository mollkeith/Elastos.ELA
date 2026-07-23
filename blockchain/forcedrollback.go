// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"errors"
	"fmt"

	"github.com/elastos/Elastos.ELA/common"
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

func (b *BlockChain) ForceRollback() error {
	target := b.chainParams.ForcedRollbackHeight
	start := uint32(len(b.Nodes) - 1)
	depth := start - target

	if depth >= maxHistoryCapacity {
		return fmt.Errorf("forced rollback depth %d exceeds history capacity %d; "+
			"refusing to rewind incrementally -- run `ela-cli rollback %d` below the target "+
			"then restart, or unset --forcedrollbacktrigger to disarm: %w",
			depth, maxHistoryCapacity, target, ErrForcedRollbackExceedsCapacity)
	}

	log.Warnf("FORCED ROLLBACK: rewinding chain store from height %d to %d (%d blocks)",
		start, target, depth)

	b.UTXOCache.CleanCache()

	for uint32(len(b.Nodes)-1) > target {
		i := len(b.Nodes) - 1
		node := b.Nodes[i]
		prevNode := b.Nodes[i-1]

		dposBlock, err := b.db.GetFFLDB().GetBlock(*node.Hash)
		if err != nil {
			return fmt.Errorf("forced rollback: get block at %d: %w", i, err)
		}

		// Permanently remove the block node from the DB block-index bucket. Unlike
		// disconnectBlock2, we DO check this error -- a swallowed failure on a
		// one-shot consensus rewind is unacceptable.
		if err := b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
			return DBRemoveBlockNode(dbTx, &dposBlock.Block.Header)
		}); err != nil {
			return fmt.Errorf("forced rollback: DBRemoveBlockNode at %d: %w", i, err)
		}

		if err := b.db.RollbackBlock(dposBlock.Block, node, dposBlock.Confirm,
			CalcPastMedianTime(prevNode)); err != nil {
			return fmt.Errorf("forced rollback: RollbackBlock %d: %w", i, err)
		}

		// Residue #2 purge -- MUST run AFTER RollbackBlock, not before. As shipped,
		// DBRemoveBlockNode + RollbackBlock clear the block-header index, the
		// main-chain height indexes and the tx-index siblings, but the raw by-hash
		// block store (ffldb-blockidx) is left behind: a rolled-back node still
		// deserialized and SERVED the discarded blocks by hash over P2P getdata /
		// RPC getblock, and reported them present via HasBlock / IsBlockInStore.
		//
		// The delete cannot move earlier: ChainStore.handleRollbackBlockTask re-fetches
		// the current block by hash (GetBlock(b.Hash())) as a precondition of the
		// rollback, so removing the ffldb-blockidx entry before RollbackBlock would make
		// the rollback itself fail. Running it here purges exactly the block that was
		// just rewound; later iterations only re-fetch lower (still-present) blocks.
		if err := b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
			return DBRemoveBlockFromStore(dbTx, node.Hash)
		}); err != nil {
			return fmt.Errorf("forced rollback: purge block store at %d: %w", i, err)
		}

		// The GetBlock above populated the in-RAM block LRU with this now-purged
		// hash; evict it so an in-process serve cannot return it before restart.
		b.db.GetFFLDB().EvictBlockCache(*node.Hash)

		// Reconcile the in-RAM index so no stale InMainChain=true node for a rewound
		// hash survives for this process's lifetime (disconnectBlock2 omitted this).
		b.index.RemoveNode(node)
		b.Nodes = b.Nodes[:i]
		b.BestChain = prevNode
		b.SetTip(prevNode)
		b.MedianTimePast = CalcPastMedianTime(prevNode)

		if i%100 == 0 || uint32(i) == target+1 {
			log.Warnf("FORCED ROLLBACK: block store at height %d", i-1)
		}
	}

	log.Warnf("FORCED ROLLBACK: block store rewound to %d; derived state will be "+
		"rebuilt by InitCheckpoint from a pre-target snapshot (asserted < target)",
		len(b.Nodes)-1)
	return nil
}
