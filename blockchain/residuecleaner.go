// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"fmt"

	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"
)

// PurgeForcedRollbackResidue removes forced-rollback residue that lives ABOVE the
// rollback target: raw by-hash block-store entries (residue #2), orphaned
// block-header-index rows, and the stale main-chain index entries an INTERRUPTED
// rollback leaves behind. ForceRollback is idempotent and never re-fires once the
// tip is at/below the target, so without this a node keeps deserializing and
// serving discarded blocks by hash forever (P2P getdata / RPC getblock / HasBlock /
// IsBlockInStore).
//
// GUARD ORDERING -- this is the PURGE-GUARD fix. The shipped version kept an entry
// whenever `dbFetchHeightByHash` resolved, i.e. whenever the block was still in the
// main-chain hash->height index. But that is the very index RollbackBlock is
// responsible for deleting, so an above-target block whose entry survived -- which
// is EXACTLY the residue an interrupted rollback produces -- was classified
// "retained" and kept, and the sound height guard below it was never reached. On
// the live harness that ordering purged 0 of 7. The main-chain lookup is now a
// SKIP FILTER for retained history (height <= target) rather than a keep-decision,
// so the height guard is always the one that decides. See ScanForcedRollbackStore.
//
// Over-deletion is still impossible: every deletion below is driven by a ref whose
// height the scan read from the block's OWN header (or, for header rows, from the
// index key), and every category is filtered on `height > target`.
//
// PRECONDITION -- it refuses to run when the retained chain itself extends above
// the target, i.e. when a block above the target still has BOTH a header-index row
// and a fetchable block, which is what startup requires to load it into b.Nodes.
// That is what keeps this safe for the offline `ela-cli purgeresidue` command: run
// against a node that simply synced forward past the target, it now reports the
// mistake instead of dismantling a live chain. The old guard (1) provided that
// protection as a side effect; the precondition provides it explicitly, and unlike
// guard (1) it does not also protect the residue.
//
// It MUST be run with the node STOPPED (single ffldb/leveldb writer) unless it is
// called from the in-line ForceRollback sweep, which holds the only writer. It
// returns the number of raw-store entries purged. It never rewrites the flat files
// or moves the write cursor, so ffldb reconcileDB stays satisfied and the node
// resumes normally.
func PurgeForcedRollbackResidue(fflDB IFFLDBChainStore, target uint32) (int, error) {
	scan, err := ScanForcedRollbackStore(fflDB, target)
	if err != nil {
		return 0, err
	}

	if len(scan.LiveAbove) > 0 {
		return 0, fmt.Errorf("purge residue: refusing to run -- the retained chain "+
			"extends above the rollback target %d: %d block(s) above it still have "+
			"both a header-index row and a stored block, so this node is NOT rolled "+
			"back to that target (%s). Purging here would dismantle a live chain",
			target, len(scan.LiveAbove), refsString(scan.LiveAbove))
	}

	// Stale main-chain index entries above the target are not residue, and this
	// function must not remove them. They can only exist there when a rollback was
	// interrupted before its transaction committed, the transaction that also reverts
	// the UTXO and derived-state processors, so they are the diagnosis of a node no
	// cleanup can repair, and they are the diagnosis the boot path refuses on
	// (DiagnoseForcedRollbackResidue -> ResidueInterrupted).
	//
	// Deleting them hides that diagnosis. On the ffldb harness, with four above-target
	// blocks in the interrupted shape, `ela-cli purgeresidue` reports "purged 4 residual
	// block(s)" and exit 0, and the next boot's refusal, which still fires because the
	// persisted best-chain state is a second witness this function never touches,
	// degrades to "the block database still records 0 block(s) above the forced-rollback
	// target 2 as part of the MAIN CHAIN ... Residue: ", a self-contradictory sentence
	// with the hash list gone. The operator would be told the store was cleaned when the
	// un-reverted UTXO state that makes the node unusable is exactly what remains.
	//
	// Refusing costs nothing: the two in-process callers (ForceRollback's closing sweep,
	// and CheckForcedRollbackResidue's ResidueRetentionOnly branch) only reach this
	// function with MainChainAbove empty. The sweep runs after every above-target block
	// on the main chain has been rolled back, and the boot-time branch is selected by
	// `len(scan.MainChainAbove) == 0`.
	if len(scan.MainChainAbove) > 0 {
		return 0, fmt.Errorf("%w: refusing to purge -- the block database still "+
			"records %d block(s) above the rollback target %d as part of the MAIN "+
			"CHAIN (best-state height %d). That is the signature of an INTERRUPTED "+
			"rollback, not retention residue: those blocks' rollback transactions, "+
			"which also revert their UTXO and derived-state processors, never ran. "+
			"Deleting the index entries would remove the evidence and leave the "+
			"un-reverted state in place, so this node would look clean and be "+
			"corrupt. %s Main-chain entries: %s",
			ErrForcedRollbackStoreInconsistent, len(scan.MainChainAbove), target,
			scan.BestStateHeight, forcedRollbackRemedy,
			refsString(scan.MainChainAbove))
	}

	// Orphaned block-header-index rows. A row whose block is no longer in the store
	// is inert at startup (initChainState skips it), but leaving it behind means the
	// index that b.Nodes is rebuilt from disagrees with the retained chain.
	if len(scan.HeaderRowsAbove) > 0 {
		if err := fflDB.Update(func(dbTx database.Tx) error {
			for _, ref := range scan.HeaderRowsAbove {
				hash := ref.Hash
				if derr := dbRemoveBlockNodeKey(dbTx, &hash, ref.Height); derr != nil {
					return derr
				}
			}
			return nil
		}); err != nil {
			return 0, fmt.Errorf("purge residue: remove header rows: %w", err)
		}
		log.Warnf("[PurgeForcedRollbackResidue] removed %d orphaned block-header index "+
			"row(s) above target %d", len(scan.HeaderRowsAbove), target)
	}

	// Raw by-hash store entries. The flat-file (.fdb) bytes are left orphaned and
	// unfetchable on purpose (see DBRemoveBlockFromStore).
	for _, ref := range scan.StoredAbove {
		if derr := fflDB.DeleteBlockFromStore(ref.Hash); derr != nil {
			return 0, fmt.Errorf("purge residue: delete %s: %w", ref.Hash.String(), derr)
		}
		log.Warnf("[PurgeForcedRollbackResidue] purged residual block %s (height %d > %d)",
			ref.Hash.String(), ref.Height, target)
	}
	return len(scan.StoredAbove), nil
}
