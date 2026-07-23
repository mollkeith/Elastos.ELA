// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"fmt"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/database"
)

// PurgeForcedRollbackResidue removes forced-rollback block-store residue
// (residue #2) from an ALREADY-rolled-back node, which the in-line ForceRollback
// purge cannot reach. ForceRollback is idempotent and never re-fires once the tip
// is at/below the target, so any ffldb-blockidx entry a node kept from a prior
// rollback -- shipped code that never purged the store, or a crash between the
// rollback transaction and the in-line purge -- would otherwise be deserialized and
// served by hash forever (P2P getdata / RPC getblock / HasBlock / IsBlockInStore).
//
// It enumerates the raw by-hash block store (ffldb-blockidx) and deletes an entry
// iff BOTH:
//
//	(1) it is NOT on the retained main chain (absent from the hash->height index), AND
//	(2) the block's own header height is strictly greater than target.
//
// The double guard removes exactly the discarded blocks above the rollback height
// (including the exploit block) and PROVABLY never touches a <= target entry: guard
// (2) keeps everything at/below target even if guard (1) somehow matched, and blocks
// still on the main chain are kept by guard (1). The flat-file (.fdb) bytes are left
// orphaned/unfetchable (see DBRemoveBlockFromStore).
//
// It MUST be run with the node STOPPED (single ffldb/leveldb writer). It returns the
// number of entries purged. It never rewrites the flat files or moves the write
// cursor, so ffldb reconcileDB stays satisfied and the node resumes normally.
func PurgeForcedRollbackResidue(fflDB IFFLDBChainStore, target uint32) (int, error) {
	var toDelete []common.Uint256

	// Read pass: collect the residue hashes. Deleting during ForEach iteration is
	// unsafe, so nothing is mutated here.
	err := fflDB.View(func(dbTx database.Tx) error {
		idx := dbTx.Metadata().Bucket(blockLocIndexBucketName)
		if idx == nil {
			return fmt.Errorf("purge residue: bucket %q missing", blockLocIndexBucketName)
		}
		return idx.ForEach(func(k, v []byte) error {
			// Block-location entries are keyed by the 32-byte block hash; ignore
			// anything else that may live in the bucket.
			if len(k) != HashSize {
				return nil
			}
			var hash common.Uint256
			copy(hash[:], k)

			// Guard (1): still on the retained main chain -> keep.
			if _, herr := dbFetchHeightByHash(dbTx, &hash); herr == nil {
				return nil
			}

			// Guard (2): read the block's own header height from the raw store
			// (FetchBlockHeader resolves via ffldb-blockidx, not the main-chain
			// index, so it works for a rolled-back block).
			headerBytes, ferr := dbTx.FetchBlockHeader(&hash)
			if ferr != nil {
				// Height indeterminable -> conservatively keep (never over-delete).
				log.Warnf("[PurgeForcedRollbackResidue] header unreadable for %s, "+
					"keeping: %v", hash.String(), ferr)
				return nil
			}
			var header common2.Header
			if derr := header.DeserializeNoAux(bytes.NewReader(headerBytes)); derr != nil {
				log.Warnf("[PurgeForcedRollbackResidue] header undecodable for %s, "+
					"keeping: %v", hash.String(), derr)
				return nil
			}
			if header.Height > target {
				toDelete = append(toDelete, hash)
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}

	// Write pass: delete the collected residue entries.
	for _, hash := range toDelete {
		if derr := fflDB.DeleteBlockFromStore(hash); derr != nil {
			return 0, fmt.Errorf("purge residue: delete %s: %w", hash.String(), derr)
		}
		log.Warnf("[PurgeForcedRollbackResidue] purged residual block %s (height > %d)",
			hash.String(), target)
	}
	return len(toDelete), nil
}
