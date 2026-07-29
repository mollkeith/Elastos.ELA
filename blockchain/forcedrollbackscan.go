// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/database"
)

// ResidueRef identifies one entry found above the forced-rollback target by
// ScanForcedRollbackStore.
type ResidueRef struct {
	Hash   common.Uint256
	Height uint32
}

// ForcedRollbackStoreScan records what the persisted block store still holds
// strictly above a forced-rollback target.
//
// "Persisted" is load-bearing. ffldb answers every read through its in-memory
// dbCache, which holds committed writes for up to 20 MiB / 300 s (both hardcoded,
// database/ffldb/db.go openDB) before they reach leveldb. A scan taken without
// forcing that cache out reports the store as the writer sees it, not as a restarted
// process would find it: on two nodes differing only in the flush interval, the
// production one reported a fully clean store at the same instant 320 above-target
// entries were still only in RAM, and test/unit/b4_rollback_durability_test.go
// reproduces it, logging the store "verified clean" with the entire rewind still in
// the cache. ScanForcedRollbackStore flushes before it counts, which is what lets
// everything below, and every message derived from it, say "persisted" honestly.
//
// It exists because the other safety nets assert nothing about the database:
// main.go's post-rollback height check compares chain.GetHeight(), which is just
// len(b.Nodes)-1, against the target, which is tautologically true given the rewind
// loop's own exit condition, and the checkpoint assertion is guarded by
// `if forcedRollbackFired`, false on exactly the boot where a ratcheted node finally
// comes up. Every field below is read from the database, never from b.Nodes, so the
// two can be compared against each other.
//
// The four categories are distinct because they carry different severities:
//
//   - LiveAbove: the retained chain itself extends above the target. The node
//     is simply not rolled back; a purge here would destroy a live chain.
//   - MainChainAbove / BestStateHeight: the database still records blocks above
//     the target as part of the main chain while the loaded chain tip is at or
//     below it. That is the signature of an interrupted rollback: the per-block
//     RollbackBlock transaction (which also reverts the UTXO and state processors)
//     never ran for those blocks, so no purge can repair the node.
//   - StoredAbove / HeaderRowsAbove: retention-only residue. The block is off
//     the main chain but still fetchable by hash, or an orphaned header-index row
//     survives. Both are safely removable.
type ForcedRollbackStoreScan struct {
	// Target is the forced-rollback height the scan was taken against.
	Target uint32

	// LiveAbove lists blocks strictly above Target that are part of a RETAINED MAIN
	// CHAIN extending past the target: a block-header-index row (what startup
	// rebuilds b.Nodes from), a fetchable block (initChainState's own admission
	// test, chainio.go: DeserializeBlockRow + dbTx.HasBlock -> LoadBlockNode), AND a
	// main-chain hash->height entry.
	//
	// All three conjuncts are load-bearing. Main-chain membership cannot be dropped:
	// the live reorg path leaves stale header rows behind for DETACHED blocks --
	// reorganizeChain (blockchain.go:1964, :1989) uses disconnectBlock, which calls
	// RollbackBlock but, unlike disconnectBlock2, never calls DBRemoveBlockNode -- so
	// a header row above the tip is reachable in ordinary operation and must be
	// treated as residue, not as a live chain. The header row cannot be dropped
	// either: it is exactly what an interrupted rollback destroys, so a ratcheted
	// node has none and must not be mistaken for a live chain.
	LiveAbove []ResidueRef

	// MainChainAbove lists hash->height main-chain index entries strictly above
	// Target. RollbackBlock is what removes these (DBRemoveBlockIndex).
	MainChainAbove []ResidueRef

	// StoredAbove lists raw by-hash store entries (ffldb-blockidx) whose own header
	// height is strictly above Target.
	StoredAbove []ResidueRef

	// HeaderRowsAbove lists block-header-index (blockheaderidx) rows strictly above
	// Target. This is the index b.Nodes is rebuilt from at startup.
	HeaderRowsAbove []ResidueRef

	// BestStateHeight/BestStateHash are the persisted best-chain state record.
	BestStateHeight uint32
	BestStateHash   common.Uint256
}

// Clean reports whether the store holds nothing at all above the target.
func (s *ForcedRollbackStoreScan) Clean() bool {
	return len(s.LiveAbove) == 0 && len(s.MainChainAbove) == 0 &&
		len(s.StoredAbove) == 0 && len(s.HeaderRowsAbove) == 0 &&
		s.BestStateHeight <= s.Target
}

// Summary renders the scan for an operator-facing log or error message.
func (s *ForcedRollbackStoreScan) Summary() string {
	return fmt.Sprintf("target=%d live-above=%d main-chain-above=%d stored-above=%d "+
		"header-rows-above=%d best-state-height=%d", s.Target, len(s.LiveAbove),
		len(s.MainChainAbove), len(s.StoredAbove), len(s.HeaderRowsAbove),
		s.BestStateHeight)
}

// refHash copies a 32-byte index value into a Uint256.
func refHash(b []byte) common.Uint256 {
	var h common.Uint256
	copy(h[:], b)
	return h
}

// scanReportLimit bounds how many hashes an error message enumerates.
const scanReportLimit = 8

// refsString renders up to scanReportLimit refs for an operator message.
func refsString(refs []ResidueRef) string {
	var b bytes.Buffer
	for i, r := range refs {
		if i >= scanReportLimit {
			fmt.Fprintf(&b, " ...(+%d more)", len(refs)-scanReportLimit)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d:%s", r.Height, r.Hash.String())
	}
	return b.String()
}

// ScanForcedRollbackStore reports the persisted store above target.
//
// It flushes the database cache before reading. That is not incidental: ffldb reads
// through its write cache, so without the flush this function, and every claim built
// on it including "persisted store verified clean above target N", would describe
// RAM. The flush publishes only writes that are already committed, so it changes no
// logical content; it just makes the answer match the question the name asks.
// Because it takes the database write lock, this function must not be called from
// inside an open transaction.
//
// Cost: the raw-store pass would be prohibitive on a 25GB mainnet store if it
// fetched a header for all ~2.26M entries, so the cheap main-chain lookup is used as
// a skip filter rather than as a keep-decision. An entry that is main-chain-indexed
// at or below the target is retained history and is skipped without touching the
// flat files. Everything else, off-chain entries and, critically, entries that are
// still main-chain-indexed above the target, falls through to the header read. That
// direction is load-bearing: skipping on main-chain membership alone classifies
// residue from an interrupted rollback as "retained" and keeps it, because its
// hashidx entry survives precisely when RollbackBlock never ran, and the sound
// height guard is then never reached.
func ScanForcedRollbackStore(fflDB IFFLDBChainStore, target uint32) (
	*ForcedRollbackStoreScan, error) {
	scan := &ForcedRollbackStoreScan{Target: target}
	// The scan walks three whole metadata buckets (~2.26M keys each on mainnet), so
	// its cost is logged: it is a real, if one-off, addition to boot time on a node
	// sitting at the rollback target, and the restart runbook should show it.
	began := time.Now()

	// Census the DISK, not the write cache. See the function comment.
	if ferr := fflDB.FlushCache(); ferr != nil {
		return nil, fmt.Errorf("forced rollback scan: flush the store before "+
			"censusing it: %w", ferr)
	}

	err := fflDB.View(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()

		// (1) Block-header index (blockheaderidx): the index b.Nodes is rebuilt
		// from. Keys are <height:4 big-endian><hash:32>, so the height is read
		// straight off the key and no row below the target costs anything.
		hdrIdx := meta.Bucket(blockIndexBucketName)
		if hdrIdx == nil {
			return fmt.Errorf("forced rollback scan: bucket %q missing",
				blockIndexBucketName)
		}
		if err := hdrIdx.ForEach(func(k, v []byte) error {
			if len(k) != HashSize+4 {
				return nil
			}
			height := binary.BigEndian.Uint32(k[0:4])
			if height <= target {
				return nil
			}
			var hash common.Uint256
			copy(hash[:], k[4:])
			ref := ResidueRef{Hash: hash, Height: height}
			scan.HeaderRowsAbove = append(scan.HeaderRowsAbove, ref)

			// A header row alone is inert: initChainState skips a row whose block is
			// not in the store, and a detached side block keeps its row without
			// being on the chain. Only a row that is BOTH loadable and still
			// main-chain indexed means the retained chain runs past the target.
			exists, herr := dbTx.HasBlock(hash)
			if herr != nil || !exists {
				return nil
			}
			if _, merr := dbFetchHeightByHash(dbTx, &hash); merr == nil {
				scan.LiveAbove = append(scan.LiveAbove, ref)
			}
			return nil
		}); err != nil {
			return err
		}

		// (2) Main-chain hash->height index (hashidx). Values are the height in
		// byteOrder; this is the index dbFetchHeightByHash/BlockExists consult.
		hashIdx := meta.Bucket(hashIndexBucketName)
		if hashIdx == nil {
			return fmt.Errorf("forced rollback scan: bucket %q missing",
				hashIndexBucketName)
		}
		if err := hashIdx.ForEach(func(k, v []byte) error {
			if len(k) != HashSize || len(v) != 4 {
				return nil
			}
			height := byteOrder.Uint32(v)
			if height <= target {
				return nil
			}
			var hash common.Uint256
			copy(hash[:], k)
			scan.MainChainAbove = append(scan.MainChainAbove,
				ResidueRef{Hash: hash, Height: height})
			return nil
		}); err != nil {
			return err
		}

		// (3) Raw by-hash block store (ffldb-blockidx).
		blkIdx := meta.Bucket(blockLocIndexBucketName)
		if blkIdx == nil {
			return fmt.Errorf("forced rollback scan: bucket %q missing",
				blockLocIndexBucketName)
		}
		if err := blkIdx.ForEach(func(k, v []byte) error {
			if len(k) != HashSize {
				return nil
			}
			var hash common.Uint256
			copy(hash[:], k)

			// Cheap skip: retained main-chain history at or below the target.
			if h, herr := dbFetchHeightByHash(dbTx, &hash); herr == nil && h <= target {
				return nil
			}

			headerBytes, ferr := dbTx.FetchBlockHeader(&hash)
			if ferr != nil {
				// Height indeterminable -> conservatively treat as retained so a
				// purge can never over-delete.
				log.Warnf("[ScanForcedRollbackStore] header unreadable for %s, "+
					"treating as retained: %v", hash.String(), ferr)
				return nil
			}
			var header common2.Header
			if derr := header.DeserializeNoAux(bytes.NewReader(headerBytes)); derr != nil {
				log.Warnf("[ScanForcedRollbackStore] header undecodable for %s, "+
					"treating as retained: %v", hash.String(), derr)
				return nil
			}
			if header.Height > target {
				scan.StoredAbove = append(scan.StoredAbove,
					ResidueRef{Hash: hash, Height: header.Height})
			}
			return nil
		}); err != nil {
			return err
		}

		// (4) Persisted best-chain state.
		if raw := meta.Get(chainStateKeyName); raw != nil {
			state, serr := deserializeBestChainState(raw)
			if serr != nil {
				return fmt.Errorf("forced rollback scan: best chain state: %w", serr)
			}
			scan.BestStateHeight = state.height
			scan.BestStateHash = state.hash
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	log.Infof("[ScanForcedRollbackStore] %s (%s)", scan.Summary(),
		time.Since(began).Truncate(time.Millisecond))
	return scan, nil
}

// ErrForcedRollbackStoreInconsistent reports a persisted store whose main-chain
// records disagree with the loaded chain in a way NO cleanup can repair, because
// the per-block RollbackBlock transaction -- which also reverts the UTXO and
// derived-state processors -- demonstrably never ran for those blocks.
var ErrForcedRollbackStoreInconsistent = errors.New(
	"forced rollback: persisted store is inconsistent with the loaded chain")

// interruptedRollbackError builds the operator-facing diagnosis for a store whose
// main chain still extends above the rollback target while the loaded tip does not.
func interruptedRollbackError(scan *ForcedRollbackStoreScan, tip uint32) error {
	return fmt.Errorf("%w: the block database still records %d block(s) above the "+
		"forced-rollback target %d as part of the MAIN CHAIN (best-state height %d) "+
		"while the loaded chain tip is %d. This is the signature of a forced rollback "+
		"that was INTERRUPTED between removing a block's header-index row and "+
		"committing its rollback transaction: the UTXO and derived-state processors "+
		"for those blocks were never reverted, so the node would run on silently "+
		"corrupt state -- refusing to start. Remedy: restore a pre-rollback backup "+
		"and restart under this binary (which rewinds resumably), or wipe the data "+
		"directory and resync. Residue: %s",
		ErrForcedRollbackStoreInconsistent, len(scan.MainChainAbove), scan.Target,
		scan.BestStateHeight, tip, refsString(scan.MainChainAbove))
}
