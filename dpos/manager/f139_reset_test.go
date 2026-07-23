// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package manager

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// F-139 fail-on-pristine test for ConsensusBlockCache.Reset.
//
// Reset(block) is meant to keep only the cached blocks whose height is >=
// block.Height and drop the rest, rebuilding both the ConsensusBlocks map and
// the ConsensusBlockList (arrival-ordered hashes) from that kept subset.
//
// On the pristine tree the map is filtered correctly but the list is built with
//
//	newConsensusBlockList = append(c.ConsensusBlockList, b.Hash())
//
// i.e. it appends each kept hash onto the OLD full list c.ConsensusBlockList
// instead of the accumulator newConsensusBlockList. The result still carries
// every dropped block's hash and has length len(original)+1, so the list and
// the (correctly filtered) map diverge. The fix appends to newConsensusBlockList.
//
// This test compiles identically on the pristine and fixed trees; it FAILS on
// pristine (wrong length, dropped hashes present, list/map inconsistent) and
// PASSES on the fixed tree.
// ---------------------------------------------------------------------------

// f139Block builds a minimal block whose header height is h. Distinct heights
// yield distinct header serializations and therefore distinct Hash() values.
func f139Block(h uint32) *types.Block {
	return &types.Block{Header: common2.Header{Height: h}}
}

func TestF139_ResetKeepsOnlyAtOrAboveThreshold(t *testing.T) {
	c := &ConsensusBlockCache{}
	c.Reset(nil) // initialise the map/slice so AddValue does not panic

	// Add five blocks at heights 10..14. AddValue keys on the block hash, the
	// same key Reset recomputes via b.Hash().
	heights := []uint32{10, 11, 12, 13, 14}
	hashByHeight := make(map[uint32]common.Uint256, len(heights))
	for _, h := range heights {
		b := f139Block(h)
		hash := b.Hash()
		hashByHeight[h] = hash
		c.AddValue(hash, b)
	}
	require.Len(t, c.ConsensusBlockList, len(heights))
	require.Len(t, c.ConsensusBlocks, len(heights))

	// Reset at height 12: keep {12,13,14}, drop {10,11}.
	const threshold = uint32(12)
	c.Reset(f139Block(threshold))

	keptHeights := []uint32{12, 13, 14}
	droppedHeights := []uint32{10, 11}

	keptSet := make(map[common.Uint256]bool, len(keptHeights))
	for _, h := range keptHeights {
		keptSet[hashByHeight[h]] = true
	}

	// The list must contain exactly the kept hashes (order-independent). On
	// pristine it has len(original)+1 entries, so this aborts first.
	require.Len(t, c.ConsensusBlockList, len(keptHeights),
		"F-139: Reset must keep exactly the at/above-threshold hashes in the list")
	require.Len(t, c.ConsensusBlocks, len(keptHeights),
		"F-139: Reset must keep exactly the at/above-threshold blocks in the map")

	listSet := make(map[common.Uint256]bool, len(c.ConsensusBlockList))
	for _, h := range c.ConsensusBlockList {
		listSet[h] = true
	}
	require.Len(t, listSet, len(keptHeights),
		"F-139: the kept list must not contain duplicate hashes")

	for _, h := range keptHeights {
		require.True(t, listSet[hashByHeight[h]],
			"F-139: kept block at height %d must appear in the list", h)
		_, ok := c.ConsensusBlocks[hashByHeight[h]]
		require.True(t, ok,
			"F-139: kept block at height %d must appear in the map", h)
	}
	for _, h := range droppedHeights {
		require.False(t, listSet[hashByHeight[h]],
			"F-139: dropped block at height %d must NOT appear in the list", h)
		_, ok := c.ConsensusBlocks[hashByHeight[h]]
		require.False(t, ok,
			"F-139: dropped block at height %d must NOT appear in the map", h)
	}

	// List and map must stay consistent: every listed hash resolves in the map.
	for _, h := range c.ConsensusBlockList {
		_, ok := c.ConsensusBlocks[h]
		require.True(t, ok,
			"F-139: every hash in the list must resolve to a cached block")
	}

	// GetFirstArrivedBlockHash must return one of the kept hashes, never a
	// dropped one (on pristine index 0 is the dropped height-10 hash).
	first, ok := c.GetFirstArrivedBlockHash()
	require.True(t, ok)
	require.True(t, keptSet[first],
		"F-139: first-arrived hash must be a kept hash, not a dropped one")
}
