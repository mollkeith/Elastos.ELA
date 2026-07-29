// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pow

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types"

	"github.com/stretchr/testify/assert"
)

// The aux-block pool must be bounded.
//
// WHY. CreateAuxBlock empties the pool ONLY when the chain height changes. On a
// STALLED chain the height does not change, while createAuxBlockInterval is 5
// seconds -- so a merge-mining pool polling createauxblock adds one entry every 5
// seconds and nothing removes it: 720/hour, unbounded. A stalled chain IS the
// restart condition (at least four hours before the in-block RevertToPOW rule can
// fire), and the node it exhausts belongs to the pool that must mine the first
// block of the recovered chain.
//
// FAIL-ON-PRISTINE: remove the eviction loop from AppendBlock and
// TestAuxBlockPoolIsBounded fails with the pool having grown past the bound.

func auxTestBlock(nonce uint32) *types.Block {
	return &types.Block{
		Header: common2.Header{Height: 2260451, Nonce: nonce},
	}
}

func TestAuxBlockPoolIsBounded(t *testing.T) {
	p := &AuxBlockPool{mapNewBlock: make(map[common.Uint256]*types.Block)}

	// simulate a stalled chain: many regenerations, height never changes so
	// ClearBlock is never called
	const appended = maxAuxBlockPoolSize * 3
	for i := 0; i < appended; i++ {
		p.AppendBlock(auxTestBlock(uint32(i)))
	}

	if len(p.mapNewBlock) > maxAuxBlockPoolSize {
		t.Fatalf("AUX BLOCK POOL UNBOUNDED: appended %d entries on a stalled chain and the "+
			"pool holds %d, above the bound of %d. At the 5s regeneration interval this is "+
			"720 entries an hour for the whole PoW window, on the pool node the restart "+
			"depends on.", appended, len(p.mapNewBlock), maxAuxBlockPoolSize)
	}
	assert.Equal(t, len(p.mapNewBlock), len(p.order),
		"map and insertion-order list must not drift")
}

// Eviction must be oldest-first. Random eviction would drop the block a pool is
// currently mining as readily as a stale one.
func TestAuxBlockPoolEvictsOldestFirst(t *testing.T) {
	p := &AuxBlockPool{mapNewBlock: make(map[common.Uint256]*types.Block)}

	first := auxTestBlock(0)
	p.AppendBlock(first)
	for i := 1; i <= maxAuxBlockPoolSize; i++ {
		p.AppendBlock(auxTestBlock(uint32(i)))
	}

	_, stillThere := p.GetBlock(first.Hash())
	assert.False(t, stillThere, "the OLDEST entry must be the one evicted")

	newest := auxTestBlock(uint32(maxAuxBlockPoolSize))
	_, found := p.GetBlock(newest.Hash())
	assert.True(t, found, "the NEWEST entry must be retained -- that is the one a pool is mining")
}

// A submitted block must still be findable within the bound, or SubmitAuxBlock
// cannot resolve what the pool mined.
func TestAuxBlockPoolRetainsRecentForSubmit(t *testing.T) {
	p := &AuxBlockPool{mapNewBlock: make(map[common.Uint256]*types.Block)}
	for i := 0; i < maxAuxBlockPoolSize/2; i++ {
		p.AppendBlock(auxTestBlock(uint32(i)))
	}
	b := auxTestBlock(99999)
	p.AppendBlock(b)
	got, ok := p.GetBlock(b.Hash())
	assert.True(t, ok, "a just-created aux block must be retrievable by SubmitAuxBlock")
	assert.Equal(t, b.Hash(), got.Hash())
}

// ClearBlock must release the order slice too, or its capacity survives the stall.
func TestClearBlockReleasesOrder(t *testing.T) {
	p := &AuxBlockPool{mapNewBlock: make(map[common.Uint256]*types.Block)}
	for i := 0; i < 100; i++ {
		p.AppendBlock(auxTestBlock(uint32(i)))
	}
	p.ClearBlock()
	assert.Equal(t, 0, len(p.mapNewBlock))
	assert.Equal(t, 0, len(p.order), "insertion-order list must be released with the map")
}
