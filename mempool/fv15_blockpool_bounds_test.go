// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
)

// FAIL-ON-PRISTINE for FV-15.
//
// F-092/F-117 bounded this pool by HEIGHT, but bm.blocks is keyed by HASH, so
// nothing bounded how many DISTINCT blocks could sit at one RETAINED height,
// and the only retention sweep is driven by the block-connected path, so on a
// stalled chain it never runs at all. Minting such a block is free: appendBlock
// validates with CheckBlockSanity only, whose work gate is CheckProofOfWork
// against PowLimit (2^255-1).
//
// Every test here drives a production entry point of the pool -- AppendDposBlock
// (called by AddDposBlock from elanet/netsync and by dpos/manager) or
// AddToBlockMap (called by dpos/manager) -- not the helpers the fix introduced.

// poolWithTip returns a BlockPool wired to a chain whose GetHeight() is tip.
// BlockChain.getHeight() is len(Nodes)-1, so the node slice length is what sets
// the tip; nothing here dereferences the nodes themselves.
func poolWithTip(tip uint32) *BlockPool {
	bm := NewBlockPool(&config.Configuration{})
	bm.Chain = &blockchain.BlockChain{
		Nodes: make([]*blockchain.BlockNode, tip+1),
	}
	return bm
}

// distinctBlockAtHeight builds a block at the given height with a hash nobody
// else has. This is the attacker's unit of work in FV-15: same height, new
// hash, and the pristine pool keeps every one of them.
func distinctBlockAtHeight(height uint32, nonce uint32) *types.Block {
	return &types.Block{Header: common2.Header{Height: height, Nonce: nonce}}
}

// TestFV15AppendBlockRejectsOutsideRetentionWindow proves the admission bound
// exists on the production path. On the pristine tree AppendDposBlock accepts a
// block at an arbitrary height and parks it in bm.blocks.
func TestFV15AppendBlockRejectsOutsideRetentionWindow(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	far := blockAtHeight(tip + retainAheadCount + 1)
	_, _, err := bm.AppendDposBlock(&types.DposBlock{Block: far})
	if err == nil {
		t.Fatalf("FV-15: AppendDposBlock accepted a block at height %d with "+
			"the tip at %d; the pool retention window ends at %d",
			far.Height, uint32(tip), uint32(tip)+retainAheadCount)
	}
	if !strings.Contains(err.Error(), "retention window") {
		t.Fatalf("FV-15: block at height %d was refused for the wrong reason: "+
			"%v", far.Height, err)
	}
	if len(bm.blocks) != 0 {
		t.Fatalf("FV-15: pool holds %d blocks after a refused admission",
			len(bm.blocks))
	}

	// Below the window too -- an attacker can mint at old heights just as
	// cheaply, and the sweep would drop them at the next connect anyway.
	old := blockAtHeight(tip - cachedCount - 1)
	if _, _, err = bm.AppendDposBlock(&types.DposBlock{Block: old}); err == nil ||
		!strings.Contains(err.Error(), "retention window") {
		t.Fatalf("FV-15: block at height %d (below the window floor %d) was "+
			"admitted: %v", old.Height, uint32(tip)-cachedCount, err)
	}
}

// TestFV15AdmissionBoundDoesNotOverReach is the over-reach guard: every height
// the retention sweep KEEPS must still reach the validator. The block used here
// carries a zero AuxPow, so passing the admission bound lands in
// CheckBlockSanity and fails there -- a different, named error. Seeing the aux
// pow error is the proof that the admission bound let the block through.
func TestFV15AdmissionBoundDoesNotOverReach(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	for h := uint32(tip) - cachedCount; h <= uint32(tip)+retainAheadCount; h++ {
		_, _, err := bm.AppendDposBlock(&types.DposBlock{Block: blockAtHeight(h)})
		if err == nil {
			t.Fatalf("height %d: expected the sanity check to reject a zero "+
				"AuxPow block", h)
		}
		if strings.Contains(err.Error(), "retention window") {
			t.Fatalf("FV-15 OVER-REACH: height %d is inside the retention "+
				"window around tip %d but admission refused it: %v",
				h, uint32(tip), err)
		}
	}
}

// TestFV15AdmissionAgreesWithRetention pins the two rules to each other: a
// height the sweep would keep must be admissible, and a height the sweep would
// drop must not be. Drift between them is how a retention bound silently stops
// bounding anything.
func TestFV15AdmissionAgreesWithRetention(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	for h := uint32(tip) - 12; h <= uint32(tip)+12; h++ {
		bm.AddToBlockMap(blockAtHeight(h))
	}
	bm.CleanFinalConfirmedBlock(tip)

	for h := uint32(tip) - 12; h <= uint32(tip)+12; h++ {
		_, retained := bm.GetBlock(blockAtHeight(h).Hash())
		admissible := retentionWindowContains(tip, h)
		if retained != admissible {
			t.Fatalf("height %d: retained=%v but admissible=%v -- the "+
				"admission bound and the retention sweep disagree",
				h, retained, admissible)
		}
	}
}

// TestFV15PoolIsBoundedByCountAtOneHeight is the leg the height bound does NOT
// close, and the one the FV-15 entry says not to skip: unlimited DISTINCT
// blocks, all at a RETAINED height, all inside [floor, ceiling], so the sweep
// keeps every one of them. On the pristine tree the pool below holds 400
// blocks; with the fix it holds at most maxPooledBlocks.
//
// AddToBlockMap is used deliberately: it is the admission path with no
// validation at all, so nothing but the cap can bound it.
func TestFV15PoolIsBoundedByCountAtOneHeight(t *testing.T) {
	const (
		tip   = 1000
		flood = 400
	)
	bm := poolWithTip(tip)

	for i := 0; i < flood; i++ {
		bm.AddToBlockMap(distinctBlockAtHeight(tip+3, uint32(i+1)))
	}

	count, _ := bm.PooledBlockStats()
	if count > maxPooledBlocks {
		t.Fatalf("FV-15: pool grew to %d distinct blocks at the single "+
			"retained height %d from %d admissions; want at most %d",
			count, uint32(tip)+3, flood, maxPooledBlocks)
	}
	if count == 0 {
		t.Fatalf("the cap emptied the pool entirely; want at most %d, got 0",
			maxPooledBlocks)
	}
}

// TestFV15EvictionPrefersBlocksFurthestFromTip proves the shedding policy: the
// block the node is about to connect must outlive the flood aimed at the far
// end of the window. A cap that evicted arbitrarily would trade a memory bug
// for a liveness bug.
func TestFV15EvictionPrefersBlocksFurthestFromTip(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	next := distinctBlockAtHeight(tip+1, 0xfeed)
	bm.AddToBlockMap(next)

	for i := 0; i < maxPooledBlocks*4; i++ {
		bm.AddToBlockMap(distinctBlockAtHeight(tip+retainAheadCount, uint32(i+1)))
	}

	if _, ok := bm.GetBlock(next.Hash()); !ok {
		t.Fatalf("FV-15: the tip+1 block was evicted in favour of blocks at "+
			"tip+%d, which are further from the tip", retainAheadCount)
	}
}

// TestFV15ByteAccountingIsExact guards the byte budget's bookkeeping. A budget
// whose counter drifts stops bounding anything, and the drift only shows up
// under eviction, which is exactly when the bound matters.
func TestFV15ByteAccountingIsExact(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	var want int
	for i := 0; i < 20; i++ {
		b := distinctBlockAtHeight(tip+2, uint32(i+1))
		bm.AddToBlockMap(b)
		want += b.GetSize()
	}

	count, bytes := bm.PooledBlockStats()
	if count != 20 {
		t.Fatalf("pool holds %d blocks, want 20", count)
	}
	if bytes != want {
		t.Fatalf("pool byte accounting is %d, want %d", bytes, want)
	}
	if bytes > maxPooledBlockBytes {
		t.Fatalf("pool holds %d bytes, above the %d byte budget",
			bytes, maxPooledBlockBytes)
	}

	// Sweeping everything out must return the counter to zero, not to a
	// residue that eventually wedges admission.
	bm.CleanFinalConfirmedBlock(tip + 1000)
	if count, bytes = bm.PooledBlockStats(); count != 0 || bytes != 0 {
		t.Fatalf("after a full sweep the pool reports %d blocks / %d bytes, "+
			"want 0 / 0", count, bytes)
	}
}

// TestFV15SweepIsSelfDrivingOnAStalledChain covers the retention half of the
// finding: pruneLocked's only production caller is the block-connected path, so
// a chain that stops connecting blocks never sweeps. Here the tip never moves
// and CleanFinalConfirmedBlock is never called, and the pool must still shed.
func TestFV15SweepIsSelfDrivingOnAStalledChain(t *testing.T) {
	const tip = 1000
	bm := poolWithTip(tip)

	// Blocks that a sweep would drop, admitted while the chain is stalled.
	for i := 0; i < maxPooledBlocks; i++ {
		bm.AddToBlockMap(distinctBlockAtHeight(tip+1000, uint32(i+1)))
	}
	// One more admission, still with no connect and no external sweep.
	bm.AddToBlockMap(distinctBlockAtHeight(tip+1, 0xbeef))

	count, _ := bm.PooledBlockStats()
	if count > maxPooledBlocks {
		t.Fatalf("FV-15: pool holds %d blocks on a stalled chain with no "+
			"sweep; want at most %d", count, maxPooledBlocks)
	}
	for i := 0; i < maxPooledBlocks; i++ {
		if _, ok := bm.GetBlock(distinctBlockAtHeight(tip+1000, uint32(i+1)).Hash()); ok {
			t.Fatalf("FV-15: a block %d heights above the stalled tip survived "+
				"admission-driven pruning", 1000)
		}
	}
}
