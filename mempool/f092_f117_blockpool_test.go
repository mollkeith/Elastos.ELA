// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
)

// The block pool logs unconditionally on the paths exercised here, so the
// package logger has to exist even when these tests run on their own.
func init() {
	log.NewDefault(filepath.Join(os.TempDir(), "ela-blockpool-test-logs"), 0, 0, 0)
}

// blockAtHeight builds the smallest block the pool can hold. Only the height
// (and therefore the header hash) matters for the retention tests.
func blockAtHeight(height uint32) *types.Block {
	return &types.Block{Header: common2.Header{Height: height}}
}

// signedOrphanConfirm builds a confirm that passes blockchain.ConfirmSanityCheck
// -- a real signature over the proposal from a freshly generated key and no
// votes at all -- for a block hash that is NOT in the pool.
//
// Building this at all is the empirical part of the F-117 signer claim: sanity
// checking a confirm costs the sender one keypair, so anybody can mint an
// unlimited number of distinct pool-admissible confirms. (The signer-is-arbiter
// verification lives downstream, in ConfirmContextCheck / IllegalConfirmContext
// Check, which is where an acceptance decision is actually made.)
func signedOrphanConfirm(t *testing.T, blockHash common.Uint256) *payload.Confirm {
	t.Helper()

	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	pubBuf, err := pub.EncodePoint(true)
	if err != nil {
		t.Fatalf("encode point: %v", err)
	}

	confirm := &payload.Confirm{
		Proposal: payload.DPOSProposal{
			Sponsor:    pubBuf,
			BlockHash:  blockHash,
			ViewOffset: 0,
		},
	}
	confirm.Proposal.Sign, err = crypto.Sign(priv, confirm.Proposal.Data())
	if err != nil {
		t.Fatalf("sign proposal: %v", err)
	}
	return confirm
}

func hashAtIndex(i int) common.Uint256 {
	var h common.Uint256
	h[0] = byte(i)
	h[1] = byte(i >> 8)
	h[2] = byte(i >> 16)
	return h
}

// TestF092CleanEvictsBlocksAboveTip is the fail-on-pristine test for F-092.
//
// appendBlock stores any block that passes CheckBlockSanity at ANY height (its
// only work gate is CheckProofOfWork against PowLimit = 2^255-1), and the
// retention sweep only ever dropped entries BELOW the reference height. A block
// announced at an arbitrary future height therefore stayed in the pool for the
// life of the process. On the pristine tree the block below survives every
// sweep; with the fix it is evicted.
func TestF092CleanEvictsBlocksAboveTip(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	const tip = 100000
	far := blockAtHeight(tip + 1000)
	bm.AddToBlockMap(far)
	if _, ok := bm.GetBlock(far.Hash()); !ok {
		t.Fatalf("setup: block not in pool")
	}

	bm.CleanFinalConfirmedBlock(tip)

	if _, ok := bm.GetBlock(far.Hash()); ok {
		t.Fatalf("block %d heights above the tip was retained by the "+
			"retention sweep (pool size %d)", 1000, len(bm.blocks))
	}
}

// TestF092CleanKeepsBlocksInWindow guards the eviction against over-reach: the
// block the node is about to connect (tip+1) and the recent history the pool is
// meant to cache must survive the sweep.
func TestF092CleanKeepsBlocksInWindow(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	const tip = 100000
	keep := []*types.Block{
		blockAtHeight(tip - cachedCount),
		blockAtHeight(tip),
		blockAtHeight(tip + 1),
	}
	for _, b := range keep {
		bm.AddToBlockMap(b)
	}

	bm.CleanFinalConfirmedBlock(tip)

	for _, b := range keep {
		if _, ok := bm.GetBlock(b.Hash()); !ok {
			t.Fatalf("block at height %d was evicted but is inside the "+
				"retention window around tip %d", b.Height, tip)
		}
	}
}

// TestF092CleanHeightUnderflow is the fail-on-pristine test for the uint32
// underflow in the same sweep: for the first cachedCount heights
// "height-cachedCount" wrapped to ~2^32, so every block in the pool -- including
// the one just connected -- was dropped during genesis bootstrap.
func TestF092CleanHeightUnderflow(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	early := blockAtHeight(3)
	bm.AddToBlockMap(early)

	bm.CleanFinalConfirmedBlock(4)

	if _, ok := bm.GetBlock(early.Hash()); !ok {
		t.Fatalf("block at height 3 was dropped by CleanFinalConfirmedBlock(4): " +
			"height-cachedCount underflowed")
	}
}

// TestF117OrphanConfirmAgedOut is the fail-on-pristine test for F-117.
//
// appendConfirm stores the confirm BEFORE confirmBlock runs, and the retention
// sweep only visited confirms keyed by blocks that are in the pool -- so a
// confirm whose block never arrives was retained for the life of the process.
// On the pristine tree the confirm below survives an unbounded number of sweeps;
// with the fix it ages out of the pool's retention window.
func TestF117OrphanConfirmAgedOut(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	const tip = 100000
	confirm := signedOrphanConfirm(t, hashAtIndex(7))

	// The block is not in the pool, so confirmBlock fails -- but the confirm is
	// stored anyway (that is deliberate: a confirm may arrive before its block).
	if _, _, err := bm.AppendConfirm(confirm); err == nil {
		t.Fatalf("expected confirmBlock to fail for a confirm with no block")
	}
	if _, ok := bm.GetConfirm(confirm.Proposal.BlockHash); !ok {
		t.Fatalf("setup: confirm not stored")
	}

	for i := uint32(0); i <= cachedCount; i++ {
		bm.CleanFinalConfirmedBlock(tip + i)
	}

	if _, ok := bm.GetConfirm(confirm.Proposal.BlockHash); ok {
		t.Fatalf("orphan confirm survived %d retention sweeps (confirm pool "+
			"size %d)", cachedCount+1, len(bm.confirms))
	}
}

// TestF117OrphanConfirmSurvivesShortGap guards the ageing against over-reach: a
// confirm that legitimately arrives before its block must still be there when
// the block shows up a couple of blocks later.
func TestF117OrphanConfirmSurvivesShortGap(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	const tip = 100000
	block := blockAtHeight(tip + 1)
	confirm := signedOrphanConfirm(t, block.Hash())

	if _, _, err := bm.AppendConfirm(confirm); err == nil {
		t.Fatalf("expected confirmBlock to fail for a confirm with no block")
	}

	bm.CleanFinalConfirmedBlock(tip)

	if _, ok := bm.GetConfirm(confirm.Proposal.BlockHash); !ok {
		t.Fatalf("confirm that arrived one sweep before its block was dropped")
	}
}

// TestF117OrphanConfirmsBounded is the fail-on-pristine test for the unbounded
// growth of the confirm map between two retention sweeps. Every confirm here is
// individually admissible (valid signature, distinct block hash) and none of
// their blocks exist, which is exactly what an attacker can mint at will.
//
// The literal 512 is maxOrphanConfirms; it is spelled out so this file also
// compiles against the pristine tree, where the constant does not exist.
func TestF117OrphanConfirmsBounded(t *testing.T) {
	bm := NewBlockPool(&config.Configuration{})

	const flood = 700
	for i := 0; i < flood; i++ {
		confirm := signedOrphanConfirm(t, hashAtIndex(i+1))
		bm.AppendConfirm(confirm)
	}

	if len(bm.confirms) > 512 {
		t.Fatalf("confirm pool grew to %d entries from %d orphan confirms; "+
			"want <= 512", len(bm.confirms), flood)
	}
}
