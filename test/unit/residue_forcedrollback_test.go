// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit — EMPIRICAL fail-on-pristine proof for TRACK A (residue #2): after a
// forced rollback, the discarded blocks (the exploit block and its successors) must
// no longer be RETAINED or SERVED by hash from the raw ffldb block store.
//
// This drives the REAL production path end to end against a REAL ffldb-backed
// ChainStore (not a mock, not the synthetic-node harness):
//
//	block store  --SaveBlock-->  ffldb-blockidx (bucket 0x00000001)
//	(*BlockChain).ForceRollback  --> the fix must delete the discarded hashes
//	GetFFLDB().GetBlock(hash)     --> FetchBlock -> fetchBlockRow -> blockIdxBucket.Get
//	GetFFLDB().IsBlockInStore(&h) --> HasBlock  -> hasBlock       -> hasKey
//
// PRISTINE behaviour: ForceRollback deletes the header index (DBRemoveBlockNode) and
// the height indexes (DBRemoveBlockIndex) but leaves ffldb-blockidx behind, so the
// rolled-back node still deserializes and serves the discarded blocks by hash. The
// assertions below FAIL on pristine and PASS with the fix. The retained-block
// assertions guard against over-deletion (nothing <= target may be removed).
package unit

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"

	"github.com/stretchr/testify/assert"
)

// residueCoinbase builds a minimal, valid, UNIQUE coinbase transaction for a test
// block at the given height. The nonce attribute carries the height so each block's
// coinbase txid is distinct (otherwise the tx index would collide across blocks).
// Structure mirrors core.GenesisBlock's coinbase so it round-trips through
// Serialize/Deserialize when the store re-reads the block in GetBlock.
func residueCoinbase(height uint32) interfaces.Transaction {
	nonce := common2.NewAttribute(common2.Nonce, []byte{
		byte(height), byte(height >> 8), byte(height >> 16), byte(height >> 24),
		0x52, 0x45, 0x53, 0x32, // "RES2"
	})
	return functions.CreateTransaction(
		0,
		common2.CoinBase,
		payload.CoinBaseVersion,
		&payload.CoinBase{},
		[]*common2.Attribute{&nonce},
		[]*common2.Input{
			{
				Previous: common2.OutPoint{TxID: common.Uint256{}, Index: 0x0000},
				Sequence: 0x00000000,
			},
		},
		[]*common2.Output{
			{
				AssetID:     core.ELAAssetID,
				Value:       common.Fixed64(100),
				ProgramHash: common.Uint168{},
			},
		},
		0,
		[]*program.Program{},
	)
}

// TestResidue2ForcedRollbackPurgesBlockStore is the fail-on-pristine test for the
// residue #2 purge. It builds a real chain (genesis + heights 1..3) over a fresh
// ffldb store, arms a forced rollback to target height 1, runs it, and asserts the
// discarded blocks (heights 2 and 3) are neither retained nor served by hash, while
// the retained blocks (genesis + height 1, i.e. <= target) still are.
func TestResidue2ForcedRollbackPurgesBlockStore(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(1) // retained: heights 0 and 1; discarded: 2 and 3
	const tip = uint32(3)

	params := config.GetDefaultParams()
	params.Sterilize()
	params.DPoSV2StartHeight = 0
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	// Arm the forced rollback at our small target. ForcedRollbackArmed's byte-order
	// trigger check is exercised elsewhere; here we drive ForceRollback directly, as
	// main.go does once armed.
	params.ForcedRollbackHeight = target
	blockchain.FoundationAddress = *params.FoundationProgramHash

	chainStore, err := blockchain.NewChainStore(
		filepath.Join(test.DataPath, "residue2forcedrollback"), params)
	assert.NoError(t, err)
	defer chainStore.Close()

	ckpManager := checkpoint.NewManager(params)
	chain, err := blockchain.New(chainStore, params,
		state.NewState(params, nil, nil, nil,
			func() bool { return false },
			nil, nil,
			nil, nil, nil, nil, nil),
		crstate.NewCommittee(params, ckpManager), ckpManager,
	)
	assert.NoError(t, err)
	assert.NoError(t, chain.Init(nil))

	// After New, the store holds genesis (height 0) and chain.Nodes == [genesis].
	genesisHash := params.GenesisBlock.Hash()

	// Append real coinbase-only blocks 1..tip through the production store path.
	hashByHeight := map[uint32]common.Uint256{0: genesisHash}
	prevHash := genesisHash
	for h := uint32(1); h <= tip; h++ {
		blk := &types.Block{
			Header: common2.Header{
				Version:   0,
				Height:    h,
				Previous:  prevHash,
				Timestamp: 1600000000 + h,
				Bits:      0x1d03ffff,
			},
			Transactions: []interfaces.Transaction{residueCoinbase(h)},
		}
		hash := blk.Hash()
		node, lerr := chain.LoadBlockNode(&blk.Header, &hash)
		assert.NoError(t, lerr, "load block node at height %d", h)
		assert.NoError(t,
			chain.GetDB().SaveBlock(blk, node, nil, blockchain.CalcPastMedianTime(node)),
			"save block at height %d", h)
		chain.SetTip(node)
		chain.BestChain = node
		hashByHeight[h] = hash
		prevHash = hash
	}

	fdb := chain.GetDB().GetFFLDB()

	// ORPHAN / side block above the target that never joins the main chain: a child
	// of the tip written straight into the raw block store (ffldb-blockidx) via the
	// low-level StoreBlock WITHOUT a main-chain height-index entry -- exactly the
	// shape of the one real mainnet residue (height 2260595, a child of the discarded
	// tip). The per-iteration ForceRollback purge walks only b.Nodes, so it cannot
	// reach this; only the completeness sweep can. This orphan is what made the
	// in-line purge off-by-one against a clean forward-synced node.
	orphan := &types.Block{
		Header: common2.Header{
			Version:   0,
			Height:    tip + 1,
			Previous:  hashByHeight[tip],
			Timestamp: 1600000000 + tip + 1,
			Bits:      0x1d03ffff,
		},
		Transactions: []interfaces.Transaction{residueCoinbase(tip + 1)},
	}
	orphanHash := orphan.Hash()
	orphanBuf := new(bytes.Buffer)
	assert.NoError(t, (&types.DposBlock{Block: orphan}).Serialize(orphanBuf))
	assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(orphanHash, orphanBuf.Bytes())
	}), "store orphan block directly into ffldb-blockidx")
	assert.True(t, fdb.IsBlockInStore(&orphanHash),
		"pre-rollback: orphan must be in the raw block store")

	// Precondition: every block (including the to-be-discarded ones) is served by
	// hash BEFORE the rollback. This proves the harness actually stored them.
	for h := uint32(0); h <= tip; h++ {
		hash := hashByHeight[h]
		blk, gerr := fdb.GetBlock(hash)
		assert.NoError(t, gerr, "pre-rollback: height %d must be fetchable by hash", h)
		assert.NotNil(t, blk, "pre-rollback: height %d block non-nil", h)
		assert.True(t, fdb.IsBlockInStore(&hash),
			"pre-rollback: height %d must be in store", h)
	}

	// Run the REAL forced rollback (tip 3 -> target 1). depth = 2 < maxHistoryCapacity.
	assert.NoError(t, chain.ForceRollback(nil), "forced rollback must succeed")

	// The in-RAM tip is now the target.
	assert.Equal(t, target, uint32(len(chain.Nodes)-1),
		"tip must be rewound to target height")

	// CORE ASSERTIONS (fail on pristine, pass with the fix): the DISCARDED blocks
	// (height > target) must NOT be retained nor served by hash.
	for _, h := range []uint32{2, 3} {
		hash := hashByHeight[h]

		blk, gerr := fdb.GetBlock(hash)
		assert.Error(t, gerr,
			"RESIDUE #2: discarded block at height %d is still served by hash after "+
				"forced rollback (GetBlock must return ErrBlockNotFound)", h)
		assert.Nil(t, blk,
			"RESIDUE #2: discarded block at height %d must not deserialize after rollback", h)

		assert.False(t, fdb.IsBlockInStore(&hash),
			"RESIDUE #2: discarded block at height %d still reported present by "+
				"IsBlockInStore/HasBlock after forced rollback", h)
	}

	// ORPHAN COMPLETENESS (fails on the per-iteration-only purge, passes with the
	// sweep): the above-target orphan/side block must ALSO be purged, so a rolled-back
	// node reaches exact clean-forward parity and serves no block above the target.
	{
		blk, gerr := fdb.GetBlock(orphanHash)
		assert.Error(t, gerr,
			"RESIDUE #2 orphan: an above-target side block stored off the main chain is "+
				"still served by hash after forced rollback (the in-line purge is off-by-one)")
		assert.Nil(t, blk, "RESIDUE #2 orphan: must not deserialize after rollback")
		assert.False(t, fdb.IsBlockInStore(&orphanHash),
			"RESIDUE #2 orphan: still reported present by IsBlockInStore after rollback")
	}

	// OVER-DELETION GUARD: retained blocks (<= target) must STILL be served by hash.
	for _, h := range []uint32{0, 1} {
		hash := hashByHeight[h]

		blk, gerr := fdb.GetBlock(hash)
		assert.NoError(t, gerr,
			"retained block at height %d (<= target) must still be served by hash", h)
		assert.NotNil(t, blk, "retained block at height %d must deserialize", h)

		assert.True(t, fdb.IsBlockInStore(&hash),
			"retained block at height %d (<= target) must still be in store", h)
	}

	// FV-25: POST-REWIND FORWARD REPLAY.
	//
	// Every assertion above is about what the rollback REMOVED and what it KEPT. None
	// of the reset tests ever drove the rewound store FORWARD again -- which is the
	// only thing the coordinated restart actually does with it.
	//
	// HONEST SCOPE, measured rather than asserted: this leg is COVERAGE, not
	// ENFORCEMENT. Disabling the forced rollback's header-index removal -- STEP 3 of
	// rollbackOneBlock AND the HeaderRowsAbove sweep in PurgeForcedRollbackResidue,
	// together -- leaves every assertion in THIS file green, including the ones below.
	// The replayed block carries a different hash from the discarded one, so a stale
	// index row for that height does not collide with it. The header-index removal is
	// enforced elsewhere (the T1 family in test/unit fails on exactly that mutation:
	// TestT1ForcedRollbackStepOrder, TestT1RollbackAtomicityNoRestartRatchet,
	// TestT1RollbackResumeIsExactlyOnce, TestT1CheckForcedRollbackResidueAllowsHealthyNodes,
	// TestT1ForcedRollbackInterruptStopsAtBlockBoundary,
	// TestT1SweepHandlesDetachedSideBlockResidue). Kept because it exercises the
	// post-rewind forward path the restart actually performs, which nothing else did --
	// but it must not be counted as a fail-on-pristine guard.
	{
		replay := &types.Block{
			Header: common2.Header{
				Version:  0,
				Height:   target + 1,
				Previous: hashByHeight[target],
				// Distinct from the DISCARDED block at this height, so the replay is a
				// genuinely new block rather than a re-save of the one just purged.
				Timestamp: 1700000000,
				Bits:      0x1d03ffff,
			},
			Transactions: []interfaces.Transaction{residueCoinbase(target + 1)},
		}
		replayHash := replay.Hash()
		discarded := hashByHeight[target+1]
		assert.NotEqual(t, discarded, replayHash,
			"the replayed block must differ from the discarded one at the same height")

		node, lerr := chain.LoadBlockNode(&replay.Header, &replayHash)
		assert.NoError(t, lerr, "post-rewind: LoadBlockNode at target+1 must succeed")
		assert.NoError(t, chain.GetDB().SaveBlock(replay, node, nil,
			blockchain.CalcPastMedianTime(node)),
			"post-rewind: the rewound store must accept a NEW block at target+1")
		chain.SetTip(node)
		chain.BestChain = node

		got, gerr := fdb.GetBlock(replayHash)
		assert.NoError(t, gerr, "post-rewind: the replayed block must be served by hash")
		assert.NotNil(t, got, "post-rewind: the replayed block must deserialize")
		assert.True(t, fdb.IsBlockInStore(&replayHash),
			"post-rewind: the replayed block must be in the raw block store")
		assert.Equal(t, target+1, uint32(len(chain.Nodes)-1),
			"post-rewind: the tip must advance to target+1")

		// The purge must not be undone by the replay.
		assert.False(t, fdb.IsBlockInStore(&discarded),
			"post-rewind: the DISCARDED block at target+1 must not reappear once the "+
				"chain moves forward again")
	}

	// STILL NOT COVERED HERE, and deliberately so: checkpoint-height restoration,
	// on-disk checkpoint restore and the snapshot-ring purge. Those are the blind spot
	// FV-01 and FV-12 live in; asserting them from this test would be asserting
	// behaviour those findings say is currently wrong, so they belong with their own
	// fixes, not with this one.
}
