// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit — proof for the OFFLINE residue #2 cleaner
// (blockchain.PurgeForcedRollbackResidue), the second TRACK A vehicle for nodes that
// ALREADY rolled back (ForceRollback is idempotent and cannot reach them).
//
// It builds a real ffldb-backed chain (genesis + heights 1..3), then reproduces the
// exact "already rolled back with residue" state: it strips heights 2 and 3 from the
// main-chain height index (as a rollback does) but leaves the raw by-hash block store
// (ffldb-blockidx) intact -- so those blocks are still served by hash. It then runs
// the cleaner at target 1 and asserts it purges exactly the two residual blocks
// (height > target, off the main chain) and never touches genesis/height-1 (<= target).
package unit

import (
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"

	"github.com/stretchr/testify/assert"
)

// TestResidue2OfflineCleanerPurgesAlreadyRolledBack drives the offline cleaner
// against a store that is already in the rolled-back-with-residue state.
func TestResidue2OfflineCleanerPurgesAlreadyRolledBack(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(1) // retained: heights 0,1 ; residue to purge: heights 2,3
	const tip = uint32(3)

	params := config.GetDefaultParams()
	params.Sterilize()
	params.DPoSV2StartHeight = 0
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	blockchain.FoundationAddress = *params.FoundationProgramHash

	chainStore, err := blockchain.NewChainStore(
		filepath.Join(test.DataPath, "residue2cleaner"), params)
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

	genesisHash := params.GenesisBlock.Hash()
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

	// Reproduce the already-rolled-back-with-residue state: strip heights 2 and 3
	// from the main-chain height index (as RollbackBlock does) but leave the raw
	// block store (ffldb-blockidx) untouched -> residue #2.
	for _, h := range []uint32{2, 3} {
		hh := h
		hash := hashByHeight[hh]
		assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
			return blockchain.DBRemoveBlockIndex(dbTx, &hash, hh)
		}), "strip main-chain index at height %d", hh)
	}

	// Precondition: the residue is present -- heights 2,3 are still served by hash
	// even though they are no longer on the main chain.
	for _, h := range []uint32{2, 3} {
		hash := hashByHeight[h]
		_, gerr := fdb.GetBlock(hash)
		assert.NoError(t, gerr,
			"residue precondition: height %d must still be served by hash before cleaning", h)
		assert.True(t, fdb.IsBlockInStore(&hash),
			"residue precondition: height %d must still be in store before cleaning", h)
	}

	// Run the offline cleaner at the rollback target.
	purged, cerr := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.NoError(t, cerr, "cleaner must run without error")
	assert.Equal(t, 2, purged, "cleaner must purge exactly the 2 residual blocks (heights 2,3)")

	// Residue gone: heights 2,3 no longer served nor present.
	for _, h := range []uint32{2, 3} {
		hash := hashByHeight[h]
		blk, gerr := fdb.GetBlock(hash)
		assert.Error(t, gerr,
			"height %d must not be served by hash after cleaning", h)
		assert.Nil(t, blk, "height %d must not deserialize after cleaning", h)
		assert.False(t, fdb.IsBlockInStore(&hash),
			"height %d must not be in store after cleaning", h)
	}

	// Over-deletion guard: retained blocks (<= target) untouched.
	for _, h := range []uint32{0, 1} {
		hash := hashByHeight[h]
		blk, gerr := fdb.GetBlock(hash)
		assert.NoError(t, gerr,
			"retained height %d (<= target) must still be served after cleaning", h)
		assert.NotNil(t, blk, "retained height %d must deserialize after cleaning", h)
		assert.True(t, fdb.IsBlockInStore(&hash),
			"retained height %d (<= target) must still be in store after cleaning", h)
	}

	// Idempotent: a second run finds nothing left to purge.
	purged2, cerr2 := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.NoError(t, cerr2)
	assert.Equal(t, 0, purged2, "second cleaner run must be a no-op")
}
