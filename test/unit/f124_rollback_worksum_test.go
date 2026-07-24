// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit - EMPIRICAL fail-on-pristine proof for F-124: after a rollback, the
// persisted best-chain-state record must be internally consistent - the work sum
// stored next to the parent's hash/height must be the PARENT's accumulated work,
// not the DISCARDED child's.
//
// This drives the real production path end to end against a real ffldb-backed
// ChainStore:
//
//	(*BlockChain).ForceRollback
//	  -> ChainStore.RollbackBlock -> ChainStoreFFLDB.RollbackBlock
//	     -> newBestState(prevNode, ...)      (hash/height = PARENT)
//	     -> dbPutBestState(dbTx, state, ...) (work sum argument under test)
//	  -> metadata key "chainstate"
//
// PRISTINE behaviour: dbPutBestState is handed node.WorkSum (the rolled-back child),
// so the persisted record pairs the parent's hash and height with the child's work.
// The assertion below FAILS on pristine and PASSES with prevNode.WorkSum.
package unit

import (
	"encoding/binary"
	"math/big"
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

// f124ChainState mirrors blockchain.deserializeBestChainState (unexported there):
//
//	<block hash 32><height u32 LE><total txns u64 LE><work sum len u32 LE><work sum BE>
func f124ChainState(t *testing.T, raw []byte) (common.Uint256, uint32, *big.Int) {
	t.Helper()
	const hashSize = 32
	if len(raw) < hashSize+16 {
		t.Fatalf("corrupt chainstate record: %d bytes", len(raw))
	}
	var hash common.Uint256
	copy(hash[:], raw[0:hashSize])
	off := uint32(hashSize)
	height := binary.LittleEndian.Uint32(raw[off : off+4])
	off += 4 + 8 // skip total txns
	wsLen := binary.LittleEndian.Uint32(raw[off : off+4])
	off += 4
	if uint32(len(raw[off:])) < wsLen {
		t.Fatalf("corrupt chainstate work sum: want %d bytes, have %d", wsLen, len(raw[off:]))
	}
	return hash, height, new(big.Int).SetBytes(raw[off : off+wsLen])
}

// TestF124RollbackPersistsParentWorkSum is the fail-on-pristine test for F-124.
func TestF124RollbackPersistsParentWorkSum(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(1) // retained: heights 0 and 1; discarded: 2 and 3
	const tip = uint32(3)

	params := config.GetDefaultParams()
	params.Sterilize()
	params.DPoSV2StartHeight = 0
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	params.ForcedRollbackHeight = target
	blockchain.FoundationAddress = *params.FoundationProgramHash

	chainStore, err := blockchain.NewChainStore(
		filepath.Join(test.DataPath, "f124bestworksum"), params)
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

	// Append real coinbase-only blocks 1..tip through the production store path and
	// keep an immutable copy of each node's accumulated work (BlockNode.WorkSum is a
	// *big.Int that later AddChildrenWork calls mutate in place).
	genesisHash := params.GenesisBlock.Hash()
	hashByHeight := map[uint32]common.Uint256{0: genesisHash}
	workByHeight := map[uint32]*big.Int{}
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
		workByHeight[h] = new(big.Int).Set(node.WorkSum)
		prevHash = hash
	}

	// Fixture guard: the two work sums under test must actually differ, otherwise the
	// assertion below could not discriminate pristine from fixed.
	assert.Equal(t, -1, workByHeight[target].Cmp(workByHeight[target+1]),
		"fixture invalid: parent work sum must be strictly below the child's")

	// Run the real forced rollback (tip 3 -> target 1). The LAST RollbackBlock call
	// rolls back height target+1, whose parent is the new tip at height target.
	assert.NoError(t, chain.ForceRollback(nil), "forced rollback must succeed")
	assert.Equal(t, target, uint32(len(chain.Nodes)-1), "tip must be rewound to target")

	var raw []byte
	assert.NoError(t, chain.GetDB().GetFFLDB().View(func(dbTx database.Tx) error {
		v := dbTx.Metadata().Get([]byte("chainstate"))
		raw = append(raw, v...)
		return nil
	}))
	assert.NotEmpty(t, raw, "best chain state record must exist after rollback")

	hash, height, workSum := f124ChainState(t, raw)

	// These two hold on pristine as well: newBestState already describes the parent.
	assert.Equal(t, hashByHeight[target], hash,
		"persisted best-state hash must be the parent (new tip)")
	assert.Equal(t, target, height,
		"persisted best-state height must be the parent's (new tip)")

	// Discriminating assertions.
	assert.Equal(t, 0, workByHeight[target].Cmp(workSum),
		"F-124: persisted work sum must be the PARENT's accumulated work (%s), got %s",
		workByHeight[target], workSum)
	assert.NotEqual(t, 0, workByHeight[target+1].Cmp(workSum),
		"F-124: persisted work sum is the DISCARDED child's accumulated work (%s) - the "+
			"best-state record pairs the parent's hash/height with the child's work",
		workByHeight[target+1])
}
