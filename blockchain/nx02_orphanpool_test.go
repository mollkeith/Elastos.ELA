// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-02 — fail-on-pristine for the orphan-block pool byte bound and the
// block-connect sweep.
//
// Both tests drive PRODUCTION entry points, not the functions that were edited:
//
//	processBlock   (blockchain.go:2031) -> AddOrphanBlock   -- admission
//	ProcessOrphans (blockchain.go:979)  -> SweepExpiredOrphans -- self-heal
//
// processBlock applies exactly one gate before parking a peer-supplied block in
// memory: CheckBlockSanity, whose work check is against PowConfiguration.PowLimit
// (2^255-1), i.e. free. Every block below is minted at that price, with a random
// unconnectable Previous, which is precisely the attacker's block.
//
// UNGATED: this is retention policy, not block acceptance. An orphan has by
// definition never passed CheckBlockContext, so refusing to RETAIN one cannot
// change which blocks are valid, and a genuinely connectable block that is
// dropped is re-requested on the next announcement. Same rationale already
// recorded in-tree for the shipped F-092/F-117 pool bounds.
package blockchain

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	program "github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/require"
)

type nx02Store struct {
	IChainStore
	ffldb IFFLDBChainStore
}

func (s *nx02Store) GetFFLDB() IFFLDBChainStore { return s.ffldb }

func nx02RandHash() common.Uint256 {
	var h common.Uint256
	rand.Read(h[:])
	return h
}

// nx02MineFreeHeader grinds the AuxPow parent nonce until the sanity work gate
// accepts. Measured mean on mainnet params: ~2 tries — the gate is free.
func nx02MineFreeHeader(h *common2.Header, powLimit *big.Int) bool {
	hash := h.Hash() // Header.Hash() excludes AuxPow, so grinding does not move it
	ap := auxpow.GenerateAuxPow(hash)
	for tries := 1; tries <= 5000; tries++ {
		ap.ParBlockHeader.Nonce = uint32(tries)
		ap.ParMerkleIndex = 0
		ap.ParentHash = ap.ParBlockHeader.Hash() // canonical (F-041/F-090)
		h.AuxPow = *ap
		if CheckProofOfWork(h, powLimit) == nil && ap.Check(&hash, auxpow.AuxPowChainID) {
			return true
		}
	}
	return false
}

// nx02Coinbase pads a coinbase to roughly `attr` bytes.
// CoinBaseTransaction.CheckAttributeProgram validates only that Programs is
// empty; attributes are entirely unchecked, so the bulk is free-form.
func nx02Coinbase(attr int) interfaces.Transaction {
	data := make([]byte, attr)
	rand.Read(data[:512])
	return functions.CreateTransaction(
		common2.TxVersion09, common2.CoinBase, 0, &payload.CoinBase{},
		[]*common2.Attribute{{Usage: common2.Nonce, Data: data}},
		[]*common2.Input{{Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 65535}, Sequence: 4294967295}},
		[]*common2.Output{
			{AssetID: core.ELAAssetID, Value: 70000000, ProgramHash: common.Uint168{}, Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 30000000, ProgramHash: common.Uint168{}, Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
		}, 0, []*program.Program{})
}

func nx02FreeOrphanBlock(t *testing.T, params *config.Configuration, size int) *types.Block {
	t.Helper()
	cb := nx02Coinbase(size)
	blk := &types.Block{
		Header: common2.Header{
			Version: 0, Previous: nx02RandHash(), MerkleRoot: cb.Hash(),
			Timestamp: uint32(time.Now().Unix()), Height: 2260596,
			Bits: BigToCompact(params.PowConfiguration.PowLimit),
		},
		Transactions: []interfaces.Transaction{cb},
	}
	require.True(t, nx02MineFreeHeader(&blk.Header, params.PowConfiguration.PowLimit),
		"the sanity work gate is supposed to be free")
	return blk
}

func nx02Chain(t *testing.T) *BlockChain {
	t.Helper()
	log.NewDefault(t.TempDir(), 0, 0, 0)
	params := config.GetDefaultParams()

	ffldb, err := NewChainStoreFFLDB(t.TempDir(), params)
	require.NoError(t, err)
	t.Cleanup(func() { ffldb.Close() })

	store := &nx02Store{ffldb: ffldb}
	return &BlockChain{
		chainParams:    params,
		db:             store,
		index:          newBlockIndex(store, params),
		Nodes:          make([]*BlockNode, 0),
		DepNodes:       make(map[common.Uint256][]*BlockNode),
		orphans:        make(map[common.Uint256]*OrphanBlock),
		prevOrphans:    make(map[common.Uint256][]*OrphanBlock),
		orphanConfirms: make(map[common.Uint256]*payload.Confirm),
		TimeSource:     NewMedianTime(),
	}
}

// TestNX02CeilingsDefaultToTheProductionConstants pins the policy the two
// behavioural tests lower. Without it, a silent weakening of the ceilings would
// leave those tests green while the node was unbounded again.
func TestNX02CeilingsDefaultToTheProductionConstants(t *testing.T) {
	require.Equal(t, uint64(maxOrphanBlocks), orphanCountCeiling)
	require.Equal(t, uint64(maxOrphanBlockBytes), orphanByteCeiling)
	require.Equal(t, uint64(256*1024*1024), orphanByteCeiling,
		"the orphan pool must be bounded by BYTES, in the low hundreds of MiB")
	require.LessOrEqual(t, orphanCountCeiling, uint64(10000),
		"the count cap must not be loosened past the upstream 10,000")
}

// TestNX02OrphanPoolIsBoundedByBytes is the primary fail-on-pristine assertion.
//
// On the pristine tree the ONLY bound is maxOrphanBlocks = 10000 with no byte
// accounting anywhere on the path, so all 24 blocks below are retained and the
// pool holds ~24 MiB — measured retention on the real pool was 1.0003x the wire
// bytes delivered, which is what makes ~85 GiB reachable at the count cap and
// kills a 16 GiB node at ~1,800 maximum-size orphans.
func TestNX02OrphanPoolIsBoundedByBytes(t *testing.T) {
	chain := nx02Chain(t)

	// Lower ONLY the byte ceiling so bytes are what binds; the count ceiling
	// stays at the production value and cannot mask the result.
	origBytes := orphanByteCeiling
	orphanByteCeiling = 8 << 20 // 8 MiB
	defer func() { orphanByteCeiling = origBytes }()

	const per = 1 << 20 // 1 MiB per block
	const n = 24        // 24 MiB delivered -- 3x the ceiling

	wire := uint64(0)
	for i := 0; i < n; i++ {
		blk := nx02FreeOrphanBlock(t, chain.chainParams, per)
		wire += uint64(blk.GetSize())

		// PRODUCTION ENTRY POINT.
		inMain, isOrphan, err := chain.processBlock(blk, nil)
		require.NoError(t, err)
		require.False(t, inMain)
		require.True(t, isOrphan, "a block with an unknown parent must become an orphan")

		count, bytes, _, maxBytes := chain.OrphanPoolStats()
		require.LessOrEqual(t, bytes, maxBytes,
			"NX-02 REGRESSION: orphan pool holds %d bytes over a %d-byte ceiling "+
				"after %d blocks (%d retained)", bytes, maxBytes, i+1, count)
	}

	count, bytes, _, maxBytes := chain.OrphanPoolStats()
	require.LessOrEqual(t, bytes, maxBytes)
	require.Less(t, count, n,
		"NX-02 REGRESSION: every one of the %d delivered blocks was retained -- "+
			"the pool is not bounded by bytes", n)
	require.Greater(t, wire, maxBytes*2,
		"harness is not honest: it must deliver well past the ceiling")

	// The accounting must be exact, not merely capped: a running total that
	// drifts upward would eventually refuse honest orphans, and one that drifts
	// downward would reopen the hole.
	var sum uint64
	for _, o := range chain.orphans {
		sum += o.size
	}
	require.Equal(t, sum, bytes,
		"NX-02: the running byte total disagrees with the retained blocks")
	t.Logf("NX-02 ok: delivered %d bytes, retained %d blocks / %d bytes (ceiling %d)",
		wire, count, bytes, maxBytes)
}

// TestNX02OrphanPoolSelfHealsOnBlockConnect is the second fail-on-pristine
// assertion. On the pristine tree the 1-hour expiry is enforced ONLY inside
// AddOrphanBlock, so once the attacker stops sending, nothing sweeps: an
// exhaustive grep showed RemoveOrphanBlock had exactly three callers (that
// sweep, the eviction two lines below it, and ProcessOrphans when a parent
// actually arrives) — no timer, no goroutine, no reaper. The pool was pinned for
// the life of the process and the node recovered only by restart.
//
// ProcessOrphans is the production block-connect hook: processBlock calls it
// after every successful maybeAcceptBlock.
func TestNX02OrphanPoolSelfHealsOnBlockConnect(t *testing.T) {
	chain := nx02Chain(t)

	for i := 0; i < 3; i++ {
		blk := nx02FreeOrphanBlock(t, chain.chainParams, 1<<10)
		_, isOrphan, err := chain.processBlock(blk, nil)
		require.NoError(t, err)
		require.True(t, isOrphan)
	}

	count, bytes, _, _ := chain.OrphanPoolStats()
	require.Equal(t, 3, count)
	require.Greater(t, bytes, uint64(0))

	// The attacker goes quiet and an hour passes.
	for _, o := range chain.orphans {
		o.Expiration = time.Now().Add(-time.Minute)
	}

	// An honest block connects somewhere else on the chain. PRODUCTION ENTRY
	// POINT: the hash names no orphan's parent, so the ONLY thing that can empty
	// the pool is the sweep.
	unrelated := nx02RandHash()
	require.NoError(t, chain.ProcessOrphans(&unrelated))

	count, bytes, _, _ = chain.OrphanPoolStats()
	require.Equal(t, 0, count,
		"NX-02 REGRESSION: expired orphans survived a block connect -- the pool "+
			"does not self-heal after the attacker stops sending")
	require.Equal(t, uint64(0), bytes,
		"NX-02: the byte total must be debited when orphans are swept")
	require.Equal(t, 0, len(chain.prevOrphans),
		"NX-02: the prevOrphans index must be emptied with the pool")
}

// TestNX02EvictionCannotBeASilentNoOp covers the eviction bookkeeping the byte
// bound depends on. The pristine code carried b.oldestOrphan ACROSS calls and
// never reset it after a sweep, so an eviction could target a pointer that had
// already been removed: delete() on an absent key is a no-op, the count stayed
// over the cap, and the pool grew past its own bound. With bytes now derived
// from the same bookkeeping, a no-op eviction would also leak the byte total
// upward until the pool refused honest orphans.
func TestNX02EvictionCannotBeASilentNoOp(t *testing.T) {
	chain := nx02Chain(t)

	origCount := orphanCountCeiling
	orphanCountCeiling = 4
	defer func() { orphanCountCeiling = origCount }()

	const n = 20
	for i := 0; i < n; i++ {
		blk := nx02FreeOrphanBlock(t, chain.chainParams, 1<<10)
		_, isOrphan, err := chain.processBlock(blk, nil)
		require.NoError(t, err)
		require.True(t, isOrphan)
		// exactly what mempool/blockpool.go:251 does on the DPoS-mode leg.
		chain.AddOrphanConfirm(&payload.Confirm{Proposal: payload.DPOSProposal{BlockHash: blk.Hash()}})

		count, bytes, maxCount, _ := chain.OrphanPoolStats()
		require.LessOrEqual(t, uint64(count), maxCount,
			"NX-02 REGRESSION: pool holds %d orphans over a %d ceiling", count, maxCount)

		var sum uint64
		for _, o := range chain.orphans {
			sum += o.size
		}
		require.Equal(t, sum, bytes,
			"NX-02 REGRESSION: byte total drifted after eviction %d (accounted %d, actual %d)",
			i, bytes, sum)
		require.LessOrEqual(t, len(chain.orphanConfirms), count,
			"NX-02: orphanConfirms must be evicted with their orphan")
	}

	// Every prevOrphans bucket must have been cleaned up with its orphan;
	// a leaked bucket is an unbounded map keyed by attacker-chosen hashes.
	require.LessOrEqual(t, len(chain.prevOrphans), int(orphanCountCeiling),
		"NX-02: prevOrphans leaked buckets for evicted orphans")
}

// TestNX02DoubleRemoveCannotCorruptTheByteTotal drives the EXPORTED
// RemoveOrphanBlock, which is the production removal API (ProcessOrphans calls
// it at blockchain.go:1002), and proves the byte total cannot be corrupted by a
// removal that names an orphan the pool no longer holds.
//
// This is what makes the byte bound trustworthy rather than merely present: a
// double debit drifts the running total DOWNWARD, which silently reopens the
// hole the ceiling was added to close (the pool would believe it is emptier than
// it is and keep admitting), while a missing debit drifts it upward until honest
// orphans are refused. The pristine code had no total to corrupt; it also had no
// existence check, and it carried b.oldestOrphan across calls without resetting
// it after a sweep, so an eviction could target an already-removed pointer and
// do nothing at all while the count stayed over the cap.
func TestNX02DoubleRemoveCannotCorruptTheByteTotal(t *testing.T) {
	chain := nx02Chain(t)

	var first *OrphanBlock
	for i := 0; i < 2; i++ {
		blk := nx02FreeOrphanBlock(t, chain.chainParams, 1<<10)
		_, isOrphan, err := chain.processBlock(blk, nil)
		require.NoError(t, err)
		require.True(t, isOrphan)
		if i == 0 {
			first = chain.orphans[blk.Hash()]
			require.NotNil(t, first)
		}
	}

	_, before, _, _ := chain.OrphanPoolStats()
	require.Greater(t, before, uint64(0))

	chain.RemoveOrphanBlock(first)
	chain.RemoveOrphanBlock(first) // stale pointer: must be a no-op, not a second debit

	count, bytes, _, _ := chain.OrphanPoolStats()
	require.Equal(t, 1, count)

	var sum uint64
	for _, o := range chain.orphans {
		sum += o.size
	}
	require.Equal(t, sum, bytes,
		"NX-02 REGRESSION: a repeated RemoveOrphanBlock corrupted the running byte "+
			"total (accounted %d, actually retained %d)", bytes, sum)
	require.Greater(t, bytes, uint64(0),
		"NX-02 REGRESSION: the byte total was debited for an orphan that was not removed")
}

// TestNX02OrphanConfirmsCannotOutliveThePool closes the sibling map on the same
// unauthenticated path: orphanConfirms is only ever drained by an orphan
// removal keyed on that orphan's hash, so a confirm admitted for a block the
// pool does not hold would be pinned for the life of the process. A Confirm can
// carry up to MaxDPOSProposalVotes votes, so this is not a negligible object.
func TestNX02OrphanConfirmsCannotOutliveThePool(t *testing.T) {
	chain := nx02Chain(t)

	// A confirm for a block that was never admitted must not be retained.
	chain.AddOrphanConfirm(&payload.Confirm{
		Proposal: payload.DPOSProposal{BlockHash: nx02RandHash()}})
	require.Equal(t, 0, len(chain.orphanConfirms),
		"NX-02 REGRESSION: a confirm for a block the pool does not hold was retained")

	// A confirm for a block that IS held is retained, and is dropped with it.
	blk := nx02FreeOrphanBlock(t, chain.chainParams, 1<<10)
	_, isOrphan, err := chain.processBlock(blk, nil)
	require.NoError(t, err)
	require.True(t, isOrphan)

	chain.AddOrphanConfirm(&payload.Confirm{
		Proposal: payload.DPOSProposal{BlockHash: blk.Hash()}})
	require.Equal(t, 1, len(chain.orphanConfirms))

	for _, o := range chain.orphans {
		o.Expiration = time.Now().Add(-time.Minute)
	}
	unrelated := nx02RandHash()
	require.NoError(t, chain.ProcessOrphans(&unrelated))
	require.Equal(t, 0, len(chain.orphanConfirms),
		"NX-02: a swept orphan must take its confirm with it")
}
