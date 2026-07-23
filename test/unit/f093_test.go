// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

// f093BestHeight backs the bestHeight closure of the Arbiters under test.
var f093BestHeight uint32

// f093InitArbiters builds a real Arbiters wired with a getBlockByHeight closure, so
// the REAL emergency ForceChange path (SnapshotByHeight -> UpdateNextArbitrators ->
// ChangeCurrentArbitrators -> History.Commit) runs, not a stub of it. The pristine
// initArbiters passes nil for getBlockByHeight, which ForceChange cannot use.
func f093InitArbiters() {
	arbitratorsStr := []string{
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
		"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
		"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
		"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
	}
	abtList = make([][]byte, 0)
	for _, v := range arbitratorsStr {
		a, _ := common.HexStringToBytes(v)
		abtList = append(abtList, a)
	}
	// A PRIVATE parameter set: every other test in this package mutates the shared
	// config.DefaultParams, and the reward/clearing rules this harness walks through
	// are parameter-sensitive. Isolate so the result does not depend on test order.
	activeNetParams := config.GetDefaultParams()
	ckpManager := checkpoint.NewManager(activeNetParams)
	activeNetParams.DPoSConfiguration.CRCArbiters = []string{
		"03e435ccd6073813917c2d841a0815d21301ec3286bc1412bb5b099178c68a10b6",
		"038a1829b4b2bee784a99bebabbfecfec53f33dadeeeff21b460f8b4fc7c2ca771",
	}
	abt, _ = state.NewArbitrators(activeNetParams, nil, nil,
		nil, nil, nil,
		nil, nil, nil, ckpManager)
	abt.RegisterFunction(func() uint32 { return f093BestHeight },
		func() *common.Uint256 { return &common.Uint256{} },
		func(h uint32) (*types.Block, error) {
			return &types.Block{Header: common2.Header{Height: h}}, nil
		}, nil)
	abt.State = state.NewState(activeNetParams, nil, nil, nil,
		func() bool { return false },
		nil, nil, nil,
		nil, nil, nil, nil)
}

// f093Chain drives the real Arbiters up to a tip that has four active, voted
// producers, and returns that tip height. Block tip+1 is the block whose special
// transaction will be pre-processed.
func f093Chain(t *testing.T) uint32 {
	f093InitArbiters()

	height := abt.ChainParams.VoteStartHeight
	f093BestHeight = height
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height},
		Transactions: []interfaces.Transaction{
			getRegisterProducerTx(abtList[0], abtList[0], "p1"),
			getRegisterProducerTx(abtList[1], abtList[1], "p2"),
			getRegisterProducerTx(abtList[2], abtList[2], "p3"),
			getRegisterProducerTx(abtList[3], abtList[3], "p4"),
		},
	}, nil)

	for i := 0; i < 5; i++ {
		height++
		f093BestHeight = height
		abt.ProcessBlock(&types.Block{
			Header: common2.Header{Height: height}}, nil)
	}
	assert.Equal(t, 4, len(abt.ActivityProducers))

	height++
	f093BestHeight = height
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height},
		Transactions: []interfaces.Transaction{
			getVoteProducerTx(10, []outputpayload.CandidateVotes{
				{Candidate: abtList[0], Votes: 5}})}}, nil)

	return height
}

// f093ArbiterViewEqual compares the ARBITERS-level view of two checkpoints: the
// rotation, the reward books and the emergency bookkeeping. It deliberately leaves
// out StateKeyFrame: State.ProcessSpecialTxPayload records its emergency-inactive
// marking as a height==0 TEMPORARY change (utils.History.tempChanges), which is
// by-design reversed when the next block arrives, not by RollbackTo. That is the
// separate, already-reviewed F-097 behaviour and is not what F-093 is about.
func f093ArbiterViewEqual(x, y *state.CheckPoint) bool {
	return x.ForceChanged == y.ForceChanged &&
		x.DutyIndex == y.DutyIndex &&
		x.CRCChangedHeight == y.CRCChangedHeight &&
		x.AccumulativeReward == y.AccumulativeReward &&
		x.FinalRoundChange == y.FinalRoundChange &&
		x.ClearingHeight == y.ClearingHeight &&
		len(x.InactiveTxs) == len(y.InactiveTxs) &&
		len(x.IllegalBlocksPayloadHashes) == len(y.IllegalBlocksPayloadHashes) &&
		len(x.NextCRCArbitersMap) == len(y.NextCRCArbitersMap) &&
		len(x.ArbitersRoundReward) == len(y.ArbitersRoundReward) &&
		arrayEqual(x.CurrentArbitrators, y.CurrentArbitrators) &&
		arrayEqual(x.NextArbitrators, y.NextArbitrators) &&
		arrayEqual(x.CurrentCandidates, y.CurrentCandidates) &&
		arrayEqual(x.NextCandidates, y.NextCandidates) &&
		rewardEqual(&x.CurrentReward, &y.CurrentReward) &&
		rewardEqual(&x.NextReward, &y.NextReward)
}

// f093InactivePayload builds an InactiveArbitrators payload for a block at height.
func f093InactivePayload(sponsor, inactive []byte,
	height uint32) *payload.InactiveArbitrators {
	return &payload.InactiveArbitrators{
		Sponsor:     sponsor,
		Arbitrators: [][]byte{inactive},
		BlockHeight: height,
	}
}

// TestF093ForceChangeStickyAfterFailedConnect is the fail-on-pristine proof of
// F-093.
//
// connectBlock runs PreProcessSpecialTx FIRST -- before CheckBlockContext, before
// checkBlockWithConfirmation and before the block is stored -- and it applies the
// emergency ForceChange at block.Height-1 (blockchain/confirmvalidator.go:169-172,
// blockchain/blockchain.go:1505). Every later step in connectBlock can fail. The
// rollback the failure path performs is OnRollbackTo(block.Height-1), i.e. exactly
// abt.RollbackTo(tip) below, and utils.History.RollbackTo only reverses groups
// STRICTLY ABOVE its target. So on a pristine tree the rotation, the forceChanged
// flag and the enlarged arbiter set all survive a block the node rejected.
func TestF093ForceChangeStickyAfterFailedConnect(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()
	assert.False(t, before.ForceChanged)

	// Block tip+1 carries an InactiveArbitrators tx: PreProcessSpecialTx applies the
	// emergency ForceChange, binding it to tip (== block.Height-1).
	assert.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[0], abtList[1], tip+1), tip))

	forced := abt.Snapshot()
	assert.True(t, forced.ForceChanged, "sanity: the real ForceChange ran")
	assert.NotEqual(t, len(before.CurrentArbitrators),
		len(forced.CurrentArbitrators), "sanity: the arbiter set really rotated")

	// Block tip+1 now FAILS to connect. connectBlock's failure path rolls the
	// checkpoint manager back to block.Height-1 == tip.
	assert.NoError(t, abt.RollbackTo(tip))
	after := abt.Snapshot()

	assert.False(t, after.ForceChanged,
		"F-093: a rejected block must not leave the node force-changed")
	assert.True(t, f093ArbiterViewEqual(before, after),
		"F-093: the arbiter set/rewards must be exactly the pre-block state")
	assert.Equal(t, len(before.CurrentArbitrators), len(after.CurrentArbitrators))
	assert.Equal(t, len(before.NextArbitrators), len(after.NextArbitrators))
}

// TestF093InactiveMarkerStickyAfterFailedConnect is the fail-on-pristine proof of
// F-094, the same mechanism one layer down: degradation.inactiveTxs lives OUTSIDE
// utils.History, so no rollback has ever un-marked it. A rejected (or reorged-away)
// block therefore poisons the marker set permanently: when the very same special
// transaction is later included in a block that DOES connect, AddInactivePayload
// reports a duplicate, ProcessSpecialTxPayload returns nil early and the ForceChange
// the surviving chain requires is silently SKIPPED -- a permanent arbiter-set
// divergence from every node that never saw the rejected block.
func TestF093InactiveMarkerStickyAfterFailedConnect(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()
	p := f093InactivePayload(abtList[0], abtList[1], tip+1)

	// Rejected block tip+1.
	assert.NoError(t, abt.ProcessSpecialTxPayload(p, tip))
	assert.Equal(t, 1, len(abt.Snapshot().InactiveTxs))
	assert.NoError(t, abt.RollbackTo(tip))

	assert.Equal(t, 0, len(abt.Snapshot().InactiveTxs),
		"F-094: the processed-payload marker must not outlive the rejected block")

	// Positive control: the surviving chain includes the same special tx at the same
	// height and it must still force-change. On a pristine tree the stale marker turns
	// this into a silent no-op -- the divergence F-094 describes.
	assert.NoError(t, abt.ProcessSpecialTxPayload(p, tip))
	replayed := abt.Snapshot()
	assert.True(t, replayed.ForceChanged,
		"F-094: the same payload must still force-change on the surviving chain")
	assert.Equal(t, 1, len(replayed.InactiveTxs))
	assert.False(t, f093ArbiterViewEqual(before, replayed),
		"F-094: the re-applied ForceChange really rotates the arbiter set again")
}

// TestF093MultiplePayloadsSameBlockUndone covers the F-106 dimension of the same
// root cause: PreProcessSpecialTx loops over EVERY InactiveArbitrators payload in
// the block, so one rejected block can apply N ForceChanges and add N markers. All
// of them share the one savepoint taken for the block and must be undone together.
func TestF093MultiplePayloadsSameBlockUndone(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()

	// InactiveArbitrators.Hash() keys on (Sponsor, BlockHeight), so two payloads in
	// the same block are distinct markers only when their sponsors differ.
	assert.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[0], abtList[1], tip+1), tip))
	assert.NoError(t, abt.ProcessSpecialTxPayload(
		f093InactivePayload(abtList[1], abtList[2], tip+1), tip))
	assert.Equal(t, 2, len(abt.Snapshot().InactiveTxs))

	assert.NoError(t, abt.RollbackTo(tip))
	after := abt.Snapshot()

	assert.Equal(t, 0, len(after.InactiveTxs),
		"F-106: every marker added by the rejected block is undone")
	assert.False(t, after.ForceChanged)
	assert.True(t, f093ArbiterViewEqual(before, after))
}

// TestF093NoSpecialTxRollbackUnchanged is the regression guard: a block that carries
// no special transaction takes no savepoint, so the ordinary reorg rollback keeps
// behaving exactly as before.
func TestF093NoSpecialTxRollbackUnchanged(t *testing.T) {
	tip := f093Chain(t)
	before := abt.Snapshot()

	next := tip + 1
	f093BestHeight = next
	block := &types.Block{
		Header: common2.Header{Height: next},
		Transactions: []interfaces.Transaction{
			getUpdateProducerTx(abtList[1], abtList[1], "node1")}}
	abt.ProcessBlock(block, nil)
	changed := abt.Snapshot()
	assert.False(t, checkPointEqual(before, changed))

	f093BestHeight = tip
	assert.NoError(t, abt.RollbackTo(tip))
	assert.True(t, checkPointEqual(before, abt.Snapshot()))

	// and it re-applies identically
	f093BestHeight = next
	abt.ProcessBlock(block, nil)
	assert.True(t, checkPointEqual(changed, abt.Snapshot()))
}
