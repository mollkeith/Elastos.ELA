// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// fv09DispatchTx is fakeNFTTx plus the three methods State.processTransaction itself
// needs: TxType() for the production dispatch switch, and Outputs()/Inputs() for the
// processDeposit / processCancelVotes tail every transaction runs through. Driving
// processTransaction instead of calling processNFTDestroyFromSideChain directly is what
// makes the production CALL SITE load-bearing: deleting
// `case common2.NFTDestroyFromSideChain: s.processNFTDestroyFromSideChain(tx, height)`
// from dpos/state/state.go makes these tests FAIL (measured, not assumed), so they cannot
// pass against a severed production path.
type fv09DispatchTx struct {
	fakeNFTTx
}

func (t *fv09DispatchTx) TxType() common2.TxType     { return common2.NFTDestroyFromSideChain }
func (t *fv09DispatchTx) Outputs() []*common2.Output { return nil }
func (t *fv09DispatchTx) Inputs() []*common2.Input   { return nil }

// fv09Tx wraps an NFTDestroy payload in a transaction that drives the real dispatch.
func fv09Tx(pld *payload.NFTDestroyFromSideChain) *fv09DispatchTx {
	return &fv09DispatchTx{fakeNFTTx: fakeNFTTx{pld: pld}}
}

// fv09NFTFixture builds the shared two-NFT reward fixture used by the tests below:
// producer holds detailed DPoSV2 votes under NFT stake addresses A and B, and
// DPoSV2RewardInfo holds a under A, b under B and ox under the final owner X.
type fv09Fixture struct {
	s                            *State
	nftA, nftB                   common.Uint256
	nftStakeA, nftStakeB, ownerX common.Uint168
	strNFTA, strNFTB, strOwnerX  string
	a, b, ox                     common.Fixed64
}

func fv09NewFixture() *fv09Fixture {
	f := &fv09Fixture{
		a:  common.Fixed64(500), // A's NFT reward
		b:  common.Fixed64(700), // B's NFT reward
		ox: common.Fixed64(100), // X's pre-existing reward
	}
	f.s = nftBaseState()

	mkNFT := func(rk, tx byte) (common.Uint256, common.Uint256, common.Uint256) {
		var referKey, createTx common.Uint256
		referKey[0] = rk
		createTx[0] = tx
		return referKey, createTx, common.GetNFTID(referKey, createTx)
	}
	rkA, txA, nftA := mkNFT(0x0A, 0xA1)
	rkB, txB, nftB := mkNFT(0x0B, 0xB1)
	f.nftA, f.nftB = nftA, nftB

	f.nftStakeA[0] = 0x11
	f.nftStakeB[0] = 0x22
	f.ownerX[0] = 0x33
	f.strNFTA, _ = f.nftStakeA.ToAddress()
	f.strNFTB, _ = f.nftStakeB.ToAddress()
	f.strOwnerX, _ = f.ownerX.ToAddress()

	const amt = common.Fixed64(1000)
	f.s.NFTIDInfoHashMap[nftA] = payload.NFTInfo{ReferKey: rkA, CreateNFTTxHash: txA}
	f.s.NFTIDInfoHashMap[nftB] = payload.NFTInfo{ReferKey: rkB, CreateNFTTxHash: txB}
	p := &Producer{
		detailedDPoSV2Votes: map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
			f.nftStakeA: {rkA: {StakeProgramHash: f.nftStakeA, Info: []payload.VotesWithLockTime{{Votes: amt}}}},
			f.nftStakeB: {rkB: {StakeProgramHash: f.nftStakeB, Info: []payload.VotesWithLockTime{{Votes: amt}}}},
		},
	}
	p.info.StakeUntil = 100
	f.s.PendingProducers["p"] = p
	f.s.DposV2VoteRights[f.nftStakeA] = amt
	f.s.DposV2VoteRights[f.nftStakeB] = amt
	f.s.UsedDposV2Votes[f.nftStakeA] = amt
	f.s.UsedDposV2Votes[f.nftStakeB] = amt
	f.s.DPoSV2RewardInfo[f.strNFTA] = f.a
	f.s.DPoSV2RewardInfo[f.strNFTB] = f.b
	f.s.DPoSV2RewardInfo[f.strOwnerX] = f.ox
	return f
}

// fv09TotalReward sums DPoSV2RewardInfo — the claimable-balance conservation invariant.
func fv09TotalReward(s *State) common.Fixed64 {
	var total common.Fixed64
	for _, v := range s.DPoSV2RewardInfo {
		total += v
	}
	return total
}

// TestFV09CrossTxAliasSplitIsRestoredOnRollback is the fail-on-pristine test for the
// STATE-APPLY half of FV-09.
//
// The F-073 alias vector SPLITS across two same-block NFTDestroy TRANSACTIONS: tx1
// destroys NFT A naming NFT B's stake address, tx2 destroys NFT B naming X. Neither
// payload self-aliases, so the per-tx F-073 guard accepts both, and the ids differ so the
// F-118 same-block id arm accepts them too. Both land in ONE History height group, so at
// Commit the forwards COMPOSE — tx2's LIVE lookup of B's reward key already contains A's
// reward — and on a reorg the old pre-block captures do not net out.
//
// PRISTINE (pre-fix) OBSERVED BEHAVIOUR: X keeps ox+a = 600 after the reorg instead of
// ox = 100, and the DPoSV2RewardInfo total is `a` sela HIGHER than before the block.
// That is a claimable-BALANCE misallocation — NO mint, NO supply inflation.
//
// MUTATION PROOF (both measured, output captured in the batch report):
//  1. revert either half of the state.go closure fix — restore the pre-Append
//     `oriRewardsInfo := s.DPoSV2RewardInfo[strNFTStakeAddress]` capture, or change the
//     revert's `s.DPoSV2RewardInfo[strNFTStakeAddress] += creditedRewards` back to `=` —
//     and this test FAILS (X keeps ox+a = 600 after the reorg). Both halves are needed:
//     the capture alone still strands the difference because utils/history.go rolls back
//     FORWARD, not LIFO.
//  2. delete the production CALL SITE — the
//     `case common2.NFTDestroyFromSideChain: s.processNFTDestroyFromSideChain(tx, height)`
//     arm of State.processTransaction — and this test FAILS too, because the driver below
//     goes through processTransaction, not through the destroy function directly.
func TestFV09CrossTxAliasSplitIsRestoredOnRollback(t *testing.T) {
	const height = uint32(1405001)
	f := fv09NewFixture()

	assert.NotEqual(t, f.nftA, f.nftB, "distinct NFT ids -> F-104/F-118 both pass")
	before := fv09TotalReward(f.s)

	// THE ATTACK, SPLIT ACROSS TWO TRANSACTIONS AT ONE HEIGHT.
	tx1 := fv09Tx(&payload.NFTDestroyFromSideChain{
		IDs:                 []common.Uint256{f.nftA},
		OwnerStakeAddresses: []common.Uint168{f.nftStakeB}, // aliases the OTHER tx's NFT
	})
	tx2 := fv09Tx(&payload.NFTDestroyFromSideChain{
		IDs:                 []common.Uint256{f.nftB},
		OwnerStakeAddresses: []common.Uint168{f.ownerX},
	})

	f.s.processTransaction(tx1, height)
	f.s.processTransaction(tx2, height)
	f.s.History.Commit(height)

	// The forwards DID compose — this is the precondition, asserted rather than assumed.
	assert.Equal(t, f.ox+f.a+f.b, f.s.DPoSV2RewardInfo[f.strOwnerX],
		"precondition: tx2's LIVE credit must have picked up A's reward folded in by tx1")

	// Reorg.
	assert.NoError(t, f.s.History.RollbackTo(height-1))

	got := f.s.DPoSV2RewardInfo[f.strOwnerX]
	t.Logf("[FV-09 cross-tx] ox=%d a=%d b=%d  X after reorg=%d  (pristine leaves %d)",
		f.ox, f.a, f.b, got, f.ox+f.a)
	assert.Equal(t, f.ox, got,
		"FV-09: the split-alias reorg must restore X's pre-block claimable reward "+
			"(pristine leaves ox+a -> claimable-BALANCE misallocation, NOT a mint)")
	assert.Equal(t, f.a, f.s.DPoSV2RewardInfo[f.strNFTA], "NFT A's reward key must be restored")
	assert.Equal(t, f.b, f.s.DPoSV2RewardInfo[f.strNFTB], "NFT B's reward key must be restored")
	assert.Equal(t, before, fv09TotalReward(f.s),
		"FV-09: total claimable reward must be conserved across apply+rollback")
}

// TestFV09OrdinaryNFTDestroyRollbackUnchanged is the positive control for the closure
// change. In every NON-aliased shape the new in-forward capture equals the old pre-block
// capture and the `+=` restore lands on a key the forward just deleted, so the fix is a
// behavioural no-op. Without this control the test above could be satisfied by a change
// that broke the ordinary path.
func TestFV09OrdinaryNFTDestroyRollbackUnchanged(t *testing.T) {
	const height = uint32(1405001)

	t.Run("two destroys sharing one legitimate owner", func(t *testing.T) {
		f := fv09NewFixture()
		before := fv09TotalReward(f.s)
		tx1 := fv09Tx(&payload.NFTDestroyFromSideChain{
			IDs:                 []common.Uint256{f.nftA},
			OwnerStakeAddresses: []common.Uint168{f.ownerX},
		})
		tx2 := fv09Tx(&payload.NFTDestroyFromSideChain{
			IDs:                 []common.Uint256{f.nftB},
			OwnerStakeAddresses: []common.Uint168{f.ownerX},
		})
		f.s.processTransaction(tx1, height)
		f.s.processTransaction(tx2, height)
		f.s.History.Commit(height)
		assert.Equal(t, f.ox+f.a+f.b, f.s.DPoSV2RewardInfo[f.strOwnerX], "both rewards fold into X")
		assert.NoError(t, f.s.History.RollbackTo(height-1))
		assert.Equal(t, f.ox, f.s.DPoSV2RewardInfo[f.strOwnerX])
		assert.Equal(t, f.a, f.s.DPoSV2RewardInfo[f.strNFTA])
		assert.Equal(t, f.b, f.s.DPoSV2RewardInfo[f.strNFTB])
		assert.Equal(t, before, fv09TotalReward(f.s))
	})

	t.Run("single destroy, fresh owner key", func(t *testing.T) {
		f := fv09NewFixture()
		before := fv09TotalReward(f.s)
		var fresh common.Uint168
		fresh[0] = 0x44
		strFresh, _ := fresh.ToAddress()
		tx := fv09Tx(&payload.NFTDestroyFromSideChain{
			IDs:                 []common.Uint256{f.nftA},
			OwnerStakeAddresses: []common.Uint168{fresh},
		})
		f.s.processTransaction(tx, height)
		f.s.History.Commit(height)
		assert.Equal(t, f.a, f.s.DPoSV2RewardInfo[strFresh])
		assert.NoError(t, f.s.History.RollbackTo(height-1))
		// The fresh key must be GONE again (the delete-if-zero cleanup still runs).
		_, present := f.s.DPoSV2RewardInfo[strFresh]
		assert.False(t, present, "a key created only by the destroy must not survive the rollback")
		assert.Equal(t, f.a, f.s.DPoSV2RewardInfo[f.strNFTA])
		assert.Equal(t, before, fv09TotalReward(f.s))
	})
}
