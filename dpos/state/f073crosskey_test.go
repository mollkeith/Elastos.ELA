// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// TestF073CrossKeyRewardMisallocation EMPIRICALLY CLASSIFIES the F-073 cross-key hole
// (fork round 2 / Fable finding I) — the reward-adjacent finding the HARD RULE forbids us to
// assert without proof. It survives F-104/F-118 (those close only a same-NFT-ID collision).
//
// Vector: two DISTINCT NFT ids A and B in one NFTDestroy tx, with OwnerStakeAddresses[A] set
// to B's NFT stake address. The forward closures COMPOSE (A credits B's key; B then reads
// B's key = its value + A's reward).
//
// UPDATED BY FV-09 — THE ASSERTION BELOW IS INVERTED FROM WHAT IT USED TO BE, DELIBERATELY.
// Originally this test recorded the state-apply layer as STILL BROKEN and relied entirely on
// the validation-layer F-073 guard to make the payload unreachable. FV-09 proved that guard
// is INTRA-TRANSACTION only and splits across two same-block txs, so the state-apply hole was
// not in fact unreachable. The closure pair in processNFTDestroyFromSideChain is now an exact
// inverse (creditedRewards captured INSIDE the forward, restored with `+=`), so the reorg
// RESTORES the pre-block claimable balances. The number below is OBSERVED.
//
// This drives the REAL State.processTransaction dispatch -> processNFTDestroyFromSideChain
// + real utils.History at the STATE-APPLY layer, so severing the production dispatch arm
// makes it FAIL (the composition precondition below is what makes that call site
// load-bearing). The validation layer rejects the payload independently — per-transaction at
// nftdestroytransaction.go (TestF073GuardRejectsCrossKeyAlias) and per-BLOCK, including the
// two-transaction split, at blockchain.CheckSameBlockConflicts
// (TestFV09SplitAliasIsRejectedAtBlockScope). Defence in depth, three layers.
// NO mint and NO supply inflation is claimed here: this is a claimable-BALANCE defect.
func TestF073CrossKeyRewardMisallocation(t *testing.T) {
	const height = uint32(1405001)
	s := nftBaseState()

	mkNFT := func(rk, tx byte) (common.Uint256, common.Uint256, common.Uint256) {
		var referKey, createTx common.Uint256
		referKey[0] = rk
		createTx[0] = tx
		return referKey, createTx, common.GetNFTID(referKey, createTx)
	}
	rkA, txA, nftA := mkNFT(0x0A, 0xA1)
	rkB, txB, nftB := mkNFT(0x0B, 0xB1)
	assert.NotEqual(t, nftA, nftB, "distinct NFT ids -> F-104/F-118 both pass")

	var nftStakeA, nftStakeB, ownerB common.Uint168
	nftStakeA[0] = 0x11
	nftStakeB[0] = 0x22
	ownerB[0] = 0x33
	strNFTA, _ := nftStakeA.ToAddress()
	strNFTB, _ := nftStakeB.ToAddress()
	strOwnerB, _ := ownerB.ToAddress()

	const amt = common.Fixed64(1000)
	const a = common.Fixed64(500) // A's NFT reward
	const b = common.Fixed64(700) // B's NFT reward
	const ob = common.Fixed64(100) // B's owner pre-existing reward

	s.NFTIDInfoHashMap[nftA] = payload.NFTInfo{ReferKey: rkA, CreateNFTTxHash: txA}
	s.NFTIDInfoHashMap[nftB] = payload.NFTInfo{ReferKey: rkB, CreateNFTTxHash: txB}
	p := &Producer{
		detailedDPoSV2Votes: map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
			nftStakeA: {rkA: {StakeProgramHash: nftStakeA, Info: []payload.VotesWithLockTime{{Votes: amt}}}},
			nftStakeB: {rkB: {StakeProgramHash: nftStakeB, Info: []payload.VotesWithLockTime{{Votes: amt}}}},
		},
	}
	p.info.StakeUntil = 100
	s.PendingProducers["p"] = p
	s.DposV2VoteRights[nftStakeA] = amt
	s.DposV2VoteRights[nftStakeB] = amt
	s.UsedDposV2Votes[nftStakeA] = amt
	s.UsedDposV2Votes[nftStakeB] = amt
	s.DPoSV2RewardInfo[strNFTA] = a
	s.DPoSV2RewardInfo[strNFTB] = b
	s.DPoSV2RewardInfo[strOwnerB] = ob

	// THE ATTACK: A's owner = B's NFT stake address.
	pld := &payload.NFTDestroyFromSideChain{
		IDs:                 []common.Uint256{nftA, nftB},
		OwnerStakeAddresses: []common.Uint168{nftStakeB, ownerB},
	}
	tx := fv09Tx(pld)

	s.processTransaction(tx, height)
	s.History.Commit(height)

	// Precondition, ASSERTED rather than assumed: the forwards must actually have
	// COMPOSED (A's reward folds into B's NFT key, which is then credited on to ownerB).
	// Without this line the post-rollback assertions below would also be satisfied by a
	// production path that never ran at all -- deleting the
	// `case common2.NFTDestroyFromSideChain` dispatch arm from State.processTransaction
	// leaves every balance at its pre-block value, which is exactly what they expect.
	// With it, severing that call site makes this test FAIL (measured, not assumed).
	assert.Equal(t, ob+a+b, s.DPoSV2RewardInfo[strOwnerB],
		"precondition: the cross-key forwards must compose before the reorg is tested")

	// Reorg.
	assert.NoError(t, s.History.RollbackTo(height-1))

	// EMPIRICAL RESULT (post-FV-09): the reorg RESTORES every pre-block claimable balance.
	got := s.DPoSV2RewardInfo[strOwnerB]
	t.Logf("[F-073 cross-key] ob=%d a=%d  ownerB after reorg=%d  (pristine left ob+a=%d)", ob, a, got, ob+a)
	assert.Equal(t, ob, got,
		"FV-09: the cross-key reorg must restore the aliased owner's pre-block claimable reward "+
			"(pristine left ob+a -> claimable-BALANCE misallocation, NOT a mint)")
	assert.Equal(t, a, s.DPoSV2RewardInfo[strNFTA], "NFT A's reward key must be restored")
	assert.Equal(t, b, s.DPoSV2RewardInfo[strNFTB], "NFT B's reward key must be restored")
	var total common.Fixed64
	for _, v := range s.DPoSV2RewardInfo {
		total += v
	}
	assert.Equal(t, a+b+ob, total, "total claimable reward must be conserved across apply+rollback")
}
