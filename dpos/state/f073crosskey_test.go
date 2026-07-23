// Copyright (c) 2026 The Elastos Foundation
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
// B's key = its value + A's reward), but BOTH reverts subtract their PRE-BLOCK captures, so a
// reorg does NOT restore state: `a` sela of claimable reward is misallocated to B's owner.
//
// This drives the REAL processNFTDestroyFromSideChain + real utils.History at the STATE-APPLY
// layer (which fix option (a) deliberately does NOT change — it blocks the payload at
// validation instead). The number below is OBSERVED, proving the inflation is real, not
// inferred. The validation-layer guard (nftdestroytransaction.go) makes such a payload
// unreachable at/above StrictMoneyRangeHeight (see TestF073GuardRejectsCrossKeyAlias).
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
	tx := &fakeNFTTx{pld: pld}

	s.processNFTDestroyFromSideChain(tx, height)
	s.History.Commit(height)
	// Reorg.
	assert.NoError(t, s.History.RollbackTo(height-1))

	// EMPIRICAL RESULT: B's owner is inflated by `a`; the pre-block state (ob) is NOT restored.
	got := s.DPoSV2RewardInfo[strOwnerB]
	t.Logf("[F-073 cross-key] ob=%d a=%d  ownerB after reorg=%d  (correct would be ob=%d)", ob, a, got, ob)
	assert.Equal(t, ob+a, got,
		"F-073 cross-key: reorg MISallocates `a` claimable-reward sela to the aliased owner "+
			"(state-apply hole; blocked at validation by the guard)")
	assert.NotEqual(t, ob, got, "the pre-block owner reward is NOT restored -> real inflation")
}
