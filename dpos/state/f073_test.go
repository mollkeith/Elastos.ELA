// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// TestF073RewardNotInflatedOnRollback proves the F-073 fix. On NFTDestroy the forward
// closure credits the owner (`owner += DPoSV2RewardInfo[NFT]`) then DELETES the NFT key;
// the pristine rollback debited `owner -= DPoSV2RewardInfo[NFT]` — a live lookup of the
// already-deleted key = 0 — so the owner KEPT the credited reward (claimable reward
// inflation on reorg). The fix debits the captured `oriRewardsInfo`. Drives the REAL
// processNFTDestroyFromSideChain (active branch) + real utils.History. FAILS on pristine
// (owner == O+R), PASSES on the fixed tree (owner == O).
func TestF073RewardNotInflatedOnRollback(t *testing.T) {
	const height = uint32(1405001)
	s := nftBaseState()

	var referKey common.Uint256
	copy(referKey[:], []byte{0x0A, 0x0B, 0x0C})
	var createTxHash common.Uint256
	copy(createTxHash[:], []byte{0xCA, 0xFE})
	nftID := common.GetNFTID(referKey, createTxHash)

	var nftStakeAddr common.Uint168
	copy(nftStakeAddr[:], []byte{0x11, 0x22, 0x33})
	var ownerStakeAddr common.Uint168
	copy(ownerStakeAddr[:], []byte{0x44, 0x55, 0x66})
	strNFT, _ := nftStakeAddr.ToAddress()
	strOwner, _ := ownerStakeAddr.ToAddress()

	const nftAmount = common.Fixed64(1000)
	const rewardR = common.Fixed64(500) // reward credited to the NFT stake address
	const ownerO = common.Fixed64(100)  // owner's pre-existing reward

	// NFT-ID map entry (CreateNFTTxHash must match so GetNFTID(referKey, txHash)==nftID).
	s.NFTIDInfoHashMap[nftID] = payload.NFTInfo{ReferKey: referKey, CreateNFTTxHash: createTxHash}
	// Producer holding the dposv2 vote under the NFT stake address.
	p := &Producer{
		detailedDPoSV2Votes: map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
			nftStakeAddr: {referKey: {StakeProgramHash: nftStakeAddr,
				Info: []payload.VotesWithLockTime{{Votes: nftAmount}}}},
		},
	}
	p.info.StakeUntil = 100
	s.PendingProducers["p"] = p
	s.DposV2VoteRights[nftStakeAddr] = nftAmount
	s.UsedDposV2Votes[nftStakeAddr] = nftAmount
	s.DPoSV2RewardInfo[strNFT] = rewardR
	s.DPoSV2RewardInfo[strOwner] = ownerO

	pld := &payload.NFTDestroyFromSideChain{
		IDs:                 []common.Uint256{nftID},
		OwnerStakeAddresses: []common.Uint168{ownerStakeAddr},
	}
	tx := &fakeNFTTx{pld: pld}

	// Forward apply + commit: reward credited to owner, NFT key deleted.
	s.processNFTDestroyFromSideChain(tx, height)
	s.History.Commit(height)
	assert.Equal(t, ownerO+rewardR, s.DPoSV2RewardInfo[strOwner], "owner credited the NFT reward on destroy")
	_, nftGone := s.DPoSV2RewardInfo[strNFT]
	assert.False(t, nftGone, "NFT reward key deleted after destroy")

	// Rollback (reorg): the owner reward must return to its ORIGINAL value.
	assert.NoError(t, s.History.RollbackTo(height-1))
	assert.Equal(t, ownerO, s.DPoSV2RewardInfo[strOwner],
		"F-073: rollback must debit the captured credited amount (pristine left owner == O+R = inflated)")
	assert.Equal(t, rewardR, s.DPoSV2RewardInfo[strNFT], "NFT reward restored on rollback")
}
