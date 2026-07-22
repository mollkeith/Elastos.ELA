// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// fakeNFTTx embeds the (nil) Transaction interface and overrides only the two methods
// processCreateNFT / processNFTDestroyFromSideChain call: Payload() and Hash().
type fakeNFTTx struct {
	interfaces.Transaction
	pld  interfaces.Payload
	hash common.Uint256
}

func (t *fakeNFTTx) Payload() interfaces.Payload { return t.pld }
func (t *fakeNFTTx) Hash() common.Uint256        { return t.hash }

func nftBaseState() *State {
	return &State{
		StateKeyFrame: &StateKeyFrame{
			PendingProducers:  map[string]*Producer{},
			ActivityProducers: map[string]*Producer{},
			NFTIDInfoHashMap:  make(map[common.Uint256]payload.NFTInfo),
			DposV2VoteRights:  make(map[common.Uint168]common.Fixed64),
			UsedDposV2Votes:   make(map[common.Uint168]common.Fixed64),
			DPoSV2RewardInfo:  make(map[string]common.Fixed64),
		},
		History: utils.NewHistory(maxHistoryCapacity),
	}
}

// TestF040GhostNFTRemovedOnRollback proves the F-040 fix: after a reorg RollbackTo, the
// CreateNFT NFT-ID map entry is REMOVED (previously it was written OUTSIDE History and
// survived rollback as a "ghost" while the vote rights — History-wrapped — reverted).
// Drives the REAL processCreateNFT + real utils.History. FAILS on pristine (ghost
// survives), PASSES on the fixed tree.
func TestF040GhostNFTRemovedOnRollback(t *testing.T) {
	const height = uint32(1405001) // > NFTStartHeight
	s := nftBaseState()

	var referKey common.Uint256
	copy(referKey[:], []byte{0xAA, 0xBB, 0xCC})
	var stakeAddress common.Uint168
	copy(stakeAddress[:], []byte{0x01, 0x02, 0x03})
	const nftAmount = common.Fixed64(1000)

	p := &Producer{
		detailedDPoSV2Votes: map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
			stakeAddress: {referKey: {StakeProgramHash: stakeAddress,
				Info: []payload.VotesWithLockTime{{Votes: nftAmount}}}},
		},
	}
	p.info.StakeUntil = 100 // dposv2 producer
	s.PendingProducers["p"] = p
	s.DposV2VoteRights[stakeAddress] = nftAmount
	s.UsedDposV2Votes[stakeAddress] = nftAmount

	pld := &payload.CreateNFT{ReferKey: referKey}
	var txHash common.Uint256
	copy(txHash[:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
	tx := &fakeNFTTx{pld: pld, hash: txHash}
	nftID := common.GetNFTID(referKey, txHash)
	ct, _ := contract.CreateStakeContractByCode(nftID.Bytes())
	nftStakeAddress := *ct.ToProgramHash()

	// Forward apply + commit: NFT created, votes moved onto the NFT stake address.
	s.processCreateNFT(tx, height)
	s.History.Commit(height)
	_, created := s.NFTIDInfoHashMap[nftID]
	assert.True(t, created, "NFT ID must exist after create")
	assert.Equal(t, nftAmount, s.DposV2VoteRights[nftStakeAddress], "NFT stake address holds the rights")

	// Rollback (reorg) to before the create.
	assert.NoError(t, s.History.RollbackTo(height-1))
	// Vote rights (History-wrapped) restored.
	assert.Equal(t, nftAmount, s.DposV2VoteRights[stakeAddress], "rollback restores original owner rights")
	// F-040 FIX: the NFT-ID map entry must ALSO be gone (pristine left it as a ghost).
	_, ghost := s.NFTIDInfoHashMap[nftID]
	assert.False(t, ghost, "F-040: NFT-ID ghost must be removed on rollback (was written outside History pre-fix)")
	assert.False(t, s.ifCreatedNFT(referKey), "F-040: ifCreatedNFT must be false after rollback (no ghost)")
}
