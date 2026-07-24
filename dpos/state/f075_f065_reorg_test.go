// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-075 and F-065 (dpos side): the two consensus-critical reorg/revert-symmetry
// fixes that shipped with NO TEST ANYWHERE IN THE TREE (commits f26ffc7, 02e41e0,
// c01951c: four production hunks, zero test files). This class is demonstrably
// bug-bearing — the two members of it that did get tests (F-064, F-168) both exposed
// real stuck-state bugs, and c01951c itself is a defect found only after the fact.
//
// Both tests drive the REAL forward production function so the REAL revert closure is
// Appended, then call the REAL History.RollbackTo — the identical closure execution a
// live chain reorg performs via CkpManager.OnRollbackTo -> State.RollbackTo.
package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// reorgDepths mirrors the Class-E convention: 1 / 2 / 5 / deep.
var reorgDepths = []uint32{1, 2, 5, 60}

// -----------------------------------------------------------------------------
// F-075 — processNFTDestroyFromSideChain, EXPIRED-NFT branch.
//
// The apply closure deliberately leaves UsedDposV2Votes untouched (the reclaimed votes
// become castable, not used — the `+=` is commented out in the source), but the revert
// closure carried an ACTIVE, UNMATCHED `UsedDposV2Votes[newOwner] -= nftAmount`. On a
// reorg RollbackTo that deflated (or underflowed) the new owner's used-vote count, and
// castable = Rights - Used, so it INFLATES castable voting rights.
// -----------------------------------------------------------------------------

// f075Tx is the minimal NFTDestroyFromSideChain the forward function reads.
type f075Tx struct {
	interfaces.Transaction
	pld *payload.NFTDestroyFromSideChain
}

func (t *f075Tx) Payload() interfaces.Payload { return t.pld }
func (t *f075Tx) Programs() []*pg.Program     { return nil }

// f075Setup builds a State holding ONE DPoSV2 producer with ONE expired NFT vote whose
// derived NFT id is the one the destroy names.
func f075Setup(t *testing.T, preUsed common.Fixed64) (
	*State, common.Uint168, common.Uint168, common.Fixed64, interfaces.Transaction) {
	t.Helper()

	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   &config.Configuration{},
	}

	const nftAmount = common.Fixed64(1_000 * 1e8)
	createNFTTxHash := common.Uint256{0x0C, 0x0A, 0x0F, 0x0E}

	// The expired vote entry. Its ReferKey is content-derived, so build it first and then
	// derive the NFT id exactly as production does.
	vote := payload.DetailedVoteInfo{
		StakeProgramHash: common.Uint168{0x1F, 0x01},
		TransactionHash:  common.Uint256{0xAB, 0xCD},
		BlockHeight:      42,
		PayloadVersion:   0,
		VoteType:         outputpayload.DposV2,
		Info:             []payload.VotesWithLockTime{{Votes: nftAmount, LockTime: 100}},
	}
	nftID := common.GetNFTID(vote.ReferKey(), createNFTTxHash)

	ct, err := contract.CreateStakeContractByCode(nftID.Bytes())
	assert.NoError(t, err)
	nftStakeAddress := *ct.ToProgramHash()
	newOwner := common.Uint168{0x2F, 0x02}

	producer := &Producer{
		expiredNFTVotes:     map[common.Uint168]payload.DetailedVoteInfo{nftStakeAddress: vote},
		detailedDPoSV2Votes: map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{},
	}
	producer.info.StakeUntil = 1 // getDposV2Producers selects on StakeUntil != 0
	s.ActivityProducers["f075"] = producer

	s.NFTIDInfoHashMap[nftID] = payload.NFTInfo{CreateNFTTxHash: createNFTTxHash}
	s.DposV2VoteRights[nftStakeAddress] = nftAmount
	if preUsed != 0 {
		s.UsedDposV2Votes[newOwner] = preUsed
	}

	tx := &f075Tx{pld: &payload.NFTDestroyFromSideChain{
		IDs:                 []common.Uint256{nftID},
		OwnerStakeAddresses: []common.Uint168{newOwner},
	}}
	return s, nftStakeAddress, newOwner, nftAmount, tx
}

// TestF075ExpiredNFTReclaimRollbackDoesNotDeflateUsedVotes is the F-075 fail-on-pristine
// test. With the pre-fix revert block restored, the rollback subtracts an amount the
// forward never added: the new owner's used-vote count goes NEGATIVE (or is deflated),
// and castable rights inflate by that much.
func TestF075ExpiredNFTReclaimRollbackDoesNotDeflateUsedVotes(t *testing.T) {
	for _, depth := range reorgDepths {
		// Case A: the new owner had NO used votes before the block.
		s, nftStake, newOwner, nftAmount, tx := f075Setup(t, 0)
		const H = uint32(3000)

		s.processNFTDestroyFromSideChain(tx, H)
		s.History.Commit(H)

		// Path-reached proof: the expired-vote reclaim actually fired.
		assert.Equalf(t, nftAmount, s.DposV2VoteRights[newOwner],
			"path reached (depth=%d): the reclaim must migrate the vote rights to the new owner", depth)
		if _, still := s.UsedDposV2Votes[newOwner]; still {
			t.Fatalf("path reached (depth=%d): the FORWARD must not touch UsedDposV2Votes "+
				"(the reclaimed votes become castable, not used)", depth)
		}

		for h := H + 1; h < H+depth; h++ {
			s.History.Commit(h)
		}
		assert.NoError(t, s.History.RollbackTo(H-1))

		// DISCRIMINATOR: apply and revert must be exact inverses on UsedDposV2Votes.
		if got, present := s.UsedDposV2Votes[newOwner]; present {
			t.Fatalf("F-075 depth=%d: rollback left UsedDposV2Votes[newOwner]=%d for a key the "+
				"forward never wrote — an unmatched revert deflates/underflows the used-vote "+
				"count and INFLATES castable rights (castable = Rights - Used)", depth, got)
		}
		// And the matched half is still a proper inverse.
		assert.Equalf(t, nftAmount, s.DposV2VoteRights[nftStake],
			"F-075 depth=%d: the matched DposV2VoteRights half must be restored", depth)

		// Case B: the new owner already HAD used votes before the block; the rollback must
		// leave that pre-block number untouched.
		const pre = common.Fixed64(5_000 * 1e8)
		s2, _, newOwner2, _, tx2 := f075Setup(t, pre)
		s2.processNFTDestroyFromSideChain(tx2, H)
		s2.History.Commit(H)
		for h := H + 1; h < H+depth; h++ {
			s2.History.Commit(h)
		}
		assert.NoError(t, s2.History.RollbackTo(H-1))
		assert.Equalf(t, pre, s2.UsedDposV2Votes[newOwner2],
			"F-075 depth=%d: rollback must restore the pre-block used-vote count exactly "+
				"(pristine deflates it by the reclaimed NFT amount)", depth)
	}
}

// -----------------------------------------------------------------------------
// F-065 (dpos sibling, commits 02e41e0 + c01951c) — processDeposit / registerProducer
// DepositOutputs.
//
// The write was unwrapped (a rollback left a stale deposit-UTXO entry that gets baked
// into the local keyframe checkpoint, diverging a reorged node from a canonically-synced
// one), and the first wrap then deleted UNCONDITIONALLY — which is not the inverse of a
// set when the key PRE-EXISTED the block.
// -----------------------------------------------------------------------------

// f065DepositState returns a State holding one pending producer whose deposit hash the
// returned transaction pays into — the precondition addProducerAssert requires before
// processDeposit reaches the DepositOutputs write.
func f065DepositState(t *testing.T, value common.Fixed64, salt byte) (*State, interfaces.Transaction) {
	t.Helper()
	code := []byte{0x21}
	for i := 0; i < 33; i++ {
		code = append(code, byte(i)+salt)
	}
	ct, err := contract.CreateDepositContractByCode(code)
	assert.NoError(t, err)
	depositHash := *ct.ToProgramHash()

	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   &config.Configuration{},
	}
	s.PendingProducers[string(code)] = &Producer{depositHash: depositHash}

	tx := &f065Tx{
		hash: common.Uint256{0xDE, 0x90, salt},
		outputs: []*common2.Output{{
			Value:       value,
			ProgramHash: depositHash,
		}},
	}
	return s, tx
}

type f065Tx struct {
	interfaces.Transaction
	hash    common.Uint256
	outputs []*common2.Output
}

func (t *f065Tx) Hash() common.Uint256       { return t.hash }
func (t *f065Tx) Outputs() []*common2.Output { return t.outputs }

// TestF065DepositOutputsRollbackIsAnExactInverse is the F-065 fail-on-pristine test for
// the DPoS side. It covers BOTH defects the two commits closed:
//
//	02e41e0 — an UNWRAPPED write survives the rollback (stale entry -> keyframe divergence)
//	c01951c — an UNCONDITIONAL delete destroys an entry that PRE-EXISTED the block
func TestF065DepositOutputsRollbackIsAnExactInverse(t *testing.T) {
	for _, depth := range reorgDepths {
		const H = uint32(4000)

		// --- (a) a deposit outpoint that did NOT exist before the block ---
		s, tx := f065DepositState(t, 5000, 1)
		key := common2.NewOutPoint(tx.Hash(), 0).ReferKey()

		s.processDeposit(tx, H)
		s.History.Commit(H)
		assert.Equalf(t, common.Fixed64(5000), s.DepositOutputs[key],
			"path reached (depth=%d): the forward must record the deposit output", depth)

		for h := H + 1; h < H+depth; h++ {
			s.History.Commit(h)
		}
		assert.NoError(t, s.History.RollbackTo(H-1))

		if v, present := s.DepositOutputs[key]; present {
			t.Fatalf("F-065 depth=%d: rollback left a stale DepositOutputs entry (%d) for a key "+
				"that did not exist before the block — the write is not History-wrapped, so a "+
				"reorged node bakes it into its keyframe checkpoint and diverges from a "+
				"canonically-synced node", depth, v)
		}

		// --- (b) a deposit outpoint that DID pre-exist (re-registration reuses the same
		// tx-hash-derived outpoint) — the revert must RESTORE it, not delete it ---
		s2, tx2 := f065DepositState(t, 7000, 2)
		key2 := common2.NewOutPoint(tx2.Hash(), 0).ReferKey()
		const preExisting = common.Fixed64(1234)
		s2.DepositOutputs[key2] = preExisting

		s2.processDeposit(tx2, H)
		s2.History.Commit(H)
		assert.Equalf(t, common.Fixed64(7000), s2.DepositOutputs[key2],
			"path reached (depth=%d): the forward overwrites the pre-existing entry", depth)

		for h := H + 1; h < H+depth; h++ {
			s2.History.Commit(h)
		}
		assert.NoError(t, s2.History.RollbackTo(H-1))

		got, present := s2.DepositOutputs[key2]
		if !present {
			t.Fatalf("F-065 depth=%d: rollback DELETED a DepositOutputs entry that pre-existed "+
				"the block — an unconditional delete is not the inverse of a set, and the "+
				"pre-block keyframe held that entry (this is the c01951c defect)", depth)
		}
		assert.Equalf(t, preExisting, got,
			"F-065 depth=%d: rollback must restore the exact pre-block value", depth)
	}
}
