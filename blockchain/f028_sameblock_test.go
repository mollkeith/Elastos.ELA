// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// B4 same-block double-pay/race cluster (F-028, F-066, F-067, F-078, F-088) — empirical
// in-block conflict proof. The mempool conflictmanager rejects two conflicting
// stake/reward/withdraw/tracking txs, but the block-level validation never mirrored those
// slots, so an on-duty producer can pack two conflicting txs into ONE block. These tests
// drive the REAL blockchain.CheckSameBlockConflicts:
//   - EXPLOIT/FIX: two conflicting txs (same stake / proposal / pending hash) in one block
//     at/above the gate -> rejected.
//   - REPLAY: the same block below the gate -> accepted (byte-identical legacy).
//   - RELATED-TX: two DISTINCT identities of the same tx type in one block -> accepted.
// The downstream multi-block DRAIN (double payout leaving the pool) is NEEDS-SIM and stays
// DEFERRED per the never-infer-inflation rule.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

const f028Gate = uint32(2260451)

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
}

// f028StakeCode returns a fresh valid stake-contract code (a standard redeem script that
// contract.CreateStakeContractByCode accepts) -> a distinct stake program hash per call.
func f028StakeCode(t *testing.T) []byte {
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	code, err := contract.CreateStandardRedeemScript(pub)
	assert.NoError(t, err)
	return code
}

func f028Block(h uint32, txs ...interfaces.Transaction) *types.Block {
	return &types.Block{
		Header:       common2.Header{Height: h},
		Transactions: txs,
	}
}

func f028Tx(txType common2.TxType, pv byte, pld interfaces.Payload, code []byte) interfaces.Transaction {
	var programs []*program.Program
	if code != nil {
		programs = []*program.Program{{Code: code}}
	}
	return functions.CreateTransaction(
		common2.TxVersion09, txType, pv, pld,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0, programs)
}

// TestF028SameStakeVoteConflict — F-028 / F-078: two vote-family txs for the SAME stake
// in one block are rejected at/above the gate (mirrors mempool slotExchangeVotes), the
// same block below the gate is accepted (replay), and two DIFFERENT stakes pass.
func TestF028SameStakeVoteConflict(t *testing.T) {
	code := f028StakeCode(t)
	// Two ReturnVotes sharing the stake code (=> same stakeProgramHash).
	rv1 := f028Tx(common2.ReturnVotes, 1, &payload.ReturnVotes{}, code)
	rv2 := f028Tx(common2.ReturnVotes, 1, &payload.ReturnVotes{}, code)

	// Above gate: conflict rejected.
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, rv1, rv2), f028Gate),
		"two same-stake ReturnVotes in one block must be rejected at/above the gate")
	// Below gate: replay-safe (accepted).
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, rv1, rv2), f028Gate),
		"below the gate the block must validate byte-identically (no dedup)")
	// Two DIFFERENT stakes: legitimate, still accepted above the gate.
	rvA := f028Tx(common2.ReturnVotes, 1, &payload.ReturnVotes{}, f028StakeCode(t))
	rvB := f028Tx(common2.ReturnVotes, 1, &payload.ReturnVotes{}, f028StakeCode(t))
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, rvA, rvB), f028Gate),
		"two ReturnVotes for DIFFERENT stakes are legitimate and must pass")
}

// TestF028SameStakeClaimRewardConflict — F-028: two DposV2ClaimReward for the same stake.
func TestF028SameStakeClaimRewardConflict(t *testing.T) {
	code := f028StakeCode(t)
	c1 := f028Tx(common2.DposV2ClaimReward, 1, &payload.DPoSV2ClaimReward{}, code)
	c2 := f028Tx(common2.DposV2ClaimReward, 1, &payload.DPoSV2ClaimReward{}, code)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, c2), f028Gate),
		"two same-stake DposV2ClaimReward in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, c1, c2), f028Gate))
	cA := f028Tx(common2.DposV2ClaimReward, 1, &payload.DPoSV2ClaimReward{}, f028StakeCode(t))
	cB := f028Tx(common2.DposV2ClaimReward, 1, &payload.DPoSV2ClaimReward{}, f028StakeCode(t))
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, cA, cB), f028Gate),
		"two claim-reward for DIFFERENT stakes are legitimate and must pass")
}

// TestF067ProposalTrackingConflict — F-067: two CRCProposalTracking for the same proposal.
func TestF067ProposalTrackingConflict(t *testing.T) {
	h := common.Uint256{1, 2, 3}
	other := common.Uint256{9, 9, 9}
	t1 := f028Tx(common2.CRCProposalTracking, 0, &payload.CRCProposalTracking{ProposalHash: h}, nil)
	t2 := f028Tx(common2.CRCProposalTracking, 0, &payload.CRCProposalTracking{ProposalHash: h}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, t1, t2), f028Gate),
		"two tracking txs for the same proposal must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, t1, t2), f028Gate))
	tOther := f028Tx(common2.CRCProposalTracking, 0, &payload.CRCProposalTracking{ProposalHash: other}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, t1, tOther), f028Gate),
		"tracking txs for DIFFERENT proposals are legitimate and must pass")
}

// TestF066RealWithdrawConflict — F-066: two RealWithdraw sharing a pending hash, plus the
// VotesRealWithdraw singleton.
func TestF066RealWithdrawConflict(t *testing.T) {
	shared := common.Uint256{7, 7, 7}
	distinct := common.Uint256{8, 8, 8}
	w1 := f028Tx(common2.CRCProposalRealWithdraw, 0,
		&payload.CRCProposalRealWithdraw{WithdrawTransactionHashes: []common.Uint256{shared}}, nil)
	w2 := f028Tx(common2.CRCProposalRealWithdraw, 0,
		&payload.CRCProposalRealWithdraw{WithdrawTransactionHashes: []common.Uint256{shared}}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, w2), f028Gate),
		"two CRCProposalRealWithdraw sharing a pending hash must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, w1, w2), f028Gate))
	// Distinct pending hashes: legitimate.
	wD := f028Tx(common2.CRCProposalRealWithdraw, 0,
		&payload.CRCProposalRealWithdraw{WithdrawTransactionHashes: []common.Uint256{distinct}}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, wD), f028Gate),
		"real-withdraws with DISTINCT pending hashes are legitimate and must pass")

	// VotesRealWithdraw is a mempool singleton -> a 2nd one in a block is rejected.
	vw1 := f028Tx(common2.VotesRealWithdraw, 0, &payload.VotesRealWithdrawPayload{}, nil)
	vw2 := f028Tx(common2.VotesRealWithdraw, 0, &payload.VotesRealWithdrawPayload{}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, vw1, vw2), f028Gate),
		"a second VotesRealWithdraw in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, vw1), f028Gate),
		"a single VotesRealWithdraw is legitimate")
}
