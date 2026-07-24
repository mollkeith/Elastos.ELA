// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — the two UNTESTED F-015 real-withdraw types.
//
// F-015 is described in its own shipping commit as LIVE MAINNET THEFT. It has three
// siblings, one per real-withdraw transaction type, and only ONE of them
// (VotesRealWithdraw, core/transaction/f015_test.go) had a test. Mutation at HEAD
// neutered the OTHER TWO guards and the entire suite stayed green.
//
// These tests drive the REAL SpecialContextCheck of each remaining type, exactly as the
// VotesRealWithdraw test does, and assert the same three properties:
//
//	THEFT   at/above the gate a non-treasury (victim) input is REJECTED
//	REPLAY  the same transaction below the gate is still ACCEPTED (byte-identical legacy,
//	        which is the pre-fix exploit surface)
//	NO FALSE POSITIVE  a treasury-funded withdraw still passes
//
// plus, for the type that also pins its change output, the change-theft variant.
package transaction

import (
	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestF015DposV2ClaimRewardRealWithdrawTreasuryBind — sibling 2 of 3.
//
// MUTATION PROOF: neuter either guard in
// DposV2ClaimRewardRealWithdrawTransaction.SpecialContextCheck (replace the input-bind or
// change-output-bind rejection with a no-op, exactly as the audit's F015-siblings mutation
// did) -> this test FAILS. Before it existed, that mutation was invisible.
func (s *txValidatorTestSuite) TestF015DposV2ClaimRewardRealWithdrawTreasuryBind() {
	cfg := s.Chain.GetParams()
	gate := cfg.StrictMoneyRangeHeight
	rewardPool := *cfg.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash
	fee := cfg.CRConfiguration.RealWithdrawSingleFee

	tx1 := *randomUint256()
	recipient := *randomUint168()
	const outVal = common.Fixed64(100 * 1e8)
	s.Chain.GetState().StateKeyFrame.WithdrawableTxInfo[tx1] = common2.OutputInfo{
		Recipient: recipient,
		Amount:    outVal + fee,
	}

	build := func(inputHash common.Uint168, height uint32, changeHash *common.Uint168) interfaces.Transaction {
		outs := []*common2.Output{{ProgramHash: recipient, Value: outVal}}
		refVal := outVal + fee
		if changeHash != nil {
			const changeVal = common.Fixed64(50 * 1e8)
			outs = append(outs, &common2.Output{ProgramHash: *changeHash, Value: changeVal})
			refVal += changeVal
		}
		txn := functions.CreateTransaction(0, common2.DposV2ClaimRewardRealWithdraw, 0,
			&payload.DposV2ClaimRewardRealWithdraw{WithdrawTransactionHashes: []common.Uint256{tx1}},
			[]*common2.Attribute{}, []*common2.Input{}, outs, 0, nil)
		txn = CreateTransactionByType(txn, s.Chain)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: height, Config: cfg, BlockChain: s.Chain})
		txn.SetReferences(map[*common2.Input]common2.Output{
			{}: {ProgramHash: inputHash, Value: refVal}})
		return txn
	}
	victim := *randomUint168()

	// NO FALSE POSITIVE: reward-pool input at the gate passes the whole check.
	errLegit, _ := build(rewardPool, gate, nil).SpecialContextCheck()
	s.NoError(errLegit)

	// THEFT: victim input at the gate is rejected by the input bind.
	errTheft, _ := build(victim, gate, nil).SpecialContextCheck()
	s.Require().Error(errTheft)
	s.Contains(errTheft.Error(), "dposv2 reward real withdraw input not from reward pool",
		"F-015: a DposV2 reward real-withdraw funded from a victim UTXO must be rejected at/above the gate")

	// REPLAY: the identical transaction below the gate is still accepted.
	errBelow, _ := build(victim, gate-1, nil).SpecialContextCheck()
	s.NoError(errBelow)

	// CHANGE THEFT: reward-pool input, change routed to the attacker, at the gate.
	attacker := *randomUint168()
	errChange, _ := build(rewardPool, gate, &attacker).SpecialContextCheck()
	s.Require().Error(errChange)
	s.Contains(errChange.Error(), "dposv2 reward real withdraw change output not to reward pool",
		"F-015: the trailing change output must be bound to the reward pool")

	// CHANGE REPLAY: the same change-theft transaction below the gate stays legacy.
	// (It is rejected further down for a different reason — the fee arithmetic — so assert
	// specifically that the F-015 change guard is NOT what rejects it.)
	errChangeBelow, _ := build(rewardPool, gate-1, &attacker).SpecialContextCheck()
	if errChangeBelow != nil {
		s.NotContains(errChangeBelow.Error(), "change output not to reward pool",
			"REPLAY BREAK: the F-015 change bind must not bind below the gate")
	}
}

// TestF015CRCProposalRealWithdrawTreasuryBind — sibling 3 of 3.
//
// MUTATION PROOF: neuter the input bind in
// CRCProposalRealWithdrawTransaction.SpecialContextCheck -> this test FAILS.
func (s *txValidatorTestSuite) TestF015CRCProposalRealWithdrawTreasuryBind() {
	cfg := s.Chain.GetParams()
	gate := cfg.StrictMoneyRangeHeight
	crExpenses := *cfg.CRConfiguration.CRExpensesProgramHash
	fee := cfg.CRConfiguration.RealWithdrawSingleFee

	tx1 := *randomUint256()
	recipient := *randomUint168()
	const outVal = common.Fixed64(100 * 1e8)
	s.Chain.GetCRCommittee().GetRealWithdrawTransactions()[tx1] = common2.OutputInfo{
		Recipient: recipient,
		Amount:    outVal + fee,
	}

	build := func(inputHash common.Uint168, height uint32) interfaces.Transaction {
		outs := []*common2.Output{{ProgramHash: recipient, Value: outVal}}
		txn := functions.CreateTransaction(0, common2.CRCProposalRealWithdraw, 0,
			&payload.CRCProposalRealWithdraw{WithdrawTransactionHashes: []common.Uint256{tx1}},
			[]*common2.Attribute{}, []*common2.Input{}, outs, 0, nil)
		txn = CreateTransactionByType(txn, s.Chain)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: height, Config: cfg, BlockChain: s.Chain})
		txn.SetReferences(map[*common2.Input]common2.Output{
			{}: {ProgramHash: inputHash, Value: outVal + fee}})
		return txn
	}
	victim := *randomUint168()

	// NO FALSE POSITIVE: CR-expenses input at the gate passes.
	errLegit, _ := build(crExpenses, gate).SpecialContextCheck()
	s.NoError(errLegit)

	// THEFT/GRIEF: victim input at the gate is rejected by the input bind.
	errTheft, _ := build(victim, gate).SpecialContextCheck()
	s.Require().Error(errTheft)
	s.Contains(errTheft.Error(), "crc proposal real withdraw input not from cr expenses",
		"F-015: a CRC proposal real-withdraw funded from a victim UTXO must be rejected at/above the gate")

	// REPLAY: the identical transaction below the gate is still accepted.
	errBelow, _ := build(victim, gate-1).SpecialContextCheck()
	s.NoError(errBelow)
}
