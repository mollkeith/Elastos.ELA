// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestF015VotesRealWithdrawTreasuryBind proves the F-015 fix. Real-withdraw txs are exempt
// from RunPrograms (checkTransactionSignature short-circuits), so with no input-treasury
// bind an attacker funds a VotesRealWithdraw from a VICTIM UTXO (empty programs, no
// signature) and pockets the unbound change = direct theft. Drives the REAL
// SpecialContextCheck: above the gate a victim input (and an off-treasury change output)
// is REJECTED; a stake-pool input passes; below the gate the victim input is still
// accepted (replay-safe legacy = the pre-fix exploit surface).
func (s *txValidatorTestSuite) TestF015VotesRealWithdrawTreasuryBind() {
	cfg := s.Chain.GetParams()
	gate := cfg.StrictMoneyRangeHeight
	stakePool := *cfg.StakePoolProgramHash
	fee := cfg.CRConfiguration.RealWithdrawSingleFee

	tx1 := *randomUint256()
	recipient := *randomUint168()
	const outVal = common.Fixed64(100 * 1e8)
	// Seed a pending withdraw entry so the recipient/fee checks pass for a well-formed tx.
	s.Chain.GetState().StateKeyFrame.VotesWithdrawableTxInfo[tx1] = common2.OutputInfo{
		Recipient: recipient,
		Amount:    outVal + fee,
	}

	// build a well-formed VotesRealWithdraw and vary the input ProgramHash / height / change.
	build := func(inputHash common.Uint168, height uint32, changeHash *common.Uint168) interfaces.Transaction {
		outs := []*common2.Output{{ProgramHash: recipient, Value: outVal}}
		refVal := outVal + fee
		if changeHash != nil {
			const changeVal = common.Fixed64(50 * 1e8)
			outs = append(outs, &common2.Output{ProgramHash: *changeHash, Value: changeVal})
			refVal += changeVal
		}
		txn := functions.CreateTransaction(0, common2.VotesRealWithdraw, 0,
			&payload.VotesRealWithdrawPayload{VotesRealWithdraw: []payload.VotesRealWidhdraw{
				{ReturnVotesTXHash: tx1, StakeAddress: *randomUint168(), Value: outVal}}},
			[]*common2.Attribute{}, []*common2.Input{}, outs, 0, nil)
		txn = CreateTransactionByType(txn, s.Chain)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: height, Config: cfg, BlockChain: s.Chain})
		txn.SetReferences(map[*common2.Input]common2.Output{
			{}: {ProgramHash: inputHash, Value: refVal}})
		return txn
	}
	victim := *randomUint168()

	// LEGIT (stake-pool input, at gate) -> full check passes.
	errLegit, _ := build(stakePool, gate, nil).SpecialContextCheck()
	s.NoError(errLegit)

	// THEFT (victim input, at gate) -> rejected by the input bind.
	errTheft, _ := build(victim, gate, nil).SpecialContextCheck()
	s.Require().Error(errTheft)
	s.Contains(errTheft.Error(), "input not from stake pool",
		"F-015: a real-withdraw funded by a non-treasury (victim) UTXO must be rejected at/above the gate")

	// REPLAY (victim input, BELOW gate) -> accepted (byte-identical legacy = exploit surface).
	errBelow, _ := build(victim, gate-1, nil).SpecialContextCheck()
	s.NoError(errBelow)

	// F-015b CHANGE THEFT (stake-pool input, change to attacker, at gate) -> rejected.
	attacker := *randomUint168()
	errChange, _ := build(stakePool, gate, &attacker).SpecialContextCheck()
	s.Require().Error(errChange)
	s.Contains(errChange.Error(), "change output not to stake pool",
		"F-015b: the trailing change output must be bound to the treasury")
}
