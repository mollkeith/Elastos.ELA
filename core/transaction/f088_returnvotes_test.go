// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// TestF088ExistingCheckCapsAtVoteRights REFUTES F-088's claimed ReturnVotes StakePool
// drain. The finding asserts the rights check "only checks Value > rights-used, no
// Value <= rights cap", so an underflowed UsedDposV2Votes would let a staker return more
// than they staked. But the check actually has FOUR category comparisons
// (voteRights-usedDposV2, -usedCR, -usedCRImpeachment, -usedCRCProposal); the F-078 clone
// only underflows UsedDposV2Votes, so the usedCR*=0 comparison already caps the return at
// voteRights. This drives the REAL ReturnVotes SpecialContextCheck with UsedDposV2Votes
// underflowed to -50 ELA, voteRights = 100 ELA, and Value = 120 ELA (> voteRights), and
// asserts the existing check REJECTS it — so no separate cap is needed. (F-088's own
// verify agent failed in wf_a7b4d4af; this is our independent empirical finding — flag for
// engineer confirm. F-088's IN-BLOCK clone, which causes the underflow, is separately
// closed by CheckSameBlockConflicts.)
func (s *txValidatorTestSuite) TestF088ExistingCheckCapsAtVoteRights() {
	_, pub, err := crypto.GenerateKeyPair()
	s.Require().NoError(err)
	cont, err := contract.CreateStandardContract(pub)
	s.Require().NoError(err)
	code := cont.Code
	ct, err := contract.CreateStakeContractByCode(code)
	s.Require().NoError(err)
	stakeHash := *ct.ToProgramHash()

	const ela = common.Fixed64(1e8)
	st := state.NewState(s.Chain.GetParams(), nil, nil, nil,
		func() bool { return false }, nil, nil, nil, nil, nil, nil, nil)
	st.DposV2VoteRights[stakeHash] = 100 * ela
	st.UsedDposV2Votes[stakeHash] = -50 * ela // underflowed (F-078 clone-expiry scenario)
	s.Chain.SetState(st)
	defer s.Chain.SetState(state.NewState(s.Chain.GetParams(), nil, nil, nil,
		func() bool { return false }, nil, nil, nil, nil, nil, nil, nil))

	pl := &payload.ReturnVotes{Value: 120 * ela, Code: code}
	txn := functions.CreateTransaction(
		9, common2.ReturnVotes, payload.ReturnVotesSchnorrVersion, pl,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: code}})
	// BlockHeight BELOW the coordinated-upgrade gate -> the F-088 cap is inactive, so
	// this observes the EXISTING rights check in isolation.
	txn.SetParameters(&TransactionParameters{
		Transaction: txn, BlockHeight: 2260451 - 1,
		Config: s.Chain.GetParams(), BlockChain: s.Chain})

	err2, _ := txn.SpecialContextCheck()
	s.Require().Error(err2,
		"F-088: the existing multi-category rights check must reject a return exceeding voteRights "+
			"even when UsedDposV2Votes underflowed (usedCR*=0 caps it at voteRights) -> the drain is blocked")
	s.Contains(err2.Error(), "vote rights not enough",
		"rejection comes from the existing rights check, not the F-088 cap (which is gated off below-gate)")
}
