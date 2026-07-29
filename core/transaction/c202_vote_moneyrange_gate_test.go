// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// C2-02 -- the per-entry vote money bound must be HEIGHT-GATED.
//
// WHY THIS TEST EXISTS. This release documents, in
// core/types/outputpayload/crosschain.go, why an unconditional money bound must
// NOT live in a height-less Validate(): "an unconditional bound rejects retained
// mainnet block 2,208,265 -- a block the released v0.9.9.6 accepted and
// DPoS-finalised -- which would stop a node replaying the chain from genesis."
// The same release then applied exactly that shape to per-entry VOTE amounts in
// three height-less places. Baseline v0.9.9.6 (c61c9e61) bounded votes only from
// below (`Votes <= 0`); the absolute `!MoneyRange(...)` conjunct is NEW, so below
// the coordinated gate it can only ever turn an ACCEPT into a REJECT. That is a
// Rule-2 defect regardless of whether a qualifying entry happens to exist in
// retained history -- and the shipped-once precedent is precisely that nobody
// expected one to exist there either.
//
// The fix moves the absolute bound to the height-aware callers, gated at
// StrictMoneyRangeHeight, so that BELOW the gate behaviour is byte-identical to
// baseline and ABOVE it every vote is bounded.
//
// FAIL-ON-PRISTINE. With the fix reverted -- i.e. the `|| !common.MoneyRange(...)`
// conjunct restored inside VoteOutput.Validate() / Voting.Validate() --
// TestC202HeightlessValidateMustNotBound and TestC202BelowGateMatchesBaseline
// both FAIL, because the height-less validator rejects the entry with no height
// to gate on. With the fix in place all four tests pass. Proven by restoring the
// pristine conjunct, not by assertion.

const c202Gate = config.MainNetStrictMoneyRangeHeight

// c202HugeVoteOutput builds a vote output whose single candidate entry is one
// sela ABOVE MaxELAMoney -- the exact value class the new absolute bound rejects
// and the baseline `Votes <= 0` check accepts.
func c202HugeVoteOutput() *common2.Output {
	var ph common.Uint168
	ph[0] = byte(contract.PrefixStandard)
	return &common2.Output{
		AssetID:     core.ELAAssetID,
		Value:       common.Fixed64(1),
		ProgramHash: ph,
		Type:        common2.OTVote,
		Payload: &outputpayload.VoteOutput{
			Version: outputpayload.VoteProducerAndCRVersion,
			Contents: []outputpayload.VoteContent{{
				VoteType: outputpayload.Delegate,
				CandidateVotes: []outputpayload.CandidateVotes{{
					Candidate: []byte{0x01, 0x02, 0x03},
					Votes:     common.MaxELAMoney + 1,
				}},
			}},
		},
	}
}

func c202VoteTxAt(h uint32) interfaces.Transaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09,
		common2.TransferAsset,
		0,
		&payload.TransferAsset{},
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{c202HugeVoteOutput()},
		0,
		[]*program.Program{},
	)
	txn.SetParameters(&TransactionParameters{
		Transaction: txn,
		BlockHeight: h,
		Config:      config.GetDefaultParams(),
	})
	return txn
}

// TestC202HeightlessValidateMustNotBound is the direct fail-on-pristine anchor.
// VoteOutput.Validate() has no block height, so it must apply ONLY the original
// unconditional lower bound. If it also applies MoneyRange, every replaying node
// re-judges retained history with a rule v0.9.9.6 never had.
func TestC202HeightlessValidateMustNotBound(t *testing.T) {
	out := c202HugeVoteOutput()
	err := out.Payload.Validate()
	if err != nil {
		t.Fatalf("RULE 2 BREACH: the height-less VoteOutput.Validate() rejects a "+
			"vote entry of %d sela.\n"+
			"  rejection: %v\n"+
			"  Validate() carries no block height, so this verdict is applied to "+
			"RETAINED blocks too.\n"+
			"  The bound belongs in the height-aware caller, gated at "+
			"StrictMoneyRangeHeight (%d).", int64(common.MaxELAMoney+1), err, c202Gate)
	}

	// and the ORIGINAL lower bound must still be enforced, unconditionally
	zero := c202HugeVoteOutput()
	zero.Payload.(*outputpayload.VoteOutput).Contents[0].CandidateVotes[0].Votes = 0
	assert.Error(t, zero.Payload.Validate(),
		"the original `Votes <= 0` bound must remain unconditional")
}

// TestC202BelowGateMatchesBaseline drives the PRODUCTION output check one block
// below the gate. Below the coordinated activation a v1.0.0 node must reach the
// same verdict the released v0.9.9.6 reached, or it cannot replay the chain.
func TestC202BelowGateMatchesBaseline(t *testing.T) {
	for _, h := range []uint32{1, 1405000, c202Gate - 1} {
		txn := c202VoteTxAt(h)
		if err := txn.CheckTransactionOutput(); err != nil {
			t.Fatalf("RULE 2 BREACH: v1.0.0 REJECTS a vote output at retained "+
				"height %d.\n  rejection: %v\n  Gate 1 is %d; below it the verdict "+
				"must be byte-identical to v0.9.9.6.", h, err, c202Gate)
		}
	}
	t.Logf("below gate %d: the absolute vote bound is correctly inert", c202Gate)
}

// TestC202AtAndAboveGateRejects is the other half. Gating the bound must not
// reopen the hole it was added to close: at and above the coordinated gate the
// entry must be refused, because these values feed unchecked
// `producer.votes += ...` accumulations in dpos/state.
func TestC202AtAndAboveGateRejects(t *testing.T) {
	for _, h := range []uint32{c202Gate, c202Gate + 1, c202Gate + 100000} {
		txn := c202VoteTxAt(h)
		err := txn.CheckTransactionOutput()
		if err == nil {
			t.Fatalf("GATE INERT: a vote entry of %d sela was ACCEPTED at height "+
				"%d, at or above gate 1 (%d). Gating must not disable the bound "+
				"for new blocks.", int64(common.MaxELAMoney+1), h, c202Gate)
		}
		t.Logf("height %d -> rejected: %v", h, err)
	}
}

// TestC202GateIsGateOneOnly enforces Rule 1: the fix must reuse the existing
// coordinated activation and must not introduce a third mainnet height.
func TestC202GateIsGateOneOnly(t *testing.T) {
	assert.Equal(t, uint32(2260451), uint32(config.MainNetStrictMoneyRangeHeight),
		"gate 1 must remain 2,260,451")
	assert.Equal(t, config.MainNetStrictMoneyRangeHeight,
		config.GetDefaultParams().StrictMoneyRangeHeight,
		"the vote bound must gate on gate 1, not a new height")
}
