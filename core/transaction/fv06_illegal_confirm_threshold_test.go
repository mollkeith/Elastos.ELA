// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

// FV-06 — IllegalConfirmContextCheck took its majority THRESHOLD from the CURRENT
// committee while checking MEMBERSHIP against the EVIDENCED-height snapshot, and let one
// signer set span MULTIPLE snapshot frames.
//
// F-082 fixed the voter UNIVERSE (GetAllProducersPublicKey -> GetSnapshot(height)) and
// never touched the THRESHOLD, which is worse than either alone because it makes the
// function read sound. Two defects survived:
//
//	(1) len(signers) was compared against GetArbitersMajorityCount(), i.e. 2/3 of
//	    len(a.CurrentArbitrators) -- the committee ON DUTY NOW -- while the sponsor and
//	    every vote were validated against the committee at the EVIDENCED height.
//	(2) GetSnapshot returns a SLICE of frames (SnapshotByHeight APPENDS on a force
//	    change), and ProposalContextCheckByHeight / VoteContextCheckByHeight accepted a
//	    match in ANY frame INDEPENDENTLY PER SIGNER, so the admissible universe was the
//	    UNION of two committees while the bar was 2/3 of ONE.
//
// These tests drive the REAL transaction path — IllegalBlockTransaction.SpecialContextCheck
// -> BlockChain.IllegalEvidenceStrictActive -> blockchain.CheckDPOSIllegalBlocks ->
// IllegalConfirmContextCheck — so the gate wiring is exercised too, and they additionally
// pin the direct pair. Gate 1 (StrictMoneyRangeHeight); the census records ZERO
// IllegalBlockEvidence transactions in 2,260,597 blocks, so re-thresholding rejects ZERO
// real history.
//
// MUTATION PROOF: restore either half of the pristine shape in
// blockchain/confirmvalidator.go -- put `len(signers) <= GetArbitersMajorityCount()` back
// in front of the strictActive branch and drop the per-frame threshold, or go back to the
// per-signer ANY-frame loops (ProposalContextCheckByHeight / VoteContextCheckByHeight) --
// and these tests FAIL. See the batch report for the captured output.
package transaction

import (
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// The one campaign gate this fix rides. Nothing here introduces a third.
const fv06Gate = uint32(2260451)

// fv06Frame builds a snapshot frame holding exactly the suite arbiters at idx.
func (s *txValidatorSpecialTxTestSuite) fv06Frame(idx ...int) *state.CheckPoint {
	members := make([]state.ArbiterMember, 0, len(idx))
	for _, i := range idx {
		members = append(members, s.arbitrators.CurrentArbitrators[i])
	}
	return &state.CheckPoint{CurrentArbitrators: members}
}

// fv06Tx wraps an illegal-block payload in a real IllegalBlockEvidence transaction at the
// given BLOCK height, so IllegalEvidenceStrictActive decides strictness exactly as it does
// in production (config.DefaultParams.StrictMoneyRangeHeight == fv06Gate).
func (s *txValidatorSpecialTxTestSuite) fv06Tx(pl *payload.DPOSIllegalBlocks,
	blockHeight uint32) interfaces.Transaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.IllegalBlockEvidence,
		payload.IllegalBlockVersion, pl,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
	txn = CreateTransactionByType(txn, s.Chain)
	txn.SetParameters(&TransactionParameters{
		Transaction: txn,
		BlockHeight: blockHeight,
		Config:      &config.DefaultParams,
		BlockChain:  s.Chain,
	})
	return txn
}

// fv06WithSnapshot swaps the arbiter snapshot ring and the current-committee majority
// count for the duration of fn, then restores both.
func (s *txValidatorSpecialTxTestSuite) fv06WithSnapshot(majority int,
	frames []*state.CheckPoint, fn func()) {
	origSnapshot := s.arbitrators.Snapshot
	origMajority := s.arbitrators.MajorityCount
	defer func() {
		s.arbitrators.Snapshot = origSnapshot
		s.arbitrators.MajorityCount = origMajority
	}()
	s.arbitrators.Snapshot = frames
	s.arbitrators.MajorityCount = majority
	fn()
}

// TestFV06ThresholdComesFromTheEvidencedFrameNotTheCurrentCommittee closes defect (1).
//
// The evidenced-height frame holds FIVE arbiters, so a real majority is 2/3*5 = 3 ->
// at least FOUR accepting signers. The CURRENT committee is small (majority count 2), so
// the pristine check `len(signers) <= 2` waves THREE signers through and every one of them
// is a genuine member of the frame -- membership alone cannot catch it. Pristine ACCEPTS a
// signer set that was never a majority of the committee the evidence is about.
func (s *txValidatorSpecialTxTestSuite) TestFV06ThresholdComesFromTheEvidencedFrameNotTheCurrentCommittee() {
	const evidenceHeight = uint32(3000)

	s.fv06WithSnapshot(2, []*state.CheckPoint{s.fv06Frame(0, 1, 2, 3, 4)}, func() {
		// THREE accepting signers, all real members of the 5-arbiter frame.
		subMajority, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 1, 2}, []int{0, 1, 2})

		errStrict, _ := s.fv06Tx(subMajority, fv06Gate).SpecialContextCheck()
		s.Require().Error(errStrict,
			"FV-06: a sub-majority of the EVIDENCED-height committee must be rejected at/above "+
				"the gate even when the CURRENT committee is small enough to admit it")
		s.Contains(errStrict.Error(), "signers less than majority count")

		// Direct pair, same verdict — pins the function as well as the call path.
		s.Error(blockchain.CheckDPOSIllegalBlocks(subMajority, true))

		// Below the gate the legacy current-committee threshold still applies, unchanged,
		// so the identical evidence is ACCEPTED. This is the replay guarantee.
		errLegacy, _ := s.fv06Tx(subMajority, fv06Gate-1).SpecialContextCheck()
		s.NoError(errLegacy,
			"REPLAY BREAK: below the gate the legacy path must behave exactly as before")

		// POSITIVE CONTROL: FOUR signers is a genuine majority of the 5-arbiter frame and
		// must be accepted at/above the gate. Without this the test above could be
		// satisfied by a guard that rejects everything.
		majority, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 1, 2, 3}, []int{0, 1, 2, 3})
		errOK, _ := s.fv06Tx(majority, fv06Gate).SpecialContextCheck()
		s.NoError(errOK,
			"FALSE POSITIVE: a real 4-of-5 majority of the evidenced frame must be accepted")
	})
}

// TestFV06SignerSetMayNotSpanTwoSnapshotFrames closes defect (2).
//
// One election key holds TWO frames (the pre- and post-force-change committees):
// frame A = {arb0, arb1, arb2}, frame B = {arb0, arb3, arb4}. The confirm is sponsored by
// arb0 (a member of both) and carries votes from arb0, arb1 and arb3 -- a set that is a
// majority of NO real committee, only of their UNION. Pristine accepts it because each
// signer is matched against ANY frame independently.
func (s *txValidatorSpecialTxTestSuite) TestFV06SignerSetMayNotSpanTwoSnapshotFrames() {
	const evidenceHeight = uint32(3000)

	frames := []*state.CheckPoint{s.fv06Frame(0, 1, 2), s.fv06Frame(0, 3, 4)}
	// Majority count 2 keeps the pristine current-committee check satisfied by 3 signers,
	// so the ONLY thing that can reject the spliced set is the per-frame binding.
	s.fv06WithSnapshot(2, frames, func() {
		spliced, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 1, 3}, []int{0, 1, 3})

		errStrict, _ := s.fv06Tx(spliced, fv06Gate).SpecialContextCheck()
		s.Require().Error(errStrict,
			"FV-06: a signer set spanning two snapshot frames must be rejected at/above the "+
				"gate -- it was never a majority of any single real committee")
		s.Contains(errStrict.Error(), "current arbitrators verify error")

		s.Error(blockchain.CheckDPOSIllegalBlocks(spliced, true))

		// Below the gate the legacy universe accepts it — byte-identical replay.
		errLegacy, _ := s.fv06Tx(spliced, fv06Gate-1).SpecialContextCheck()
		s.NoError(errLegacy, "REPLAY BREAK: the legacy path must be untouched")

		// POSITIVE CONTROL 1: a set contained in frame B alone still passes.
		inB, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 3, 4}, []int{0, 3, 4})
		errB, _ := s.fv06Tx(inB, fv06Gate).SpecialContextCheck()
		s.NoError(errB, "FALSE POSITIVE: a 3-of-3 majority of frame B must be accepted")

		// POSITIVE CONTROL 2: and so does a set contained in frame A alone, proving the
		// fix genuinely tries EVERY frame rather than pinning the first or the last.
		inA, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 1, 2}, []int{0, 1, 2})
		errA, _ := s.fv06Tx(inA, fv06Gate).SpecialContextCheck()
		s.NoError(errA, "FALSE POSITIVE: a 3-of-3 majority of frame A must be accepted")
	})
}

// TestFV06EmptySnapshotRingFailsClosed pins the explicit rejection. An evidence height
// outside the retained ring (MaxSnapshotLength = 20 election keys) yields no frame at all;
// the strict path must reject rather than fall through to any current-committee answer.
func (s *txValidatorSpecialTxTestSuite) TestFV06EmptySnapshotRingFailsClosed() {
	const evidenceHeight = uint32(3000)

	s.fv06WithSnapshot(2, []*state.CheckPoint{}, func() {
		pl, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(
			evidenceHeight, []int{0, 1, 2, 3}, []int{0, 1, 2, 3})
		errStrict, _ := s.fv06Tx(pl, fv06Gate).SpecialContextCheck()
		s.Require().Error(errStrict, "an empty snapshot ring must fail closed")
		s.Contains(errStrict.Error(), "no arbiter snapshot retained for the evidenced height")
	})
}
