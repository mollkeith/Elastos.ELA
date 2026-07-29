// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// f057BuildNoBlock builds a NoBlock RevertToPOW transaction with the given
// working/block height and in-block header timestamp, wired to the suite chain.
func (s *txValidatorTestSuite) f057BuildNoBlock(height, blockTs uint32) interfaces.Transaction {
	revertToPow := &payload.RevertToPOW{
		Type:          payload.NoBlock,
		WorkingHeight: height,
	}
	txn := functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		revertToPow,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		nil,
	)
	txn = CreateTransactionByType(txn, s.Chain)
	txn.SetParameters(&TransactionParameters{
		Transaction: txn,
		BlockHeight: height,
		TimeStamp:   blockTs,
		Config:      s.Chain.GetParams(),
		BlockChain:  s.Chain,
	})
	return txn
}

// FV-22 SUPERSEDES F-057's node-clock leg. TestF057FixForgedStall used to live here
// and asserted the behaviour that has now been WITHDRAWN, so it is replaced rather
// than patched. The reasoning is recorded in full because the withdrawal gives up a
// protection this campaign had already shipped:
//
//   - WHAT F-057 DID. At/above the recovery gate it added a second condition,
//     MedianAdjustedTime().Unix() - lastBlockTime >= noBlockTime. MedianAdjustedTime is
//     TimeSource.AdjustedTime() -- the node's own wall clock plus the median of up to
//     199 peer offsets -- floored at MedianTimePast+1s. It defended a real attack: with
//     RevertToPOWNoBlockTimeV1 == MaxTimeOffsetSeconds, a producer can future-date one
//     header by exactly the stall window and satisfy the block-timestamp condition with
//     zero real elapsed time (TestF057ExploitIsReal, still green, proves that below the
//     gate).
//
//   - WHY IT IS WITHDRAWN. It puts a node-local, peer-set-dependent quantity into a
//     BLOCK ACCEPTANCE decision. Two honest nodes holding identical chain state, with
//     different peer sets or clocks, can reach opposite accept/reject verdicts on the
//     same block. It is reject-only and self-healing, so it is a stall rather than a
//     permanent fork -- but it is a category error, it is OUR OWN change, and it arms on
//     the first block of the recovery fork, so it had to be decided before the restart.
//
//   - WHY THE PROPOSED REPLACEMENT WAS NOT TAKEN. Review suggested substituting
//     header.Timestamp - CalcPastMedianTime(prevNode) >= noBlockTime. CalcPastMedianTime
//     is the median of the parent and its 10 ancestors (blockchain.go), i.e. the
//     6th-smallest of 11 timestamps, which sits BELOW the parent's own timestamp on any
//     normally-spaced chain. Substituting it would therefore have made the at/above-gate
//     leg STRICTLY MORE PERMISSIVE than the pre-gate leg it replaces -- removing F-057's
//     protection AND weakening upstream's. It was measured over the retained chain rather
//     than assumed; see the batch report.
//
//   - HOW F-057 IS CLOSED INSTEAD -- OPTION (b), DECIDED BY THE OWNER AND SHIPPED. At
//     and above gate 1 the demanded gap is noBlockTime + MaxTimeOffsetSeconds: more than
//     a producer can manufacture by post-dating its own header, so whatever it forges at
//     least noBlockTime of REAL time must have passed since the parent. It is
//     deterministic and ancestry-only (header timestamp minus PARENT timestamp, both
//     consensus data), needs no third height, and consults no clock. Below the gate the
//     legacy comparison is kept verbatim so retained history replays byte-identically.
//     The accepted cost is failsafe latency 2h -> 4h; the measured cost over the retained
//     chain is that 28 of the 29 historical NoBlock rescues would have had to wait
//     between 1h53m27s and 1h59m48s longer (all 30 historical RevertToPOW transactions
//     sit at heights 1184559..2129088, i.e. entirely below gate 1, so no retained block
//     changes verdict).
//
// What IS asserted below is the determinism contract plus the option-(b) threshold. The
// forgery itself is proven rejected through the PRODUCTION BLOCK PATH in
// blockchain/fv22_prevblock_test.go (TestFV22OptionBRejectsTheForgedStall); these are
// the unit-level companions.

// f057BuildNoBlockFromParent is f057BuildNoBlock with the parent of the block under
// validation made explicit -- the FV-22 change-1 input.
func (s *txValidatorTestSuite) f057BuildNoBlockFromParent(
	height, blockTs, parentTs uint32) interfaces.Transaction {
	revertToPow := &payload.RevertToPOW{
		Type:          payload.NoBlock,
		WorkingHeight: height,
	}
	txn := functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		revertToPow,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		nil,
	)
	txn = CreateTransactionByType(txn, s.Chain)
	params := &TransactionParameters{
		Transaction: txn,
		BlockHeight: height,
		TimeStamp:   blockTs,
		Config:      s.Chain.GetParams(),
		BlockChain:  s.Chain,
	}
	params.SetPrevBlockTimestamp(parentTs)
	txn.SetParameters(params)
	return txn
}

// TestFV22NoBlockRevertIsDeterministic drives the production
// (*RevertToPOWTransaction).SpecialContextCheck and asserts the three properties the
// withdrawn clock leg could not satisfy:
//
//  1. the verdict is a function of the block's OWN parent, not the validating node's tip
//  2. the verdict does not move when the node's clock moves
//  3. gate 1 moves the THRESHOLD (option (b)) and nothing else: below the gate the
//     legacy noBlockTime, at/above it noBlockTime+MaxTimeOffsetSeconds, and the rule
//     does not move a second time above the gate
//
// MUTATION PROOF: re-add the MedianAdjustedTime condition at/above the gate and (2)
// fails; make lastBlockTime read BestChain.Timestamp again and (1) fails; revert the
// option-(b) hunk and (3) fails.
func (s *txValidatorTestSuite) TestFV22NoBlockRevertIsDeterministic() {
	params := s.Chain.GetParams()
	gate := params.StrictMoneyRangeHeight
	noBlockTime := uint32(params.DPoSConfiguration.RevertToPOWNoBlockTimeV1)
	// f057Demanded is the gap the production rule demands at a height: the legacy value
	// below gate 1, the option-(b) value at and above it.
	f057Demanded := func(h uint32) uint32 {
		if h >= gate {
			return noBlockTime + uint32(blockchain.MaxTimeOffsetSeconds)
		}
		return noBlockTime
	}

	origHeight := s.Chain.BestChain.Height
	origTs := s.Chain.BestChain.Timestamp
	origMTP := s.Chain.MedianTimePast
	defer func() {
		s.Chain.BestChain.Height = origHeight
		s.Chain.BestChain.Timestamp = origTs
		s.Chain.MedianTimePast = origMTP
	}()

	// Deliberately in the future: under the withdrawn clock leg the node's clock has
	// not reached these timestamps, so every at/above-gate case below would be rejected.
	base := uint32(time.Now().Unix()) + 3000000
	heights := []uint32{params.DPoSConfiguration.ChangeViewV1Height, 2000000, gate - 1,
		gate, gate + 1, 5000000}

	// ---- 1. the parent decides, not the validating node's tip ----
	for _, h := range heights {
		s.Chain.BestChain.Height = h
		s.Chain.MedianTimePast = time.Unix(1, 0)

		// Node tip says NO time elapsed; the block's own parent says a full interval did.
		s.Chain.BestChain.Timestamp = base + f057Demanded(h)
		err, end := s.f057BuildNoBlockFromParent(h, base+f057Demanded(h), base).SpecialContextCheck()
		s.True(end, "RevertToPOW check must be terminal")
		s.NoError(err, "FV-22: the no-block interval must be measured against the "+
			"block's OWN parent, not the validating node's tip; height=%d", h)

		// Node tip says a full interval elapsed; the block's own parent says none did.
		s.Chain.BestChain.Timestamp = base - f057Demanded(h)
		err, _ = s.f057BuildNoBlockFromParent(h, base+100, base).SpecialContextCheck()
		s.Error(err, "FV-22: a revert with no genuine gap against its OWN parent must "+
			"be rejected however old the validating node's unrelated tip is; height=%d", h)
	}

	// ---- 2. the node clock must not move the verdict ----
	for _, h := range heights {
		s.Chain.BestChain.Height = h
		s.Chain.BestChain.Timestamp = base
		var first bool
		for i, floor := range []time.Time{
			time.Unix(1, 0),
			time.Unix(int64(base)+int64(f057Demanded(h))+1, 0),
			time.Unix(int64(base), 0),
		} {
			s.Chain.MedianTimePast = floor
			err, _ := s.f057BuildNoBlockFromParent(h, base+f057Demanded(h), base).SpecialContextCheck()
			if i == 0 {
				first = err == nil
				s.NoError(err, "FV-22: a genuine gap against the parent must be accepted "+
					"wherever the node clock is; height=%d", h)
				continue
			}
			s.Equal(first, err == nil, "CLOCK IN CONSENSUS: the same block and parent "+
				"produced different verdicts under different node clocks; height=%d", h)
		}
	}

	// ---- 3. gate 1 moves the THRESHOLD, exactly once, in exactly one direction ----
	optB := noBlockTime + uint32(blockchain.MaxTimeOffsetSeconds)
	s.Chain.MedianTimePast = time.Unix(1, 0)
	for _, c := range []struct {
		delta         uint32
		wantBelow     bool
		wantAtOrAbove bool
	}{
		{noBlockTime - 1, false, false},
		{noBlockTime, true, false}, // the forgeable band opens here ...
		{optB - 1, true, false},    // ... and closes here
		{optB, true, true},
		{10 * optB, true, true},
	} {
		var verdicts []bool
		for _, h := range []uint32{gate - 1, gate, gate + 1} {
			s.Chain.BestChain.Height = h
			s.Chain.BestChain.Timestamp = base
			err, _ := s.f057BuildNoBlockFromParent(h, base+c.delta, base).SpecialContextCheck()
			verdicts = append(verdicts, err == nil)
		}
		s.Equal(c.wantBelow, verdicts[0], "below gate 1 the legacy comparison must be "+
			"unchanged (retained history replays byte-identically); delta=%d", c.delta)
		s.Equal(c.wantAtOrAbove, verdicts[1], "at gate 1 option (b) must demand "+
			"noBlockTime+MaxTimeOffsetSeconds; delta=%d", c.delta)
		s.Equal(verdicts[1], verdicts[2], "the rule must not move a SECOND time above "+
			"gate 1 — a third activation height has appeared; delta=%d", c.delta)
	}

	// ---- 4. positive control: the deterministic threshold still bites ----
	for _, h := range heights {
		s.Chain.BestChain.Height = h
		s.Chain.BestChain.Timestamp = base
		err, _ := s.f057BuildNoBlockFromParent(h, base+f057Demanded(h)-1, base).SpecialContextCheck()
		s.Error(err, "a gap one second short of the demanded threshold must still be rejected — the "+
			"condition must be deterministic, not absent; height=%d", h)
		if err != nil {
			s.Contains(err.Error(), "invalid block time")
		}
	}
}

// TestFV22FallsBackToBestChainWhenNoParentSupplied pins the compatibility edge: a
// caller that builds parameters without a parent (only tests do; every production entry
// supplies one) still gets exactly the previous behaviour.
func (s *txValidatorTestSuite) TestFV22FallsBackToBestChainWhenNoParentSupplied() {
	params := s.Chain.GetParams()
	// h is at gate 1, so the demanded gap is the option-(b) threshold.
	noBlockTime := uint32(params.DPoSConfiguration.RevertToPOWNoBlockTimeV1) +
		uint32(blockchain.MaxTimeOffsetSeconds)
	h := params.StrictMoneyRangeHeight

	origHeight := s.Chain.BestChain.Height
	origTs := s.Chain.BestChain.Timestamp
	origMTP := s.Chain.MedianTimePast
	defer func() {
		s.Chain.BestChain.Height = origHeight
		s.Chain.BestChain.Timestamp = origTs
		s.Chain.MedianTimePast = origMTP
	}()
	s.Chain.MedianTimePast = time.Unix(1, 0)

	base := uint32(time.Now().Unix()) + 3000000
	s.Chain.BestChain.Height = h
	s.Chain.BestChain.Timestamp = base

	err, _ := s.f057BuildNoBlock(h, base+noBlockTime).SpecialContextCheck()
	s.NoError(err, "with no parent supplied the tip is the reference, as before")

	err, _ = s.f057BuildNoBlock(h, base+noBlockTime-1).SpecialContextCheck()
	s.Error(err, "with no parent supplied the threshold still applies against the tip")
}

// TestF057RelatedTxUnaffected verifies the fix does not disturb the sibling
// RevertToPOW branches that share SpecialContextCheck (NoProducers,
// NoClaimDPOSNode) nor the F-098 unknown-type guard, at/above the gate.
func (s *txValidatorTestSuite) TestF057RelatedTxUnaffected() {
	params := s.Chain.GetParams()
	gate := params.StrictMoneyRangeHeight

	origHeight := s.Chain.BestChain.Height
	origNoProducers := s.Chain.GetState().NoProducers
	origNoClaim := s.Chain.GetState().NoClaimDPOSNode
	defer func() {
		s.Chain.BestChain.Height = origHeight
		s.Chain.GetState().NoProducers = origNoProducers
		s.Chain.GetState().NoClaimDPOSNode = origNoClaim
	}()
	s.Chain.BestChain.Height = gate

	build := func(rtype payload.RevertType) interfaces.Transaction {
		revertToPow := &payload.RevertToPOW{Type: rtype, WorkingHeight: gate}
		txn := functions.CreateTransaction(
			common2.TxVersion09, common2.RevertToPOW, payload.RevertToPOWVersion,
			revertToPow, []*common2.Attribute{}, []*common2.Input{},
			[]*common2.Output{}, 0, nil)
		txn = CreateTransactionByType(txn, s.Chain)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: gate, Config: params, BlockChain: s.Chain,
		})
		return txn
	}

	// NoProducers: flag off -> reject; flag on -> accept (time-independent).
	s.Chain.GetState().NoProducers = false
	err, _ := build(payload.NoProducers).SpecialContextCheck()
	s.EqualError(err, "transaction validate error: payload content invalid:current producers is enough")
	s.Chain.GetState().NoProducers = true
	err, _ = build(payload.NoProducers).SpecialContextCheck()
	s.NoError(err, "NoProducers revert must still work at/above gate")

	// NoClaimDPOSNode: flag off -> reject; flag on -> accept.
	s.Chain.GetState().NoClaimDPOSNode = false
	err, _ = build(payload.NoClaimDPOSNode).SpecialContextCheck()
	s.EqualError(err, "transaction validate error: payload content invalid:current CR member claimed DPoS node")
	s.Chain.GetState().NoClaimDPOSNode = true
	err, _ = build(payload.NoClaimDPOSNode).SpecialContextCheck()
	s.NoError(err, "NoClaimDPOSNode revert must still work at/above gate")

	// F-098 unknown type still rejected at/above gate (not disturbed by F-057).
	err, _ = build(payload.RevertType(3)).SpecialContextCheck()
	s.EqualError(err, "transaction validate error: payload content invalid:invalid RevertToPOW type")
}
