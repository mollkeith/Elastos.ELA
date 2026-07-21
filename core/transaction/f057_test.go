// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"time"

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

// TestF057FixForgedStall verifies the F-057 fix:
//   - FIX-PROOF (>=20): at/above the recovery gate, a forged NoBlock revert
//     (recent tip, future-dated block timestamp, ZERO real stall) is REJECTED.
//   - REPLAY-SAFETY: below the gate the same forgery is still accepted (pre-gate
//     history validates byte-for-byte unchanged).
//   - RELATED-TX / genuine rescue: at/above the gate a real >=noBlockTime stall
//     still triggers the revert with no added delay.
func (s *txValidatorTestSuite) TestF057FixForgedStall() {
	params := s.Chain.GetParams()
	gate := params.StrictMoneyRangeHeight
	noBlockTimeV1 := uint32(params.DPoSConfiguration.RevertToPOWNoBlockTimeV1) // 7200

	// Save/restore all shared chain state this test mutates.
	origHeight := s.Chain.BestChain.Height
	origTs := s.Chain.BestChain.Timestamp
	origMTP := s.Chain.MedianTimePast
	defer func() {
		s.Chain.BestChain.Height = origHeight
		s.Chain.BestChain.Timestamp = origTs
		s.Chain.MedianTimePast = origMTP
	}()

	// Pin the node clock floor to the distant past so MedianAdjustedTime() ==
	// TimeSource.AdjustedTime() == real now (no peers => zero offset). This makes
	// the node-clock guard deterministic in the test.
	s.Chain.MedianTimePast = time.Unix(1, 0)
	now := uint32(time.Now().Unix())

	// ---- FIX-PROOF: 5 gate heights x 4 future-date offsets = 20 forgeries ----
	fixHeights := []uint32{gate, gate + 1, gate + 40000, 3000000, 5000000}
	extras := []uint32{0, 1, 100, noBlockTimeV1}
	rejected := 0
	for _, h := range fixHeights {
		for _, extra := range extras {
			// Recent tip (healthy chain, no real stall).
			tip := now
			s.Chain.BestChain.Height = h
			s.Chain.BestChain.Timestamp = tip
			// Forged: header timestamp future-dated past the first (header-only)
			// check; the new node-clock guard must still reject it.
			txn := s.f057BuildNoBlock(h, tip+noBlockTimeV1+extra)
			err, end := txn.SpecialContextCheck()
			s.True(end, "RevertToPOW check must be terminal")
			s.Error(err, "FIX: forged NoBlock revert (zero real stall) must be "+
				"REJECTED at/above gate; height=%d extra=%d", h, extra)
			if err != nil {
				s.Contains(err.Error(), "invalid block time")
				rejected++
			}
		}
	}
	s.GreaterOrEqual(rejected, 20, "expected >=20 forgeries rejected; got %d", rejected)

	// ---- RELATED-TX / genuine rescue: real stall still fires at/above gate ----
	genHeights := []uint32{gate, gate + 40000, 5000000}
	margins := []uint32{1, 300, 100000}
	accepted := 0
	for _, h := range genHeights {
		for _, margin := range margins {
			// Genuine stall: the tip is truly >= noBlockTime old vs the node clock.
			tip := now - noBlockTimeV1 - margin
			s.Chain.BestChain.Height = h
			s.Chain.BestChain.Timestamp = tip
			// Honest block timestamp ~= now (not future-dated).
			txn := s.f057BuildNoBlock(h, now)
			err, end := txn.SpecialContextCheck()
			s.True(end)
			s.NoError(err, "GENUINE stall revert must still be ACCEPTED at/above "+
				"gate (no delay); height=%d margin=%d", h, margin)
			if err == nil {
				accepted++
			}
		}
	}
	s.GreaterOrEqual(accepted, 9, "genuine rescue must survive; got %d accepts", accepted)

	// ---- REPLAY-SAFETY: below the gate the forgery is STILL accepted ----
	// (V1-era heights below the gate; fix inactive -> original behavior.)
	belowHeights := []uint32{params.DPoSConfiguration.ChangeViewV1Height, 2000000, gate - 1}
	for _, h := range belowHeights {
		tip := now
		s.Chain.BestChain.Height = h
		s.Chain.BestChain.Timestamp = tip
		txn := s.f057BuildNoBlock(h, tip+noBlockTimeV1)
		err, _ := txn.SpecialContextCheck()
		s.NoError(err, "REPLAY-SAFETY: below-gate forgery must remain accepted "+
			"(unchanged historical behavior); height=%d", h)
	}
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
