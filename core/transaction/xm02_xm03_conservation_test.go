// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// XM-02 (per-asset conservation) and XM-03 (one authoritative fee).
//
// XM-02: GetTxFeeMapStrict computed fee = inputs[asset] - outputs[asset] with
// SubtractFixed64, which guards overflow but not SIGN. An asset present in the outputs
// with no input backing simply produced a NEGATIVE entry and no error, and since every
// caller reads only feeMap[core.ELAAssetID] the negative entry for another asset was
// silently dropped. That is the missing conservation rule and the leg that converts a
// fabricated asset (XM-01) into ELA.
//
// XM-03: DefaultChecker.ContextCheck computed the strict fee and threw it away
// (`if _, err := ...`), while CheckTransactionFee gated the minimum fee -- and, worse,
// STORED the fee via SetFee -- from getTransactionFee, an asset-blind aggregate of every
// input Value minus every output Value. tx.Fee() is what the DPoS reward state sums.
//
// Every test here drives the production functions and proves the gate in both directions.
package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

type xmLeg struct {
	asset common.Uint256
	value common.Fixed64
}

// xmTransfer builds a real TransferAsset transaction plus the reference set the
// validator would resolve for it, one input per `in` leg and one output per `out` leg.
func xmTransfer(in, out []xmLeg) (interfaces.Transaction, map[*common2.Input]common2.Output) {
	inputs := make([]*common2.Input, 0, len(in))
	refs := make(map[*common2.Input]common2.Output, len(in))
	for i, leg := range in {
		input := &common2.Input{Previous: common2.OutPoint{
			TxID: common.Uint256{byte(i + 1)}, Index: uint16(i)}}
		inputs = append(inputs, input)
		refs[input] = common2.Output{
			AssetID:     leg.asset,
			Value:       leg.value,
			Type:        common2.OTNone,
			ProgramHash: common.Uint168{0x21},
			Payload:     &outputpayload.DefaultOutput{},
		}
	}
	outputs := make([]*common2.Output, 0, len(out))
	for _, leg := range out {
		outputs = append(outputs, &common2.Output{
			AssetID:     leg.asset,
			Value:       leg.value,
			Type:        common2.OTNone,
			ProgramHash: common.Uint168{0x21},
			Payload:     &outputpayload.DefaultOutput{},
		})
	}

	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.TransferAsset, 0, &payload.TransferAsset{},
		[]*common2.Attribute{}, inputs, outputs, 0, []*program.Program{},
	)
	return txn, refs
}

// xmCheckFee drives the production DefaultChecker.CheckTransactionFee at `height`.
func xmCheckFee(txn interfaces.Transaction, refs map[*common2.Input]common2.Output,
	height uint32) error {
	txn.SetParameters(&TransactionParameters{
		Transaction: txn, BlockHeight: height, Config: xmParams(height)})
	return txn.CheckTransactionFee(refs)
}

const (
	xmELA        = common.Fixed64(1_0000_0000)
	xmMinFee     = common.Fixed64(100) // config default MinTransactionFee
	xmBelowGateH = uint32(2260450)
	xmAboveGateH = uint32(2260451)
)

// ---------------------------------------------------------------- XM-02

// TestXM02ForeignAssetInputCannotMintELA is the headline rule: value denominated in an
// asset you did not spend cannot come out as ELA.
// FAILS ON PRISTINE: GetTxFeeStrict returns a negative ELA fee with no error, and the
// asset-blind minimum-fee gate sees a healthy positive aggregate, so the mint is accepted.
func TestXM02ForeignAssetInputCannotMintELA(t *testing.T) {
	fake := xmNonELAAsset()

	// Every value is strictly above MinTransactionFee, so ELA out > ELA in and the
	// transaction genuinely creates (mint - minfee) sela of ELA that no ELA input backs.
	for _, mint := range []common.Fixed64{xmMinFee + 1, 10000, xmELA, 5 * xmELA, 1_000_000 * xmELA} {
		// Spend `mint` of a foreign asset plus 1 ELA; emit (1 ELA + mint - minfee) of ELA.
		// Asset-blind aggregate fee == minfee (looks fine); ELA-only fee == -(mint-minfee).
		txn, refs := xmTransfer(
			[]xmLeg{{fake, mint}, {core.ELAAssetID, xmELA}},
			[]xmLeg{{core.ELAAssetID, xmELA + mint - xmMinFee}},
		)

		// sanity: this really is a mint -- more ELA leaves than entered.
		assert.True(t, txn.Outputs()[0].Value > xmELA,
			"test setup: expected an ELA mint of %d sela", mint-xmMinFee)

		// The authoritative per-asset accounting must refuse it.
		_, err := blockchain.GetTxFeeStrict(txn, core.ELAAssetID, refs)
		assert.Error(t, err, "minting %d sela of ELA from a foreign asset must not compute a fee", mint)

		// And the production fee check must refuse it, at and above the gate.
		assert.Error(t, xmCheckFee(txn, refs, xmAboveGateH),
			"minting %d sela of ELA from a foreign asset must be rejected", mint)

		// Below the gate the pristine verdict is preserved: this is exactly the
		// behaviour retained history was validated under.
		assert.NoError(t, xmCheckFee(txn, refs, xmBelowGateH),
			"below the gate the legacy asset-blind rule must be unchanged")
	}
}

// TestXM02NegativeFeeForAnyAssetRejected -- a transaction that emits an asset it never
// spent runs that asset's fee negative. Rejected whichever asset it is.
// FAILS ON PRISTINE: only feeMap[ELAAssetID] is ever read, so a negative entry for any
// other asset is discarded and the transaction is accepted.
func TestXM02NegativeFeeForAnyAssetRejected(t *testing.T) {
	fake := xmNonELAAsset()
	var fake2 common.Uint256
	fake2[3] = 0x77

	cases := []struct {
		name string
		in   []xmLeg
		out  []xmLeg
	}{
		{"fabricate a foreign asset out of an ELA spend",
			[]xmLeg{{core.ELAAssetID, 20 * xmELA}},
			[]xmLeg{{core.ELAAssetID, 10 * xmELA}, {fake, 5 * xmELA}}},
		{"fabricate a second foreign asset",
			[]xmLeg{{core.ELAAssetID, 20 * xmELA}, {fake, xmELA}},
			[]xmLeg{{core.ELAAssetID, xmELA}, {fake, xmELA}, {fake2, 1}}},
		{"emit more of a foreign asset than was spent",
			[]xmLeg{{core.ELAAssetID, 20 * xmELA}, {fake, xmELA}},
			[]xmLeg{{core.ELAAssetID, xmELA}, {fake, xmELA + 1}}},
		{"emit more ELA than was spent",
			[]xmLeg{{core.ELAAssetID, xmELA}},
			[]xmLeg{{core.ELAAssetID, xmELA + 1}}},
	}

	for _, c := range cases {
		txn, refs := xmTransfer(c.in, c.out)

		_, err := blockchain.GetTxFeeStrict(txn, core.ELAAssetID, refs)
		assert.Error(t, err, "%s: per-asset fee must not go negative", c.name)

		assert.Error(t, xmCheckFee(txn, refs, xmAboveGateH),
			"%s: must be rejected at and above the gate", c.name)
	}
}

// TestXM02BelowGateFeeMapUnchanged -- GetTxFeeMap (the legacy, wrapping calculation used
// below the gate) is untouched, so replay of retained history is unaffected by XM-02.
func TestXM02BelowGateFeeMapUnchanged(t *testing.T) {
	fake := xmNonELAAsset()
	txn, refs := xmTransfer(
		[]xmLeg{{core.ELAAssetID, 20 * xmELA}},
		[]xmLeg{{core.ELAAssetID, 10 * xmELA}, {fake, 5 * xmELA}},
	)
	feeMap, err := blockchain.GetTxFeeMap(txn, refs)
	assert.NoError(t, err, "the legacy fee map must still tolerate a negative entry")
	assert.Equal(t, common.Fixed64(10*xmELA), feeMap[core.ELAAssetID])
	assert.Equal(t, common.Fixed64(-5*xmELA), feeMap[fake],
		"the legacy path must keep the negative entry verbatim")
}

// ---------------------------------------------------------------- XM-03

// TestXM03MinimumFeeUsesStrictValue -- the minimum-fee gate must be judged on the
// authoritative ELA-only fee, not on an aggregate that a foreign asset can pad.
// FAILS ON PRISTINE: the asset-blind aggregate is enormous, so a transaction paying
// almost no ELA fee sails through.
func TestXM03MinimumFeeUsesStrictValue(t *testing.T) {
	fake := xmNonELAAsset()
	const elaFee = common.Fixed64(50) // deliberately BELOW MinTransactionFee (100)

	// Spend 100 ELA + 1000 units of a foreign asset; return 100 ELA - 50 and the whole
	// foreign leg is kept as "fee". Asset-blind fee = 50 + 1000e8. Strict ELA fee = 50.
	txn, refs := xmTransfer(
		[]xmLeg{{core.ELAAssetID, 100 * xmELA}, {fake, 1000 * xmELA}},
		[]xmLeg{{core.ELAAssetID, 100*xmELA - elaFee}},
	)

	// The asset-blind number the pristine gate used.
	assert.Equal(t, elaFee+1000*xmELA, getTransactionFee(txn, refs),
		"sanity: the legacy aggregate is padded by the foreign leg")
	// The authoritative number.
	strict, err := blockchain.GetTxFeeStrict(txn, core.ELAAssetID, refs)
	assert.NoError(t, err)
	assert.Equal(t, elaFee, strict)

	err = xmCheckFee(txn, refs, xmAboveGateH)
	assert.Error(t, err, "an ELA fee below the minimum must be rejected however large "+
		"the foreign leg is")
	assert.Contains(t, err.Error(), "transaction fee not enough")

	// Below the gate the pristine (padded) verdict is preserved.
	assert.NoError(t, xmCheckFee(txn, refs, xmBelowGateH),
		"below the gate the legacy asset-blind minimum-fee rule must be unchanged")
}

// TestXM03StoredFeeIsTheStrictValue -- the fee STORED on the transaction, which is what
// interfaces.Transaction.Fee() returns and what the DPoS reward state sums, must be the
// authoritative ELA-only value at and above the gate.
// FAILS ON PRISTINE: SetFee stores the asset-blind aggregate.
func TestXM03StoredFeeIsTheStrictValue(t *testing.T) {
	fake := xmNonELAAsset()
	const elaFee = common.Fixed64(10000)

	txn, refs := xmTransfer(
		[]xmLeg{{core.ELAAssetID, 100 * xmELA}, {fake, 777 * xmELA}},
		[]xmLeg{{core.ELAAssetID, 100*xmELA - elaFee}},
	)

	assert.NoError(t, xmCheckFee(txn, refs, xmAboveGateH))
	assert.Equal(t, elaFee, txn.Fee(),
		"above the gate the stored fee must be the ELA-only fee, not the padded aggregate")

	txn2, refs2 := xmTransfer(
		[]xmLeg{{core.ELAAssetID, 100 * xmELA}, {fake, 777 * xmELA}},
		[]xmLeg{{core.ELAAssetID, 100*xmELA - elaFee}},
	)
	assert.NoError(t, xmCheckFee(txn2, refs2, xmBelowGateH))
	assert.Equal(t, elaFee+777*xmELA, txn2.Fee(),
		"below the gate the stored fee must remain the legacy aggregate, verbatim")
}

// TestXM03NonELAFeeNoLongerInflatesTheRewardBase closes the loop with the F-011 wedge:
// the fee a non-ELA leg contributes to the reward base must now be zero.
func TestXM03NonELAFeeNoLongerInflatesTheRewardBase(t *testing.T) {
	fake := xmNonELAAsset()
	for _, wedge := range []common.Fixed64{1, 100, 100000, xmELA, 5000 * xmELA} {
		txn, refs := xmTransfer(
			[]xmLeg{{core.ELAAssetID, xmELA}, {fake, wedge}},
			[]xmLeg{{core.ELAAssetID, xmELA - xmMinFee}},
		)
		assert.NoError(t, xmCheckFee(txn, refs, xmAboveGateH))
		assert.Equal(t, xmMinFee, txn.Fee(),
			"a non-ELA leg of %d sela must contribute nothing to the reward base", wedge)
	}
}

// ---------------------------------------------------------------- no collateral damage

// TestOrdinaryELATransfersStillAccepted -- the regression guard. Plain ELA payments must
// behave identically on both sides of the gate.
func TestOrdinaryELATransfersStillAccepted(t *testing.T) {
	heights := []uint32{100000, 1000000, 2260450, 2260451, 2265000, 3000000}
	fees := []common.Fixed64{xmMinFee, 1000, 10000, xmELA}

	for _, h := range heights {
		for _, fee := range fees {
			// single input, two outputs (payment + change)
			txn, refs := xmTransfer(
				[]xmLeg{{core.ELAAssetID, 100 * xmELA}},
				[]xmLeg{{core.ELAAssetID, 60 * xmELA}, {core.ELAAssetID, 40*xmELA - fee}},
			)
			assert.NoError(t, xmCheckFee(txn, refs, h),
				"ordinary ELA transfer with fee %d at height %d must be accepted", fee, h)
			assert.Equal(t, fee, txn.Fee(),
				"ordinary ELA transfer: stored fee must be inputs-outputs at height %d", h)

			// multi-input consolidation
			txn2, refs2 := xmTransfer(
				[]xmLeg{{core.ELAAssetID, 10 * xmELA}, {core.ELAAssetID, 20 * xmELA},
					{core.ELAAssetID, 30 * xmELA}},
				[]xmLeg{{core.ELAAssetID, 60*xmELA - fee}},
			)
			assert.NoError(t, xmCheckFee(txn2, refs2, h),
				"consolidation with fee %d at height %d must be accepted", fee, h)
			assert.Equal(t, fee, txn2.Fee())
		}
	}
}

// TestXM02ZeroFeeSystemTransactionsStillAccepted -- the guard is `fee < 0`, NOT `fee <= 0`.
// Several node-built system transactions balance EXACTLY: CRCAppropriation requires
// totalInput == totalOutput and its SpecialContextCheck returns end=true, so it never runs
// the minimum-fee check but it DOES run GetTxFeeStrict from ContextCheck. A rule that
// rejected a zero fee would stop CR appropriation dead.
func TestXM02ZeroFeeSystemTransactionsStillAccepted(t *testing.T) {
	// CRCAppropriation shape: inputs from CR assets, two outputs summing to the input.
	txn, refs := xmTransfer(
		[]xmLeg{{core.ELAAssetID, 100 * xmELA}},
		[]xmLeg{{core.ELAAssetID, 30 * xmELA}, {core.ELAAssetID, 70 * xmELA}},
	)
	for _, h := range []uint32{xmBelowGateH, xmAboveGateH, 3000000} {
		fee, err := blockchain.GetTxFeeStrict(txn, core.ELAAssetID, refs)
		assert.NoError(t, err, "an exactly balanced transaction must not be rejected")
		assert.Equal(t, common.Fixed64(0), fee)
		_ = h
	}

	// A transaction with no outputs at all (illegal-evidence, UpdateVersion,
	// NextTurnDPOSInfo, DposV2ClaimReward ...) must also compute cleanly.
	txn2, refs2 := xmTransfer([]xmLeg{{core.ELAAssetID, 5 * xmELA}}, nil)
	fee, err := blockchain.GetTxFeeStrict(txn2, core.ELAAssetID, refs2)
	assert.NoError(t, err)
	assert.Equal(t, 5*xmELA, fee)

	// And a transaction with neither inputs nor outputs.
	txn3, refs3 := xmTransfer(nil, nil)
	fee, err = blockchain.GetTxFeeStrict(txn3, core.ELAAssetID, refs3)
	assert.NoError(t, err)
	assert.Equal(t, common.Fixed64(0), fee)
}

// TestOrdinaryELATransferBelowMinimumStillRejected -- the minimum-fee rule itself is
// unchanged for plain ELA payments; only its INPUT changed.
func TestOrdinaryELATransferBelowMinimumStillRejected(t *testing.T) {
	for _, h := range []uint32{2260450, 2260451, 3000000} {
		txn, refs := xmTransfer(
			[]xmLeg{{core.ELAAssetID, 100 * xmELA}},
			[]xmLeg{{core.ELAAssetID, 100*xmELA - (xmMinFee - 1)}},
		)
		assert.Error(t, xmCheckFee(txn, refs, h),
			"a below-minimum ELA fee must still be rejected at height %d", h)
	}
}
