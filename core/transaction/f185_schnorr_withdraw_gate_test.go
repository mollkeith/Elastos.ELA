// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package transaction

import (
	"fmt"
	"math"

	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// f185GateHeight stands in for the coordinated StrictMoneyRangeHeight (gate 1).
const f185GateHeight uint32 = 1000

// f185UnknownPayloadVersion is one past the highest defined WithdrawFromSideChain
// payload version (V2 == 0x02).
const f185UnknownPayloadVersion byte = 0x03

// f185Recover turns a panic into an error so a pristine-tree run reports a clean
// test failure instead of aborting the whole package test binary.
func f185Recover(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PANIC: %v", r)
		}
	}()
	return fn()
}

func (s *txValidatorSpecialTxTestSuite) f185WithdrawTx(payloadVersion byte,
	pld *payload.WithdrawFromSideChain) interfaces.Transaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09,
		common2.WithdrawFromSideChain,
		payloadVersion,
		pld,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
	return CreateTransactionByType(txn, s.Chain)
}

// TestF185WithdrawSchnorrPayloadVersionGate proves the F-185 fix: the declared
// SchnorrStartHeight is now a two-sided activation gate for the aggregate-Schnorr
// WithdrawFromSideChain payload (V2), enforced from StrictMoneyRangeHeight.
//
// Fail-on-pristine: without the fix WithdrawFromSideChainTransaction inherits
// DefaultChecker.HeightVersionCheck, which unconditionally returns nil, so the
// V2-off and unknown-version cases below get no error at all.
func (s *txValidatorSpecialTxTestSuite) TestF185WithdrawSchnorrPayloadVersionGate() {
	testCases := []struct {
		name               string
		payloadVersion     byte
		schnorrStartHeight uint32
		blockHeight        uint32
		wantErrContains    string
	}{
		{
			// The MainNet posture: SchnorrStartHeight == math.MaxUint32 means the
			// schnorr withdraw feature is configured OFF, so a V2 payload must be
			// refused rather than dispatched into the plain-sum group-key path.
			name:               "V2 refused at the gate while schnorr withdraw is off",
			payloadVersion:     payload.WithdrawFromSideChainVersionV2,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight,
			wantErrContains:    "before SchnorrStartHeight",
		},
		{
			// Below gate 1 the acceptance decision must be bit-identical to the
			// pristine tree, so retained history still validates unchanged.
			name:               "V2 untouched below the coordinated gate",
			payloadVersion:     payload.WithdrawFromSideChainVersionV2,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight - 1,
		},
		{
			// The path the production Arbiter actually uses (7,786 V1 withdrawals
			// in real mainnet history) must be unaffected.
			name:               "V1 still accepted at the gate",
			payloadVersion:     payload.WithdrawFromSideChainVersionV1,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight,
		},
		{
			name:               "V0 still accepted at the gate",
			payloadVersion:     payload.WithdrawFromSideChainVersion,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight,
		},
		{
			// Where the feature is genuinely activated the gate must let V2 through.
			name:               "V2 accepted once SchnorrStartHeight is reached",
			payloadVersion:     payload.WithdrawFromSideChainVersionV2,
			schnorrStartHeight: f185GateHeight / 2,
			blockHeight:        f185GateHeight,
		},
		{
			name:               "unknown payload version refused at the gate",
			payloadVersion:     f185UnknownPayloadVersion,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight,
			wantErrContains:    "unsupported",
		},
		{
			name:               "unknown payload version untouched below the gate",
			payloadVersion:     f185UnknownPayloadVersion,
			schnorrStartHeight: math.MaxUint32,
			blockHeight:        f185GateHeight - 1,
		},
	}

	for _, testCase := range testCases {
		chainParams := *s.Chain.GetParams()
		chainParams.StrictMoneyRangeHeight = f185GateHeight
		chainParams.SchnorrStartHeight = testCase.schnorrStartHeight

		txn := s.f185WithdrawTx(testCase.payloadVersion,
			&payload.WithdrawFromSideChain{})
		txn.SetParameters(&TransactionParameters{
			Transaction: txn,
			BlockHeight: testCase.blockHeight,
			Config:      &chainParams,
			BlockChain:  s.Chain,
		})

		err := txn.HeightVersionCheck()
		if testCase.wantErrContains == "" {
			s.NoError(err, testCase.name)
			continue
		}
		s.Require().Error(err, testCase.name)
		s.Contains(err.Error(), testCase.wantErrContains, testCase.name)
	}
}

// TestF185SchnorrAggregationInputsFailClosed proves the ungated crash-harden of
// the group-key accumulator inputs.
//
// Fail-on-pristine: without the fix the first case panics on arbiters[0xff]
// (index out of range) and the second panics inside Curve.Add, because
// crypto.Unmarshal returns (nil, nil) for a key it cannot decode. Both are
// recovered here and reported as "PANIC: ...", which does not match the expected
// error strings.
func (s *txValidatorSpecialTxTestSuite) TestF185SchnorrAggregationInputsFailClosed() {
	// Case 1: out-of-range signer index with the F-070 index guard inactive
	// (validateSignerIndexes == false, i.e. below CrossChainUTXORestrictionHeight
	// or wherever that height is left disabled).
	outOfRange := &payload.WithdrawFromSideChain{Signers: []uint8{0xff}}
	err := f185Recover(func() error {
		return checkSchnorrWithdrawFromSidechain(
			s.f185WithdrawTx(payload.WithdrawFromSideChainVersionV2, outOfRange),
			outOfRange, false)
	})
	s.Require().Error(err)
	s.EqualError(err, "schnorr withdraw signer index out of range")

	// Case 2: an arbiter NodePublicKey that cannot be unmarshalled to a curve
	// point must be refused instead of feeding a nil point into Curve.Add.
	originalArbitrators := s.arbitrators.CurrentArbitrators
	defer func() {
		s.arbitrators.CurrentArbitrators = originalArbitrators
	}()
	malformedArbiter, newErr := state.NewOriginArbiter(make([]byte, 32))
	s.Require().NoError(newErr)
	s.arbitrators.CurrentArbitrators = []state.ArbiterMember{malformedArbiter}

	malformed := &payload.WithdrawFromSideChain{Signers: []uint8{0}}
	err = f185Recover(func() error {
		return checkSchnorrWithdrawFromSidechain(
			s.f185WithdrawTx(payload.WithdrawFromSideChainVersionV2, malformed),
			malformed, true)
	})
	s.Require().Error(err)
	s.EqualError(err, "invalid schnorr withdraw arbiter public key length")
}
