// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package unit

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"

	"github.com/stretchr/testify/assert"
)

// TestF049UnknownStandardDepositFailsClosedAtGate proves F-049 (Class A auth gap): a
// Standard/Deposit-prefixed program whose Code hashes to the address (ownerHash==codeHash)
// but is neither Schnorr, Standard, nor MultiSig previously fell through RunPrograms with
// NO signature check -- an anyone-can-spend of any UTXO parked at such an address. The
// gated fix fails it closed at/above StrictMoneyRangeHeight while leaving pre-gate history
// byte-identical (retained blocks below the rollback are unchanged).
//
// Fail-on-pristine: neutralize the `else if blockHeight >= strictMoneyHeight` guard in
// blockchain/validation.go and the at/above assertion below flips to NoError (the latent
// accept), so this test genuinely depends on the fix.
func TestF049UnknownStandardDepositFailsClosedAtGate(t *testing.T) {
	// A code that is NOT a valid Standard(len 35)/Schnorr(len 35)/MultiSig(len>=37) script.
	code := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55}
	assert.False(t, contract.IsStandard(code), "precondition: not Standard")
	assert.False(t, contract.IsSchnorr(code), "precondition: not Schnorr")
	assert.False(t, contract.IsMultiSig(code), "precondition: not MultiSig")

	// ownerHash == codeHash by construction (ToProgramHash stores Hash160(code)).
	ph := common.ToProgramHash(byte(contract.PrefixStandard), code)
	hashes := []common.Uint168{*ph}
	programs := []*program.Program{{Code: code, Parameter: []byte{}}}
	data := []byte("f049-payload")

	const gate = uint32(100)

	// BELOW the gate: retained-history behavior -- accepted (the latent bug), byte-identical.
	errBelow := blockchain.RunPrograms(data, hashes, programs, gate-1, gate)
	assert.NoError(t, errBelow, "below gate must stay byte-identical to history (accepted)")

	// AT/ABOVE the gate: the fix fails it closed.
	errAbove := blockchain.RunPrograms(data, hashes, programs, gate, gate)
	assert.Error(t, errAbove, "at/above gate the unknown standard/deposit program must be rejected")
	if errAbove != nil {
		assert.Contains(t, errAbove.Error(), "unknown standard/deposit signature type")
	}
}

// TestF091CrossChainMLessThanOneRejectedAtGate proves F-091 (Class A auth gap):
// VerifyMultisigSignatures treats m<=0 as trivially satisfied, so an m<1 crosschain
// redeem script was anyone-can-spend on freeze-OFF paths (masked on mainnet only by the
// freeze/restriction admit-list). The gated fix rejects m<1||m>n at/above the gate,
// BEFORE ParseCrossChainScript; below the gate the guard is inert (history unchanged).
//
// Fail-on-pristine: neutralize the `if blockHeight >= strictMoneyHeight && (m<1||m>n)`
// guard in checkCrossChainSignatures and the at/above assertion loses the marker error.
func TestF091CrossChainMLessThanOneRejectedAtGate(t *testing.T) {
	// code[0]=0x50 -> m = 0x50 - PUSH1(0x51) + 1 = 0 (< 1). code[len-2]=0x51 -> n = 1.
	code := []byte{0x50, 0x00, 0x51, 0xae}
	assert.False(t, contract.IsSchnorr(code), "precondition: crosschain non-schnorr branch")

	ph := common.ToProgramHash(byte(contract.PrefixCrossChain), code)
	hashes := []common.Uint168{*ph}
	programs := []*program.Program{{Code: code, Parameter: []byte{}}}
	data := []byte("f091-payload")

	const gate = uint32(100)
	const marker = "invalid crosschain multisig m/n"

	// AT/ABOVE the gate: the new guard rejects m<1 before ParseCrossChainScript.
	errAbove := blockchain.RunPrograms(data, hashes, programs, gate, gate)
	assert.Error(t, errAbove, "at/above gate an m<1 crosschain script must be rejected")
	if errAbove != nil {
		assert.Contains(t, errAbove.Error(), marker,
			"at/above gate rejection must come from the F-091 m/n guard")
	}

	// BELOW the gate: guard inert -> the m/n marker must NOT be the outcome (history
	// byte-identical; any rejection here is the pre-existing parser, not the new guard).
	errBelow := blockchain.RunPrograms(data, hashes, programs, gate-1, gate)
	if errBelow != nil {
		assert.NotContains(t, errBelow.Error(), marker,
			"below gate the F-091 guard must be inert")
	}
}
