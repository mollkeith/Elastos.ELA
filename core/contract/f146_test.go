// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package contract

import (
	"testing"

	"github.com/elastos/Elastos.ELA/crypto"
)

// TestF146CreateMultiSigRedeemScriptRejectsInvalidThreshold is the
// fail-on-pristine test for F-146. CreateMultiSigRedeemScript returned
// (nil, nil) for an out-of-range m/n, so callers saw success and a nil script.
//
// The reachable caller is ProposalDispatcher.createArbitratorsRedeemScript: it
// computes the required signature count from the configured CRC arbiter count
// but only collects the arbiters that are currently IsNormal, so m can exceed
// len(pubkeys) whenever enough CRC arbiters are abnormal.
func TestF146CreateMultiSigRedeemScriptRejectsInvalidThreshold(t *testing.T) {
	// Two usable signers, but nine signatures required - the shape produced by
	// a 12-member CRC council with only two normal arbiters left.
	pubkeys := []*crypto.PublicKey{{}, {}}

	code, err := CreateMultiSigRedeemScript(9, pubkeys)
	if err == nil {
		t.Fatalf("F-146: m=9 over %d public keys returned no error "+
			"(code=%v); callers cannot tell this failed",
			len(pubkeys), code)
	}
	if code != nil {
		t.Fatal("a failed redeem script build must not return a script")
	}
}

// TestF146CreateMultiSigContractNeverReturnsNilCode is the second
// fail-on-pristine assertion: CreateMultiSigContract used to hand back a
// Contract whose Code was nil together with a nil error, and the DPoS caller
// then built an InactiveArbitrators transaction around that nil code.
func TestF146CreateMultiSigContractNeverReturnsNilCode(t *testing.T) {
	pubkeys := []*crypto.PublicKey{{}, {}}

	con, err := CreateMultiSigContract(9, pubkeys)
	if err == nil {
		t.Fatalf("F-146: CreateMultiSigContract reported success for an "+
			"invalid threshold, returning %+v", con)
	}
	if con != nil && con.Code == nil {
		t.Fatal("F-146: returned a Contract with a nil Code")
	}
}

// TestF146AllInvalidInputsRejected pins that the two pre-existing error paths
// (empty key set, nil key) still reject, and adds the third F-146 case: m below
// 1, which also fell into the (nil, nil) branch before the fix.
func TestF146AllInvalidInputsRejected(t *testing.T) {
	if _, err := CreateMultiSigRedeemScript(1, nil); err == nil {
		t.Fatal("empty public key set must still be rejected")
	}
	if _, err := CreateMultiSigRedeemScript(1,
		[]*crypto.PublicKey{nil}); err == nil {
		t.Fatal("nil public key must still be rejected")
	}
	if _, err := CreateMultiSigRedeemScript(0,
		[]*crypto.PublicKey{{}, {}}); err == nil {
		t.Fatal("m below 1 must be rejected")
	}
}
