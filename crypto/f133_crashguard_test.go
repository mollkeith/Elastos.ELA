// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-133 crash-hardening, previously UNTESTED.
//
// Commit 509d9ce shipped six halt-DoS crash guards with NO test at all. Each one is
// reachable PRE-AUTHENTICATION (P2P gossip or a parent AuxPoW), so an un-guarded index
// is a remote, unauthenticated node halt. This file covers the crypto one.
package crypto

import (
	"testing"

	"github.com/elastos/Elastos.ELA/core/contract/program"
)

// TestF133CheckMultiSigSignaturesShortCodeDoesNotPanic drives the REAL
// CheckMultiSigSignatures with the codes that used to index out of range:
// code[len(code)-2] and code[0]. Reachable pre-auth via the DPoS gossip handler
// (CheckInactiveArbitrators / CheckRevertToDPOSTransaction), which runs no SanityCheck
// and therefore no CheckAttributeProgram length check.
//
// Fail-on-pristine: remove the `if len(code) < 2` guard and this test PANICS
// (index out of range), which is a test failure.
func TestF133CheckMultiSigSignaturesShortCodeDoesNotPanic(t *testing.T) {
	for _, code := range [][]byte{nil, {}, {0x52}} {
		err := CheckMultiSigSignatures(program.Program{Code: code, Parameter: []byte{}},
			[]byte("f133"))
		if err == nil {
			t.Fatalf("F-133: a %d-byte multisig code must be rejected, not accepted", len(code))
		}
	}
}

// TestF133CheckMultiSigSignaturesLongCodesUnchanged is the no-regression control: the
// guard must not alter the error path for any code of length >= 2, which is where the
// semantic ParseMultisigScript checks live.
func TestF133CheckMultiSigSignaturesLongCodesUnchanged(t *testing.T) {
	// 2 bytes: passes the crash guard, still rejected downstream on format.
	if err := CheckMultiSigSignatures(program.Program{Code: []byte{0x52, 0xAE},
		Parameter: []byte{}}, []byte("f133")); err == nil {
		t.Fatal("a 2-byte code must still be rejected by the semantic checks")
	}
}
