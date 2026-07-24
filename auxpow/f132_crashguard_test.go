// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-132 crash-hardening, previously UNTESTED (commit 509d9ce).
package auxpow

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// TestF132CheckZeroInputParentCoinbaseDoesNotPanic drives the REAL AuxPow.Check with a
// parent coinbase that has NO inputs. BtcTx.Deserialize enforces no minimum, so this is
// exactly what an attacker can put on the wire — and Check indexed ParCoinbaseTx.TxIn[0]
// unconditionally, panicking the receiving node BEFORE any proof-of-work is verified.
//
// Fail-on-pristine: remove the `if len(ap.ParCoinbaseTx.TxIn) == 0` guard and this test
// PANICS (index out of range).
func TestF132CheckZeroInputParentCoinbaseDoesNotPanic(t *testing.T) {
	auxBlockHash := common.Uint256{0x11, 0x22, 0x33}
	ap := GenerateAuxPow(auxBlockHash)

	// Strip the parent coinbase inputs but keep the merkle commitment consistent, so the
	// zero-input coinbase is what Check reaches rather than an earlier mismatch.
	ap.ParCoinbaseTx.TxIn = nil
	ap.ParBlockHeader.MerkleRoot = ap.ParCoinbaseTx.Hash()

	if ap.Check(&auxBlockHash, AuxPowChainID) {
		t.Fatal("F-132: a parent coinbase with zero inputs must be rejected, not accepted")
	}
}
