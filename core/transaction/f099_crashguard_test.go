// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-099 crash-hardening, previously UNTESTED (commit 509d9ce).
package transaction

import (
	"testing"

	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// f099Tx builds an InactiveArbitrators transaction carrying a single short program code.
func f099Tx(code []byte) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09, common2.InactiveArbitrators, 0,
		&payload.InactiveArbitrators{},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*pg.Program{{Code: code, Parameter: []byte{}}})
}

// TestF099ArbiterMultisigShortCodeDoesNotPanic drives the REAL
// checkCRCArbitratorsSignatures with the codes that used to index out of range
// (code[len(code)-2] and code[0]). This function is reachable PRE-AUTH from the DPoS
// gossip path — no SanityCheck, so no CheckAttributeProgram length check runs first —
// so an unguarded index is a remote unauthenticated node halt.
//
// Fail-on-pristine: remove the `if len(code) < 2` guard and this test PANICS.
func TestF099ArbiterMultisigShortCodeDoesNotPanic(t *testing.T) {
	for _, code := range [][]byte{{}, {0x52}} {
		err := checkCRCArbitratorsSignatures(f099Tx(code), 1, 2260451)
		if err == nil {
			t.Fatalf("F-099: a %d-byte arbiter multisig code must be rejected", len(code))
		}
	}
}
