// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// The SECOND copy of the arbiter-signature crash guard — the one nothing tested.
//
// THE EVIDENCE GAP THIS CLOSES. blockchain/txvalidator.go carries the F-099-sibling bounds
// guard TWICE, in two near-identical functions:
//
//	checkArbitratorsSignatures   (:983/:987)  reached via CheckRevertToDPOSTransaction
//	checkCRCArbitratorsSignatures(:1063/:1067) reached via CheckInactiveArbitrators
//
// h_crashguard_test.go covers the first. A mutation battery neutered both: the first copy
// was killed, the second SURVIVED the entire shipping gate. The second copy is live —
// blockchain/confirmvalidator.go calls CheckInactiveArbitrators on the confirm leg, and the
// comment on the guard itself records that this path has NO SanityCheck and NO
// CheckAttributeProgram in front of it. Neutered, an InactiveArbitrators special
// transaction with an empty Programs() or a one-byte Code panics the receiving CRC arbiter
// on Programs()[0] / code[len(code)-2].
//
// FAIL-ON-PRISTINE (measured): neuter either guard at :1063 or :1067 and the matching case
// below panics instead of returning an error.
//
// Ungated crash-hardening, exactly like the copy it mirrors: such a program never validly
// existed, so retained history is unchanged. No height literal is introduced — 2260451 is
// the same constant h_crashguard_test.go already uses.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	program "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

// TestHInactiveArbitratorsSignatureCrashGuard is the fail-on-pristine test for the second
// copy of the guard.
func TestHInactiveArbitratorsSignatureCrashGuard(t *testing.T) {
	// The sponsor must be a CRC arbiter, otherwise CheckInactiveArbitrators returns before
	// the signature check and the guard under test is never reached.
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	sponsor, err := pub.EncodePoint(true)
	assert.NoError(t, err)
	arb, err := state.NewOriginArbiter(sponsor)
	assert.NoError(t, err)

	orig := blockchain.DefaultLedger
	blockchain.DefaultLedger = &blockchain.Ledger{Arbitrators: &state.ArbitratorsMock{
		CRCArbitrators: []state.ArbiterMember{arb},
	}}
	t.Cleanup(func() { blockchain.DefaultLedger = orig })

	mk := func(programs []*program.Program) interfaces.Transaction {
		return functions.CreateTransaction(
			common2.TxVersion09, common2.InactiveArbitrators, 0,
			&payload.InactiveArbitrators{Sponsor: sponsor},
			[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0, programs)
	}

	// PRECONDITION: the sponsor really does pass the membership check, so a rejection
	// below is attributable to the bounds guard and not to an earlier check.
	assert.True(t, blockchain.DefaultLedger.Arbitrators.IsCRCArbitrator(sponsor),
		"test vector broken: the sponsor must be a CRC arbiter")

	// (a) empty Programs -> pristine panics on Programs()[0].
	assert.NotPanics(t, func() {
		err := blockchain.CheckInactiveArbitrators(mk([]*program.Program{}), 2260451)
		assert.Error(t, err, "empty-program InactiveArbitrators must be rejected, not panic")
	}, "REMOTE NODE KILL: an empty-program InactiveArbitrators panicked the confirm leg")

	// (b) 1-byte code -> pristine panics on code[len(code)-2].
	assert.NotPanics(t, func() {
		err := blockchain.CheckInactiveArbitrators(
			mk([]*program.Program{{Code: []byte{0x01}}}), 2260451)
		assert.Error(t, err, "short-code InactiveArbitrators must be rejected, not panic")
	}, "REMOTE NODE KILL: a short-code InactiveArbitrators panicked the confirm leg")
}
