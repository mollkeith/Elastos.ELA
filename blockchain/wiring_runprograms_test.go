// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TEST — F-049 / F-091 block-height threading into RunPrograms.
//
// The blocker: the F-049/F-091 default-deny gate is INERT unless the real block height
// reaches RunPrograms, and nothing tested that threading. Mutation at HEAD passed a
// literal 0 as blockHeight from BOTH callers — the gate is then never active — and the
// entire suite stayed green, including test/unit/f049_f091_gate_test.go, because that
// test calls RunPrograms directly with a height it chooses itself.
//
// This test drives the REAL blockchain.checkTransactionSignature (the production function
// that owns the call) and asserts the decision moves with the height it is GIVEN: a
// Standard-prefixed program with an unknown code type is accepted below the gate
// (byte-identical replay) and rejected at/above it. If the call site substitutes a
// constant for blockHeight, one of the two directions breaks.
package blockchain

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// unknownStandardCode is Standard-prefixed by construction but is neither a Standard,
// Schnorr, nor MultiSig script — the exact F-049 shape that used to fall through
// RunPrograms with no signature check at all.
var unknownStandardCode = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55}

// f049Tx builds a transfer whose single input is parked at the unknown-standard address.
func f049Tx(t *testing.T) (interfaces.Transaction, map[*common2.Input]common2.Output) {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	if contract.IsStandard(unknownStandardCode) || contract.IsSchnorr(unknownStandardCode) ||
		contract.IsMultiSig(unknownStandardCode) {
		t.Fatal("precondition: the code must be none of Standard/Schnorr/MultiSig")
	}
	ph := common.ToProgramHash(byte(contract.PrefixStandard), unknownStandardCode)

	in := &common2.Input{Previous: common2.OutPoint{TxID: common.Uint256{0x5A}, Index: 0}}
	tx := functions.CreateTransaction(
		common2.TxVersion09, common2.TransferAsset, 0, &payload.TransferAsset{},
		[]*common2.Attribute{}, []*common2.Input{in},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: 1, ProgramHash: *ph,
			Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}}},
		0, []*program.Program{{Code: unknownStandardCode, Parameter: []byte{}}})

	refs := map[*common2.Input]common2.Output{in: {AssetID: core.ELAAssetID, Value: 2, ProgramHash: *ph}}
	return tx, refs
}

// TestWiringRunProgramsReceivesTheBlockHeight is the F-049/F-091 threading proof.
//
// MUTATION PROOF: change the RunPrograms call in checkTransactionSignature to pass a
// literal 0 (or any constant) instead of blockHeight -> the at/above-gate case is no
// longer rejected -> this test FAILS. test/unit/f049_f091_gate_test.go passes under that
// mutation, which is exactly the gap this closes.
func TestWiringRunProgramsReceivesTheBlockHeight(t *testing.T) {
	tx, refs := f049Tx(t)
	const gate = uint32(2260451)

	// BELOW the gate: retained-history behaviour — accepted.
	if err := checkTransactionSignature(tx, refs, gate-1, gate); err != nil {
		t.Fatalf("REPLAY BREAK: below the gate the unknown standard program must still be "+
			"accepted (byte-identical history), got: %v", err)
	}

	// AT/ABOVE the gate: the default-deny gate must fire — which it can only do if the
	// block height actually reached RunPrograms.
	for _, h := range []uint32{gate, gate + 1_000_000} {
		err := checkTransactionSignature(tx, refs, h, gate)
		if err == nil {
			t.Fatalf("WIRING SEVERED at height %d: checkTransactionSignature accepted an "+
				"unknown standard/deposit program — the block height is not threaded into "+
				"RunPrograms, so the F-049/F-091 default-deny gate is inert "+
				"(anyone-can-spend of any UTXO parked at such an address)", h)
		}
		if !strings.Contains(err.Error(), "unknown standard/deposit signature type") {
			t.Fatalf("WIRING SEVERED at height %d: rejected for the wrong reason: %v", h, err)
		}
	}
}

// TestWiringRunProgramsReceivesTheStrictMoneyHeight pins the OTHER argument: the gate
// itself must be the campaign gate the caller supplies, not a constant. Moving the gate
// moves the decision boundary.
func TestWiringRunProgramsReceivesTheStrictMoneyHeight(t *testing.T) {
	tx, refs := f049Tx(t)
	const moved = uint32(777_777)

	if err := checkTransactionSignature(tx, refs, moved-1, moved); err != nil {
		t.Fatalf("below the moved gate the program must be accepted, got: %v", err)
	}
	if err := checkTransactionSignature(tx, refs, moved, moved); err == nil {
		t.Fatal("at the moved gate the program must be rejected: the strict-money height is " +
			"not threaded into RunPrograms")
	}
}
