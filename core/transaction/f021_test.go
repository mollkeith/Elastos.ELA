// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
)

// TestF021ActivateInputSignatureEnforced proves the security mechanism the F-021 fix
// gates in. The fix makes the CR-member ActivateProducer path return end=false at/above
// the gate, so the tx runs checkTransactionSignature (RunPrograms) over its inputs —
// exactly the check the pre-fix end=true return skipped. This test drives the REAL
// checkTransactionSignature + CheckTransactionFee:
//   - THEFT-CATCH: an activate spending a victim UTXO with a non-matching (attacker)
//     program is rejected — so once end=false runs the check, the unauthorized spend
//     that F-021 enabled is caught.
//   - NO-BREAK: a legitimate no-cost (zero-input) activate still passes both checks, so
//     making end=false above the gate rejects nothing legitimate.
// The end-flip itself mirrors the adjacent, production-tested producer-branch gate
// (end = blockHeight <= NFTStartHeight); see f021 fix comment in
// activateproducertransaction.go.
func TestF021ActivateInputSignatureEnforced(t *testing.T) {
	// Victim UTXO owner hash; attacker program hashes to a different value.
	_, victimPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	victimCode, _ := contract.CreateStandardRedeemScript(victimPub)
	victimHash := common.ToProgramHash(byte(contract.PrefixStandard), victimCode)
	_, attackerPub, _ := crypto.GenerateKeyPair()
	attackerCode, _ := contract.CreateStandardRedeemScript(attackerPub)

	input := &common2.Input{Previous: common2.OutPoint{Index: 0}, Sequence: 0}
	victimOut := common2.Output{
		AssetID: core.ELAAssetID, Value: common.Fixed64(100), Type: common2.OTNone,
		ProgramHash: *victimHash, Payload: &outputpayload.DefaultOutput{},
	}
	refs := map[*common2.Input]common2.Output{input: victimOut}

	// THEFT-CATCH: spending an unowned UTXO with a non-matching program -> rejected.
	theft := functions.CreateTransaction(
		common2.TxVersion09, common2.ActivateProducer, 0,
		&payload.ActivateProducer{}, []*common2.Attribute{},
		[]*common2.Input{input},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: common.Fixed64(100),
			Type: common2.OTNone, ProgramHash: common.Uint168{}, Payload: &outputpayload.DefaultOutput{}}},
		0, []*program.Program{{Code: attackerCode}})
	if err := checkTransactionSignature(theft, refs); err == nil {
		t.Fatal("F-021: activate spending an unowned UTXO with a non-matching program must be REJECTED by checkTransactionSignature")
	}

	// NO-BREAK: a zero-input activation passes both checks (legit unaffected by end=false).
	legit := functions.CreateTransaction(
		common2.TxVersion09, common2.ActivateProducer, 0,
		&payload.ActivateProducer{}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0, []*program.Program{})
	legit.SetParameters(&TransactionParameters{Transaction: legit, BlockHeight: b3Gate, Config: b3MinCfg()})
	emptyRefs := map[*common2.Input]common2.Output{}
	if err := checkTransactionSignature(legit, emptyRefs); err != nil {
		t.Fatalf("F-021: legit zero-input activate must pass checkTransactionSignature, got %v", err)
	}
	if err := legit.CheckTransactionFee(emptyRefs); err != nil {
		t.Fatalf("F-021: legit zero-input activate must pass CheckTransactionFee, got %v", err)
	}
}
