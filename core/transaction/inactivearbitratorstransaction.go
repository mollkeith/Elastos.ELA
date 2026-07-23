// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/elastos/Elastos.ELA/blockchain"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type InactiveArbitratorsTransaction struct {
	BaseTransaction
}

func (t *InactiveArbitratorsTransaction) CheckTransactionInput() error {
	if len(t.Inputs()) != 0 {
		return errors.New("no cost transactions must has no input")
	}
	return nil
}

func (t *InactiveArbitratorsTransaction) CheckTransactionOutput() error {

	if len(t.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}
	if len(t.Outputs()) != 0 {
		return errors.New("no cost transactions should have no output")
	}

	return nil
}

func (t *InactiveArbitratorsTransaction) CheckAttributeProgram() error {

	// check programs count and attributes count
	if len(t.Programs()) != 1 {
		return errors.New("inactive arbitrators transactions should have one and only one program")
	}
	if len(t.Attributes()) != 1 {
		return errors.New("inactive arbitrators transactions should have one and only one arbitrator")
	}

	// Check attributes
	for _, attr := range t.Attributes() {
		if !common2.IsValidAttributeType(attr.Usage) {
			return fmt.Errorf("invalid attribute usage %v", attr.Usage)
		}
	}

	// Check programs
	if len(t.Programs()) == 0 {
		return fmt.Errorf("no programs found in transaction")
	}
	for _, program := range t.Programs() {
		if program.Code == nil {
			return fmt.Errorf("invalid program code nil")
		}
		if program.Parameter == nil {
			return fmt.Errorf("invalid program parameter nil")
		}
	}

	return nil
}

func (t *InactiveArbitratorsTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.InactiveArbitrators:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *InactiveArbitratorsTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *InactiveArbitratorsTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {

	if t.parameters.BlockChain.GetState().SpecialTxExists(t) {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("tx already exists")), true
	}

	if err := CheckInactiveArbitrators(t, t.parameters.BlockHeight,
		t.parameters.Config.StrictMoneyRangeHeight); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	return nil, true
}

func CheckInactiveArbitrators(t interfaces.Transaction, blockHeight, gate uint32) error {
	p, ok := t.Payload().(*payload.InactiveArbitrators)
	if !ok {
		return errors.New("invalid payload")
	}

	if !blockchain.DefaultLedger.Arbitrators.IsCRCArbitrator(p.Sponsor) {
		return errors.New("sponsor is not belong to arbitrators")
	}

	for _, v := range p.Arbitrators {
		if !blockchain.DefaultLedger.Arbitrators.IsActiveProducer(v) &&
			!blockchain.DefaultLedger.Arbitrators.IsDisabledProducer(v) {
			return errors.New("inactive arbitrator is not belong to " +
				"arbitrators")
		}
		if blockchain.DefaultLedger.Arbitrators.IsCRCArbitrator(v) {
			return errors.New("inactive arbiters should not include CRC")
		}
	}

	if err := checkCRCArbitratorsSignatures(t, blockHeight, gate); err != nil {
		return err
	}

	return nil
}

func checkCRCArbitratorsSignatures(t interfaces.Transaction, blockHeight, gate uint32) error {

	code := t.Programs()[0].Code
	// F-099: guard before indexing code[0]/code[len-2] so a <2-byte code cannot panic;
	// the semantic checks (ParseMultisigScript etc.) stay downstream with their existing
	// error paths for all len>=2 codes. Crash-harden only.
	if len(code) < 2 {
		return errors.New("invalid arbiter multisig code, length not enough")
	}
	// Get N parameter
	// todo check
	n := int(code[len(code)-2]) - crypto.PUSH1 + 1
	// Get M parameter
	m := int(code[0]) - crypto.PUSH1 + 1

	crcArbitratorsCount := blockchain.DefaultLedger.Arbitrators.GetCRCArbitersCount()
	minSignCount := int(float64(crcArbitratorsCount)*
		state.MajoritySignRatioNumerator/state.MajoritySignRatioDenominator) + 1
	if m < 1 || m > n || n != crcArbitratorsCount || m < minSignCount {
		fmt.Printf("m:%d n:%d minSignCount:%d crc:  %d", m, n, minSignCount, crcArbitratorsCount)
		return errors.New("invalid multi sign script code")
	}
	publicKeys, err := crypto.ParseMultisigScript(code)
	if err != nil {
		return err
	}

	for _, pk := range publicKeys {
		if !blockchain.DefaultLedger.Arbitrators.IsCRCArbitrator(pk[1:]) {
			return errors.New("invalid multi sign public key")
		}
	}
	return verifyArbitratorsMultisigSignatures(t, blockHeight, gate)
}

// verifyArbitratorsMultisigSignatures verifies that the program Parameter
// actually carries valid M-of-N arbiter signatures over the tx's unsigned
// digest. F-022: the structure/pubkey checks above only prove the CODE lists
// authorized arbiters; without this an unsigned special tx (empty or garbage
// Parameter, all-public inputs) would be accepted permissionlessly and could
// trigger an emergency ForceChange / RevertToDPOS. Height-gated at
// StrictMoneyRangeHeight for replay-safety of pre-gate history; the digest is
// exactly what the honest CRC signer path signs over (tx.SerializeUnsigned).
func verifyArbitratorsMultisigSignatures(t interfaces.Transaction, blockHeight, gate uint32) error {
	if blockHeight < gate {
		return nil
	}
	buf := new(bytes.Buffer)
	if err := t.SerializeUnsigned(buf); err != nil {
		return err
	}
	return crypto.CheckMultiSigSignatures(*t.Programs()[0], buf.Bytes())
}
