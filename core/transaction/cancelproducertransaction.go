// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type CancelProducerTransaction struct {
	BaseTransaction
}

func (t *CancelProducerTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.ProcessProducer:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *CancelProducerTransaction) IsAllowedInPOWConsensus() bool {
	return false
}

func (t *CancelProducerTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if blockHeight < chainParams.SupportMultiCodeHeight {
		if t.PayloadVersion() == payload.ProcessMultiCodeVersion {
			return errors.New(fmt.Sprintf("not support %s transaction "+
				"with payload version %d before SupportMultiCodeHeight",
				t.TxType().Name(), t.PayloadVersion()))
		}
	}
	// Reject unknown CancelProducer payload versions at/above the coordinated-upgrade
	// gate. checkProcessProducer only authenticates v0/v1/v2; a v>=3 payload falls
	// through the version dispatch with no owner proof and cancels an arbitrary
	// producer, permissionlessly and on a live chain. Below the gate is left
	// byte-identical for replay-safety (mirrors RegisterProducer's default-deny).
	if blockHeight >= chainParams.StrictMoneyRangeHeight &&
		t.PayloadVersion() > payload.ProcessMultiCodeVersion {
		return errors.New(fmt.Sprintf("unsupported %s transaction payload version %d",
			t.TxType().Name(), t.PayloadVersion()))
	}
	// RegisterProducer gates the Schnorr producer version on ProducerSchnorrStartHeight
	// (dormant on mainnet, MaxUint32), but CancelProducer enforces no such gate of its
	// own: the Schnorr process-producer version reaches checkProcessProducer bounded
	// only by the general NormalSchnorrStartHeight (1405000), which leaks the dormant
	// Schnorr cancel path in via the cancel route. Mirror the register gate, activated
	// only at/above StrictMoneyRangeHeight so retained below-gate history replays
	// byte-identically. Reuses gate 1; no third gate.
	if blockHeight >= chainParams.StrictMoneyRangeHeight &&
		t.PayloadVersion() == payload.ProcessProducerSchnorrVersion &&
		blockHeight < chainParams.ProducerSchnorrStartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before ProducerSchnorrStartHeight", t.TxType().Name()))
	}
	return nil
}

func (t *CancelProducerTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {
	producer, err := t.checkProcessProducer(t.parameters, t)
	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	height := t.parameters.BlockHeight
	switch producer.Identity() {
	case state.DPoSV1:
	case state.DPoSV2:
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not cancel DPoS V2 producer")), true
	case state.DPoSV1V2:
		if height <= producer.Info().StakeUntil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not cancel DPoS V1&V2 producer")), true
		}
	}

	if producer.State() == state.Illegal ||
		producer.State() == state.Canceled {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not cancel this producer")), true
	}

	return nil, false
}

func (t *CancelProducerTransaction) checkProcessProducer(params *TransactionParameters, txn interfaces.Transaction) (*state.Producer, error) {
	processProducer, ok := txn.Payload().(*payload.ProcessProducer)
	if !ok {
		return nil, errors.New("invalid payload")
	}

	// check signature
	if t.PayloadVersion() == payload.ProcessProducerVersion {
		publicKey, err := crypto.DecodePoint(processProducer.OwnerKey)
		if err != nil {
			return nil, errors.New("invalid public key in payload")
		}
		signedBuf := new(bytes.Buffer)
		err = processProducer.SerializeUnsigned(signedBuf, t.PayloadVersion())
		if err != nil {
			return nil, err
		}
		err = crypto.Verify(*publicKey, signedBuf.Bytes(), processProducer.Signature)
		if err != nil {
			return nil, errors.New("invalid signature in payload")
		}
	} else if t.PayloadVersion() == payload.ProcessProducerSchnorrVersion {
		if !contract.IsSchnorr(t.Programs()[0].Code) {
			return nil, errors.New("only schnorr code can use ProcessProducerSchnorrVersion")
		}
		pk := t.Programs()[0].Code[2:]
		if !bytes.Equal(pk, processProducer.OwnerKey) {
			return nil, errors.New("tx program pk must equal with processProducer OwnerKey ")
		}
	} else if t.PayloadVersion() == payload.ProcessMultiCodeVersion {
		if !contract.IsMultiSig(t.Programs()[0].Code) {
			return nil, elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("only multi sign code can use ProcessMultiCodeVersion"))
		}
		// Bind the multisig program code to the payload OwnerKey (mirror
		// RegisterProducer :187 / UpdateProducer :142). Without this, a caller pays
		// the fee with their own unrelated multisig program yet sets OwnerKey to a
		// victim, cancelling any eligible producer without the victim's key. Gated at
		// the coordinated-upgrade height for replay-safety; the branch is itself gated
		// by SupportMultiCodeHeight (MaxUint32 on mainnet, so dead until flipped, at
		// which point this bind is active because StrictMoneyRangeHeight is far below).
		if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight &&
			!bytes.Equal(t.Programs()[0].Code, processProducer.OwnerKey) {
			return nil, errors.New("ProcessMultiCodeVersion program code must equal OwnerKey")
		}
	}

	producer := t.parameters.BlockChain.GetState().GetProducer(processProducer.OwnerKey)
	if producer == nil || !bytes.Equal(producer.OwnerPublicKey(),
		processProducer.OwnerKey) {
		return nil, errors.New("getting unknown producer")
	}
	return producer, nil
}
