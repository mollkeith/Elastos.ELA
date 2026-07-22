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

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type ActivateProducerTransaction struct {
	BaseTransaction
}

func (t *ActivateProducerTransaction) CheckTransactionInput() error {
	chainParams := t.parameters.Config
	blockHeight := t.parameters.BlockHeight
	newActivateHeight := chainParams.DPoSConfiguration.NFTStartHeight

	if blockHeight <= newActivateHeight {
		if len(t.Inputs()) != 0 {
			return errors.New("no cost transactions must has no input")
		}
	}
	return nil
}

func (t *ActivateProducerTransaction) CheckTransactionOutput() error {
	chainParams := t.parameters.Config
	blockHeight := t.parameters.BlockHeight
	newActivateHeight := chainParams.DPoSConfiguration.NFTStartHeight

	if blockHeight <= newActivateHeight {
		if len(t.Outputs()) > math.MaxUint16 {
			return errors.New("output count should not be greater than 65535(MaxUint16)")
		}
		if len(t.Outputs()) != 0 {
			return errors.New("no cost transactions should have no output")
		}
	}
	return nil
}

func (t *ActivateProducerTransaction) CheckAttributeProgram() error {
	chainParams := t.parameters.Config
	blockHeight := t.parameters.BlockHeight
	newActivateHeight := chainParams.DPoSConfiguration.NFTStartHeight
	if blockHeight <= newActivateHeight {
		if len(t.Programs()) != 0 || len(t.Attributes()) != 0 {
			return errors.New("zero cost tx should have no attributes and programs")
		}
	}
	return nil
}

func (t *ActivateProducerTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.ActivateProducer:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *ActivateProducerTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *ActivateProducerTransaction) CheckTransactionFee(references map[*common2.Input]common2.Output) error {
	log.Debug("ActivateProducerTransaction checkTransactionFee begin")
	fee := getTransactionFee(t, references)
	if fee != 0 {
		log.Debug("checkTransactionFee end fee != 0")

		return fmt.Errorf("transaction fee should be 0")
	}
	// set Fee and FeePerKB if check has passed
	t.SetFee(fee)
	buf := new(bytes.Buffer)
	t.Serialize(buf)
	t.SetFeePerKB(0)
	log.Debug("ActivateProducerTransaction checkTransactionFee end")

	return nil
}

// checkActivateValueCreation closes F-166: ActivateProducer is a no-cost tx
// (CheckTransactionFee requires fee==0), but the CR-member path returns end=true
// which makes ContextCheck SKIP CheckTransactionFee -- the only outputs<=inputs
// guard. Combined with CheckTransactionOutput allowing outputs above NFTStartHeight,
// a CR member could mint value outputs from 0 inputs. Above StrictMoneyRangeHeight we
// re-apply the fee==0 invariant here so no ActivateProducer path can create (or
// destroy) value. Below the gate: legacy behavior preserved for replay-safety.
func (t *ActivateProducerTransaction) checkActivateValueCreation() elaerr.ELAError {
	if t.parameters.BlockHeight < t.parameters.Config.StrictMoneyRangeHeight {
		return nil
	}
	if fee := getTransactionFee(t, t.references); fee != 0 {
		return elaerr.Simple(elaerr.ErrTxBalance, errors.New(
			"ActivateProducer must not create or destroy value at or above StrictMoneyRangeHeight"))
	}
	return nil
}

func (t *ActivateProducerTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {
	if e := t.checkActivateValueCreation(); e != nil {
		return e, true
	}

	activateProducer, ok := t.Payload().(*payload.ActivateProducer)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}

	err := t.checkActivateProducerSignature(activateProducer)
	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	if t.parameters.BlockChain.GetCRCommittee().IsInElectionPeriod() {
		crMember := t.parameters.BlockChain.GetCRCommittee().GetMemberByNodePublicKey(activateProducer.NodePublicKey)
		if crMember != nil && (crMember.MemberState == crstate.MemberInactive ||
			crMember.MemberState == crstate.MemberIllegal) {
			if t.parameters.BlockHeight < t.parameters.Config.EnableActivateIllegalHeight &&
				crMember.MemberState == crstate.MemberIllegal {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New(
					"activate MemberIllegal CR is not allowed before EnableActivateIllegalHeight")), true
			}
			if t.parameters.BlockChain.GetCRCommittee().GetAvailableDepositAmount(crMember.Info.CID) < 0 {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("balance of CR is not enough ")), true
			}
			// F-021: the CR-member activation path returns end=true, which skips
			// CheckTransactionFee AND checkTransactionSignature. Above NFTStartHeight a
			// CR activate may carry Inputs(), so end=true lets it spend arbitrary UTXOs
			// with NO input-ownership proof (theft; F-166's fee==0 guard only prevents
			// net inflation, not equal-value theft). At/above the coordinated-upgrade
			// gate, fall through so the fee + input-signature checks run. Below the gate
			// keep end=true for replay-safety (the producer branch already gates end on
			// NFTStartHeight, but re-gating the CR branch there would change acceptance
			// for the historical 1405000..2260451 window -> gate at StrictMoneyRangeHeight).
			end := true
			if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
				end = false
			}
			return nil, end
		}
	}

	producer := t.parameters.BlockChain.GetState().GetProducer(activateProducer.NodePublicKey)
	if producer == nil || !bytes.Equal(producer.NodePublicKey(),
		activateProducer.NodePublicKey) {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("getting unknown producer")), true
	}

	if t.parameters.BlockHeight < t.parameters.Config.EnableActivateIllegalHeight {
		if producer.State() != state.Inactive {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not activate this producer")), true
		}
	} else {
		if t.parameters.BlockHeight < t.parameters.Config.CRConfiguration.ChangeCommitteeNewCRHeight {
			if producer.State() != state.Active &&
				producer.State() != state.Inactive &&
				producer.State() != state.Illegal {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not activate this producer")), true
			}
		} else {
			if producer.State() != state.Inactive &&
				producer.State() != state.Illegal {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can not activate this producer")), true
			}
		}

	}

	if t.parameters.BlockHeight > producer.ActivateRequestHeight() &&
		t.parameters.BlockHeight-producer.ActivateRequestHeight() <= state.ActivateDuration {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("can only activate once during inactive state")), true
	}

	depositAmount := common.Fixed64(0)
	if t.parameters.BlockHeight < t.parameters.Config.CRConfiguration.CRVotingStartHeight {
		programHash, err := state.GetOwnerKeyDepositProgramHash(producer.OwnerPublicKey())
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}

		utxos, err := t.parameters.BlockChain.GetDB().GetFFLDB().GetUTXO(programHash)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}

		for _, u := range utxos {
			depositAmount += u.Value
		}
	} else {
		depositAmount = producer.TotalAmount()
	}

	var minActivateAmount common.Fixed64
	if t.parameters.BlockHeight >= t.parameters.BlockChain.GetState().DPoSV2ActiveHeight {
		switch producer.Identity() {
		case state.DPoSV1:
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("not allow to activate producer 1.0")), true
		case state.DPoSV1V2, state.DPoSV2:
			minActivateAmount = crstate.MinDPoSV2DepositAmount
		}
	} else {
		switch producer.Identity() {
		case state.DPoSV1, state.DPoSV1V2:
			minActivateAmount = crstate.MinDepositAmount
		case state.DPoSV2:
			minActivateAmount = crstate.MinDPoSV2DepositAmount
		}
	}

	if depositAmount-producer.Penalty() < minActivateAmount {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("insufficient deposit amount")), true
	}

	chainParams := t.parameters.Config
	blockHeight := t.parameters.BlockHeight
	newActivateHeight := chainParams.DPoSConfiguration.NFTStartHeight
	end := false
	if blockHeight <= newActivateHeight {
		end = true
	}
	return nil, end
}

func (t *ActivateProducerTransaction) checkActivateProducerSignature(
	activateProducer *payload.ActivateProducer) error {

	// check signature
	publicKey, err := crypto.DecodePoint(activateProducer.NodePublicKey)
	if err != nil {
		return errors.New("invalid public key in payload")
	}
	signedBuf := new(bytes.Buffer)
	err = activateProducer.SerializeUnsigned(signedBuf, t.payloadVersion)
	if err != nil {
		return err
	}
	err = crypto.Verify(*publicKey, signedBuf.Bytes(), activateProducer.Signature)
	if err != nil {
		return errors.New("invalid signature in payload")
	}

	return nil
}
