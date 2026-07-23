// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/elastos/Elastos.ELA/core/contract"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
	"github.com/elastos/Elastos.ELA/vm"
)

type UpdateProducerTransaction struct {
	BaseTransaction
}

func (t *UpdateProducerTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if blockHeight < chainParams.DPoSV2StartHeight {
		producerPayload, ok := t.Payload().(*payload.ProducerInfo)
		if !ok {
			return errors.New("[HeightVersionCheck] invalid UpdateProducer  payload")
		}
		if producerPayload.StakeUntil != 0 {
			return errors.New("not support update DPoS " +
				"2.0 producer transaction before RevertToPOWStartHeight")
		}
	}
	if blockHeight < chainParams.SupportMultiCodeHeight {
		if t.PayloadVersion() == payload.ProducerInfoMultiVersion {
			return errors.New(fmt.Sprintf("not support %s transaction "+
				"with payload version %d before SupportMultiCodeHeight",
				t.TxType().Name(), t.PayloadVersion()))
		}
	}
	// F-069: reject unknown UpdateProducer payload versions at/above the
	// coordinated-upgrade gate. SpecialContextCheck only authenticates versions up to
	// ProducerInfoMultiVersion (0x03); a v>=4 payload falls through with NO owner
	// proof and then overwrites the producer info (nickname / NodePublicKey re-key =
	// identity takeover; LIVE, permissionless). Below the gate is left byte-identical
	// for replay-safety (mirrors RegisterProducer's default-deny).
	if blockHeight >= chainParams.StrictMoneyRangeHeight &&
		t.PayloadVersion() > payload.ProducerInfoMultiVersion {
		return errors.New(fmt.Sprintf("unsupported %s transaction payload version %d",
			t.TxType().Name(), t.PayloadVersion()))
	}
	return nil
}

func (t *UpdateProducerTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.ProducerInfo:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *UpdateProducerTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func checkChangeStakeUntil(BlockHeight uint32, newinfo *payload.ProducerInfo, producer *state.Producer) *elaerr.SimpleErr {
	switch producer.State() {
	case state.Active, state.Inactive, state.Illegal:
		if newinfo.StakeUntil < producer.Info().StakeUntil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("stake time is smaller than before"))
		} else if newinfo.StakeUntil > producer.Info().StakeUntil {
			//new StakeUntil must bigger than BlockHeight
			if BlockHeight >= newinfo.StakeUntil {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("producer StakeUntil less than BlockHeight"))
			}
		}
	default:
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("Pending Canceled or Returned producer can  not update  StakeUntil "))

	}
	return nil
}

func (t *UpdateProducerTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {
	info, ok := t.Payload().(*payload.ProducerInfo)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}
	multiSignOwner := false
	if t.PayloadVersion() == payload.ProducerInfoMultiVersion {
		multiSignOwner = true
	}
	if multiSignOwner && len(info.OwnerKey) == crypto.NegativeBigLength {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("ProducerInfoMultiVersion match multi code")), true
	}
	// check nick name
	if err := checkStringField(info.NickName, "NickName", false); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	// check url
	if err := checkStringField(info.Url, "Url", true); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	if err := t.additionalProducerInfoCheck(info); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	// NOTE (F-205, VERIFIED REAL but DEFERRED -- and do NOT "fix" it by binding the
	// transaction to OwnerKey: that rule was MEASURED against the real chain and it
	// breaks consensus). info.Signature below is verified over
	// info.SerializeUnsigned(payloadVersion) ALONE -- no network magic, no genesis
	// hash, no nonce, no binding to the carrying transaction. It is therefore a
	// context-free BEARER CREDENTIAL with an unbounded lifetime.
	//
	// PROVEN (core/transaction/f205_test.go drives the production validator AND the
	// production DPoS state machine; 10/10 runs, and it fails when the expectation is
	// inverted): any third party can lift a previously published (payload, signature)
	// pair out of chain history, wrap it in a new transaction funded and signed by an
	// unrelated key, and roll the producer's record -- NodePublicKey / NickName / Url
	// / Location / NetAddress -- back to that stale state without the owner's
	// consent. Reverting NodePublicKey de-registers the key the producer is actually
	// signing DPoS messages with (State.updateProducerInfo deletes the old
	// NodeOwnerKeys entry), so this is a cheap, repeatable liveness attack against
	// any producer that has ever updated. The same shape applies to every payload
	// signature of this family (UpdateCR, CancelProducer, ActivateProducer, ...).
	//
	// REFUTED, same finding: the "cross-network replay" headline does NOT reach
	// input-spending transactions -- a transaction signature covers the inputs'
	// outpoints and the mainnet/testnet UTXO sets are disjoint. And replayability of
	// honest pre-fork transactions across the v0.9.9.7 recovery fork is INHERENT AND
	// INTENDED in a rollback; the malicious ones are exactly what the
	// StrictMoneyRangeHeight acceptance change already rejects.
	//
	// WHY NO FIX SHIPS HERE. Three candidate consensus rules, all measured against
	// the full 2,260,597-block mainnet history:
	//   R. require a program bound to OwnerKey (what the ProducerInfoSchnorrVersion
	//      and ProducerInfoMultiVersion branches below already do): would reject 720
	//      of 961 real UpdateProducer, 254/259 RegisterProducer, 33/117
	//      CancelProducer and all 902 ActivateProducer (0-input, 0-program).
	//      Third-party carriage of the credential is the DOMINANT real-world pattern,
	//      so R is chain-breaking. AFFIRMATIVELY DANGEROUS -- do not revive it.
	//   P. reject a signed message already applied to this producer: 71 of 863
	//      distinct messages were legitimately re-submitted (up to 3x, months apart),
	//      so P false-rejects honest A/B node failovers.
	//   C. reject an already-applied (message||signature) credential: 0 measured
	//      false rejects (961 credentials, 0 duplicates) but INEFFECTIVE -- crypto.
	//      Verify calls ecdsa.Verify with no low-S canonicalisation, so (r, n-s)
	//      verifies and hashes differently and walks straight past the blacklist
	//      (sibling F-129; proven in f205_test.go). Canonicalising S first is itself
	//      an ecosystem break -- 48.3% of all real mainnet program signatures
	//      (1,487,608 of 3,077,730) and 22.9% of real producer payload credentials
	//      are high-S -- and C additionally needs new unbounded per-producer
	//      consensus state plus a fresh History/rollback surface.
	// The only complete fix is D: domain-separate the payload signing message
	// (network magic / genesis hash plus an anti-replay binding). D changes what
	// EVERY wallet must sign. StrictMoneyRangeHeight is already below the tip, so a
	// gate there activates on the first block of the recovery fork with no upgrade
	// window and would brick producer/CR management ecosystem-wide; a third gate is
	// not permitted. D is therefore an owner-level coordinated-upgrade decision and
	// must move together with its root-cause siblings (F-129 low-S canonicality,
	// F-189 node-key proof-of-possession, F-174, F-206, F-119), not one at a time.
	// RESIDUAL RISK: unfixed at HEAD, exactly as characterised above.
	if t.PayloadVersion() < payload.ProducerInfoSchnorrVersion {
		publicKey, err := crypto.DecodePoint(info.OwnerKey)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid owner public key in payload")), true
		}
		signedBuf := new(bytes.Buffer)
		err = info.SerializeUnsigned(signedBuf, t.payloadVersion)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}
		err = crypto.Verify(*publicKey, signedBuf.Bytes(), info.Signature)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid signature in payload")), true
		}
	} else if t.PayloadVersion() == payload.ProducerInfoSchnorrVersion {
		if len(t.Programs()) != 1 {
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("ProducerInfoSchnorrVersion can only have one program code")), true
		}
		if !contract.IsSchnorr(t.Programs()[0].Code) {
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("only schnorr code can use ProducerInfoSchnorrVersion")), true
		}
		pk := t.Programs()[0].Code[2:]
		if !bytes.Equal(pk, info.OwnerKey) {
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("tx program pk must equal with OwnerKey")), true
		}
	} else if t.PayloadVersion() == payload.ProducerInfoMultiVersion {
		if !contract.IsMultiSig(t.Programs()[0].Code) {
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("only multi sign code can use ProducerInfoMultiVersion")), true
		}
		//t.Programs()[0].Code equal info.OwnerKey
		if !bytes.Equal(t.Programs()[0].Code, info.OwnerKey) {
			return elaerr.Simple(elaerr.ErrTxPayload,
				errors.New("ProducerInfoMultiVersion tx program pk must equal with OwnerKey")), true
		}
	}

	producer := t.parameters.BlockChain.GetState().GetProducer(info.OwnerKey)
	if producer == nil {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("updating unknown producer")), true
	}
	stake := t.parameters.BlockChain.GetState()
	//if producer is already dposv2
	switch producer.Identity() {
	case state.DPoSV1:
		//if this producer want to be dposv2
		if info.StakeUntil != 0 {
			if producer.State() != state.Active {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("only active producer can update to DPoSV1V2")), true
			}
			if t.parameters.BlockHeight+t.parameters.Config.DPoSConfiguration.DPoSV2DepositCoinMinLockTime >= info.StakeUntil {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("v2 producer StakeUntil less than DPoSV2DepositCoinMinLockTime")), true
			}
		}
	case state.DPoSV2:
		// height > stakeUntil: can't change anything anymore.
		if t.parameters.BlockHeight > producer.Info().StakeUntil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("DPoS 2.0 node has expired")), true
		}

		if info.StakeUntil < producer.Info().StakeUntil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("stake time is smaller than before")), true
		}

	case state.DPoSV1V2:
		if t.parameters.BlockHeight >= stake.DPoSV2ActiveHeight {
			if t.parameters.BlockHeight > producer.Info().StakeUntil {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("producer already expired and dposv2 already started, can not update anything ")), true
			}
			if info.StakeUntil != producer.Info().StakeUntil { //change StakeUntil
				if err := checkChangeStakeUntil(t.parameters.BlockHeight, info, producer); err != nil {
					return err, true
				}
			}
		} else { //still in dpos1.0
			if info.StakeUntil != producer.Info().StakeUntil { //change StakeUntil
				if err := checkChangeStakeUntil(t.parameters.BlockHeight, info, producer); err != nil {
					return err, true
				}
			}
		}
	}

	// check nickname usage.
	if producer.Info().NickName != info.NickName &&
		t.parameters.BlockChain.GetState().NicknameExists(info.NickName) {
		return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("nick name %s already exist", info.NickName)), true
	}

	// check if public keys conflict with cr program code
	nodeCode := append([]byte{byte(crypto.COMPRESSEDLEN)}, info.NodePublicKey...)
	nodeCode = append(nodeCode, vm.CHECKSIG)
	if t.parameters.BlockChain.GetCRCommittee().ExistCR(nodeCode) {
		return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("node public key %s already exist in cr list",
			common.BytesToHexString(info.NodePublicKey))), true
	}

	// It is not necessary to check if OwnerKey is others' NodePublicKey since we can not change OwnerKey

	// check node public key duplication
	if bytes.Equal(info.NodePublicKey, producer.Info().NodePublicKey) {
		return nil, false
	}

	//if update producer tx change NodePublicKey
	if t.parameters.BlockChain.GetHeight() < t.parameters.Config.PublicDPOSHeight {
		if t.parameters.BlockChain.GetState().ProducerExists(info.NodePublicKey) {
			return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer %s already exist",
				hex.EncodeToString(info.NodePublicKey))), true
		}
	} else {
		// here only check  if NodePublicKey is others' NodePublicKey
		if t.parameters.BlockChain.GetState().ProducerOrCRNodePublicKeyExists(info.NodePublicKey) {
			return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer %s already exist",
				hex.EncodeToString(info.NodePublicKey))), true
		}

		if t.parameters.BlockHeight > t.parameters.Config.DPoSV2StartHeight {
			//check if NodePublicKey is others' ownerpublickey
			//NodePublicKey can not be change into  one producer's OwnerKey only if it is the same producer.
			producer := t.parameters.BlockChain.GetState().GetProducerByOwnerPublicKey(info.NodePublicKey)
			if producer != nil && !bytes.Equal(info.OwnerKey, producer.OwnerPublicKey()) {
				return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("NodePublicKey %s can not be other producer's ownerPublicKey ",
					hex.EncodeToString(info.NodePublicKey))), true
			}
		}
	}

	return nil, false
}

func (t *UpdateProducerTransaction) additionalProducerInfoCheck(info *payload.ProducerInfo) error {
	if t.parameters.BlockChain.GetHeight() >= t.parameters.Config.PublicDPOSHeight {
		_, err := crypto.DecodePoint(info.NodePublicKey)
		if err != nil {
			return errors.New("invalid node public key in payload")
		}

		for _, m := range t.parameters.BlockChain.GetCRCommittee().Members {
			if bytes.Equal(m.DPOSPublicKey, info.NodePublicKey) {
				return errors.New("node public key can't equal with current CR Node PK")
			}
			if bytes.Equal(m.Info.Code[1:len(m.Info.Code)-1], info.NodePublicKey) {
				return errors.New("node public key can't equal with current CR Owner PK")
			}
		}

		for _, m := range t.parameters.BlockChain.GetCRCommittee().NextMembers {
			if bytes.Equal(m.DPOSPublicKey, info.NodePublicKey) {
				return errors.New("node public key can't equal with next CR Node PK")
			}
			if bytes.Equal(m.Info.Code[1:len(m.Info.Code)-1], info.NodePublicKey) {
				return errors.New("node public key can't equal with current CR Owner PK")
			}
		}

		for _, p := range t.parameters.Config.DPoSConfiguration.CRCArbiters {
			if p == common.BytesToHexString(info.NodePublicKey) {
				return errors.New("node public key can't equal with CR Arbiters")
			}
		}
	}
	return nil
}
