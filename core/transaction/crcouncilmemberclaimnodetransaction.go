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

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/crypto"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type CRCouncilMemberClaimNodeTransaction struct {
	BaseTransaction
}

func (t *CRCouncilMemberClaimNodeTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *CRCouncilMemberClaimNodeTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.CRCouncilMemberClaimNode:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *CRCouncilMemberClaimNodeTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if blockHeight < chainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before CRClaimDPOSNodeStartHeight", t.TxType().Name()))
	}
	return nil
}

func (t *CRCouncilMemberClaimNodeTransaction) SpecialContextCheck() (result elaerr.ELAError, end bool) {
	manager, ok := t.Payload().(*payload.CRCouncilMemberClaimNode)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}

	if t.parameters.BlockHeight < t.parameters.Config.DPoSV2StartHeight &&
		!t.parameters.BlockChain.GetCRCommittee().IsInElectionPeriod() {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("CRCouncilMemberClaimNode must during election period")), true
	}

	did := manager.CRCouncilCommitteeDID
	var crMember *crstate.CRMember
	comm := t.parameters.BlockChain.GetCRCommittee()
	if t.parameters.BlockHeight >= t.parameters.Config.DPoSV2StartHeight {
		switch t.payloadVersion {
		case payload.CurrentCRClaimDPoSNodeVersion:
			crMember = t.parameters.BlockChain.GetCRCommittee().GetMember(did)
			if _, ok := comm.ClaimedDPoSKeys[hex.EncodeToString(manager.NodePublicKey)]; ok {
				return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer already registered")), true
			}
			// check duplication of node.
			if t.parameters.BlockChain.GetState().ProducerAndCurrentCRNodePublicKeyExists(manager.NodePublicKey) {
				return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer already registered")), true
			}
			if err := t.checkClaimedNodeKeyOutsideOwnerKeyspace(manager.NodePublicKey); err != nil {
				return elaerr.Simple(elaerr.ErrTxPayload, err), true
			}
		case payload.NextCRClaimDPoSNodeVersion:
			crMember = t.parameters.BlockChain.GetCRCommittee().GetNextMember(did)
			if _, ok := comm.NextClaimedDPoSKeys[hex.EncodeToString(manager.NodePublicKey)]; ok {
				return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer already registered")), true
			}
			// check duplication of node.
			if t.parameters.BlockChain.GetState().ProducerAndNextCRNodePublicKeyExists(manager.NodePublicKey) {
				return elaerr.Simple(elaerr.ErrTxPayload, fmt.Errorf("producer already registered")), true
			}
			if err := t.checkClaimedNodeKeyOutsideOwnerKeyspace(manager.NodePublicKey); err != nil {
				return elaerr.Simple(elaerr.ErrTxPayload, err), true
			}
		}
	} else {
		crMember = t.parameters.BlockChain.GetCRCommittee().GetMember(did)
	}
	if crMember == nil {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("the originator must be members")), true
	}

	if crMember.MemberState != crstate.MemberElected && crMember.MemberState != crstate.MemberInactive {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("CR Council Member should be an elected or inactive CR members")), true
	}

	if len(crMember.DPOSPublicKey) != 0 {
		if bytes.Equal(crMember.DPOSPublicKey, manager.NodePublicKey) {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("NodePublicKey is the same as crMember.DPOSPublicKey")), true
		}
	}

	_, err := crypto.DecodePoint(manager.NodePublicKey)
	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid operating public key")), true
	}

	err = checkCRCouncilMemberClaimNodeSignature(manager, crMember.Info.Code)
	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("CR claim DPOS signature check failed")), true
	}

	return nil, false
}

// checkClaimedNodeKeyOutsideOwnerKeyspace rejects a CRCouncilMemberClaimNode
// whose claimed NodePublicKey is some producer's owner public key.
//
// getProducerKey resolves a public key by consulting NodeOwnerKeys, then
// CurrentCRNodeOwnerKeys, then NextCRNodeOwnerKeys, and getProducer is
// getProducerByOwnerPublicKey(getProducerKey(pk)). A CR node claim writes
// CurrentCRNodeOwnerKeys[claimedKey] = crMemberOwnerKey, so a council member who
// claims a producer's owner key redirects that owner key away from its own
// producer: from the next commit getProducer(victimOwnerKey) is nil while the
// producer object itself is untouched and still resolvable by its node key, so
// the victim keeps producing blocks and looks healthy. Everything authorised on
// the owner identity then fails closed: UpdateProducer ("updating unknown
// producer"), CancelProducer, ReturnDepositCoin (the 2,000/5,000 ELA deposit
// becomes unreturnable) and RenewalVote. Worse, checkDPoSV2Content validates a
// vote for the shadowed producer against a candidate map built by iterating
// ActivityProducers and keying on OwnerKey, which the shadow does not affect, so
// the vote is accepted, UsedDposV2Votes is charged unconditionally, and nothing is
// ever credited to release it: a third-party voter permanently loses access to
// staked ELA equal to the votes cast. That is a lock, not a mint and not inflation.
//
// The producer-side validators already forbid the mirror image of this
// (registerproducertransaction.go: "NodePublicKey is already other's OwnerKey",
// updateproducertransaction.go additionalProducerInfoCheck); only the CR-side
// validator omits it. This mirrors those exactly.
//
// Gated at StrictMoneyRangeHeight (gate 1) because it is acceptance-changing:
// below the gate the rule must not exist at all or retained history stops
// validating byte-identically.
//
// Deliberately not the reverse widening, which would let the two node-key guards
// see both CR maps: mainnet checkpoints show a sitting council member re-elected
// for the next term re-claims the same DPoS node key, so that widening would break
// legitimate council key continuity across terms.
//
// Measured against real state: across all 96 retained DPoS checkpoints
// (h=1,891,833..2,260,297) there is not one owner-key collision in
// CurrentCRNodeOwnerKeys or NextCRNodeOwnerKeys, and of the 143
// CRCouncilMemberClaimNode transactions in all of history none is at or above the
// gate and none names a producer's owner key. This guard therefore rejects nothing
// in observed history.
func (t *CRCouncilMemberClaimNodeTransaction) checkClaimedNodeKeyOutsideOwnerKeyspace(
	nodePublicKey []byte) error {
	if t.parameters.BlockHeight < t.parameters.Config.StrictMoneyRangeHeight {
		return nil
	}

	if t.parameters.BlockChain.GetState().
		ProducerOwnerPublicKeyExists(nodePublicKey) {
		return errors.New("NodePublicKey is already other's OwnerKey")
	}

	return nil
}

func checkCRCouncilMemberClaimNodeSignature(
	managementPayload *payload.CRCouncilMemberClaimNode, code []byte) error {
	signBuf := new(bytes.Buffer)
	managementPayload.SerializeUnsigned(signBuf, payload.CurrentCRClaimDPoSNodeVersion)
	if err := blockchain.CheckCRTransactionSignature(managementPayload.CRCouncilCommitteeSignature, code,
		signBuf.Bytes()); err != nil {
		return errors.New("CR signature check failed")
	}
	return nil
}
