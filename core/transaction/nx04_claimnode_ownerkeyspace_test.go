// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"encoding/hex"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/crypto"
	dposstate "github.com/elastos/Elastos.ELA/dpos/state"
)

// FAIL-ON-PRISTINE for NX-04.
//
// Everything here drives the REAL validator, SpecialContextCheck, through the
// suite's real *blockchain.BlockChain, real CR committee and real signature
// over the council member's own code -- the same entry point
// CheckTransactionContext calls for every CRCouncilMemberClaimNode in a block.
//
// On the pristine tree the shadow claim is ACCEPTED: getProducerKey consults
// NodeOwnerKeys, then CurrentCRNodeOwnerKeys, then NextCRNodeOwnerKeys, so a
// council member who claims a producer's OWNER key redirects that owner key
// away from its own producer -- the producer keeps producing blocks on its node
// key and looks healthy, while UpdateProducer, CancelProducer,
// ReturnDepositCoin and RenewalVote all take their unknown-producer branch, and
// any DPoSV2 vote cast for it is validated against a candidate map keyed on
// OwnerKey (unaffected by the shadow), charged to the voter and credited to
// nobody. That vote charge is only ever released by iterating the producer's
// detailedDPoSV2Votes, and nothing was recorded there -- so the voter
// permanently loses access to staked ELA equal to the votes cast. A LOCK, not a
// mint: no supply inflation is claimed or implied.

const (
	// nx04VictimOwner is a producer owner key; nx04VictimNode is that same
	// producer's DIFFERENT node key. A producer that registered with one key
	// for both is immune, which is why the census matters: 207 of 259 mainnet
	// producers -- including every one of the 61 active ones -- are exposed.
	nx04VictimOwner = "031e12374bae471aa09ad479f66c2306f4bcc4ca5b754609a82a1839b94b4721b9"
	nx04VictimNode  = "027c4f35081821da858f5c7197bac5e33e77e5af4a3551285f8a8da0a59bd37c45"

	nx04CouncilPub  = "036db5984e709d2e0ec62fd974283e9a18e7b87e8403cc784baf1f61f775926535"
	nx04CouncilPriv = "b2c25e877c8a87d54e8a20a902d27c7f24ed52810813ba175ca4e8d3036d130e"
)

// nx04Fixture installs one exposed producer and one elected council seat, and
// returns the seat's DID plus a restore function.
func (s *txValidatorTestSuite) nx04Fixture() (common.Uint168, func()) {
	victimOwner, _ := common.HexStringToBytes(nx04VictimOwner)
	victimNode, _ := common.HexStringToBytes(nx04VictimNode)

	st := s.Chain.GetState()
	comm := s.Chain.GetCRCommittee()

	st.NodeOwnerKeys = make(map[string]string)
	st.CurrentCRNodeOwnerKeys = make(map[string]string)
	st.NextCRNodeOwnerKeys = make(map[string]string)
	comm.ClaimedDPoSKeys = make(map[string]struct{})
	comm.NextClaimedDPoSKeys = make(map[string]struct{})

	// Register the victim producer exactly as the state indexes it.
	st.ActivityProducers[hex.EncodeToString(victimOwner)] = &dposstate.Producer{}
	st.NodeOwnerKeys[hex.EncodeToString(victimNode)] = hex.EncodeToString(victimOwner)

	// The producer IS registered on its owner key ...
	s.True(st.ProducerOwnerPublicKeyExists(victimOwner),
		"setup: victim producer must be registered on its owner key")
	// ... and neither guard the claim validator used consults that keyspace.
	s.False(st.ProducerAndCurrentCRNodePublicKeyExists(victimOwner))
	s.False(st.ProducerAndNextCRNodePublicKeyExists(victimOwner))

	did := randomUint168()
	previousElection := comm.InElectionPeriod
	previousHeight := s.Chain.BestChain.Height
	comm.InElectionPeriod = true
	member := &crstate.CRMember{
		MemberState: crstate.MemberElected,
		Info:        payload.CRInfo{Code: getCodeByPubKeyStr(nx04CouncilPub), DID: *did},
	}
	comm.Members[*did] = member
	comm.NextMembers = map[common.Uint168]*crstate.CRMember{*did: member}

	return *did, func() {
		delete(st.ActivityProducers, hex.EncodeToString(victimOwner))
		st.NodeOwnerKeys = make(map[string]string)
		st.CurrentCRNodeOwnerKeys = make(map[string]string)
		st.NextCRNodeOwnerKeys = make(map[string]string)
		delete(comm.Members, *did)
		comm.NextMembers = make(map[common.Uint168]*crstate.CRMember)
		comm.InElectionPeriod = previousElection
		s.Chain.BestChain.Height = previousHeight
	}
}

// nx04Claim builds and validates a signed CRCouncilMemberClaimNode at the given
// height, returning the validator's verdict.
func (s *txValidatorTestSuite) nx04Claim(did common.Uint168, nodeKey []byte,
	payloadVersion byte, height uint32) error {
	priv, _ := common.HexStringToBytes(nx04CouncilPriv)

	claim := &payload.CRCouncilMemberClaimNode{
		NodePublicKey:         nodeKey,
		CRCouncilCommitteeDID: did,
	}
	buf := new(bytes.Buffer)
	claim.SerializeUnsigned(buf, payload.CurrentCRClaimDPoSNodeVersion)
	sig, err := crypto.Sign(priv, buf.Bytes())
	s.NoError(err)
	claim.CRCouncilCommitteeSignature = sig

	// BlockHeight is taken from the chain tip by CreateTransactionByType, so
	// this is what arms or disarms the gate on the production path.
	s.Chain.BestChain.Height = height

	txn := functions.CreateTransaction(
		0, common2.CRCouncilMemberClaimNode, payloadVersion,
		claim, []*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: getCodeByPubKeyStr(nx04CouncilPub)}},
	)
	txn = CreateTransactionByType(txn, s.Chain)
	verr, _ := txn.SpecialContextCheck()
	if verr == nil {
		return nil
	}

	return verr
}

// TestNX04ClaimOfProducerOwnerKeyIsRejectedAtTheGate is the discriminator.
func (s *txValidatorTestSuite) TestNX04ClaimOfProducerOwnerKeyIsRejectedAtTheGate() {
	did, restore := s.nx04Fixture()
	defer restore()

	gate := s.Chain.GetParams().StrictMoneyRangeHeight
	victimOwner, _ := common.HexStringToBytes(nx04VictimOwner)

	err := s.nx04Claim(did, victimOwner,
		payload.CurrentCRClaimDPoSNodeVersion, gate)
	s.Error(err, "NX-04: at the gate the validator still accepts a claim of a "+
		"live producer's OWNER public key")
	s.Contains(err.Error(), "NodePublicKey is already other's OwnerKey")

	// The Next arm has the same hole and the same fix.
	err = s.nx04Claim(did, victimOwner,
		payload.NextCRClaimDPoSNodeVersion, gate+1000)
	s.Error(err, "NX-04: the NextCRClaimDPoSNode arm is unguarded")
	s.Contains(err.Error(), "NodePublicKey is already other's OwnerKey")
}

// TestNX04BelowTheGateHistoryIsUnchanged is the replay-safety half. The guard
// is acceptance-changing, so below StrictMoneyRangeHeight it must not exist:
// retained history has to validate byte-identically. The census says this
// costs nothing -- 143 CRCouncilMemberClaimNode transactions in all of history,
// none at or above the gate, none naming a producer owner key -- but the rule
// must still be off below it.
func (s *txValidatorTestSuite) TestNX04BelowTheGateHistoryIsUnchanged() {
	did, restore := s.nx04Fixture()
	defer restore()

	gate := s.Chain.GetParams().StrictMoneyRangeHeight
	victimOwner, _ := common.HexStringToBytes(nx04VictimOwner)

	s.NoError(s.nx04Claim(did, victimOwner,
		payload.CurrentCRClaimDPoSNodeVersion, gate-1),
		"NX-04: the guard fired one block BELOW the gate; retained history "+
			"would stop validating")
}

// TestNX04NodeKeyspaceGuardStillWorks is the negative control that proves the
// new rule is a DIFFERENT rule, not a duplicate of the guard that already
// existed: claiming the victim's NODE key was always rejected, and still is,
// with its own message.
func (s *txValidatorTestSuite) TestNX04NodeKeyspaceGuardStillWorks() {
	did, restore := s.nx04Fixture()
	defer restore()

	gate := s.Chain.GetParams().StrictMoneyRangeHeight
	victimNode, _ := common.HexStringToBytes(nx04VictimNode)

	err := s.nx04Claim(did, victimNode,
		payload.CurrentCRClaimDPoSNodeVersion, gate)
	s.Error(err)
	s.Contains(err.Error(), "producer already registered")
}

// TestNX04UnrelatedKeyIsStillAccepted is the over-reach guard: an ordinary
// council node claim of a key that belongs to nobody must keep working at and
// above the gate, or the fix breaks every honest CR node rotation.
func (s *txValidatorTestSuite) TestNX04UnrelatedKeyIsStillAccepted() {
	did, restore := s.nx04Fixture()
	defer restore()

	gate := s.Chain.GetParams().StrictMoneyRangeHeight

	_, unrelated, err := crypto.GenerateKeyPair()
	s.NoError(err)
	unrelatedKey, err := unrelated.EncodePoint(true)
	s.NoError(err)

	s.NoError(s.nx04Claim(did, unrelatedKey,
		payload.CurrentCRClaimDPoSNodeVersion, gate),
		"NX-04 OVER-REACH: an ordinary CR node claim was rejected at the gate")
}

// TestNX04ReElectionKeyContinuityIsPreserved is the second over-reach guard,
// and it is the reason the ORIGINAL report's suggested fix was not applied. It
// proposed widening the two node-key guards to see both CR maps (or to call
// ProducerOrCRNodePublicKeyExists). Mainnet checkpoints show a sitting council
// member re-elected for the next term re-claims the SAME DPoS node key through
// the Next arm -- observed repeatedly in real state -- so that widening would
// reject legitimate council key continuity across terms. This test fails if
// anybody applies it later.
func (s *txValidatorTestSuite) TestNX04ReElectionKeyContinuityIsPreserved() {
	did, restore := s.nx04Fixture()
	defer restore()

	gate := s.Chain.GetParams().StrictMoneyRangeHeight

	_, pub, err := crypto.GenerateKeyPair()
	s.NoError(err)
	nodeKey, err := pub.EncodePoint(true)
	s.NoError(err)

	// The seat already holds this node key for the CURRENT term.
	st := s.Chain.GetState()
	st.CurrentCRNodeOwnerKeys[hex.EncodeToString(nodeKey)] = "cr-owner-key"

	s.NoError(s.nx04Claim(did, nodeKey,
		payload.NextCRClaimDPoSNodeVersion, gate),
		"NX-04 OVER-REACH: a re-elected council member re-claiming its own "+
			"current DPoS node key for the next term was rejected -- this is "+
			"the legitimate flow mainnet actually uses")
}
