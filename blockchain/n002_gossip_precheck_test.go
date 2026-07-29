// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// The DPoS gossip pre-check versus the complete-transaction check.
//
// InactiveArbitrators and RevertToDPOS are broadcast by their sponsor carrying
// exactly ONE signature. ProposalDispatcher.CreateInactiveArbitrators signs once,
// wraps that signature as the single program Parameter and broadcasts; collecting
// the remaining co-signatures IS the gossip round. On mainnet the multisig code is
// 9-of-12 over the CRC arbiters, so a full M-of-N check applied to the gossiped
// message rejects every legitimate message.
//
// The two entry points therefore have different contracts:
//
//	CheckInactiveArbitratorsGossip      / CheckRevertToDPOSTransactionGossip
//	    structure only, for a message whose co-signatures are still being collected
//	CheckInactiveArbitrators            / CheckRevertToDPOSTransaction
//	    structure plus M-of-N over the unsigned digest, for a COMPLETE transaction,
//	    height-gated on the block height
//
// These tests build the transaction the way the sponsor builds it, with a real
// 9-of-12 code over twelve CRC arbiter keys whose private halves the test holds,
// and pin both contracts plus the below-gate inertness required by rule 2.
package blockchain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n002CRCCount and n002MinSign mirror mainnet: twelve CRC arbiters and the
// MajoritySignRatio threshold computed over them, which is nine.
const n002CRCCount = 12

// n002Arbiters answers exactly the lookups the two structure checks make. Every
// other method comes from the embedded nil interface and panics if called, so a
// silent change of the lookups on this path cannot pass unnoticed.
type n002Arbiters struct {
	state.Arbitrators
	pubs     [][]byte
	producer []byte
}

func (a *n002Arbiters) GetCRCArbitersCount() int { return len(a.pubs) }
func (a *n002Arbiters) GetArbitersCount() int    { return len(a.pubs) }

func (a *n002Arbiters) GetArbitrators() []*state.ArbiterInfo {
	out := make([]*state.ArbiterInfo, 0, len(a.pubs))
	for _, p := range a.pubs {
		out = append(out, &state.ArbiterInfo{NodePublicKey: p, IsNormal: true})
	}
	return out
}

func (a *n002Arbiters) has(pk []byte) bool {
	for _, p := range a.pubs {
		if bytes.Equal(p, pk) {
			return true
		}
	}
	return false
}

func (a *n002Arbiters) IsCRCArbitrator(pk []byte) bool  { return a.has(pk) }
func (a *n002Arbiters) IsArbitrator(pk []byte) bool     { return a.has(pk) }
func (a *n002Arbiters) IsActiveProducer(pk []byte) bool { return bytes.Equal(pk, a.producer) }
func (a *n002Arbiters) IsDisabledProducer([]byte) bool  { return false }

// n002Env holds the arbiter key material plus the gate the ledger reports.
type n002Env struct {
	privs    [][]byte
	pubs     []*crypto.PublicKey
	encoded  [][]byte
	producer []byte
	gate     uint32
}

// n002Setup installs a DefaultLedger whose Arbitrators are twelve CRC arbiters
// the test can sign for and whose Blockchain carries the real chain params, so
// arbitratorsMultisigActive reads the production StrictMoneyRangeHeight.
func n002Setup(t *testing.T) *n002Env {
	t.Helper()
	require.NotNil(t, functions.CreateTransaction,
		"transaction constructor registry not populated, see wiring_support_test.go")

	env := &n002Env{}
	for i := 0; i < n002CRCCount; i++ {
		priv, pub, err := crypto.GenerateKeyPair()
		require.NoError(t, err)
		enc, err := pub.EncodePoint(true)
		require.NoError(t, err)
		env.privs = append(env.privs, priv)
		env.pubs = append(env.pubs, pub)
		env.encoded = append(env.encoded, enc)
	}
	_, prodPub, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	env.producer, err = prodPub.EncodePoint(true)
	require.NoError(t, err)

	params := config.GetDefaultParams()
	env.gate = params.StrictMoneyRangeHeight

	prev := DefaultLedger
	DefaultLedger = &Ledger{
		Arbitrators: &n002Arbiters{pubs: env.encoded, producer: env.producer},
		Blockchain:  &BlockChain{chainParams: params},
	}
	t.Cleanup(func() { DefaultLedger = prev })
	return env
}

// n002MinSignCount is the threshold the production structure checks demand, and
// the same one createArbitratorsRedeemScript uses to build the code.
func n002MinSignCount(n int) int {
	return int(float64(n)*state.MajoritySignRatioNumerator/
		state.MajoritySignRatioDenominator) + 1
}

// n002Tx builds the transaction the way ProposalDispatcher builds it: a multisig
// code over the arbiter keys, the program-hash script attribute, no inputs or
// outputs, and one program whose Parameter is filled in by n002Sign.
func n002Tx(t *testing.T, env *n002Env, m int, txType common2.TxType,
	ver byte, p interfaces.Payload) interfaces.Transaction {
	t.Helper()
	code, err := contract.CreateMultiSigRedeemScript(m, env.pubs)
	require.NoError(t, err)
	ct := contract.Contract{Prefix: contract.PrefixMultiSig, Code: code}
	ph := ct.ToProgramHash()
	return functions.CreateTransaction(
		common2.TxVersion09, txType, ver, p,
		[]*common2.Attribute{{Usage: common2.Script, Data: ph.Bytes()}},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*pg.Program{{Code: code}},
	)
}

// n002Sign appends signers signatures over the unsigned digest, in the same
// [length][signature] parameter encoding the sponsor and the response collector
// produce.
func n002Sign(t *testing.T, env *n002Env, tx interfaces.Transaction, signers int) {
	t.Helper()
	buf := new(bytes.Buffer)
	require.NoError(t, tx.SerializeUnsigned(buf))
	var param []byte
	for i := 0; i < signers; i++ {
		sign := n002RawSign(t, env.privs[i], buf.Bytes())
		param = append(param, byte(len(sign)))
		param = append(param, sign...)
	}
	tx.SetPrograms([]*pg.Program{{Code: tx.Programs()[0].Code, Parameter: param}})
}

// n002RawSign produces the same fixed-width r||s signature crypto.Sign produces,
// over the same sha256 digest and the same curve. It fills in the public half of
// the ecdsa key, which crypto.Sign leaves zero; Go 1.20 accepts a key without it
// and later toolchains do not, so signing here keeps the suite runnable on both.
// The signatures are checked by the production verifier, unmodified.
func n002RawSign(t *testing.T, priv []byte, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	key := new(ecdsa.PrivateKey)
	key.Curve = crypto.DefaultCurve
	key.D = new(big.Int).SetBytes(priv)
	key.PublicKey.X, key.PublicKey.Y = crypto.DefaultCurve.ScalarBaseMult(priv)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)

	signature := make([]byte, crypto.SignatureLength)
	rb, sb := r.Bytes(), s.Bytes()
	copy(signature[crypto.SignerLength-len(rb):], rb)
	copy(signature[crypto.SignatureLength-len(sb):], sb)
	return signature
}

func n002InactivePayload(env *n002Env, height uint32) *payload.InactiveArbitrators {
	return &payload.InactiveArbitrators{
		Sponsor:     env.encoded[0],
		Arbitrators: [][]byte{env.producer},
		BlockHeight: height,
	}
}

func n002RevertPayload() *payload.RevertToDPOS {
	return &payload.RevertToDPOS{WorkHeightInterval: payload.WorkHeightInterval}
}

// TestN002InactiveArbitratorsGossipAcceptsSingleSignature is the defect itself.
// Above the gate the complete-transaction check rejects the singly-signed message
// the sponsor actually broadcasts, so an emergency ForceChange round could never
// begin. The gossip entry point must accept it.
func TestN002InactiveArbitratorsGossipAcceptsSingleSignature(t *testing.T) {
	env := n002Setup(t)
	m := n002MinSignCount(n002CRCCount)
	require.Equal(t, 9, m, "mainnet threshold is nine of twelve")

	tip := env.gate + 1000

	tx := n002Tx(t, env, m, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, tip))
	n002Sign(t, env, tx, 1)

	// What the gossip handler used to call, with the chain tip.
	err := CheckInactiveArbitrators(tx, tip)
	require.Error(t, err,
		"a one-signature message cannot satisfy a nine-of-twelve check")
	assert.Contains(t, err.Error(), "not enough signatures")

	// What the gossip handler must call.
	assert.NoError(t, CheckInactiveArbitratorsGossip(tx),
		"the gossip pre-check must accept the singly-signed message that starts the round")
}

// TestN002InactiveArbitratorsCompleteStillVerified proves the protection this
// check exists for is not lost: a complete nine-of-twelve transaction passes and
// a tampered one is rejected, on the complete-transaction path, above the gate.
func TestN002InactiveArbitratorsCompleteStillVerified(t *testing.T) {
	env := n002Setup(t)
	m := n002MinSignCount(n002CRCCount)
	height := env.gate + 1000

	complete := n002Tx(t, env, m, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, height))
	n002Sign(t, env, complete, m)
	assert.NoError(t, CheckInactiveArbitrators(complete, height),
		"a complete nine-of-twelve transaction must still pass")

	// Sign, then change the payload the signatures covered. The structure is
	// untouched, so only the digest check can catch it.
	tampered := n002Tx(t, env, m, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, height))
	n002Sign(t, env, tampered, m)
	tampered.Payload().(*payload.InactiveArbitrators).BlockHeight = height + 7
	assert.Error(t, CheckInactiveArbitrators(tampered, height),
		"a forged complete transaction must be rejected at or above the gate")

	// Rule 2: below the gate the verdict is the legacy structure-only verdict.
	assert.NoError(t, CheckInactiveArbitrators(tampered, env.gate-1),
		"below the gate the verdict must stay structure-only")
}

// TestN002InactiveArbitratorsGossipStillRejectsBadStructure pins the pre-check
// itself. Delete the call site in the gossip handler and nothing rejects a code
// that does not list authorized arbiters at the required threshold.
func TestN002InactiveArbitratorsGossipStillRejectsBadStructure(t *testing.T) {
	env := n002Setup(t)

	// Threshold below the majority the CRC arbiter count demands.
	weak := n002Tx(t, env, 1, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, env.gate+1))
	n002Sign(t, env, weak, 1)
	assert.Error(t, CheckInactiveArbitratorsGossip(weak),
		"the gossip pre-check must still reject an under-threshold multisig code")

	// Sponsor that is not a CRC arbiter.
	m := n002MinSignCount(n002CRCCount)
	stranger := n002Tx(t, env, m, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, env.gate+1))
	stranger.Payload().(*payload.InactiveArbitrators).Sponsor = env.producer
	n002Sign(t, env, stranger, 1)
	assert.Error(t, CheckInactiveArbitratorsGossip(stranger),
		"the gossip pre-check must still reject a non-CRC sponsor")

	// Empty program set, the crash-guard path.
	empty := n002Tx(t, env, m, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion, n002InactivePayload(env, env.gate+1))
	empty.SetPrograms([]*pg.Program{})
	assert.Error(t, CheckInactiveArbitratorsGossip(empty),
		"the gossip pre-check must still reject a transaction with no program")
}

// TestN002RevertToDPOSGossipAcceptsSingleSignature is the same defect on the
// RevertToDPOS message, which is the only way a chain stuck in PoW gets back to
// DPoS consensus.
func TestN002RevertToDPOSGossipAcceptsSingleSignature(t *testing.T) {
	env := n002Setup(t)
	m := n002MinSignCount(n002CRCCount)
	tip := env.gate + 1000

	tx := n002Tx(t, env, m, common2.RevertToDPOS,
		payload.RevertToDPOSVersion, n002RevertPayload())
	n002Sign(t, env, tx, 1)

	err := CheckRevertToDPOSTransaction(tx, tip)
	require.Error(t, err,
		"a one-signature message cannot satisfy a nine-of-twelve check")
	assert.Contains(t, err.Error(), "not enough signatures")

	assert.NoError(t, CheckRevertToDPOSTransactionGossip(tx),
		"the gossip pre-check must accept the singly-signed message that starts the round")
}

// TestN002RevertToDPOSCompleteStillVerified holds the complete-transaction
// contract for RevertToDPOS, including below-gate inertness.
func TestN002RevertToDPOSCompleteStillVerified(t *testing.T) {
	env := n002Setup(t)
	m := n002MinSignCount(n002CRCCount)
	height := env.gate + 1000

	complete := n002Tx(t, env, m, common2.RevertToDPOS,
		payload.RevertToDPOSVersion, n002RevertPayload())
	n002Sign(t, env, complete, m)
	assert.NoError(t, CheckRevertToDPOSTransaction(complete, height),
		"a complete nine-of-twelve transaction must still pass")

	tampered := n002Tx(t, env, m, common2.RevertToDPOS,
		payload.RevertToDPOSVersion, n002RevertPayload())
	n002Sign(t, env, tampered, m)
	tampered.Payload().(*payload.RevertToDPOS).RevertToPOWBlockHeight = height - 3
	assert.Error(t, CheckRevertToDPOSTransaction(tampered, height),
		"a forged complete transaction must be rejected at or above the gate")
	assert.NoError(t, CheckRevertToDPOSTransaction(tampered, env.gate-1),
		"below the gate the verdict must stay structure-only")
}

// TestN002RevertToDPOSGossipStillRejectsBadStructure pins the RevertToDPOS
// pre-check the same way.
func TestN002RevertToDPOSGossipStillRejectsBadStructure(t *testing.T) {
	env := n002Setup(t)

	weak := n002Tx(t, env, 1, common2.RevertToDPOS,
		payload.RevertToDPOSVersion, n002RevertPayload())
	n002Sign(t, env, weak, 1)
	assert.Error(t, CheckRevertToDPOSTransactionGossip(weak),
		"the gossip pre-check must still reject an under-threshold multisig code")

	m := n002MinSignCount(n002CRCCount)
	empty := n002Tx(t, env, m, common2.RevertToDPOS,
		payload.RevertToDPOSVersion, n002RevertPayload())
	empty.SetPrograms([]*pg.Program{})
	assert.Error(t, CheckRevertToDPOSTransactionGossip(empty),
		"the gossip pre-check must still reject a transaction with no program")
}
