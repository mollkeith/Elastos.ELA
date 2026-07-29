// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// RevertToDPOS response dedup (rescue-path defect 4 site B, A3.2).
//
// OnResponseRevertToDPOSTxReceived verifies each response signature but kept
// no record of which signers had already been merged, while completeness is
// counted from the length of the program parameter. One arbiter responding
// repeatedly therefore made the transaction count-complete with fewer than the
// required distinct signers, and every peer rejects the result. On a restarted
// mainnet this transaction is the only exit from PoW mode, and without the set
// a single misbehaving arbiter can burn every attempt.
//
// The tests observe the transaction's own program parameter and the
// SetNeedRevertToDPOSTX flag, not a stub's call count.
package manager

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/require"
)

// a32Arbiters answers the arbiter lookups the response path makes and records
// whether the RevertToDPOS transaction was declared complete.
type a32Arbiters struct {
	state.Arbitrators
	pubs       [][]byte
	needRevert bool
}

func (a *a32Arbiters) GetArbitersCount() int           { return len(a.pubs) }
func (a *a32Arbiters) SetNeedRevertToDPOSTX(need bool) { a.needRevert = need }

func (a *a32Arbiters) GetArbitrators() []*state.ArbiterInfo {
	out := make([]*state.ArbiterInfo, 0, len(a.pubs))
	for _, p := range a.pubs {
		out = append(out, &state.ArbiterInfo{NodePublicKey: p, IsNormal: true})
	}
	return out
}

func a32Dispatcher(env *n002Env) (*ProposalDispatcher, *a32Arbiters) {
	arb := &a32Arbiters{pubs: env.encoded}
	mgr := &DPOSManager{publicKey: env.encoded[0], arbitrators: arb}
	p := &ProposalDispatcher{
		signedTxs: make(map[common.Uint256]interface{}),
		cfg: ProposalDispatcherConfig{
			EventAnalyzerConfig: EventAnalyzerConfig{Arbitrators: arb},
			Manager:             mgr,
			Account:             n002Account{},
		},
	}
	mgr.dispatcher = p
	return p, arb
}

// a32Respond signs the current RevertToDPOS transaction with one arbiter key
// and hands the response to the dispatcher. It recovers and reports whether
// the handler panicked: a count-complete transaction runs on into
// transaction-pool submission this harness does not provide, and by then the
// behaviour under test has already happened.
func a32Respond(t *testing.T, p *ProposalDispatcher, env *n002Env, signer int) (panicked bool) {
	t.Helper()
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	data := new(bytes.Buffer)
	require.NoError(t, p.RevertToDPOSTx.SerializeUnsigned(data))
	sign := n002RawSign(t, env.privs[signer], data.Bytes())
	hash := p.RevertToDPOSTx.Hash()
	p.OnResponseRevertToDPOSTxReceived(&hash, env.encoded[signer], sign)
	return
}

// a32SignCount counts the signatures merged into the transaction. It reads the
// transaction directly because completing it clears the dispatcher's reference.
func a32SignCount(tx interfaces.Transaction) int {
	return len(tx.Programs()[0].Parameter) / crypto.SignatureScriptLength
}

func a32Seed(p *ProposalDispatcher, env *n002Env) {
	p.revertToDPOSRequests = map[string]struct{}{
		common.BytesToHexString(env.encoded[0]): {},
	}
}

// TestA32DuplicateSignerCannotCompleteTx is the defect. The transaction starts
// carrying the sponsor's own signature; one other arbiter then answers often
// enough to reach the threshold by count alone.
func TestA32DuplicateSignerCannotCompleteTx(t *testing.T) {
	env := n002Setup(t)
	p, arb := a32Dispatcher(env)
	need := n002MinSignCount(n002CRCCount)
	tx := n002RevertTx(t, env, need, 1)
	p.RevertToDPOSTx = tx
	a32Seed(p, env)
	require.Equal(t, 1, a32SignCount(tx), "the sponsor's own signature is already in")

	for i := 0; i < need; i++ {
		a32Respond(t, p, env, 1)
	}

	require.Equal(t, 2, a32SignCount(tx),
		"a signer that answers repeatedly must contribute exactly one signature")
	require.False(t, arb.needRevert,
		"two distinct signers must not complete a transaction that needs more")
}

// TestA32SponsorEchoDoesNotDoubleCount pins the seeding: the program parameter
// is born carrying the sponsor's signature, so a response echoing the
// sponsor's own key back must not be merged a second time.
func TestA32SponsorEchoDoesNotDoubleCount(t *testing.T) {
	env := n002Setup(t)
	p, _ := a32Dispatcher(env)
	need := n002MinSignCount(n002CRCCount)
	tx := n002RevertTx(t, env, need, 1)
	p.RevertToDPOSTx = tx
	a32Seed(p, env)

	a32Respond(t, p, env, 0)

	require.Equal(t, 1, a32SignCount(tx),
		"the sponsor's embedded signature must not be merged again")
}

// TestA32DistinctSignersCompleteTx is the control. The uniqueness set must not
// block the legitimate round: one response from each required distinct signer
// still completes the transaction.
func TestA32DistinctSignersCompleteTx(t *testing.T) {
	env := n002Setup(t)
	p, arb := a32Dispatcher(env)
	need := n002MinSignCount(n002CRCCount)
	tx := n002RevertTx(t, env, need, 1)
	p.RevertToDPOSTx = tx
	a32Seed(p, env)

	for i := 1; i < need; i++ {
		a32Respond(t, p, env, i)
	}

	require.Equal(t, need, a32SignCount(tx),
		"every distinct signer must contribute a signature")
	require.True(t, arb.needRevert,
		"the required number of distinct signers must complete the transaction")
}

// TestA32CreateSeedsSponsor pins the production seeding site: CreateRevertToDPOS
// must start the signer set holding this node's own key.
func TestA32CreateSeedsSponsor(t *testing.T) {
	env := n002Setup(t)
	p, _ := a32Dispatcher(env)

	_, err := p.CreateRevertToDPOS(100)
	require.NoError(t, err)

	require.Len(t, p.revertToDPOSRequests, 1,
		"creation must seed the signer set with exactly the sponsor")
	_, ok := p.revertToDPOSRequests[common.BytesToHexString(env.encoded[0])]
	require.True(t, ok, "the seeded signer must be this node's public key")

	// The created transaction's script comes from the production builder
	// (CreateRevertToPOWRedeemScript), so a co-signer merging through it also
	// pins that registerDistinctSigner parses that script shape in-flow.
	a32Respond(t, p, env, 1)
	require.Len(t, p.revertToDPOSRequests, 2,
		"a co-signer must merge through the production-built redeem script")
}

// TestA32GarbageSignatureCannotClaimSlot pins the order of operations: the
// signer set is consulted only AFTER the signature verifies, so a forged
// message naming a real arbiter cannot occupy that arbiter's slot and lock
// its genuine response out.
func TestA32GarbageSignatureCannotClaimSlot(t *testing.T) {
	env := n002Setup(t)
	p, _ := a32Dispatcher(env)
	need := n002MinSignCount(n002CRCCount)
	tx := n002RevertTx(t, env, need, 1)
	p.RevertToDPOSTx = tx
	a32Seed(p, env)

	hash := tx.Hash()
	p.OnResponseRevertToDPOSTxReceived(&hash, env.encoded[1],
		make([]byte, crypto.SignatureLength))

	require.Equal(t, 1, a32SignCount(tx),
		"a response that fails verification must merge nothing")
	require.Len(t, p.revertToDPOSRequests, 1,
		"a response that fails verification must not claim the signer's slot")

	a32Respond(t, p, env, 1)
	require.Equal(t, 2, a32SignCount(tx),
		"the genuine response must still merge after the forgery")
}

// TestA32OutOfScriptSignerIgnored: a verified signature by a key outside the
// transaction's own redeem script can never satisfy it, so merging it would
// only inflate the parameter toward an invalid completion.
func TestA32OutOfScriptSignerIgnored(t *testing.T) {
	env := n002Setup(t)
	p, _ := a32Dispatcher(env)
	need := n002MinSignCount(n002CRCCount)
	tx := n002RevertTx(t, env, need, 1)
	p.RevertToDPOSTx = tx
	a32Seed(p, env)

	outPriv, outPub, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	outEnc, err := outPub.EncodePoint(true)
	require.NoError(t, err)
	data := new(bytes.Buffer)
	require.NoError(t, tx.SerializeUnsigned(data))
	hash := tx.Hash()
	p.OnResponseRevertToDPOSTxReceived(&hash, outEnc,
		n002RawSign(t, outPriv, data.Bytes()))

	require.Equal(t, 1, a32SignCount(tx),
		"a signer absent from the redeem script must be ignored")
	require.Len(t, p.revertToDPOSRequests, 1)
}

// TestA32ProductionRevertScriptAdmitsMembers drives registerDistinctSigner
// against the mainnet-shaped script: 36 keys through the production
// CreateRevertToPOWRedeemScript builder, which exists because the standard
// multisig builder caps at 24 keys. The parser must admit script members and
// reject duplicates and outsiders at that width.
func TestA32ProductionRevertScriptAdmitsMembers(t *testing.T) {
	pks := make([]*crypto.PublicKey, 0, 36)
	encoded := make([][]byte, 0, 36)
	for i := 0; i < 36; i++ {
		_, pub, err := crypto.GenerateKeyPair()
		require.NoError(t, err)
		enc, err := pub.EncodePoint(true)
		require.NoError(t, err)
		pks = append(pks, pub)
		encoded = append(encoded, enc)
	}
	code, err := contract.CreateRevertToPOWRedeemScript(25, pks)
	require.NoError(t, err)

	signers := make(map[string]struct{})
	require.True(t, registerDistinctSigner(signers, code, encoded[35], "[test]"),
		"a script member must be admitted")
	require.False(t, registerDistinctSigner(signers, code, encoded[35], "[test]"),
		"the same member must be rejected as a duplicate")

	_, outPub, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	outEnc, err := outPub.EncodePoint(true)
	require.NoError(t, err)
	require.False(t, registerDistinctSigner(signers, code, outEnc, "[test]"),
		"a key outside the script must be rejected")
}
