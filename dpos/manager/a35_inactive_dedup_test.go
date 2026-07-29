// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// InactiveArbitrators response dedup (rescue-path defect 4 site A, A3.5).
//
// OnResponseInactiveArbitratorsReceived has the same defect as the
// RevertToDPOS response path: each response signature is verified, but no set
// of seen signers is kept, and completeness is counted from the length of the
// program parameter. One CRC arbiter responding repeatedly makes the
// transaction count-complete with fewer than the required nine distinct
// signatures, so the emergency ForceChange the whole rescue path exists to
// deliver is submitted consensus-invalid and rejected by every peer.
//
// Completion cannot be observed through the transaction pool here, because the
// harness provides none: reaching the completion branch surfaces as a panic in
// AppendToTxnPool, which the respond helper recovers and reports. The
// distinct-signer merging itself is observed on the transaction's own program
// parameter.
package manager

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/require"
)

// a35Arbiters answers the one lookup the completion branch makes: the CRC
// arbiter set whose two-thirds-plus-one majority the transaction needs.
type a35Arbiters struct {
	state.Arbitrators
	pubs [][]byte
}

func (a *a35Arbiters) GetCRCArbiters() []*state.ArbiterInfo {
	out := make([]*state.ArbiterInfo, 0, len(a.pubs))
	for _, p := range a.pubs {
		out = append(out, &state.ArbiterInfo{NodePublicKey: p, IsNormal: true})
	}
	return out
}

func a35Dispatcher(env *n002Env) *ProposalDispatcher {
	arb := &a35Arbiters{pubs: env.encoded}
	mgr := &DPOSManager{publicKey: env.encoded[0], arbitrators: arb}
	p := &ProposalDispatcher{
		signedTxs: make(map[common.Uint256]interface{}),
		cfg: ProposalDispatcherConfig{
			EventAnalyzerConfig: EventAnalyzerConfig{Arbitrators: arb},
			Manager:             mgr,
		},
	}
	mgr.dispatcher = p
	return p
}

// a35InactiveTx builds what CreateInactiveArbitrators produces: a
// nine-of-twelve code over the CRC arbiter keys and exactly ONE signature, the
// sponsor's, in the program parameter.
func a35InactiveTx(t *testing.T, env *n002Env) interfaces.Transaction {
	t.Helper()
	code, err := contract.CreateMultiSigRedeemScript(
		n002MinSignCount(n002CRCCount), env.pubs)
	require.NoError(t, err)
	ct := contract.Contract{Prefix: contract.PrefixMultiSig, Code: code}
	ph := ct.ToProgramHash()
	tx := functions.CreateTransaction(
		common2.TxVersion09, common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion,
		&payload.InactiveArbitrators{
			Sponsor:     env.encoded[0],
			Arbitrators: [][]byte{env.encoded[11]},
			BlockHeight: env.gate + 2,
		},
		[]*common2.Attribute{{Usage: common2.Script, Data: ph.Bytes()}},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*pg.Program{{Code: code}},
	)
	buf := new(bytes.Buffer)
	require.NoError(t, tx.SerializeUnsigned(buf))
	sig := n002RawSign(t, env.privs[0], buf.Bytes())
	tx.SetPrograms([]*pg.Program{{
		Code:      code,
		Parameter: append([]byte{byte(len(sig))}, sig...),
	}})
	return tx
}

// a35Respond signs the current inactive-arbitrators transaction with one CRC
// key and hands the response to the dispatcher. It recovers and reports
// whether the handler panicked, which is what reaching the completion branch
// looks like under this harness (see the package comment above).
func a35Respond(t *testing.T, p *ProposalDispatcher, env *n002Env, signer int) (panicked bool) {
	t.Helper()
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	data := new(bytes.Buffer)
	require.NoError(t, p.currentInactiveArbitratorTx.SerializeUnsigned(data))
	sign := n002RawSign(t, env.privs[signer], data.Bytes())
	hash := p.currentInactiveArbitratorTx.Hash()
	p.OnResponseInactiveArbitratorsReceived(&hash, env.encoded[signer], sign)
	return
}

func a35Seed(p *ProposalDispatcher, env *n002Env) {
	p.inactiveArbitratorsRequests = map[string]struct{}{
		common.BytesToHexString(env.encoded[0]): {},
	}
}

// TestA35DuplicateSignerCannotCompleteTx is the defect. The transaction starts
// carrying the sponsor's own signature; one other CRC arbiter then answers
// often enough to reach the nine-signature threshold by count alone.
func TestA35DuplicateSignerCannotCompleteTx(t *testing.T) {
	env := n002Setup(t)
	p := a35Dispatcher(env)
	tx := a35InactiveTx(t, env)
	p.currentInactiveArbitratorTx = tx
	a35Seed(p, env)
	require.Equal(t, 1, a32SignCount(tx), "the sponsor's own signature is already in")

	need := n002MinSignCount(n002CRCCount)
	completed := false
	for i := 0; i < need; i++ {
		completed = a35Respond(t, p, env, 1) || completed
	}

	require.Equal(t, 2, a32SignCount(tx),
		"a signer that answers repeatedly must contribute exactly one signature")
	require.False(t, completed,
		"two distinct signers must not reach the emergency completion branch")
}

// TestA35SponsorEchoDoesNotDoubleCount pins the seeding: a response echoing
// the sponsor's own key back must not be merged a second time.
func TestA35SponsorEchoDoesNotDoubleCount(t *testing.T) {
	env := n002Setup(t)
	p := a35Dispatcher(env)
	tx := a35InactiveTx(t, env)
	p.currentInactiveArbitratorTx = tx
	a35Seed(p, env)

	a35Respond(t, p, env, 0)

	require.Equal(t, 1, a32SignCount(tx),
		"the sponsor's embedded signature must not be merged again")
}

// TestA35DistinctSignersCompleteTx is the control. One response from each
// required distinct signer merges every signature and reaches the completion
// branch; the uniqueness set must not block the legitimate round.
func TestA35DistinctSignersCompleteTx(t *testing.T) {
	env := n002Setup(t)
	p := a35Dispatcher(env)
	tx := a35InactiveTx(t, env)
	p.currentInactiveArbitratorTx = tx
	a35Seed(p, env)

	need := n002MinSignCount(n002CRCCount)
	completed := false
	for i := 1; i < need; i++ {
		completed = a35Respond(t, p, env, i) || completed
	}

	require.Equal(t, need, a32SignCount(tx),
		"every distinct signer must contribute a signature")
	require.True(t, completed,
		"the required number of distinct signers must reach the completion branch")
}

// TestA35GarbageSignatureCannotClaimSlot pins the order of operations: the
// signer set is consulted only AFTER the signature verifies, so a forged
// message naming a real CRC arbiter cannot occupy that arbiter's slot and
// lock its genuine response out.
func TestA35GarbageSignatureCannotClaimSlot(t *testing.T) {
	env := n002Setup(t)
	p := a35Dispatcher(env)
	tx := a35InactiveTx(t, env)
	p.currentInactiveArbitratorTx = tx
	a35Seed(p, env)

	hash := tx.Hash()
	p.OnResponseInactiveArbitratorsReceived(&hash, env.encoded[1],
		make([]byte, crypto.SignatureLength))

	require.Equal(t, 1, a32SignCount(tx),
		"a response that fails verification must merge nothing")
	require.Len(t, p.inactiveArbitratorsRequests, 1,
		"a response that fails verification must not claim the signer's slot")

	a35Respond(t, p, env, 1)
	require.Equal(t, 2, a32SignCount(tx),
		"the genuine response must still merge after the forgery")
}

// TestA35OutOfScriptSignerIgnored: a verified signature by a key outside the
// transaction's redeem script can never satisfy it and must contribute
// nothing.
func TestA35OutOfScriptSignerIgnored(t *testing.T) {
	env := n002Setup(t)
	p := a35Dispatcher(env)
	tx := a35InactiveTx(t, env)
	p.currentInactiveArbitratorTx = tx
	a35Seed(p, env)

	outPriv, outPub, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	outEnc, err := outPub.EncodePoint(true)
	require.NoError(t, err)
	data := new(bytes.Buffer)
	require.NoError(t, tx.SerializeUnsigned(data))
	hash := tx.Hash()
	p.OnResponseInactiveArbitratorsReceived(&hash, outEnc,
		n002RawSign(t, outPriv, data.Bytes()))

	require.Equal(t, 1, a32SignCount(tx),
		"a signer absent from the redeem script must be ignored")
	require.Len(t, p.inactiveArbitratorsRequests, 1)
}
