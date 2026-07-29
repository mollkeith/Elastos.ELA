// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// The DPoS gossip handler wiring.
//
// OnRevertToDPOSTxReceived and OnInactiveArbitratorsReceived run a pre-check
// before handing the message to the dispatcher. The message they receive carries
// the sponsor's single signature, and on a restarted mainnet the chain tip is
// above StrictMoneyRangeHeight from the first block, so a pre-check that demands
// full M-of-N drops every legitimate message permanently: no emergency
// ForceChange, no way back out of PoW.
//
// These tests drive the real handler against a real nine-of-twelve message with
// one signature, at a tip above the gate, and observe the dispatcher's signedTxs
// map, which the handler reaches only if the pre-check accepted.
//
//	accepted   -> signedTxs holds the tx hash
//	rejected   -> signedTxs is empty
//
// Wire the handler to the complete-transaction check and the first test fails.
// Delete the pre-check call entirely and the second fails.
package manager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	dposaccount "github.com/elastos/Elastos.ELA/dpos/account"
	dpeer "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/p2p"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const n002CRCCount = 12

// n002Arbiters answers exactly the lookups the gossip structure check makes.
type n002Arbiters struct {
	state.Arbitrators
	pubs [][]byte
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

func (a *n002Arbiters) IsArbitrator(pk []byte) bool {
	for _, p := range a.pubs {
		if bytes.Equal(p, pk) {
			return true
		}
	}
	return false
}

// n002Account and n002Network are the two collaborators the dispatcher touches
// after it accepts the message. Neither decides anything.
type n002Account struct{ dposaccount.Account }

func (n002Account) SignTx(interfaces.Transaction) ([]byte, error) { return []byte{}, nil }

type n002Network struct{ DPOSNetwork }

func (n002Network) SendMessageToPeer(dpeer.PID, p2p.Message) error { return nil }

// n002RawSign produces the same fixed-width r||s signature crypto.Sign produces.
// It fills in the public half of the ecdsa key, which crypto.Sign leaves zero;
// Go 1.20 accepts a key without it and later toolchains do not, so signing here
// keeps the suite runnable on both.
func n002RawSign(t *testing.T, priv, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	key := new(ecdsa.PrivateKey)
	key.Curve = crypto.DefaultCurve
	key.D = new(big.Int).SetBytes(priv)
	key.PublicKey.X, key.PublicKey.Y = crypto.DefaultCurve.ScalarBaseMult(priv)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)
	sig := make([]byte, crypto.SignatureLength)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[crypto.SignerLength-len(rb):], rb)
	copy(sig[crypto.SignatureLength-len(sb):], sb)
	return sig
}

type n002Env struct {
	privs   [][]byte
	pubs    []*crypto.PublicKey
	encoded [][]byte
	gate    uint32
}

// n002Setup installs a ledger whose arbiters the test can sign for and whose
// chain tip is above StrictMoneyRangeHeight, the condition a restarted mainnet
// is in from its first block.
func n002Setup(t *testing.T) *n002Env {
	t.Helper()
	env := &n002Env{gate: config.GetDefaultParams().StrictMoneyRangeHeight}
	for i := 0; i < n002CRCCount; i++ {
		priv, pub, err := crypto.GenerateKeyPair()
		require.NoError(t, err)
		enc, err := pub.EncodePoint(true)
		require.NoError(t, err)
		env.privs = append(env.privs, priv)
		env.pubs = append(env.pubs, pub)
		env.encoded = append(env.encoded, enc)
	}

	// getHeight is len(Nodes)-1, so this tip is gate+1.
	chain := &blockchain.BlockChain{
		Nodes: make([]*blockchain.BlockNode, env.gate+2),
	}
	require.Greater(t, chain.GetHeight(), env.gate,
		"the harness must reproduce a tip above the gate")

	prev := blockchain.DefaultLedger
	blockchain.DefaultLedger = &blockchain.Ledger{
		Arbitrators: &n002Arbiters{pubs: env.encoded},
		Blockchain:  chain,
	}
	t.Cleanup(func() { blockchain.DefaultLedger = prev })
	return env
}

func n002MinSignCount(n int) int {
	return int(float64(n)*state.MajoritySignRatioNumerator/
		state.MajoritySignRatioDenominator) + 1
}

// n002RevertTx builds the RevertToDPOS message the sponsor broadcasts: an
// m-of-twelve code over the arbiter keys and exactly ONE signature, which is what
// ProposalDispatcher produces before the gossip round collects the rest.
func n002RevertTx(t *testing.T, env *n002Env, m, signers int) interfaces.Transaction {
	t.Helper()
	code, err := contract.CreateMultiSigRedeemScript(m, env.pubs)
	require.NoError(t, err)
	ct := contract.Contract{Prefix: contract.PrefixMultiSig, Code: code}
	ph := ct.ToProgramHash()
	tx := functions.CreateTransaction(
		common2.TxVersion09, common2.RevertToDPOS, payload.RevertToDPOSVersion,
		&payload.RevertToDPOS{WorkHeightInterval: payload.WorkHeightInterval},
		[]*common2.Attribute{{Usage: common2.Script, Data: ph.Bytes()}},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*pg.Program{{Code: code}},
	)
	buf := new(bytes.Buffer)
	require.NoError(t, tx.SerializeUnsigned(buf))
	var param []byte
	for i := 0; i < signers; i++ {
		sig := n002RawSign(t, env.privs[i], buf.Bytes())
		param = append(param, byte(len(sig)))
		param = append(param, sig...)
	}
	tx.SetPrograms([]*pg.Program{{Code: code, Parameter: param}})
	return tx
}

func n002Manager(env *n002Env) *DPOSManager {
	arb := blockchain.DefaultLedger.Arbitrators
	mgr := &DPOSManager{publicKey: env.encoded[0], arbitrators: arb}
	disp := &ProposalDispatcher{
		signedTxs: make(map[common.Uint256]interface{}),
		cfg: ProposalDispatcherConfig{
			Manager: mgr,
			Account: n002Account{},
			Network: n002Network{},
		},
	}
	mgr.dispatcher = disp
	return mgr
}

// n002Deliver hands the message to the handler. It recovers, because a handler
// wired to the complete-transaction check reads the chain params through the
// ledger, which a test in this package cannot populate: the panic is reported as
// a non-acceptance rather than crashing the run.
func n002Deliver(t *testing.T, d *DPOSManager, tx interfaces.Transaction) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Logf("gossip handler did not accept the message: %v", r)
		}
	}()
	d.OnRevertToDPOSTxReceived(dpeer.PID{}, tx)
}

// TestN002GossipHandlerAcceptsSingleSignature is the defect. Above the gate the
// handler must still hand the singly-signed RevertToDPOS message to the
// dispatcher, otherwise a chain stuck in PoW can never return to DPoS.
func TestN002GossipHandlerAcceptsSingleSignature(t *testing.T) {
	env := n002Setup(t)
	d := n002Manager(env)
	tx := n002RevertTx(t, env, n002MinSignCount(n002CRCCount), 1)

	n002Deliver(t, d, tx)

	_, ok := d.dispatcher.signedTxs[tx.Hash()]
	assert.True(t, ok,
		"the gossip handler must accept the singly-signed message that starts the round")
}

// TestN002GossipHandlerRejectsBadStructure pins the pre-check call itself. Remove
// it from the handler and an under-threshold multisig code reaches the dispatcher.
func TestN002GossipHandlerRejectsBadStructure(t *testing.T) {
	env := n002Setup(t)
	d := n002Manager(env)
	tx := n002RevertTx(t, env, 1, 1)

	n002Deliver(t, d, tx)

	assert.Empty(t, d.dispatcher.signedTxs,
		"the gossip handler must still reject an under-threshold multisig code")
}
