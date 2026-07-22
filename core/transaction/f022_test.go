// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// f022Gate is the mainnet StrictMoneyRangeHeight (recovery gate). The signature
// fix is active at/above it; below it the legacy structure-only behavior is
// preserved for replay-safety of pre-gate history.
const f022Gate uint32 = 2260451

// f022GenArbiters generates n arbiter keypairs and returns their private keys
// and ArbiterMembers (public side), retaining the private keys for signing.
func f022GenArbiters(n int) (privs [][]byte, members []state.ArbiterMember) {
	for i := 0; i < n; i++ {
		priv, pub, _ := crypto.GenerateKeyPair()
		pkBuf, _ := pub.EncodePoint(true)
		ar, _ := state.NewOriginArbiter(pkBuf)
		privs = append(privs, priv)
		members = append(members, ar)
	}
	return privs, members
}

// f022MultisigParameter signs the tx's unsigned digest with the first m private
// keys and assembles the standard [len][sig]... multisig Parameter.
func f022MultisigParameter(tx interfaces.Transaction, privs [][]byte, m int) []byte {
	buf := new(bytes.Buffer)
	_ = tx.SerializeUnsigned(buf)
	data := buf.Bytes()
	var param []byte
	for i := 0; i < m; i++ {
		sign, _ := crypto.Sign(privs[i], data)
		param = append(param, byte(len(sign)))
		param = append(param, sign...)
	}
	return param
}

// f022BuildInactive builds an InactiveArbitrators tx with the given sponsor,
// inactive targets, multisig code and program parameter.
func (s *txValidatorSpecialTxTestSuite) f022BuildInactive(
	sponsor []byte, targets [][]byte, code, parameter []byte) interfaces.Transaction {
	p := &payload.InactiveArbitrators{
		Sponsor:     sponsor,
		Arbitrators: targets,
		BlockHeight: f022Gate + 10,
	}
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.InactiveArbitrators,
		payload.InactiveArbitratorsVersion,
		p,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{{Code: code, Parameter: parameter}},
	)
}

// f022SetupCRC wires n freshly-generated CRC arbiters (retaining privs) plus one
// non-CRC active-producer target, returning privs, the M-of-N code, sponsor and
// the target public key. Callers must restore mock state (done via defer).
func (s *txValidatorSpecialTxTestSuite) f022SetupCRC(n int) (
	privs [][]byte, code, sponsor, target []byte) {
	privs, crc := f022GenArbiters(n)
	s.arbitrators.CRCArbitrators = crc
	// A single non-CRC active producer to be the inactive target.
	_, tmembers := f022GenArbiters(1)
	s.arbitrators.ActiveProducer = tmembers
	code = s.createArbitratorsRedeemScript(crc)
	sponsor = crc[0].GetNodePublicKey()
	target = tmembers[0].GetNodePublicKey()
	return privs, code, sponsor, target
}

// TestF022ExploitIsReal proves F-022 is real against production code: a forged
// InactiveArbitrators tx with a valid CRC multisig CODE (all-public info) but an
// invalid/garbage Parameter (no real signatures) is ACCEPTED. Exercised at
// mainnet heights BELOW the recovery gate, where the fix is inactive — this is
// exactly the code that ran on mainnet, so acceptance proves the exploit was
// live. Durable (below-gate behavior is unchanged by the height-gated fix).
func (s *txValidatorSpecialTxTestSuite) TestF022ExploitIsReal() {
	origCRC := s.arbitrators.CRCArbitrators
	origAP := s.arbitrators.ActiveProducer
	defer func() {
		s.arbitrators.CRCArbitrators = origCRC
		s.arbitrators.ActiveProducer = origAP
	}()

	_, code, sponsor, target := s.f022SetupCRC(5)

	// >=5 distinct forged Parameters (no valid signatures).
	forged := [][]byte{
		{},                                // empty
		make([]byte, crypto.SignatureScriptLength),   // one all-zero sig
		make([]byte, crypto.SignatureScriptLength*4), // four all-zero sigs
		[]byte{0x40, 0x01, 0x02, 0x03},               // garbage prefix
		randomSignature(),                            // one random sig
	}
	belowHeights := []uint32{1911200, 2000000, f022Gate - 1}

	accepted := 0
	for _, h := range belowHeights {
		for _, param := range forged {
			tx := s.f022BuildInactive(sponsor, [][]byte{target}, code, param)
			err := CheckInactiveArbitrators(tx, h, f022Gate)
			s.NoError(err, "EXPLOIT: forged unsigned InactiveArbitrators accepted "+
				"below gate (h=%d, paramLen=%d)", h, len(param))
			if err == nil {
				accepted++
			}
		}
	}
	s.GreaterOrEqual(accepted, 5, "exploit must reproduce >=5 times; got %d", accepted)
}

// TestF022FixForgedRejected verifies the fix: at/above the gate a forged unsigned
// InactiveArbitrators is REJECTED; below the gate it is still accepted (replay).
func (s *txValidatorSpecialTxTestSuite) TestF022FixForgedRejected() {
	origCRC := s.arbitrators.CRCArbitrators
	origAP := s.arbitrators.ActiveProducer
	defer func() {
		s.arbitrators.CRCArbitrators = origCRC
		s.arbitrators.ActiveProducer = origAP
	}()

	_, code, sponsor, target := s.f022SetupCRC(5)

	forged := [][]byte{
		make([]byte, crypto.SignatureScriptLength),   // one all-zero sig
		make([]byte, crypto.SignatureScriptLength*4), // four all-zero sigs
		randomSignature(),                            // one random sig
		append([]byte{0x40}, randomSignature()...),   // random-ish
	}
	aboveHeights := []uint32{f022Gate, f022Gate + 1, f022Gate + 40000, 3000000, 5000000}

	rejected := 0
	for _, h := range aboveHeights {
		for _, param := range forged {
			tx := s.f022BuildInactive(sponsor, [][]byte{target}, code, param)
			err := CheckInactiveArbitrators(tx, h, f022Gate)
			s.Error(err, "FIX: forged unsigned InactiveArbitrators must be REJECTED "+
				"at/above gate (h=%d, paramLen=%d)", h, len(param))
			if err != nil {
				rejected++
			}
		}
	}
	s.GreaterOrEqual(rejected, 20, "expected >=20 forgeries rejected; got %d", rejected)

	// Replay-safety: identical forgery still accepted below the gate.
	tx := s.f022BuildInactive(sponsor, [][]byte{target}, code, randomSignature())
	s.NoError(CheckInactiveArbitrators(tx, f022Gate-1, f022Gate),
		"REPLAY-SAFETY: below-gate forgery must remain accepted")
}

// TestF022LegitSignedAccepted verifies the fix does not break genuine txs: a real
// M-of-N CRC multisig over the tx's unsigned digest is ACCEPTED at/above the gate
// (and below), while corrupting one signature is REJECTED at/above the gate.
func (s *txValidatorSpecialTxTestSuite) TestF022LegitSignedAccepted() {
	origCRC := s.arbitrators.CRCArbitrators
	origAP := s.arbitrators.ActiveProducer
	defer func() {
		s.arbitrators.CRCArbitrators = origCRC
		s.arbitrators.ActiveProducer = origAP
	}()

	n := 5
	m := n*2/3 + 1 // matches createArbitratorsRedeemScript threshold
	privs, code, sponsor, target := s.f022SetupCRC(n)

	// Build once to compute the digest, sign it, then attach the real Parameter.
	tx := s.f022BuildInactive(sponsor, [][]byte{target}, code, nil)
	tx.Programs()[0].Parameter = f022MultisigParameter(tx, privs, m)

	s.NoError(CheckInactiveArbitrators(tx, f022Gate+100, f022Gate),
		"LEGIT: genuine %d-of-%d CRC-signed InactiveArbitrators must be accepted "+
			"at/above gate", m, n)
	s.NoError(CheckInactiveArbitrators(tx, f022Gate-100, f022Gate),
		"LEGIT: genuine signed tx must also be accepted below gate")

	// Corrupt one signature byte -> must be rejected at/above the gate.
	bad := s.f022BuildInactive(sponsor, [][]byte{target}, code, nil)
	param := f022MultisigParameter(bad, privs, m)
	param[len(param)-1] ^= 0xFF
	bad.Programs()[0].Parameter = param
	s.Error(CheckInactiveArbitrators(bad, f022Gate+100, f022Gate),
		"tampered signature must be rejected at/above gate")

	// Too few signatures (m-1) -> rejected at/above the gate.
	few := s.f022BuildInactive(sponsor, [][]byte{target}, code, nil)
	few.Programs()[0].Parameter = f022MultisigParameter(few, privs, m-1)
	s.Error(CheckInactiveArbitrators(few, f022Gate+100, f022Gate),
		"insufficient signatures must be rejected at/above gate")
}

// TestF022SiblingRevertToDPOS covers the whole auth-bypass class: the all-arbiter
// variant checkArbitratorsSignatures (RevertToDPOS). Forged rejected at/above
// gate, accepted below; genuine arbiter multisig accepted at/above gate.
func (s *txValidatorSpecialTxTestSuite) TestF022SiblingRevertToDPOS() {
	origCur := s.arbitrators.CurrentArbitrators
	defer func() { s.arbitrators.CurrentArbitrators = origCur }()

	n := 5
	m := n*2/3 + 1
	privs, arbs := f022GenArbiters(n)
	s.arbitrators.CurrentArbitrators = arbs // IsArbitrator + GetArbitrators universe
	code := s.createArbitratorsRedeemScript(arbs)

	// The all-arbiter variant validates the program code + (gated) signatures; it
	// does not read the payload, so a RevertToDPOS-shaped tx is sufficient.
	buildRevert := func(param []byte) interfaces.Transaction {
		return functions.CreateTransaction(
			common2.TxVersion09, common2.RevertToDPOS, payload.RevertToDPOSVersion,
			&payload.RevertToDPOS{}, []*common2.Attribute{}, []*common2.Input{},
			[]*common2.Output{}, 0, []*program.Program{{Code: code, Parameter: param}})
	}

	// Forged: rejected at/above gate, accepted below.
	forged := buildRevert(randomSignature())
	s.Error(checkArbitratorsSignatures(forged, f022Gate, f022Gate),
		"SIBLING: forged RevertToDPOS multisig must be rejected at/above gate")
	s.NoError(checkArbitratorsSignatures(forged, f022Gate-1, f022Gate),
		"SIBLING replay-safety: forged accepted below gate")

	// Genuine arbiter multisig: accepted at/above gate.
	legit := buildRevert(nil)
	legit.Programs()[0].Parameter = f022MultisigParameter(legit, privs, m)
	s.NoError(checkArbitratorsSignatures(legit, f022Gate, f022Gate),
		"SIBLING: genuine arbiter-signed RevertToDPOS must be accepted at/above gate")
}

// TestF022PathBGatesOnBlockHeight verifies the blockchain-copy (Path B, invoked
// by PreProcessSpecialTx during InitCheckpoint / connectBlock) gates on the
// BLOCK height, not the current tip. A prior bug gated on GetHeight(); during
// fresh-from-genesis replay the tip is pinned above the gate, so it wrongly
// re-verified signatures on below-gate historical special txs (a bootstrap
// hazard). With the fix, gating follows the passed block height regardless of
// the (near-zero) live tip.
func (s *txValidatorSpecialTxTestSuite) TestF022PathBGatesOnBlockHeight() {
	gate := s.Chain.GetParams().StrictMoneyRangeHeight

	prev := blockchain.DefaultLedger.Blockchain
	blockchain.DefaultLedger.Blockchain = s.Chain // so arbitratorsMultisigActive can read the gate
	defer func() { blockchain.DefaultLedger.Blockchain = prev }()

	origCRC := s.arbitrators.CRCArbitrators
	origAP := s.arbitrators.ActiveProducer
	defer func() {
		s.arbitrators.CRCArbitrators = origCRC
		s.arbitrators.ActiveProducer = origAP
	}()

	_, code, sponsor, target := s.f022SetupCRC(5)
	tx := s.f022BuildInactive(sponsor, [][]byte{target}, code, randomSignature())

	// The live tip (s.Chain.GetHeight()) is ~0, far below the gate. If Path B
	// (wrongly) gated on the tip, ALL of these would be structure-only/accepted.
	// The fix gates on the passed block height:
	s.NoError(blockchain.CheckInactiveArbitrators(tx, gate-1),
		"Path B below-gate block: structure-only, forged accepted (replay-safe)")
	s.Error(blockchain.CheckInactiveArbitrators(tx, gate),
		"Path B at-gate block: signatures verified, forged REJECTED")
	s.Error(blockchain.CheckInactiveArbitrators(tx, gate+100000),
		"Path B above-gate block: signatures verified, forged REJECTED")
}
