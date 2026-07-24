// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-10 / FV-08 — BLOCK-LEVEL IDENTITY-CONFLICT PARITY.
//
// The mempool holds FIVE transaction types in ONE conflict slot keyed on the DPoS node
// public key (mempool/conflictmanager.go slotDPoSNodePublicKey: RegisterProducer,
// UpdateProducer, ActivateProducer, RegisterCR, CRCouncilMemberClaimNode) and TWO in
// slotDPoSNickname (RegisterProducer, UpdateProducer). The block mirror had arms for two
// of the five and NO nickname handling of any kind, so a malicious block packer -- which
// does not have to route anything through a stock mempool -- could pack a pairing the
// mempool forbids into one block. Every per-transaction check that might have caught it
// reads COMMITTED state and so cannot see an earlier transaction in the same block.
//
// These tests drive the REAL (*BlockChain).CheckBlockSanity end to end using the
// wiring_blocksanity_test.go harness (real AuxPow, real PoW, real merkle root), so the
// production call site inside CheckBlockSanity is part of what is being asserted:
// TestWiringBlockSanityBaselineAccepts proves the harness block is otherwise valid, and
// each test below adds exactly ONE defect.
//
// MUTATION PROOF (run, recorded in the batch report): delete any one of the three new arms
// in CheckSameBlockConflicts -- the UpdateProducer case, the producerCRKeys write in the
// CRCouncilMemberClaimNode case, or the addProducerNickname calls -- and the corresponding
// test below FAILS with "PARITY GAP". Deleting the whole CheckSameBlockConflicts call site
// fails all of them.
package blockchain

import (
	"math"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
)

// nx10Key returns a fresh compressed public key and the standard CHECKSIG redeem script
// wrapping it. RegisterCR's conflict key is derived as code[1:len-1] == the public key, so
// a producer key equal to pk collides with a RegisterCR built from code.
func nx10Key(t *testing.T) (pk []byte, code []byte) {
	t.Helper()
	_, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	pk, err = pub.EncodePoint(true)
	if err != nil {
		t.Fatalf("encode point: %v", err)
	}
	code, err = contract.CreateStandardRedeemScript(pub)
	if err != nil {
		t.Fatalf("redeem script: %v", err)
	}
	return pk, code
}

// nx10Tx builds a transaction that passes CheckTransactionSanity at the heights used here
// (>= 2260450): one input, one ELA output, one well-formed program, and a payload version
// each type's HeightVersionCheck accepts. `salt` keeps the txid and the UTXO distinct so
// the duplicate-txid / duplicate-UTXO checks that run FIRST are never what rejects a block.
func nx10Tx(t *testing.T, txType common2.TxType, ver byte, pld interfaces.Payload, salt byte) interfaces.Transaction {
	t.Helper()
	_, code := nx10Key(t)
	var prev common.Uint256
	prev[0] = 0xA1
	prev[1] = salt
	return functions.CreateTransaction(
		common2.TxVersion09,
		txType,
		ver,
		pld,
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: prev, Index: uint16(salt)},
			Sequence: math.MaxUint32,
		}},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: 1, ProgramHash: common.Uint168{},
			Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}}},
		0,
		[]*program.Program{{Code: code, Parameter: []byte{0x00}}},
	)
}

func nx10RegisterProducer(t *testing.T, owner, node []byte, nick string, salt byte) interfaces.Transaction {
	return nx10Tx(t, common2.RegisterProducer, payload.ProducerInfoVersion,
		&payload.ProducerInfo{OwnerKey: owner, NodePublicKey: node, NickName: nick}, salt)
}

func nx10UpdateProducer(t *testing.T, owner, node []byte, nick string, salt byte) interfaces.Transaction {
	return nx10Tx(t, common2.UpdateProducer, payload.ProducerInfoVersion,
		&payload.ProducerInfo{OwnerKey: owner, NodePublicKey: node, NickName: nick}, salt)
}

func nx10RegisterCR(t *testing.T, code []byte, salt byte) interfaces.Transaction {
	return nx10Tx(t, common2.RegisterCR, payload.CRInfoVersion,
		&payload.CRInfo{Code: code, NickName: "cr-" + string(rune('a'+salt))}, salt)
}

func nx10ClaimNode(t *testing.T, node []byte, did common.Uint168, salt byte) interfaces.Transaction {
	return nx10Tx(t, common2.CRCouncilMemberClaimNode, payload.CurrentCRClaimDPoSNodeVersion,
		&payload.CRCouncilMemberClaimNode{NodePublicKey: node, CRCouncilCommitteeDID: did}, salt)
}

// nx10Assert runs one pairing through the real CheckBlockSanity at three heights and
// asserts the gate-1 shape: REJECTED at and above the gate for the stated reason, ACCEPTED
// below it (byte-identical replay of retained history).
func nx10Assert(t *testing.T, wantErr string, mk func() []interfaces.Transaction) {
	t.Helper()
	b := wiringChain(t)

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		err := b.CheckBlockSanity(wiringBlock(t, h, mk()...))
		if err == nil {
			t.Fatalf("PARITY GAP at height %d: CheckBlockSanity ACCEPTED a block the mempool's "+
				"conflict slots forbid — the block-level arm is missing", h)
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("at height %d the block was rejected for the WRONG reason (%v); the "+
				"same-block identity-conflict arm must be what rejects it", h, err)
		}
	}

	if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate, mk()...)); err != nil {
		t.Fatalf("REPLAY BREAK: the identical block below the gate must be accepted, got: %v", err)
	}
}

// nx10AssertAccepted is the false-positive control: a legitimate block with DISJOINT
// identities must pass at and above the gate.
func nx10AssertAccepted(t *testing.T, mk func() []interfaces.Transaction) {
	t.Helper()
	b := wiringChain(t)
	if err := b.CheckBlockSanity(wiringBlock(t, wiringGate+1, mk()...)); err != nil {
		t.Fatalf("FALSE POSITIVE: a block with disjoint identities must be accepted, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// slotDPoSNodePublicKey — the UpdateProducer member (had no block-level arm at all).
// -----------------------------------------------------------------------------

// TestNX10UpdateProducerVsRegisterCRSameNodeKey is the pairing the merged finding names
// first: UpdateProducer(node=X) + RegisterCR(key=X). CheckDuplicateTx shares
// existingProducerNode across RegisterProducer/UpdateProducer only and has no RegisterCR
// arm; the F-100 producerCRKeys map had no UpdateProducer arm. UpdateProducer's
// ExistCR(nodeCode) and RegisterCR's ProducerExists are both committed-state reads.
func TestNX10UpdateProducerVsRegisterCRSameNodeKey(t *testing.T) {
	pk, code := nx10Key(t) // the shared key: producer NODE key and CR registration key
	owner, _ := nx10Key(t)
	nx10Assert(t, "conflicting producer/CR public key", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10UpdateProducer(t, owner, pk, "upd-node-vs-cr", 1),
			nx10RegisterCR(t, code, 2),
		}
	})
}

// TestNX10UpdateProducerVsRegisterCRSameOwnerKey — the same slot's owner-key half
// (mempool slotDPoSOwnerPublicKey / slotDPoSOwnerNodePublicKeys, which share one block-level
// map by design).
func TestNX10UpdateProducerVsRegisterCRSameOwnerKey(t *testing.T) {
	pk, code := nx10Key(t)
	node, _ := nx10Key(t)
	nx10Assert(t, "conflicting producer/CR public key", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10UpdateProducer(t, pk, node, "upd-owner-vs-cr", 3),
			nx10RegisterCR(t, code, 4),
		}
	})
}

// -----------------------------------------------------------------------------
// slotDPoSNodePublicKey — the CRCouncilMemberClaimNode member (its key only ever reached
// the F-071 claim-vs-claim map, which is never compared against the producer/CR map).
// -----------------------------------------------------------------------------

func TestNX10RegisterProducerVsClaimNodeSameNodeKey(t *testing.T) {
	pk, _ := nx10Key(t)
	owner, _ := nx10Key(t)
	did := common.Uint168{0x10, 0x01}
	nx10Assert(t, "conflicting producer/CR public key", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10RegisterProducer(t, owner, pk, "reg-vs-claim", 5),
			nx10ClaimNode(t, pk, did, 6),
		}
	})
}

func TestNX10UpdateProducerVsClaimNodeSameNodeKey(t *testing.T) {
	pk, _ := nx10Key(t)
	owner, _ := nx10Key(t)
	did := common.Uint168{0x10, 0x02}
	nx10Assert(t, "conflicting producer/CR public key", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10UpdateProducer(t, owner, pk, "upd-vs-claim", 7),
			nx10ClaimNode(t, pk, did, 8),
		}
	})
}

// TestNX10ClaimNodeVsRegisterCRSameKey — the two non-producer members of the same slot.
func TestNX10ClaimNodeVsRegisterCRSameKey(t *testing.T) {
	pk, code := nx10Key(t)
	did := common.Uint168{0x10, 0x03}
	nx10Assert(t, "conflicting producer/CR public key", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10RegisterCR(t, code, 9),
			nx10ClaimNode(t, pk, did, 10),
		}
	})
}

// -----------------------------------------------------------------------------
// slotDPoSNickname — FV-08's genuinely new half: there was NO nickname handling anywhere
// at block level, and StateKeyFrame.Nicknames is a SET, so the two forward inserts are
// idempotent while the two reverts each delete once.
// -----------------------------------------------------------------------------

func TestFV08TwoRegisterProducersOneNickname(t *testing.T) {
	o1, _ := nx10Key(t)
	n1, _ := nx10Key(t)
	o2, _ := nx10Key(t)
	n2, _ := nx10Key(t)
	nx10Assert(t, "conflicting producer nickname", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10RegisterProducer(t, o1, n1, "one-nickname", 11),
			nx10RegisterProducer(t, o2, n2, "one-nickname", 12),
		}
	})
}

func TestFV08RegisterAndUpdateOneNickname(t *testing.T) {
	o1, _ := nx10Key(t)
	n1, _ := nx10Key(t)
	o2, _ := nx10Key(t)
	n2, _ := nx10Key(t)
	nx10Assert(t, "conflicting producer nickname", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10RegisterProducer(t, o1, n1, "shared-nick", 13),
			nx10UpdateProducer(t, o2, n2, "shared-nick", 14),
		}
	})
}

func TestFV08TwoUpdateProducersOneNickname(t *testing.T) {
	o1, _ := nx10Key(t)
	n1, _ := nx10Key(t)
	o2, _ := nx10Key(t)
	n2, _ := nx10Key(t)
	nx10Assert(t, "conflicting producer nickname", func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10UpdateProducer(t, o1, n1, "both-update", 15),
			nx10UpdateProducer(t, o2, n2, "both-update", 16),
		}
	})
}

// -----------------------------------------------------------------------------
// FALSE-POSITIVE CONTROLS — without these the arms above could be a blanket reject.
// -----------------------------------------------------------------------------

func TestNX10DisjointIdentitiesPass(t *testing.T) {
	o1, _ := nx10Key(t)
	n1, _ := nx10Key(t)
	o2, _ := nx10Key(t)
	n2, _ := nx10Key(t)
	_, crCode := nx10Key(t)
	claimKey, _ := nx10Key(t)
	did := common.Uint168{0x10, 0x04}

	// Four identity transactions, every key and every nickname distinct: legitimate.
	nx10AssertAccepted(t, func() []interfaces.Transaction {
		return []interfaces.Transaction{
			nx10RegisterProducer(t, o1, n1, "alpha", 17),
			nx10UpdateProducer(t, o2, n2, "beta", 18),
			nx10RegisterCR(t, crCode, 19),
			nx10ClaimNode(t, claimKey, did, 20),
		}
	})

	// An UpdateProducer whose owner key EQUALS its own node key must not self-collide
	// (the dedupHexKeys path, mirroring the mempool's strDPoSOwnerNodePublicKeys dedup).
	shared, _ := nx10Key(t)
	nx10AssertAccepted(t, func() []interfaces.Transaction {
		return []interfaces.Transaction{nx10UpdateProducer(t, shared, shared, "self", 21)}
	})
}
