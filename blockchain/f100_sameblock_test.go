// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// same-block producer/CR-registration + council-member-claim cluster (F-100, F-083) —
// empirical in-block conflict proofs at the block-validation layer. Both mirror a mempool
// conflict slot the block validator never mirrored, so a malicious block-packer can pack a
// pairing the mempool forbids into ONE block:
//   - F-100: a producer owner/node public key colliding across producers, OR a
//     RegisterProducer key == a RegisterCR key, in one block (mempool
//     slotDPoSOwnerPublicKey / slotDPoSNodePublicKey). Committed-state ProducerExists /
//     ExistCR reads never see the sibling tx -> one key bound to two identities.
//   - F-083: two claims by the SAME council member (same CRCouncilCommitteeDID) with
//     DIFFERENT node keys in one block (mempool slotCRCouncilMemberDID). The node-key guard
//     (F-071) does not catch distinct node keys, and processCRCouncilMemberClaimNode
//     captures the member's old key/state OUTSIDE the History forward closure.
// Each test asserts EXPLOIT/FIX (rejected at/above the gate), REPLAY (accepted below the
// gate, byte-identical legacy) and RELATED-TX (distinct identities pass). Reuses the
// f028_sameblock_test.go helpers (f028Tx / f028Block / f028Gate) and the f047 key helpers.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

// f100Key returns a fresh compressed public key ([]byte) plus a standard CHECKSIG redeem
// script wrapping it. The RegisterCR key extraction yields code[1:len-1] == the pubkey, so
// a RegisterProducer whose OwnerKey/NodePublicKey == pk collides with a RegisterCR built
// from code.
func f100Key(t *testing.T) (pk []byte, code []byte) {
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pk, err = pub.EncodePoint(true)
	assert.NoError(t, err)
	code, err = contract.CreateStandardRedeemScript(pub)
	assert.NoError(t, err)
	return pk, code
}

func f100Producer(owner, node []byte) interfaces.Transaction {
	return f028Tx(common2.RegisterProducer, payload.ProducerInfoVersion,
		&payload.ProducerInfo{OwnerKey: owner, NodePublicKey: node}, nil)
}

func f100CR(code []byte) interfaces.Transaction {
	return f028Tx(common2.RegisterCR, payload.CRInfoVersion, &payload.CRInfo{Code: code}, nil)
}

// TestF100ProducerCRSameKey — a RegisterProducer (owner==X) and a RegisterCR whose
// registration public key == X in ONE block bind the same key to a producer AND a CR.
func TestF100ProducerCRSameKey(t *testing.T) {
	pk, code := f100Key(t)
	// Distinct node key so the collision is strictly owner<->CR.
	nodePk, _ := f100Key(t)

	prod := f100Producer(pk, nodePk)
	cr := f100CR(code)

	// Above gate: producer owner key == CR key -> rejected.
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, prod, cr), f028Gate),
		"a RegisterProducer owner key that equals a RegisterCR key in one block must be rejected at/above the gate")
	// Below gate: replay-safe (accepted, byte-identical legacy).
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, prod, cr), f028Gate),
		"below the gate the block must validate byte-identically")
}

// TestF100ProducerNodeCRSameKey — the collision is producer NODE key <-> CR key.
func TestF100ProducerNodeCRSameKey(t *testing.T) {
	pk, code := f100Key(t)   // pk is the CR key
	ownerPk, _ := f100Key(t) // distinct owner
	prod := f100Producer(ownerPk, pk)
	cr := f100CR(code)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, prod, cr), f028Gate),
		"a RegisterProducer node key that equals a RegisterCR key in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, prod, cr), f028Gate),
		"below the gate the block must validate byte-identically")
}

// TestF100TwoProducersSameKey — two RegisterProducer sharing an owner key.
func TestF100TwoProducersSameKey(t *testing.T) {
	pk, _ := f100Key(t)
	nodeA, _ := f100Key(t)
	nodeB, _ := f100Key(t)
	p1 := f100Producer(pk, nodeA)
	p2 := f100Producer(pk, nodeB)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, p1, p2), f028Gate),
		"two producers sharing an owner key in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, p1, p2), f028Gate),
		"below the gate the block must validate byte-identically")
}

// TestF100DistinctKeysPass — a producer and a CR with entirely disjoint keys are
// legitimate and must pass at/above the gate (guards against a false positive).
func TestF100DistinctKeysPass(t *testing.T) {
	ownerPk, _ := f100Key(t)
	nodePk, _ := f100Key(t)
	_, code := f100Key(t) // CR key disjoint from both producer keys
	prod := f100Producer(ownerPk, nodePk)
	cr := f100CR(code)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, prod, cr), f028Gate),
		"a producer and a CR with disjoint keys are legitimate and must pass")

	// A single producer whose owner key EQUALS its own node key must not self-collide.
	shared, _ := f100Key(t)
	selfProd := f100Producer(shared, shared)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, selfProd), f028Gate),
		"a producer with owner==node must not self-collide")
}

// TestF083SameMemberDifferentNodeKey — two CRCouncilMemberClaimNode by the SAME council
// member (same CRCouncilCommitteeDID) with DIFFERENT node keys in one block. The F-071
// node-key guard does not catch distinct node keys; the F-083 DID guard must.
func TestF083SameMemberDifferentNodeKey(t *testing.T) {
	did := common.Uint168{0x08, 0x03, 0x01}
	c1 := f028Tx(common2.CRCouncilMemberClaimNode, payload.CurrentCRClaimDPoSNodeVersion,
		&payload.CRCouncilMemberClaimNode{NodePublicKey: f047NodeKey(t), CRCouncilCommitteeDID: did}, nil)
	c2 := f028Tx(common2.CRCouncilMemberClaimNode, payload.CurrentCRClaimDPoSNodeVersion,
		&payload.CRCouncilMemberClaimNode{NodePublicKey: f047NodeKey(t), CRCouncilCommitteeDID: did}, nil)

	// Above gate: same member, different node keys -> rejected.
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, c2), f028Gate),
		"two claims by the same council member (different node keys) in one block must be rejected at/above the gate")
	// Below gate: replay-safe (accepted).
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, c1, c2), f028Gate),
		"below the gate the block must validate byte-identically")

	// DIFFERENT members with different node keys are legitimate and must pass.
	otherDID := common.Uint168{0x08, 0x03, 0x02}
	cOther := f028Tx(common2.CRCouncilMemberClaimNode, payload.CurrentCRClaimDPoSNodeVersion,
		&payload.CRCouncilMemberClaimNode{NodePublicKey: f047NodeKey(t), CRCouncilCommitteeDID: otherDID}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, cOther), f028Gate),
		"claims by DIFFERENT council members are legitimate and must pass")
}
