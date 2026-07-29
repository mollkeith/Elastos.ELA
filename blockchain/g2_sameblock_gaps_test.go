// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Two same-block conflict arms that shipped with NO discriminating test.
//
// THE EVIDENCE GAP THIS CLOSES. CheckSameBlockConflicts mirrors fourteen mempool conflict
// slots. A mutation battery neutered each arm in turn and measured the shipping gate. Two
// arms survived — the guard could be made to never fire and every suite stayed green:
//
//	blockvalidator.go UpdateProducer arm  : `if _, exists := producerCRKeys[k]; exists`
//	blockvalidator.go ClaimNode  arm      : `if _, exists := claimNodeKeys[nodeKey]; exists`
//
// f100_sameblock_test.go covers the RegisterProducer and RegisterCR arms of the same shared
// map and the F-083 council-member-DID arm, but never a pair of UpdateProducer transactions
// and never two claims of the SAME node key. Both are the malicious-block-packer case the
// family exists for: the per-transaction checks (ProducerExists, ClaimedDPoSKeys) are
// COMMITTED-state reads that cannot see a sibling transaction in the same block.
//
// The ClaimNode assertion below is deliberately keyed on the ARM`S OWN error message. Two
// claims sharing a node key are also caught one statement later by the NX-10/FV-08
// producerCRKeys guard, which returns a different message — so a test that only asserted
// "an error came back" would stay green with the F-071 arm disarmed. That is precisely how
// this arm survived.
//
// FAIL-ON-PRISTINE (measured, per arm): neuter the arm`s `exists` test and the matching
// test below reports "ACCEPTED".
//
// Reuses the f028_sameblock_test.go helpers (f028Tx / f028Block / f028Gate), the f100 key
// helper and f047NodeKey. No new height literal: f028Gate is StrictMoneyRangeHeight.
package blockchain_test

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

func g2UpdateProducer(owner, node []byte) interfaces.Transaction {
	return f028Tx(common2.UpdateProducer, payload.ProducerInfoVersion,
		&payload.ProducerInfo{OwnerKey: owner, NodePublicKey: node}, nil)
}

func g2ClaimNode(node []byte, did common.Uint168) interfaces.Transaction {
	return f028Tx(common2.CRCouncilMemberClaimNode, payload.CurrentCRClaimDPoSNodeVersion,
		&payload.CRCouncilMemberClaimNode{NodePublicKey: node, CRCouncilCommitteeDID: did}, nil)
}

// TestG2UpdateProducerSameKeyConflict — the UpdateProducer arm of the F-100 shared
// producer/CR key map. Two UpdateProducer transactions in one block re-pointing the SAME
// owner key: the second is validated against committed state that still shows the
// pre-block binding, so both pass and one key ends up bound twice.
func TestG2UpdateProducerSameKeyConflict(t *testing.T) {
	ownerPk, _ := f100Key(t)
	nodeA, _ := f100Key(t)
	nodeB, _ := f100Key(t)

	u1 := g2UpdateProducer(ownerPk, nodeA)
	u2 := g2UpdateProducer(ownerPk, nodeB) // same owner key, different node key

	err := blockchain.CheckSameBlockConflicts(f028Block(f028Gate, u1, u2), f028Gate)
	if err == nil {
		t.Fatal("SAME-OWNER-KEY UPDATE ACCEPTED: two UpdateProducer transactions in one " +
			"block re-pointing the same owner key must be rejected at/above the gate")
	}
	assert.Contains(t, err.Error(), "conflicting producer/CR public key",
		"rejected for the wrong reason")

	// The cross-arm pairing: a RegisterProducer seeds the shared map and the UpdateProducer
	// arm is what must catch the collision (register first, so the register arm cannot).
	reg := f100Producer(ownerPk, nodeA)
	upd := g2UpdateProducer(ownerPk, nodeB)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, reg, upd), f028Gate),
		"RegisterProducer + UpdateProducer sharing an owner key in one block must be rejected")

	// REPLAY: below the gate the identical block is accepted, byte-identically.
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, u1, u2), f028Gate),
		"below the gate the block must validate byte-identically")

	// POSITIVE CONTROL: two UpdateProducer with entirely disjoint keys are legitimate.
	otherOwner, _ := f100Key(t)
	otherNode, _ := f100Key(t)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(
		f028Block(f028Gate, u1, g2UpdateProducer(otherOwner, otherNode)), f028Gate),
		"two UpdateProducer with disjoint keys are legitimate and must pass")

	// A single UpdateProducer whose owner key EQUALS its own node key must not self-collide.
	shared, _ := f100Key(t)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(
		f028Block(f028Gate, g2UpdateProducer(shared, shared)), f028Gate),
		"an UpdateProducer with owner==node must not self-collide")
}

// TestG2ClaimNodeSameNodeKeyConflict — the F-071 arm. Two council members claiming the SAME
// DPoS node public key in one block: ClaimedDPoSKeys is a committed-state read, so both
// pass and two members end up bound to one node key.
func TestG2ClaimNodeSameNodeKeyConflict(t *testing.T) {
	const armErr = "duplicate CR claim DPOS node public key"

	node := f047NodeKey(t)
	did1 := common.Uint168{0x07, 0x01, 0x01}
	did2 := common.Uint168{0x07, 0x01, 0x02} // DIFFERENT members, so the F-083 DID arm is silent

	c1 := g2ClaimNode(node, did1)
	c2 := g2ClaimNode(node, did2)

	err := blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, c2), f028Gate)
	if err == nil {
		t.Fatal("SAME NODE KEY CLAIMED TWICE ACCEPTED: two council members claiming one " +
			"DPoS node public key in the same block must be rejected at/above the gate")
	}
	if !strings.Contains(err.Error(), armErr) {
		t.Fatalf("rejected, but NOT by the F-071 claim-vs-claim arm — the arm can still be "+
			"disarmed without this test noticing. got: %v", err)
	}

	// REPLAY: below the gate, accepted byte-identically.
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, c1, c2), f028Gate),
		"below the gate the block must validate byte-identically")

	// POSITIVE CONTROL: different members claiming DIFFERENT node keys are legitimate.
	assert.NoError(t, blockchain.CheckSameBlockConflicts(
		f028Block(f028Gate, c1, g2ClaimNode(f047NodeKey(t), did2)), f028Gate),
		"distinct members claiming distinct node keys are legitimate and must pass")
}
