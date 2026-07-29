// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-08 — the same-block arm.
//
// payload.SpecialTxDedupKey is used by THREE sites that must agree: the committed-state
// read (dpos/state State.SpecialTxExists), the write (State.recordSpecialTx) and the
// block-level guard (blockchain.CheckSameBlockConflicts). F-030's commit note requires
// them to flip together. The transaction-path read is proven in
// core/transaction/nx08_illegal_evidence_dedup_test.go; this file proves the BLOCK guard,
// end to end through the real (*BlockChain).CheckBlockSanity — so two trailing-byte
// re-encodings of ONE logical equivocation can no longer ride in the SAME block, which is
// how the attacker doubled his rate without even needing two blocks.
//
// MUTATION PROOF: revert payload.SpecialTxDedupKey to the pristine
// `if blk, ok := d.(*DPOSIllegalBlocks); ok { ... }; return d.Hash()` form -> this test
// FAILS ("SAME-BLOCK MALLEABLE KEY ACCEPTED"). Deleting the CheckSameBlockConflicts call
// site from CheckBlockSanity fails it too.
package blockchain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// nx08Uint256 returns a deterministic Uint256 seeded by a byte.
func nx08Uint256(seed byte) common.Uint256 {
	var u common.Uint256
	for i := range u {
		u[i] = seed + byte(i)
	}
	return u
}

// nx08Header builds a fully serialisable ELA block header (with a well-formed AuxPow)
// whose LOGICAL identity (Header.Hash() == SerializeNoAux) is fixed by seed. Mirrors the
// f030 helper, re-declared here because that one lives in the external blockchain_test
// package while this file must sit in the internal one to use the wiring harness.
func nx08Header(height uint32, seed byte) *common2.Header {
	return &common2.Header{
		Version:    1,
		Previous:   nx08Uint256(seed),
		MerkleRoot: nx08Uint256(seed + 1),
		Timestamp:  1000 + uint32(seed),
		Bits:       0x1d00ffff,
		Nonce:      uint32(seed),
		Height:     height,
		AuxPow: auxpow.AuxPow{
			AuxMerkleBranch: []common.Uint256{nx08Uint256(seed + 2)},
			AuxMerkleIndex:  0,
			ParCoinbaseTx: auxpow.BtcTx{
				Version: 1,
				TxIn: []*auxpow.BtcTxIn{{
					PreviousOutPoint: auxpow.BtcOutPoint{Hash: nx08Uint256(seed + 3), Index: 0},
					SignatureScript:  []byte{0x51},
					Sequence:         0xffffffff,
				}},
				TxOut:    []*auxpow.BtcTxOut{{Value: 1, PkScript: []byte{0x51}}},
				LockTime: 0,
			},
			ParCoinBaseMerkle: []common.Uint256{nx08Uint256(seed + 4)},
			ParMerkleIndex:    0,
			ParBlockHeader: auxpow.BtcHeader{
				Version:    1,
				Previous:   nx08Uint256(seed + 5),
				MerkleRoot: nx08Uint256(seed + 6),
				Timestamp:  2000 + uint32(seed),
				Bits:       0x1d00ffff,
				Nonce:      uint32(seed) + 7,
			},
			ParentHash: nx08Uint256(seed + 8),
		},
	}
}

// nx08Proposal builds a DPOSProposal over the given header, deterministic in `seed`.
// The block guard computes the dedup key only, so no real signature is needed here; the
// signature-bearing path is exercised in the core/transaction suite.
func nx08Proposal(hdr *common2.Header, seed byte) payload.DPOSProposal {
	return payload.DPOSProposal{
		Sponsor:    []byte{0x02, seed, seed + 1, seed + 2},
		BlockHash:  hdr.Hash(),
		ViewOffset: 1,
		Sign:       []byte{seed, seed ^ 0xff},
	}
}

// nx08Evidence serialises `hdr` and appends `pad` trailing bytes. Header.Deserialize
// discards a trailing sentinel without asserting the buffer was consumed, so the padded
// blob still decodes to the same header with the same Height and the same Hash() — but the
// raw payload Hash() (the pristine dedup key) changes.
func nx08Evidence(t *testing.T, hdr *common2.Header, p payload.DPOSProposal,
	height uint32, pad int) payload.ProposalEvidence {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := hdr.Serialize(buf); err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	blob := buf.Bytes()
	for i := 0; i < pad; i++ {
		blob = append(blob, byte(0xE0+i))
	}
	return payload.ProposalEvidence{Proposal: p, BlockHeader: blob, BlockHeight: height}
}

// nx08ProposalsTx wraps an illegal-proposal payload in a zero-cost transaction that passes
// CheckTransactionSanity (no inputs, outputs, attributes or programs).
func nx08ProposalsTx(pl *payload.DPOSIllegalProposals) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09, common2.IllegalProposalEvidence,
		payload.IllegalProposalVersion, pl,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
}

// TestNX08SameBlockReEncodedProposalEvidenceIsRejected is the fail-on-pristine test for
// the block guard: two trailing-byte re-encodings of ONE logical equivocation must collide
// inside one block at and above gate 1, and must NOT collide below it.
func TestNX08SameBlockReEncodedProposalEvidenceIsRejected(t *testing.T) {
	b := wiringChain(t)

	build := func(height uint32, pad int) *payload.DPOSIllegalProposals {
		h1 := nx08Header(height, 10)
		h2 := nx08Header(height, 40)
		p1 := nx08Proposal(h1, 0x11)
		p2 := nx08Proposal(h2, 0x22)
		return &payload.DPOSIllegalProposals{
			Evidence:        nx08Evidence(t, h1, p1, height, pad),
			CompareEvidence: nx08Evidence(t, h2, p2, height, 0),
		}
	}

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		e1 := build(h, 0)
		e2 := build(h, 1) // one appended byte — the cheapest vector
		tx1 := nx08ProposalsTx(e1)
		tx2 := nx08ProposalsTx(e2)

		// The malleability precondition, asserted rather than assumed.
		if e1.Hash() == e2.Hash() {
			t.Fatalf("height %d: test vector broken — the raw payload hashes must differ", h)
		}
		if tx1.Hash() == tx2.Hash() {
			t.Fatalf("height %d: test vector broken — CheckDuplicateTx would collapse these", h)
		}

		err := b.CheckBlockSanity(wiringBlock(t, h, tx1, tx2))
		if err == nil {
			t.Fatalf("SAME-BLOCK MALLEABLE KEY ACCEPTED at height %d: two trailing-byte "+
				"re-encodings of ONE logical illegal-proposal equivocation rode in one block", h)
		}
		if !strings.Contains(err.Error(), "duplicate illegal-evidence special tx") {
			t.Fatalf("height %d: rejected for the WRONG reason: %v", h, err)
		}
	}

	// Below gate 1 the legacy raw key applies, so the identical block is ACCEPTED —
	// retained history replays byte-identically.
	e1 := build(wiringBelowGate, 0)
	e2 := build(wiringBelowGate, 1)
	if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate,
		nx08ProposalsTx(e1), nx08ProposalsTx(e2))); err != nil {
		t.Fatalf("REPLAY BREAK below the gate: %v", err)
	}
}

// TestNX08SameBlockDistinctEquivocationsStillPass is the positive control: the fold must
// not over-collapse. Two genuinely DIFFERENT equivocations in one block stay legitimate.
func TestNX08SameBlockDistinctEquivocationsStillPass(t *testing.T) {
	b := wiringChain(t)

	build := func(height uint32, seedA, seedB byte) *payload.DPOSIllegalProposals {
		h1 := nx08Header(height, seedA)
		h2 := nx08Header(height, seedB)
		return &payload.DPOSIllegalProposals{
			Evidence:        nx08Evidence(t, h1, nx08Proposal(h1, seedA), height, 0),
			CompareEvidence: nx08Evidence(t, h2, nx08Proposal(h2, seedB), height, 0),
		}
	}

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		tx1 := nx08ProposalsTx(build(h, 10, 40))
		tx2 := nx08ProposalsTx(build(h, 70, 100))
		if err := b.CheckBlockSanity(wiringBlock(t, h, tx1, tx2)); err != nil {
			t.Fatalf("FALSE POSITIVE at height %d: two DISTINCT equivocations must both be "+
				"accepted in one block, got: %v", h, err)
		}
	}
}

// TestNX08FoldIgnoresTheHeaderBlobButNotTheEquivocation pins the key function itself, so a
// future refactor cannot quietly widen or narrow what the key covers.
func TestNX08FoldIgnoresTheHeaderBlobButNotTheEquivocation(t *testing.T) {
	const height = wiringGate

	mk := func(seedA, seedB byte, pad int) *payload.DPOSIllegalProposals {
		h1 := nx08Header(height, seedA)
		h2 := nx08Header(height, seedB)
		return &payload.DPOSIllegalProposals{
			Evidence:        nx08Evidence(t, h1, nx08Proposal(h1, seedA), height, pad),
			CompareEvidence: nx08Evidence(t, h2, nx08Proposal(h2, seedB), height, 0),
		}
	}

	base := payload.SpecialTxDedupKey(mk(10, 40, 0), wiringGate)
	for _, pad := range []int{1, 4, 64, 1024} {
		if got := payload.SpecialTxDedupKey(mk(10, 40, pad), wiringGate); got != base {
			t.Fatalf("pad %d: the fold must ignore the raw header blob entirely", pad)
		}
	}
	if payload.SpecialTxDedupKey(mk(70, 100, 0), wiringGate) == base {
		t.Fatal("a DIFFERENT equivocation must produce a different dedup key")
	}
	// Below the gate the legacy raw key must be preserved exactly.
	legacy := mk(10, 40, 0)
	if payload.SpecialTxDedupKey(legacy, wiringGate+1) != legacy.Hash() {
		t.Fatal("below the gate the dedup key must be the legacy raw payload hash")
	}
}
