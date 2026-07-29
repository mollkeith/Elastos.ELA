// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// F-118 — same-block duplicate NFTDestroy id.
//
// THE EVIDENCE GAP THIS CLOSES. The F-118 arm of CheckSameBlockConflicts (the
// `nftDestroyIDs` map in blockchain/blockvalidator.go) shipped with NO test of any kind.
// An external reviewer neutered the production guard, rebuilt, and the entire shipping
// gate — ./blockchain/, ./dpos/state/, ./cr/state/, ./core/transaction/, ./test/unit/,
// ./pow/ — stayed green. A mint-class guard with zero discriminating evidence.
//
// Why the neighbouring tests did not catch it:
//   - core/transaction/f104_test.go covers the WITHIN-TRANSACTION dedup only. That guard
//     lives in NFTDestroy SpecialContextCheck, which CheckBlockSanity never calls, and it
//     cannot see a second transaction at all.
//   - blockchain/fv09_sameblock_nftalias_test.go drives the right entry point but exercises
//     the POST-LOOP stake-address intersection with two DIFFERENT NFT ids, so the in-loop
//     id map is only ever written, never hit.
//
// THE DEFECT. NFTDestroy SpecialContextCheck reads COMMITTED state only (ExistNFTID /
// CanNFTDestroy are read-only during validation). Two same-block NFTDestroy transactions
// naming the same NFT id therefore both pass per-transaction validation, and
// processNFTDestroyFromSideChain then applies the destroy TWICE — folding the NFT`s
// DPoSV2 reward into two different owner stake addresses from one NFT.
//
// These tests drive the REAL (*BlockChain).CheckBlockSanity end to end on the harness in
// wiring_blocksanity_test.go (real AuxPow, real merged-mining proof, real PoW, real merkle
// root). The baseline control there proves such a block is otherwise valid, so the ONLY
// thing that can produce the expected rejection is the production call site inside
// CheckBlockSanity reaching the production guard inside CheckSameBlockConflicts.
//
// FAIL-ON-PRISTINE (measured, both severances):
//  1. neuter the in-loop id check in CheckSameBlockConflicts
//     (`if _, exists := nftDestroyIDs[id]; exists`) -> "DUPLICATE NFTDestroy id ACCEPTED".
//  2. neuter the `CheckSameBlockConflicts(block, ...)` call inside CheckBlockSanity
//     -> the same failure.
//
// REPLAY SAFETY. The guard is gated with its function (CheckSameBlockConflicts returns nil
// below StrictMoneyRangeHeight = 2,260,451), and the below-gate leg below asserts the
// identical block is still ACCEPTED at 2,260,450 — the forced-rollback target and last
// retained block. No new height literal is introduced; the two campaign gates stay two.
package blockchain

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
)

const f118DupErr = "duplicate NFTDestroy id"

// f118OrdinaryOwner returns a user stake address that is NOT any NFT`s derived stake
// address, so the FV-09 post-loop intersection cannot be what rejects these blocks.
func f118OrdinaryOwner(seed byte) common.Uint168 {
	var u common.Uint168
	u[0] = 0x21 // standard-contract prefix, as a real stake address carries
	u[1] = seed
	u[2] = 0xF1
	return u
}

// TestF118DuplicateNFTDestroyIDAcrossTwoTxsIsRejected is the fail-on-pristine test:
// two DISTINCT transactions in one block destroying the SAME NFT id.
func TestF118DuplicateNFTDestroyIDAcrossTwoTxsIsRejected(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x63)
	ownerX := f118OrdinaryOwner(0x01)
	ownerY := f118OrdinaryOwner(0x02)
	if ownerX == ownerY {
		t.Fatal("test vector broken: the two owners must differ")
	}

	// THE ATTACK: one NFT, destroyed twice in one block, crediting two different owners.
	tx1 := fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 0x41)
	tx2 := fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerY}, 0x42)

	// PRECONDITIONS — prove the block is rejected by the F-118 arm and nothing else.
	if tx1.Hash() == tx2.Hash() {
		t.Fatal("test vector broken: CheckDuplicateTx would reject the block before the " +
			"conflict check is reached")
	}
	if fv09SelfAliases(t, tx1) || fv09SelfAliases(t, tx2) {
		t.Fatal("test vector broken: a payload self-aliases, so the per-tx F-073 guard " +
			"would be the thing under test")
	}
	for _, o := range []common.Uint168{ownerX, ownerY} {
		if o == fv09StakeAddr(t, nftA) {
			t.Fatal("test vector broken: an owner is a derived NFT stake address, so the " +
				"FV-09 post-loop guard would be the thing under test")
		}
	}

	orders := map[string][]interfaces.Transaction{
		"tx1-then-tx2": {tx1, tx2},
		"tx2-then-tx1": {tx2, tx1},
	}

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		for name, txs := range orders {
			err := b.CheckBlockSanity(wiringBlock(t, h, txs...))
			if err == nil {
				t.Fatalf("DUPLICATE NFTDestroy id ACCEPTED at height %d (%s): CheckBlockSanity "+
					"accepted a block that destroys NFT %s twice — the F-118 block-scope "+
					"guard is not reached", h, name, nftA)
			}
			if !strings.Contains(err.Error(), f118DupErr) {
				t.Fatalf("rejected for the WRONG reason at height %d (%s): %v", h, name, err)
			}
		}
	}

	// Below gate 1 the identical block must still be ACCEPTED: retained history replays
	// byte-identically. This also proves the guard reads the real gate argument rather
	// than rejecting unconditionally.
	for name, txs := range orders {
		if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate, txs...)); err != nil {
			t.Fatalf("REPLAY BREAK below the gate (%s): %v", name, err)
		}
	}
}

// TestF118DuplicateNFTDestroyIDWithinOneTxIsRejectedAtBlockScope covers the id repeated
// inside a SINGLE payload. F-104 rejects that in NFTDestroy SpecialContextCheck, but
// CheckBlockSanity never calls SpecialContextCheck, so at this layer the block-scope map
// is the only thing standing between the block and a double-apply.
func TestF118DuplicateNFTDestroyIDWithinOneTxIsRejectedAtBlockScope(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x71)
	owners := []common.Uint168{f118OrdinaryOwner(0x11), f118OrdinaryOwner(0x12)}
	tx := fv09NFTDestroyTx([]common.Uint256{nftA, nftA}, owners, 0x51)

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		err := b.CheckBlockSanity(wiringBlock(t, h, tx))
		if err == nil {
			t.Fatalf("REPEATED NFTDestroy id ACCEPTED at height %d: CheckBlockSanity accepted "+
				"a payload naming NFT %s twice", h, nftA)
		}
		if !strings.Contains(err.Error(), f118DupErr) {
			t.Fatalf("rejected for the WRONG reason at height %d: %v", h, err)
		}
	}
	if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate, tx)); err != nil {
		t.Fatalf("REPLAY BREAK below the gate: %v", err)
	}
}

// TestF118DistinctNFTDestroyIDsStillPass is the positive control. Without it the two tests
// above would also be satisfied by a guard that rejects every block containing more than
// one NFTDestroy.
func TestF118DistinctNFTDestroyIDsStillPass(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x81)
	nftB := fv09NFTID(0x91)
	nftC := fv09NFTID(0xA1)
	if nftA == nftB || nftB == nftC || nftA == nftC {
		t.Fatal("test vector broken: the NFT ids must differ")
	}
	ownerX := f118OrdinaryOwner(0x21)

	cases := map[string][]interfaces.Transaction{
		"two txs, different ids, different owners": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 0x61),
			fv09NFTDestroyTx([]common.Uint256{nftB}, []common.Uint168{f118OrdinaryOwner(0x22)}, 0x62),
		},
		"two txs, different ids, SAME owner (a legitimate consolidation)": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 0x63),
			fv09NFTDestroyTx([]common.Uint256{nftB}, []common.Uint168{ownerX}, 0x64),
		},
		"one tx, several distinct ids": {
			fv09NFTDestroyTx([]common.Uint256{nftA, nftB, nftC},
				[]common.Uint168{ownerX, f118OrdinaryOwner(0x23), f118OrdinaryOwner(0x24)}, 0x65),
		},
	}

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		for name, txs := range cases {
			if err := b.CheckBlockSanity(wiringBlock(t, h, txs...)); err != nil {
				t.Fatalf("FALSE REJECT at height %d (%s): %v", h, name, err)
			}
		}
	}
}
