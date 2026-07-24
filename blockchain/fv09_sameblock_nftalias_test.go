// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-09 — the F-073 NFTDestroy alias guard is INTRA-TRANSACTION only and splits across
// two same-block transactions.
//
// F-073 (core/transaction/nftdestroytransaction.go) builds its NFT stake-address set from
// THIS payload's own IDs and rejects only an OwnerStakeAddresses entry that intersects it.
// Two payloads defeat it trivially: tx1 destroys NFT A naming NFT B's DERIVED stake
// address, tx2 destroys NFT B naming an ordinary address. tx1's set is {stake(A)} and its
// owner is stake(B); tx2's set is {stake(B)} and its owner is ordinary. Neither payload
// self-intersects. The F-118 same-block arm keys on the NFT ID and A != B, so it does not
// fire either. NOTHING AT ANY LAYER SAW THE COMPOSITION — and at Commit the state-apply
// forwards DO compose (dpos/state/state.go credits with a LIVE lookup), misallocating
// claimable reward on a reorg. This is a claimable-BALANCE accounting defect; NO mint and
// NO supply inflation is involved.
//
// These tests drive the REAL (*BlockChain).CheckBlockSanity end to end on the harness in
// wiring_blocksanity_test.go (real AuxPow, real PoW, real merkle root), so the ONLY thing
// that can produce the expected rejection is the production call site inside
// CheckBlockSanity reaching the production guard inside CheckSameBlockConflicts.
//
// MUTATION PROOF (both severances make these tests FAIL; see the batch report):
//  1. delete the FV-09 post-loop intersection from CheckSameBlockConflicts
//     (blockchain/blockvalidator.go) -> "SPLIT ALIAS ACCEPTED".
//  2. delete the `CheckSameBlockConflicts(block, ...)` call from CheckBlockSanity
//     -> same failure.
//
// The pre-existing per-tx F-073 guard test (core/transaction/f073guard_test.go,
// TestF073GuardRejectsCrossKeyAlias) stays GREEN under BOTH mutations — measured, not
// assumed — which is precisely why the gap survived to be found here.
package blockchain

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

const fv09AliasErr = "aliasing an NFT stake address destroyed in the same block"

// fv09NFTID returns a deterministic NFT id seeded by a byte.
func fv09NFTID(seed byte) common.Uint256 {
	var u common.Uint256
	for i := range u {
		u[i] = seed*7 + byte(i)
	}
	return u
}

// fv09StakeAddr derives an NFT's stake address EXACTLY as the production code does —
// core/contract.CreateStakeContractByCode over the raw id bytes. Both the F-073 per-tx
// guard and dpos/state's DPoSV2RewardInfo key use this derivation, so the attack address
// is the real one, not a stand-in.
func fv09StakeAddr(t *testing.T, id common.Uint256) common.Uint168 {
	t.Helper()
	ct, err := contract.CreateStakeContractByCode(id.Bytes())
	if err != nil {
		t.Fatalf("derive stake address: %v", err)
	}
	return *ct.ToProgramHash()
}

// fv09NFTDestroyTx builds an NFTDestroyFromSideChain that passes CheckTransactionSanity
// (no inputs, no outputs, exactly one attribute and one program). `salt` makes the tx id
// unique so the block-level duplicate-txid check is not what rejects the block.
func fv09NFTDestroyTx(ids []common.Uint256, owners []common.Uint168, salt byte) interfaces.Transaction {
	code := make([]byte, program.MinProgramCodeSize+1)
	for i := range code {
		code[i] = salt + byte(i)
	}
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.NFTDestroyFromSideChain,
		payload.NFTDestroyFromSideChainVersion,
		&payload.NFTDestroyFromSideChain{IDs: ids, OwnerStakeAddresses: owners},
		[]*common2.Attribute{{Usage: common2.Nonce, Data: []byte{salt, 0x5A}}},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{{Code: code, Parameter: []byte{salt}}},
	)
}

// fv09SelfAliases re-derives the EXACT intra-transaction F-073 predicate
// (nftdestroytransaction.go: reject an OwnerStakeAddresses entry that intersects this
// payload's OWN ids' stake-address set). Used as a precondition assertion so the tests
// prove the split payloads are ones F-073 genuinely accepts, rather than assuming it.
func fv09SelfAliases(t *testing.T, tx interfaces.Transaction) bool {
	t.Helper()
	p, ok := tx.Payload().(*payload.NFTDestroyFromSideChain)
	if !ok {
		t.Fatal("not an NFTDestroy payload")
	}
	own := make(map[common.Uint168]struct{}, len(p.IDs))
	for _, id := range p.IDs {
		own[fv09StakeAddr(t, id)] = struct{}{}
	}
	for _, o := range p.OwnerStakeAddresses {
		if _, clash := own[o]; clash {
			return true
		}
	}
	return false
}

// TestFV09SplitAliasIsRejectedAtBlockScope is the fail-on-pristine test. On the pristine
// tree CheckBlockSanity ACCEPTS the split-alias block at every height; with the FV-09
// guard it must reject it at and above gate 1, in EITHER transaction order, while every
// legitimate NFTDestroy shape and all below-gate history stay accepted.
func TestFV09SplitAliasIsRejectedAtBlockScope(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x11)
	nftB := fv09NFTID(0x22)
	if nftA == nftB {
		t.Fatal("test vector broken: the two NFT ids must differ")
	}
	stakeB := fv09StakeAddr(t, nftB)

	var ordinaryOwner common.Uint168
	ordinaryOwner[0] = 0x99

	// THE ATTACK, SPLIT: tx1 names NFT B's derived stake address as A's new owner.
	tx1 := fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{stakeB}, 1)
	tx2 := fv09NFTDestroyTx([]common.Uint256{nftB}, []common.Uint168{ordinaryOwner}, 2)

	// PRECONDITION — the vector must be one the EXISTING guards accept, otherwise this
	// test would be proving nothing new.
	if fv09SelfAliases(t, tx1) || fv09SelfAliases(t, tx2) {
		t.Fatal("test vector broken: a payload self-aliases, so the intra-tx F-073 guard " +
			"would reject it and the split would not be the thing under test")
	}
	if tx1.Hash() == tx2.Hash() {
		t.Fatal("test vector broken: the two txs must have distinct hashes")
	}

	orders := map[string][]interfaces.Transaction{
		"destroyer-then-namer": {tx1, tx2},
		"namer-after-target":   {tx2, tx1}, // the aliased id is seen only in the SECOND tx
	}

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		for name, txs := range orders {
			err := b.CheckBlockSanity(wiringBlock(t, h, txs...))
			if err == nil {
				t.Fatalf("SPLIT ALIAS ACCEPTED at height %d (%s): CheckBlockSanity accepted a "+
					"block whose two NFTDestroy txs compose the F-073 alias — the FV-09 "+
					"block-scope guard is not reached", h, name)
			}
			if !strings.Contains(err.Error(), fv09AliasErr) {
				t.Fatalf("rejected for the WRONG reason at height %d (%s): %v", h, name, err)
			}
		}
	}

	// Below gate 1 the identical block must still be ACCEPTED — retained history replays
	// byte-identically. This also proves the guard reads the real gate argument.
	for name, txs := range orders {
		if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate, txs...)); err != nil {
			t.Fatalf("REPLAY BREAK below the gate (%s): %v", name, err)
		}
	}
}

// TestFV09LegitimateNFTDestroyBlocksStillPass is the positive control. Without it the
// test above could be satisfied by a guard that rejects every NFTDestroy block.
func TestFV09LegitimateNFTDestroyBlocksStillPass(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x31)
	nftB := fv09NFTID(0x41)
	nftC := fv09NFTID(0x51)

	var ownerX, ownerY common.Uint168
	ownerX[0] = 0xA1
	ownerY[0] = 0xB2

	cases := map[string][]interfaces.Transaction{
		"single destroy, ordinary owner": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 3),
		},
		"two destroys, unrelated owners": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 4),
			fv09NFTDestroyTx([]common.Uint256{nftB}, []common.Uint168{ownerY}, 5),
		},
		"two destroys sharing ONE legitimate owner (the reward folds net out)": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{ownerX}, 6),
			fv09NFTDestroyTx([]common.Uint256{nftB}, []common.Uint168{ownerX}, 7),
		},
		"multi-id destroy, ordinary owners": {
			fv09NFTDestroyTx([]common.Uint256{nftA, nftB}, []common.Uint168{ownerX, ownerY}, 8),
		},
		"destroy naming the stake address of an NFT NOT destroyed in this block": {
			fv09NFTDestroyTx([]common.Uint256{nftA}, []common.Uint168{fv09StakeAddr(t, nftC)}, 9),
		},
	}

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		for name, txs := range cases {
			if err := b.CheckBlockSanity(wiringBlock(t, h, txs...)); err != nil {
				t.Fatalf("FALSE POSITIVE at height %d (%s): %v", h, name, err)
			}
		}
	}
}

// TestFV09IntraTxAliasStillRejectedAndBlockGuardAlsoCatchesIt pins the belt-and-braces
// relationship the fix deliberately keeps: the per-tx F-073 guard is NOT removed (it keeps
// the mempool honest and gives the cleaner per-tx error), and the new block-scope guard
// independently catches the SAME single-transaction shape. If someone later deletes the
// per-tx guard as "now redundant", the block path still rejects it.
func TestFV09IntraTxAliasStillRejectedAndBlockGuardAlsoCatchesIt(t *testing.T) {
	b := wiringChain(t)

	nftA := fv09NFTID(0x61)
	nftB := fv09NFTID(0x71)
	var ordinaryOwner common.Uint168
	ordinaryOwner[0] = 0xC3

	// The ORIGINAL (single-transaction) F-073 vector.
	tx := fv09NFTDestroyTx(
		[]common.Uint256{nftA, nftB},
		[]common.Uint168{fv09StakeAddr(t, nftB), ordinaryOwner},
		10)
	if !fv09SelfAliases(t, tx) {
		t.Fatal("test vector broken: this payload must self-alias")
	}

	err := b.CheckBlockSanity(wiringBlock(t, wiringGate, tx))
	if err == nil {
		t.Fatal("the single-tx F-073 alias must also be rejected at block scope")
	}
	if !strings.Contains(err.Error(), fv09AliasErr) {
		t.Fatalf("rejected for the WRONG reason: %v", err)
	}

	if err := b.CheckBlockSanity(wiringBlock(t, wiringBelowGate, tx)); err != nil {
		t.Fatalf("REPLAY BREAK below the gate: %v", err)
	}
}
