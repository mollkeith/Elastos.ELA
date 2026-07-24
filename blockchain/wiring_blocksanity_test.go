// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TESTS — CheckBlockSanity.
//
// The blocker these close: every existing test for the same-block conflict family and
// for the canonical-AuxPow gate asserts on the HELPER (blockchain.CheckSameBlockConflicts,
// auxpow.IsCanonical, or a locally re-computed copy of the gate decision). A helper test
// passes even when NOTHING CALLS THE HELPER — proven by mutation at HEAD: deleting the
// single CheckSameBlockConflicts call from CheckBlockSanity, or the canonical-AuxPow gate
// from the same function, left the entire suite green.
//
// These tests instead build a block that passes (*BlockChain).CheckBlockSanity END TO END
// — real AuxPow, real merged-mining proof, real PoW, real merkle root — and then introduce
// exactly ONE defect: the one the guard under test is supposed to catch. The baseline
// control proves the block is otherwise valid, so the ONLY thing that can produce the
// expected rejection is the production call site inside CheckBlockSanity. Delete the call
// site and CheckBlockSanity returns nil -> these tests fail.
package blockchain

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
)

// The two campaign gates, verbatim. Nothing here introduces a third.
const (
	wiringGate      = uint32(2260451) // StrictMoneyRangeHeight
	wiringBelowGate = wiringGate - 1  // 2260450 == the rollback target / last retained block
)

// wiringChain is the smallest BlockChain that can run the real CheckBlockSanity.
func wiringChain(t *testing.T) *BlockChain {
	t.Helper()
	// core/transaction imports blockchain, so this internal test package cannot import it;
	// the constructor registry is populated by the external blockchain_test package
	// (wiring_support_test.go), whose init runs before any test function.
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = wiringGate
	return &BlockChain{chainParams: params, TimeSource: NewMedianTime()}
}

// wiringCoinbase builds a coinbase that passes CheckTransactionSanity at any height.
func wiringCoinbase(height uint32) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.CoinBase,
		payload.CoinBaseVersion,
		&payload.CoinBase{Content: []byte{byte(height), byte(height >> 8), byte(height >> 16)}},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: math.MaxUint16},
			Sequence: math.MaxUint32,
		}},
		[]*common2.Output{
			{AssetID: core.ELAAssetID, Value: 100, ProgramHash: common.Uint168{}, Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 0, ProgramHash: common.Uint168{}, Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
		},
		height, // F-031: coinbase LockTime == its own height
		[]*program.Program{},
	)
}

// wiringRealWithdraw builds a CRCProposalRealWithdraw that passes CheckTransactionSanity
// (no programs, no attributes, >=1 input, >=1 output) and carries `pending` as its single
// pending withdraw hash. `salt` makes the tx id unique so the block-level duplicate-txid
// and duplicate-UTXO checks (which run BEFORE the conflict check) are not what rejects it.
func wiringRealWithdraw(pending common.Uint256, salt byte) interfaces.Transaction {
	var prev common.Uint256
	prev[0] = 0xC0
	prev[1] = salt
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.CRCProposalRealWithdraw,
		0,
		&payload.CRCProposalRealWithdraw{WithdrawTransactionHashes: []common.Uint256{pending}},
		[]*common2.Attribute{},
		[]*common2.Input{{Previous: common2.OutPoint{TxID: prev, Index: uint16(salt)}, Sequence: math.MaxUint32}},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: 1, ProgramHash: common.Uint168{}, Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}}},
		0,
		[]*program.Program{},
	)
}

// wiringBlock assembles a block at `height` whose merkle root is correct and whose header
// carries a freshly mined, CANONICAL AuxPow committing to this exact header. The result
// passes CheckBlockSanity unless one of the guards under test rejects it.
func wiringBlock(t *testing.T, height uint32, txs ...interfaces.Transaction) *types.Block {
	t.Helper()
	all := append([]interfaces.Transaction{wiringCoinbase(height)}, txs...)

	ids := make([]common.Uint256, 0, len(all))
	for _, tx := range all {
		ids = append(ids, tx.Hash())
	}
	root, err := crypto.ComputeRoot(ids)
	if err != nil {
		t.Fatalf("merkle compute: %v", err)
	}

	header := common2.Header{
		Version:    0,
		Previous:   common.EmptyHash,
		MerkleRoot: root,
		Timestamp:  uint32(time.Now().Add(-time.Minute).Unix()),
		Bits:       0x207fffff, // target ~2^255-2^232, below the 2^255-1 PowLimit
		Nonce:      0,
		Height:     height,
	}

	// Header.Hash() is AuxPow-independent (SerializeNoAux), so the aux proof can be built
	// after the header is otherwise final — exactly what pow/service.go does.
	auxBlockHash := header.Hash()
	ap := auxpow.GenerateAuxPow(auxBlockHash)

	// "Mine": the parent-block header hash must be under the target. ~2 tries.
	target := CompactToBig(header.Bits)
	for i := 0; ; i++ {
		if i > 1_000_000 {
			t.Fatal("could not mine the wiring block")
		}
		h := ap.ParBlockHeader.Hash()
		if HashToBig(&h).Cmp(target) <= 0 {
			break
		}
		ap.ParBlockHeader.Nonce++
	}
	// Canonical encoding (F-041/F-090): ParentHash == parent header hash, ParMerkleIndex 0.
	ap.ParentHash = ap.ParBlockHeader.Hash()
	ap.ParMerkleIndex = 0
	header.AuxPow = *ap

	return &types.Block{Header: header, Transactions: all}
}

// -----------------------------------------------------------------------------
// POSITIVE CONTROL — without it none of the negatives below mean anything.
// -----------------------------------------------------------------------------

// TestWiringBlockSanityBaselineAccepts proves the harness produces a block the REAL
// CheckBlockSanity accepts, at and below the gate. Every rejection asserted further down
// is therefore attributable to the single defect that test introduces.
func TestWiringBlockSanityBaselineAccepts(t *testing.T) {
	b := wiringChain(t)
	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		if err := b.CheckBlockSanity(wiringBlock(t, h)); err != nil {
			t.Fatalf("baseline block at height %d must pass CheckBlockSanity, got: %v", h, err)
		}
	}
}

// -----------------------------------------------------------------------------
// WIRING #1 — CheckSameBlockConflicts is CALLED from CheckBlockSanity.
// Protects ~15 findings: F-016/017/028/030/047/051/066/067/068/071/072/078/083/100/118.
// -----------------------------------------------------------------------------

// TestWiringSameBlockConflictsReachedFromCheckBlockSanity drives the REAL
// CheckBlockSanity with a block whose ONLY defect is a same-block conflict (two
// CRCProposalRealWithdraw txs sharing one pending withdraw hash — the mempool
// slotCRCProposalRealWithdrawKey pairing). The baseline control above proves everything
// else about the block is valid, so a nil return can ONLY mean the production call site
// is gone.
//
// MUTATION PROOF: delete the `CheckSameBlockConflicts(block, ...)` call from
// CheckBlockSanity (blockvalidator.go) -> this test FAILS ("accepted a conflicting
// block"). The pre-existing helper tests (f028/f030/f047/f100_sameblock_test.go) all
// still pass under that mutation.
func TestWiringSameBlockConflictsReachedFromCheckBlockSanity(t *testing.T) {
	b := wiringChain(t)

	var pending common.Uint256
	pending[0] = 0x77

	// At and above the gate the conflicting block MUST be rejected, by the call site.
	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		blk := wiringBlock(t, h,
			wiringRealWithdraw(pending, 1),
			wiringRealWithdraw(pending, 2))
		err := b.CheckBlockSanity(blk)
		if err == nil {
			t.Fatalf("WIRING SEVERED at height %d: CheckBlockSanity accepted a block with a "+
				"same-block real-withdraw conflict — CheckSameBlockConflicts is not called", h)
		}
		if !strings.Contains(err.Error(), "duplicate real withdraw pending hash") {
			t.Fatalf("WIRING SEVERED at height %d: rejected for the wrong reason (%v); the "+
				"same-block conflict guard must be what rejects this block", h, err)
		}
	}

	// Below the gate the identical block must still be ACCEPTED — byte-identical replay of
	// retained history. This also proves the call site passes the real gate parameter
	// (b.chainParams.StrictMoneyRangeHeight) rather than a hardcoded/zero value.
	blk := wiringBlock(t, wiringBelowGate,
		wiringRealWithdraw(pending, 1),
		wiringRealWithdraw(pending, 2))
	if err := b.CheckBlockSanity(blk); err != nil {
		t.Fatalf("REPLAY BREAK: the same conflicting block below the gate must be accepted, got: %v", err)
	}
}

// TestWiringSameBlockConflictsGateArgumentIsTheCampaignGate pins the ARGUMENT the call
// site passes. A call site that passed 0 (always strict) or MaxUint32 (never strict)
// would still be "wired" but would break replay or be inert; both are caught here by
// moving the chain's gate and observing the decision boundary move with it.
func TestWiringSameBlockConflictsGateArgumentIsTheCampaignGate(t *testing.T) {
	b := wiringChain(t)
	moved := uint32(1_000_000)
	b.chainParams.StrictMoneyRangeHeight = moved
	defer func() { b.chainParams.StrictMoneyRangeHeight = wiringGate }()

	var pending common.Uint256
	pending[0] = 0x78

	if err := b.CheckBlockSanity(wiringBlock(t, moved-1,
		wiringRealWithdraw(pending, 3), wiringRealWithdraw(pending, 4))); err != nil {
		t.Fatalf("below the moved gate the conflicting block must be accepted, got: %v", err)
	}
	if err := b.CheckBlockSanity(wiringBlock(t, moved,
		wiringRealWithdraw(pending, 3), wiringRealWithdraw(pending, 4))); err == nil {
		t.Fatal("at the moved gate the conflicting block must be rejected: the call site does " +
			"not pass b.chainParams.StrictMoneyRangeHeight")
	}
}

// -----------------------------------------------------------------------------
// WIRING #2 — the canonical-AuxPow gate (F-041/F-090) is CALLED from CheckBlockSanity.
// -----------------------------------------------------------------------------

// TestWiringCanonicalAuxPowGateReachedFromCheckBlockSanity drives the REAL
// CheckBlockSanity with a block whose AuxPow still satisfies AuxPow.Check and
// CheckProofOfWork (both malleations are invisible to them) but is non-canonical.
//
// MUTATION PROOF: delete the
//
//	if b.auxPowMalleationActive(header.Height) && !header.AuxPow.IsCanonical() { ... }
//
// gate from CheckBlockSanity -> this test FAILS. The pre-existing f041_f090_gate_test.go
// re-computes that same boolean locally and passes under the mutation.
func TestWiringCanonicalAuxPowGateReachedFromCheckBlockSanity(t *testing.T) {
	b := wiringChain(t)

	malleate := map[string]func(*types.Block){
		// F-090: high bits of ParMerkleIndex are unconstrained by Check (the parent
		// coinbase branch is empty, so GetMerkleRoot consumes none of them).
		"F-090-ParMerkleIndex": func(blk *types.Block) { blk.Header.AuxPow.ParMerkleIndex = 0x40000000 },
		// F-041: ParentHash is read by neither Check nor CheckProofOfWork.
		"F-041-ParentHash": func(blk *types.Block) { blk.Header.AuxPow.ParentHash[0] ^= 0xff },
	}

	for name, mutate := range malleate {
		t.Run(name, func(t *testing.T) {
			for _, h := range []uint32{wiringGate, wiringGate + 1} {
				blk := wiringBlock(t, h)
				mutate(blk)
				// Control: the malleation is invisible to the two checks that run first,
				// so ONLY the canonical gate can reject it.
				hash := blk.Header.Hash()
				if !blk.Header.AuxPow.Check(&hash, auxpow.AuxPowChainID) {
					t.Fatalf("harness bug: malleation must remain invisible to AuxPow.Check")
				}
				if err := CheckProofOfWork(&blk.Header, b.chainParams.PowConfiguration.PowLimit); err != nil {
					t.Fatalf("harness bug: malleation must remain invisible to CheckProofOfWork: %v", err)
				}

				err := b.CheckBlockSanity(blk)
				if err == nil {
					t.Fatalf("WIRING SEVERED at height %d: CheckBlockSanity accepted a "+
						"non-canonical AuxPow — the F-041/F-090 gate is not called", h)
				}
				if !strings.Contains(err.Error(), "non-canonical (malleable) AuxPow encoding") {
					t.Fatalf("WIRING SEVERED at height %d: rejected for the wrong reason: %v", h, err)
				}
			}

			// Below the gate the identical malleated block must be ACCEPTED (replay parity),
			// which also pins the height argument to the block's OWN height.
			blk := wiringBlock(t, wiringBelowGate)
			mutate(blk)
			if err := b.CheckBlockSanity(blk); err != nil {
				t.Fatalf("REPLAY BREAK: a non-canonical AuxPow below the gate must be accepted, got: %v", err)
			}
		})
	}
}
