// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Fail-on-pristine tests for B2 (F-041 production side): SolveBlock fakes a
// parent (BTC) block header with auxpow.GenerateAuxPow, which never sets
// AuxPow.ParentHash, and the nonce search never stamped it either. Every
// self-mined block therefore carried ParentHash == 0x00..00, which is exactly
// the encoding the canonical-AuxPow gate rejects at and above
// StrictMoneyRangeHeight -- the height the chain restarts on.
//
// Mainnet census over the frozen store (2,260,597 records, heights 0..2,260,595)
// finds that shape 177,337 times, all at height <= 180,217: the internal miner
// really did produce mainnet blocks, it just stopped being used long before the
// gate.
package pow

import (
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
)

// b2Bits is a compact difficulty of 0x010000 << (8*(0x1f-3)) == 2^240, i.e. one
// expected solution every 2^16 nonces. It is deliberately NOT trivial: at a
// trivial target nonce 0 wins, and a fix that stamped ParentHash once before
// the nonce search - which is stale for every nonce after the first - would
// pass by accident.
const b2Bits uint32 = 0x1f010000

// b2Rounds solves several independent blocks. The chance that every one of them
// is solved by nonce 0, leaving the nonce-bound assertion unexercised, is 2^-64.
const b2Rounds = 4

// b2Block builds a bare block to mine at the given height. SolveBlock reads only
// the header (Bits for the target, Hash() for the merged-mining commitment), so
// no transactions, chain or mempool are needed.
func b2Block(height, salt uint32) *types.Block {
	return &types.Block{
		Header: common2.Header{
			Version:    0,
			Previous:   common.Uint256{byte(salt), byte(salt >> 8)},
			MerkleRoot: common.Uint256{byte(salt + 1)},
			Timestamp:  uint32(time.Now().Unix()),
			Bits:       b2Bits,
			Nonce:      salt,
			Height:     height,
		},
	}
}

// TestB2SolveBlockStampsCanonicalParentHash drives the real Service.SolveBlock
// at the real restart height and requires the block it produces to be
// acceptable to the node that has to validate it.
//
// Fail-on-pristine: with the stamp reverted, SolveBlock returns a block whose
// AuxPow.ParentHash is the zero hash, IsCanonical() is false, and
// CheckBlockSanity rejects it at every height >= StrictMoneyRangeHeight - a
// node cannot self-mine the first block of the restart.
func TestB2SolveBlockStampsCanonicalParentHash(t *testing.T) {
	params := config.GetDefaultParams()
	gate := params.StrictMoneyRangeHeight
	if gate != config.MainNetStrictMoneyRangeHeight {
		t.Fatalf("expected the mainnet incident gate %d, got %d",
			config.MainNetStrictMoneyRangeHeight, gate)
	}

	// SolveBlock touches no Service field, so a bare Service is the whole
	// dependency set - the defect is in block production, not in chain state.
	svc := &Service{}

	sawNonZeroNonce := false
	for r := uint32(0); r < b2Rounds; r++ {
		blk := b2Block(gate, r)
		identity := blk.Hash()

		if !svc.SolveBlock(blk, nil) {
			t.Fatalf("round %d: SolveBlock did not solve at bits %#x", r, b2Bits)
		}
		ap := blk.Header.AuxPow

		if ap.ParBlockHeader.Nonce != 0 {
			sawNonZeroNonce = true
		}

		// Block identity excludes the AuxPow (Header.Hash uses SerializeNoAux),
		// so stamping cannot move it and the commitment still matches.
		if blk.Hash() != identity {
			t.Fatalf("round %d: attaching the AuxPow changed block identity", r)
		}
		if !ap.Check(&identity, auxpow.AuxPowChainID) {
			t.Fatalf("round %d: merged-mining proof no longer passes AuxPow.Check", r)
		}
		// ParentHash is not a BtcHeader field, so the proof of work is untouched.
		if err := blockchain.CheckProofOfWork(&blk.Header,
			params.PowConfiguration.PowLimit); err != nil {
			t.Fatalf("round %d: solved block fails CheckProofOfWork: %v", r, err)
		}

		// The fail-on-pristine assertion.
		want := ap.ParBlockHeader.Hash()
		if ap.ParentHash != want {
			t.Fatalf("round %d: SolveBlock left ParentHash %s, want the solved "+
				"parent header hash %s (pristine leaves it 0x00..00)",
				r, ap.ParentHash, want)
		}
		if !ap.IsCanonical() {
			t.Fatalf("round %d: self-mined AuxPow is not canonical", r)
		}
		// The exact decision CheckBlockSanity makes at the restart height.
		if blk.Header.Height >= gate && !blk.Header.AuxPow.IsCanonical() {
			t.Fatalf("round %d: CheckBlockSanity would reject this self-mined "+
				"block at height %d - the chain cannot be restarted by a "+
				"self-mining node", r, blk.Header.Height)
		}
	}

	if !sawNonZeroNonce {
		t.Fatal("every round solved at nonce 0, so the stamp was never proven " +
			"to track the winning nonce; raise b2Bits")
	}
}

// TestB2ParentHashStampIsNonceBound pins WHY the stamp has to come after the
// nonce search: ParBlockHeader.Hash() moves with the nonce, so a ParentHash
// captured at any other nonce is stale and still fails the gate.
func TestB2ParentHashStampIsNonceBound(t *testing.T) {
	svc := &Service{}
	blk := b2Block(config.GetDefaultParams().StrictMoneyRangeHeight, 77)
	if !svc.SolveBlock(blk, nil) {
		t.Fatalf("SolveBlock did not solve at bits %#x", b2Bits)
	}
	if !blk.Header.AuxPow.IsCanonical() {
		t.Fatal("solved block must carry a canonical AuxPow")
	}

	stale := blk.Header.AuxPow
	stale.ParBlockHeader.Nonce++
	if stale.IsCanonical() {
		t.Fatal("ParentHash must be bound to the exact solved parent header, " +
			"nonce included")
	}

	// The pristine shape, spelled out: GenerateAuxPow's product is
	// non-canonical from the very first nonce onwards, so stamping before the
	// search would not have helped either.
	pristine := auxpow.GenerateAuxPow(blk.Hash())
	if pristine.IsCanonical() {
		t.Fatal("GenerateAuxPow must not yield a canonical AuxPow on its own")
	}
	pristine.ParentHash = pristine.ParBlockHeader.Hash() // stamp at nonce 0
	pristine.ParBlockHeader.Nonce = 12345                // ...then keep searching
	if pristine.IsCanonical() {
		t.Fatal("a stamp taken before the nonce search must be stale")
	}
}

// TestB2SolveBlockUngatedBelowGate confirms the fix is block production only:
// mining below StrictMoneyRangeHeight still yields a block that satisfies both
// AuxPow acceptance clauses, and no acceptance rule is consulted here at all.
// Retained history is never re-produced, so below-gate replay is untouched.
func TestB2SolveBlockUngatedBelowGate(t *testing.T) {
	params := config.GetDefaultParams()
	svc := &Service{}
	blk := b2Block(params.StrictMoneyRangeHeight-1, 5)
	identity := blk.Hash()

	if !svc.SolveBlock(blk, nil) {
		t.Fatalf("SolveBlock did not solve at bits %#x", b2Bits)
	}
	ap := blk.Header.AuxPow
	if !ap.Check(&identity, auxpow.AuxPowChainID) {
		t.Fatal("below the gate the merged-mining proof must still pass Check")
	}
	if err := blockchain.CheckProofOfWork(&blk.Header,
		params.PowConfiguration.PowLimit); err != nil {
		t.Fatalf("below the gate the solved block must still pass CheckProofOfWork: %v", err)
	}
	if !ap.IsCanonical() {
		t.Fatal("the stamp is unconditional, so blocks mined below the gate are " +
			"canonical too")
	}
}
