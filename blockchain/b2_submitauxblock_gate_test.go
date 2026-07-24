// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// B2: above-gate coverage for submitauxblock, the primary mainnet
// block-production path. Before this file nothing in the tree referenced
// SubmitAuxBlock or CreateAuxBlock at all, so the route real merge miners use
// had no test at any height, let alone against the canonical-AuxPow gate the
// incident hard fork arms at StrictMoneyRangeHeight.
//
// servers.SubmitAuxBlock takes a block hash plus a hex AuxPow, runs
// AuxPow.Deserialize over it and assigns the result straight onto the pooled
// block's header (pow.Service.SubmitAuxBlock). The AuxPow is therefore entirely
// miner-supplied: nothing on the node builds it, and auxpow.GenerateAuxPow is
// not involved. These tests reproduce that wire path and then run the real
// BlockChain.CheckBlockSanity over the result.
//
// The three ParentHash encodings exercised here are the three that actually
// occur in the frozen mainnet store (2,260,597 records, heights 0..2,260,595):
//
//	canonical      2,260,597 - 609,240 records; the only shape seen since 2,090,419
//	display-order    431,903 records, last at height 2,090,418 (pool software that
//	                 serialised the parent hash reversed, i.e. as displayed)
//	zero             177,337 records, last at height   180,217 (the shape the
//	                 node's own SolveBlock produced)
//
// ParMerkleIndex is 0 in every one of the 2,260,597 records.
package blockchain

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
)

// b2NonCanonicalErr is the CheckBlockSanity rejection the gate produces.
const b2NonCanonicalErr = "non-canonical (malleable) AuxPow encoding"

// b2NoTxErr is the next rejection a header-only block hits, and therefore the
// proof that a submission cleared both AuxPow clauses and the proof of work.
const b2NoTxErr = "does not contain any transactions"

// b2SubmitBits is a compact difficulty of 2^240: cheap to solve, and well
// inside the mainnet PowLimit of 2^255-1 so CheckProofOfWork accepts it.
const b2SubmitBits uint32 = 0x1f010000

const b2MaxSearch = 1 << 26

// b2ParentHashEncoding selects which of the three real-world ParentHash
// encodings the simulated miner submits.
type b2ParentHashEncoding int

const (
	b2Canonical b2ParentHashEncoding = iota
	b2DisplayOrder
	b2Zero
)

// b2SubmittedBlock simulates one merge-mined submission end to end: build the
// aux block, let the pool solve the parent header, encode ParentHash the chosen
// way, put the AuxPow on the wire as hex and bring it back through
// AuxPow.Deserialize exactly as servers.SubmitAuxBlock does, then attach it to
// the pooled block the way pow.Service.SubmitAuxBlock does.
func b2SubmittedBlock(t *testing.T, height uint32, enc b2ParentHashEncoding) *types.Block {
	t.Helper()

	blk := &types.Block{
		Header: common2.Header{
			Version:   0,
			Timestamp: uint32(time.Now().Unix()),
			Bits:      b2SubmitBits,
			Height:    height,
		},
	}
	identity := blk.Hash()

	// The commitment a pool puts in its parent coinbase.
	ap := auxpow.GenerateAuxPow(identity)

	// The pool's proof-of-work search over the parent (BTC) header.
	target := CompactToBig(blk.Header.Bits)
	solved := false
	for i := uint32(0); i < b2MaxSearch; i++ {
		ap.ParBlockHeader.Nonce = i
		h := ap.ParBlockHeader.Hash()
		if HashToBig(&h).Cmp(target) <= 0 {
			solved = true
			break
		}
	}
	if !solved {
		t.Fatalf("could not solve the parent header within %d nonces", b2MaxSearch)
	}

	parent := ap.ParBlockHeader.Hash()
	switch enc {
	case b2Canonical:
		ap.ParentHash = parent
	case b2DisplayOrder:
		rev, err := common.Uint256FromBytes(common.BytesReverse(parent.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		ap.ParentHash = *rev
	case b2Zero:
		ap.ParentHash = common.Uint256{}
	}

	// The submitauxblock wire form.
	buf := new(bytes.Buffer)
	if err := ap.Serialize(buf); err != nil {
		t.Fatal(err)
	}
	raw, err := common.HexStringToBytes(common.BytesToHexString(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var submitted auxpow.AuxPow
	if err := submitted.Deserialize(bytes.NewReader(raw)); err != nil {
		t.Fatalf("auxpow deserialization failed: %v", err)
	}
	blk.Header.AuxPow = submitted

	if blk.Hash() != identity {
		t.Fatal("attaching the submitted AuxPow must not change block identity")
	}
	// Every encoding, including the two non-canonical ones, is a valid merged
	// mining proof: AuxPow.Check never reads ParentHash. The gate is the only
	// thing that separates them.
	if !blk.Header.AuxPow.Check(&identity, auxpow.AuxPowChainID) {
		t.Fatal("the submitted merged-mining proof must pass AuxPow.Check")
	}
	return blk
}

// TestB2SubmitAuxBlockAboveGate runs the real CheckBlockSanity over simulated
// submitauxblock submissions at and around the mainnet incident gate.
func TestB2SubmitAuxBlockAboveGate(t *testing.T) {
	gate := config.GetDefaultParams().StrictMoneyRangeHeight
	if gate != config.MainNetStrictMoneyRangeHeight {
		t.Fatalf("expected the mainnet incident gate %d, got %d",
			config.MainNetStrictMoneyRangeHeight, gate)
	}
	b := gateChain(t, gate)
	b.TimeSource = NewMedianTime()

	sanity := func(height uint32, enc b2ParentHashEncoding) string {
		err := b.CheckBlockSanity(b2SubmittedBlock(t, height, enc))
		if err == nil {
			t.Fatal("a header-only block must still be rejected for having no transactions")
		}
		return err.Error()
	}

	// A canonical miner submission clears both AuxPow clauses and the proof of
	// work at and above the gate: the restart is minable by real miners.
	for _, h := range []uint32{gate, gate + 1} {
		got := sanity(h, b2Canonical)
		if strings.Contains(got, b2NonCanonicalErr) {
			t.Fatalf("height %d: canonical submission rejected by the gate: %s", h, got)
		}
		if !strings.Contains(got, b2NoTxErr) {
			t.Fatalf("height %d: canonical submission should have reached the "+
				"transaction check, got: %s", h, got)
		}
	}

	// Both non-canonical encodings that mainnet has actually carried are
	// rejected at and above the gate, even though AuxPow.Check passes them.
	for _, enc := range []b2ParentHashEncoding{b2DisplayOrder, b2Zero} {
		for _, h := range []uint32{gate, gate + 1} {
			if got := sanity(h, enc); !strings.Contains(got, b2NonCanonicalErr) {
				t.Fatalf("height %d, encoding %d: submission should have been "+
					"rejected as non-canonical, got: %s", h, enc, got)
			}
		}
	}

	// Below the gate nothing changes - retained history that carried these
	// encodings still replays byte-identically.
	for _, enc := range []b2ParentHashEncoding{b2DisplayOrder, b2Zero} {
		got := sanity(gate-1, enc)
		if strings.Contains(got, b2NonCanonicalErr) {
			t.Fatalf("below the gate, encoding %d must not be rejected: %s", enc, got)
		}
		if !strings.Contains(got, b2NoTxErr) {
			t.Fatalf("below the gate, encoding %d should have reached the "+
				"transaction check, got: %s", enc, got)
		}
	}
}
