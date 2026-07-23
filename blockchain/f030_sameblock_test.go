// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// F-030 same-block closeout (Track A) — the illegal-evidence / inactive-arbitrators arm of
// blockchain.CheckSameBlockConflicts. The committed-state dedup GetState().SpecialTxExists
// reads pre-block state and CheckDuplicateTx keys on the full tx hash, so within ONE block
// two txs carrying one LOGICAL illegal evidence but distinct tx hashes both pass and the
// evidence is processed (and penalized) twice. F-030 folds the illegal-block dedup key by
// the AuxPow-independent logical block identity; this guard applies that same key at the
// block layer so the two encodings collide in-block. Mirrors the mempool slotSpecialTxHash
// (which covers all five special-tx types) and the f028/f100 same-block test style.
//
// Vectors:
//   - IllegalBlock (logical-key branch): two AuxPow encodings of ONE logical illegal-block
//     evidence (distinct tx hashes, same logical dedup key) in one block -> rejected
//     at/above the gate, accepted below (replay), and two DISTINCT evidences pass.
//   - InactiveArbitrators (raw-Hash branch, shared by IllegalProposal/Vote/Sidechain too):
//     two txs with the same Sponsor+BlockHeight but different Arbitrators lists (the Hash()
//     dedup key ignores the Arbitrators list -> same key, distinct tx hash) -> rejected
//     at/above the gate, accepted below, and a distinct Sponsor passes.
package blockchain_test

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// f030Uint256 returns a deterministic Uint256 seeded by a byte, so the vectors are stable
// (fail-on-pristine must be deterministic).
func f030Uint256(seed byte) common.Uint256 {
	var u common.Uint256
	for i := range u {
		u[i] = seed + byte(i)
	}
	return u
}

// f030Header builds a fully serializable ELA block header (with a well-formed AuxPow) whose
// LOGICAL identity (Header.Hash() == SerializeNoAux, AuxPow excluded) is fixed by seed.
func f030Header(height uint32, seed byte) *common2.Header {
	return &common2.Header{
		Version:    1,
		Previous:   f030Uint256(seed),
		MerkleRoot: f030Uint256(seed + 1),
		Timestamp:  1000 + uint32(seed),
		Bits:       0x1d00ffff,
		Nonce:      uint32(seed),
		Height:     height,
		AuxPow: auxpow.AuxPow{
			AuxMerkleBranch: []common.Uint256{f030Uint256(seed + 2)},
			AuxMerkleIndex:  0,
			ParCoinbaseTx: auxpow.BtcTx{
				Version: 1,
				TxIn: []*auxpow.BtcTxIn{{
					PreviousOutPoint: auxpow.BtcOutPoint{Hash: f030Uint256(seed + 3), Index: 0},
					SignatureScript:  []byte{0x51},
					Sequence:         0xffffffff,
				}},
				TxOut: []*auxpow.BtcTxOut{{
					Value:    1,
					PkScript: []byte{0x51},
				}},
				LockTime: 0,
			},
			ParCoinBaseMerkle: []common.Uint256{f030Uint256(seed + 4)},
			ParMerkleIndex:    0,
			ParBlockHeader: auxpow.BtcHeader{
				Version:    1,
				Previous:   f030Uint256(seed + 5),
				MerkleRoot: f030Uint256(seed + 6),
				Timestamp:  2000 + uint32(seed),
				Bits:       0x1d00ffff,
				Nonce:      uint32(seed) + 7,
			},
			ParentHash: f030Uint256(seed + 8),
		},
	}
}

func f030SerializeHeader(t *testing.T, h *common2.Header) []byte {
	buf := new(bytes.Buffer)
	assert.NoError(t, h.Serialize(buf))
	return buf.Bytes()
}

// f030IllegalBlocksTx wraps an ELA illegal-block evidence pair (two raw header byte strings)
// in an IllegalBlockEvidence tx at the given evidence BlockHeight.
func f030IllegalBlocksTx(height uint32, h1raw, h2raw []byte) interfaces.Transaction {
	pl := &payload.DPOSIllegalBlocks{
		CoinType:        payload.ELACoin,
		BlockHeight:     height,
		Evidence:        payload.BlockEvidence{Header: h1raw},
		CompareEvidence: payload.BlockEvidence{Header: h2raw},
	}
	return f028Tx(common2.IllegalBlockEvidence, payload.IllegalBlockVersion, pl, nil)
}

// TestF030SameBlockDuplicateIllegalBlockEvidence — two AuxPow encodings of ONE logical
// illegal-block evidence in a single block collide on the AuxPow-independent logical dedup
// key and are rejected at/above the gate; below the gate the same block validates
// byte-identically (the guard does not run); two DISTINCT logical evidences pass.
func TestF030SameBlockDuplicateIllegalBlockEvidence(t *testing.T) {
	// Evidence BlockHeight at the gate so SpecialTxDedupKey takes the logical (F-030) branch.
	const height = f028Gate

	h1 := f030Header(height, 10)
	h2 := f030Header(height, 40)
	h1raw := f030SerializeHeader(t, h1)
	h2raw := f030SerializeHeader(t, h2)

	// Encoding E2 of h2: mutate an AuxPow sub-field EXCLUDED from Header.Hash().
	h2b := f030Header(height, 40)
	h2b.AuxPow.AuxMerkleBranch = append(h2b.AuxPow.AuxMerkleBranch, f030Uint256(200))
	h2braw := f030SerializeHeader(t, h2b)

	// Same logical block, different raw bytes -> the F-030 malleability precondition.
	assert.NotEqual(t, h2raw, h2braw, "two AuxPow encodings must differ byte-wise")
	assert.Equal(t, h2.Hash(), h2b.Hash(), "two AuxPow encodings must share ONE logical block hash")

	tx1 := f030IllegalBlocksTx(height, h1raw, h2raw)  // E1
	tx2 := f030IllegalBlocksTx(height, h1raw, h2braw) // E2 (same logical evidence)

	// Distinct tx hashes -> CheckDuplicateTx never collapses them (the bypass is real).
	assert.NotEqual(t, tx1.Hash(), tx2.Hash(), "the two encodings must have distinct tx hashes")

	// Above gate: the guard folds both to one logical key -> rejected.
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, tx1, tx2), f028Gate),
		"two AuxPow encodings of one logical illegal-block evidence in one block must be rejected at/above the gate")

	// Below gate: guard returns nil for the whole block -> accepted (byte-identical legacy).
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, tx1, tx2), f028Gate),
		"below the gate the block must validate byte-identically")

	// Two DISTINCT logical illegal blocks are legitimate and must pass above the gate.
	h3 := f030Header(height, 70)
	h3raw := f030SerializeHeader(t, h3)
	txOther := f030IllegalBlocksTx(height, h1raw, h3raw)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, tx1, txOther), f028Gate),
		"two DISTINCT illegal-block evidences in one block are legitimate and must pass")
}

// TestF030SameBlockDuplicateInactiveArbitrators — the raw-Hash() branch of the same arm
// (shared by IllegalProposal/Vote/Sidechain). InactiveArbitrators.Hash() folds only
// Sponsor+BlockHeight (SerializeUnsigned), so two txs with the same Sponsor+BlockHeight but
// different Arbitrators lists share ONE dedup key yet have distinct tx hashes -> rejected
// at/above the gate, accepted below, and a distinct Sponsor passes.
func TestF030SameBlockDuplicateInactiveArbitrators(t *testing.T) {
	sponsor := []byte{0x02, 0xaa, 0xbb, 0xcc}
	mk := func(arbs [][]byte) interfaces.Transaction {
		pl := &payload.InactiveArbitrators{
			Sponsor:     sponsor,
			Arbitrators: arbs,
			BlockHeight: f028Gate,
		}
		return f028Tx(common2.InactiveArbitrators, payload.InactiveArbitratorsVersion, pl, nil)
	}
	ia1 := mk([][]byte{{0x01}})
	ia2 := mk([][]byte{{0x01}, {0x02}}) // same Sponsor+BlockHeight, different Arbitrators

	assert.NotEqual(t, ia1.Hash(), ia2.Hash(), "the two inactive-arbitrator txs must have distinct tx hashes")

	// Above gate: same Sponsor+BlockHeight -> one dedup key -> rejected.
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, ia1, ia2), f028Gate),
		"two inactive-arbitrator txs sharing Sponsor+BlockHeight in one block must be rejected at/above the gate")
	// Below gate: replay-safe (accepted).
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, ia1, ia2), f028Gate),
		"below the gate the block must validate byte-identically")

	// A DISTINCT sponsor is a distinct emergency record and must pass above the gate.
	iaOther := func() interfaces.Transaction {
		pl := &payload.InactiveArbitrators{
			Sponsor:     []byte{0x02, 0xdd, 0xee, 0xff},
			Arbitrators: [][]byte{{0x01}},
			BlockHeight: f028Gate,
		}
		return f028Tx(common2.InactiveArbitrators, payload.InactiveArbitratorsVersion, pl, nil)
	}()
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, ia1, iaOther), f028Gate),
		"inactive-arbitrator txs with distinct sponsors are legitimate and must pass")
}
