// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package auxpow

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"

	"github.com/elastos/Elastos.ELA/common"
)

var (
	AuxPowChainID         = 1224
	pchMergedMiningHeader = []byte{0xfa, 0xbe, 'm', 'm'}
)

type AuxPow struct {
	AuxMerkleBranch   []common.Uint256
	AuxMerkleIndex    int
	ParCoinbaseTx     BtcTx
	ParCoinBaseMerkle []common.Uint256
	ParMerkleIndex    int
	ParBlockHeader    BtcHeader
	ParentHash        common.Uint256
}

func NewAuxPow(AuxMerkleBranch []common.Uint256, AuxMerkleIndex int,
	ParCoinbaseTx BtcTx, ParCoinBaseMerkle []common.Uint256,
	ParMerkleIndex int, ParBlockHeader BtcHeader) *AuxPow {

	return &AuxPow{
		AuxMerkleBranch:   AuxMerkleBranch,
		AuxMerkleIndex:    AuxMerkleIndex,
		ParCoinbaseTx:     ParCoinbaseTx,
		ParCoinBaseMerkle: ParCoinBaseMerkle,
		ParMerkleIndex:    ParMerkleIndex,
		ParBlockHeader:    ParBlockHeader,
	}
}

func (ap *AuxPow) Serialize(w io.Writer) error {
	err := ap.ParCoinbaseTx.Serialize(w)
	if err != nil {
		return err
	}

	err = ap.ParentHash.Serialize(w)
	if err != nil {
		return err
	}

	count := uint64(len(ap.ParCoinBaseMerkle))
	err = common.WriteVarUint(w, count)
	if err != nil {
		return err
	}

	for _, pcbm := range ap.ParCoinBaseMerkle {
		err = pcbm.Serialize(w)
		if err != nil {
			return err
		}
	}

	index := uint32(ap.ParMerkleIndex)
	err = common.WriteUint32(w, index)
	if err != nil {
		return err
	}

	count = uint64(len(ap.AuxMerkleBranch))
	err = common.WriteVarUint(w, count)
	if err != nil {
		return err
	}

	for _, amb := range ap.AuxMerkleBranch {
		err = amb.Serialize(w)
		if err != nil {
			return err
		}
	}

	index = uint32(ap.AuxMerkleIndex)
	err = common.WriteUint32(w, index)
	if err != nil {
		return err
	}

	err = ap.ParBlockHeader.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}

func (ap *AuxPow) Deserialize(r io.Reader) error {
	err := ap.ParCoinbaseTx.Deserialize(r)
	if err != nil {
		return err
	}

	err = ap.ParentHash.Deserialize(r)
	if err != nil {
		return err
	}

	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}

	ap.ParCoinBaseMerkle = make([]common.Uint256, 0)
	for i := uint64(0); i < count; i++ {
		var hash common.Uint256
		err = hash.Deserialize(r)
		if err != nil {
			return err
		}
		ap.ParCoinBaseMerkle = append(ap.ParCoinBaseMerkle, hash)
	}

	index, err := common.ReadUint32(r)
	if err != nil {
		return err
	}
	ap.ParMerkleIndex = int(index)

	count, err = common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}

	ap.AuxMerkleBranch = make([]common.Uint256, 0)
	for i := uint64(0); i < count; i++ {
		var hash common.Uint256
		err = hash.Deserialize(r)
		if err != nil {
			return err
		}
		ap.AuxMerkleBranch = append(ap.AuxMerkleBranch, hash)
	}

	index, err = common.ReadUint32(r)
	if err != nil {
		return err
	}
	ap.AuxMerkleIndex = int(index)

	err = ap.ParBlockHeader.Deserialize(r)
	if err != nil {
		return err
	}

	return nil
}

func (ap *AuxPow) Check(hashAuxBlock *common.Uint256, chainID int) bool {
	if GetMerkleRoot(ap.ParCoinbaseTx.Hash(), ap.ParCoinBaseMerkle, ap.ParMerkleIndex) != ap.ParBlockHeader.MerkleRoot {
		return false
	}

	// reverse the hashAuxBlock
	hashAuxBlockBytes := common.BytesReverse(hashAuxBlock.Bytes())
	hashAuxBlock, _ = common.Uint256FromBytes(hashAuxBlockBytes)

	auxRootHash := GetMerkleRoot(*hashAuxBlock, ap.AuxMerkleBranch, ap.AuxMerkleIndex)

	// F-132: a valid AuxPoW parent coinbase always has >=1 input; a 0-input coinbase
	// (BtcTx.Deserialize enforces no minimum) would panic here. Reject it (crash-harden).
	if len(ap.ParCoinbaseTx.TxIn) == 0 {
		return false
	}
	script := ap.ParCoinbaseTx.TxIn[0].SignatureScript
	scriptStr := hex.EncodeToString(script)

	// reverse the auxRootHash
	auxRootHashReverseStr := hex.EncodeToString(common.BytesReverse(auxRootHash.Bytes()))
	pchMergedMiningHeaderStr := hex.EncodeToString(pchMergedMiningHeader)

	headerIndex := strings.Index(scriptStr, pchMergedMiningHeaderStr)
	rootHashIndex := strings.Index(scriptStr, auxRootHashReverseStr)

	if (headerIndex == -1) || (rootHashIndex == -1) {
		return false
	}

	if strings.Index(scriptStr[headerIndex+2:], pchMergedMiningHeaderStr) != -1 {
		return false
	}

	if headerIndex+len(pchMergedMiningHeaderStr) != rootHashIndex {
		return false
	}

	rootHashIndex += len(auxRootHashReverseStr)
	// F-172: scriptStr is a HEX string (2 chars/byte); the reads below take 8 raw
	// bytes (4-byte size + 4-byte nonce), i.e. 16 hex chars. The original `< 8` guard
	// counted hex chars as bytes, so a coinbase ending 4-7 bytes (8-15 hex chars) after
	// the aux-root commit passed the guard then sliced OOB at the nonce read -> pre-PoW
	// remote panic. Require 16 hex chars.
	if len(scriptStr)-rootHashIndex < 16 {
		return false
	}

	size := binary.LittleEndian.Uint32(script[rootHashIndex/2 : rootHashIndex/2+4])
	merkleHeight := len(ap.AuxMerkleBranch)
	// F-173: merkleHeight is attacker-controlled (len(AuxMerkleBranch) via ReadVarUint).
	// For merkleHeight >= 32 the uint32 shift `1 << merkleHeight` overflows to 0, which
	// (a) degenerates this size guard (0 == 0 passes when size==0) and (b) makes
	// GetExpectedIndex do `rand % 0` -> divide-by-zero panic. A legitimate aux branch is
	// far shorter; reject oversized branches. Ungated crash-harden.
	if merkleHeight >= 32 {
		return false
	}
	if size != uint32(1<<uint32(merkleHeight)) {
		return false
	}

	nonce := binary.LittleEndian.Uint32(script[rootHashIndex/2+4 : rootHashIndex/2+8])
	if ap.AuxMerkleIndex != GetExpectedIndex(nonce, chainID, merkleHeight) {
		return false
	}

	return true
}

// IsCanonical reports whether the AuxPow uses the single canonical encoding of
// the two fields that Check() leaves unconstrained yet Header.Serialize folds
// into Header.HashWithAux(). HashWithAux() seeds DPoSV2 committee selection
// (dpos/state/arbitrators.go getRandomDposV2Producers); because the block's
// consensus identity Header.Hash() is computed WITHOUT the AuxPow
// (SerializeNoAux), two encodings of one block (identical Hash(), identical
// PoW) that differ in these fields yield a divergent HashWithAux() -> a
// zero-PoW-cost committee/seat split. Pinning them to their canonical value
// makes HashWithAux() a deterministic function of block identity.
//
//   F-090: ParMerkleIndex must be 0. The parent coinbase is always the first
//          (leftmost) leaf of the parent merkle tree, so its branch index is 0
//          for every real block (mainnet census: 0 of 2,260,597 stored blocks
//          are non-zero). GetMerkleRoot only consumes the low
//          len(ParCoinBaseMerkle) bits, leaving the high bits free to malleate
//          while Check() still passes; pinning to 0 removes them. Matches
//          Bitcoin CAuxPow::check ("AuxPow is not a generate" when nIndex != 0).
//   F-041: ParentHash must equal ParBlockHeader.Hash(). ParentHash is read by
//          neither Check() nor CheckProofOfWork(), so any 32 bytes pass; the
//          canonical value is the parent block hash the field names (mainnet
//          census: every stored block at and above the StrictMoneyRangeHeight
//          gate satisfies this; the last non-canonical block was height
//          2,090,418, 170,033 blocks below the gate).
//
// Callers gate this at StrictMoneyRangeHeight so below-gate history -- which
// carried non-canonical ParentHash values -- still replays byte-identically.
func (ap *AuxPow) IsCanonical() bool {
	if ap.ParMerkleIndex != 0 {
		return false
	}
	if ap.ParentHash != ap.ParBlockHeader.Hash() {
		return false
	}
	return true
}

func GetMerkleRoot(hash common.Uint256, merkleBranch []common.Uint256, index int) common.Uint256 {
	if index == -1 {
		return common.Uint256{}
	}
	var sha [64]byte
	for _, it := range merkleBranch {
		if (index & 1) == 1 {
			copy(sha[:32], it[:])
			copy(sha[32:], hash[:])
			hash = common.Hash(sha[:])
		} else {
			copy(sha[:32], hash[:])
			copy(sha[32:], it[:])
			hash = common.Hash(sha[:])
		}
		index >>= 1
	}
	return hash
}

func GetExpectedIndex(nonce uint32, chainID, h int) int {
	// F-173 defense-in-depth: `1 << uint32(h)` overflows to 0 for h >= 32 (uint32),
	// making the modulus a divide-by-zero. Callers should reject such heights (Check
	// does), but guard here too since GetExpectedIndex is exported.
	if h < 0 || h >= 32 {
		return -1
	}
	rand := nonce
	rand = rand*1103515245 + 12345
	rand += uint32(chainID)
	rand = rand*1103515245 + 12345

	return int(rand % (1 << uint32(h)))
}
