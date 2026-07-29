// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/elanet/pact"
)

// MaxDPoSIllegalSigners bounds the signer slice at decode time (DoS ceiling, the
// same shape as MaxSidechainIllegalSigns). Far above any legitimate signer set.
const MaxDPoSIllegalSigners = 1024

type CoinType uint32

const (
	ELACoin = CoinType(0)

	IllegalBlockVersion byte = 0x00
)

type BlockEvidence struct {
	Header       []byte
	BlockConfirm []byte
	Signers      [][]byte

	hash *common.Uint256
}

type DPOSIllegalBlocks struct {
	CoinType        CoinType
	BlockHeight     uint32
	Evidence        BlockEvidence
	CompareEvidence BlockEvidence

	hash *common.Uint256
}

func (b *BlockEvidence) SerializeUnsigned(w io.Writer) error {
	if err := common.WriteVarBytes(w, b.Header); err != nil {
		return err
	}
	return nil
}

func (b *BlockEvidence) SerializeOthers(w io.Writer) error {
	if err := common.WriteVarBytes(w, b.BlockConfirm); err != nil {
		return err
	}

	if err := common.WriteVarUint(w, uint64(len(b.Signers))); err != nil {
		return err
	}

	for _, v := range b.Signers {
		if err := common.WriteVarBytes(w, v); err != nil {
			return err
		}
	}

	return nil
}

func (b *BlockEvidence) Serialize(w io.Writer) error {
	if err := b.SerializeUnsigned(w); err != nil {
		return err
	}

	if err := b.SerializeOthers(w); err != nil {
		return err
	}

	return nil
}

func (b *BlockEvidence) DeserializeUnsigned(r io.Reader) error {
	var err error
	if b.Header, err = common.ReadVarBytes(r, pact.MaxBlockContextSize,
		"block data"); err != nil {
		return err
	}
	return nil
}

func (b *BlockEvidence) DeserializeOthers(r io.Reader) (err error) {
	if b.BlockConfirm, err = common.ReadVarBytes(r, pact.MaxBlockHeaderSize,
		"confirm data"); err != nil {
		return err
	}

	var len uint64
	if len, err = common.ReadVarUint(r, 0); err != nil {
		return err
	}
	// Cap before allocating: a crafted varint gives `makeslice: cap out of range`
	// or OOM, reachable pre-auth via IllegalBlockEvidence relay.
	if len > MaxDPoSIllegalSigners {
		return errors.New("dpos illegal signers length exceeds maximum")
	}

	b.Signers = make([][]byte, 0, len)
	for i := uint64(0); i < len; i++ {
		var signer []byte
		if signer, err = common.ReadVarBytes(r, crypto.COMPRESSEDLEN,
			"public key"); err != nil {
			return err
		}
		b.Signers = append(b.Signers, signer)
	}

	return nil
}

func (b *BlockEvidence) Deserialize(r io.Reader) error {
	if err := b.DeserializeUnsigned(r); err != nil {
		return err
	}

	if err := b.DeserializeOthers(r); err != nil {
		return err
	}

	return nil
}

func (b *BlockEvidence) BlockHash() common.Uint256 {
	if b.hash == nil {
		buf := new(bytes.Buffer)
		b.Serialize(buf)
		hash := common.Hash(buf.Bytes())
		b.hash = &hash
	}
	return *b.hash
}

func (d *DPOSIllegalBlocks) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := d.Serialize(buf, version); err != nil {
		return []byte{0}
	}
	return buf.Bytes()
}

func (d *DPOSIllegalBlocks) SerializeUnsigned(w io.Writer, version byte) error {
	if err := common.WriteUint32(w, uint32(d.CoinType)); err != nil {
		return err
	}

	if err := common.WriteUint32(w, d.BlockHeight); err != nil {
		return err
	}

	if err := d.Evidence.SerializeUnsigned(w); err != nil {
		return err
	}

	if err := d.CompareEvidence.SerializeUnsigned(w); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalBlocks) Serialize(w io.Writer, version byte) error {
	if err := d.SerializeUnsigned(w, version); err != nil {
		return err
	}

	if err := d.Evidence.SerializeOthers(w); err != nil {
		return err
	}

	if err := d.CompareEvidence.SerializeOthers(w); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalBlocks) DeserializeUnsigned(r io.Reader, version byte) error {
	var err error
	var coinType uint32
	if coinType, err = common.ReadUint32(r); err != nil {
		return err
	}
	d.CoinType = CoinType(coinType)

	if d.BlockHeight, err = common.ReadUint32(r); err != nil {
		return err
	}

	if err = d.Evidence.DeserializeUnsigned(r); err != nil {
		return err
	}

	if err = d.CompareEvidence.DeserializeUnsigned(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalBlocks) Deserialize(r io.Reader, version byte) error {
	if err := d.DeserializeUnsigned(r, version); err != nil {
		return err
	}

	if err := d.Evidence.DeserializeOthers(r); err != nil {
		return err
	}

	if err := d.CompareEvidence.DeserializeOthers(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalBlocks) Hash() common.Uint256 {
	if d.hash == nil {
		buf := new(bytes.Buffer)
		d.SerializeUnsigned(buf, IllegalBlockVersion)
		hash := common.Hash(buf.Bytes())
		d.hash = &hash
	}
	return *d.hash
}

func (d *DPOSIllegalBlocks) GetBlockHeight() uint32 {
	return d.BlockHeight
}

func (d *DPOSIllegalBlocks) Type() IllegalDataType {
	return IllegalBlock
}

// DedupHash returns the SpecialTxHashes dedup key for this illegal-block evidence.
//
// The legacy Hash() folds the raw evidence-header bytes, but a block header's
// consensus identity common2.Header.Hash() is SerializeNoAux: it excludes the AuxPow
// (and the trailing sentinel byte). The illegal-block validation path never calls
// AuxPow.Check(), and even the canonical-AuxPow gate (AuxPow.IsCanonical) pins only two
// of the AuxPow fields, so the remaining sub-fields (AuxMerkleBranch, ParBlockHeader,
// ParCoinbaseTx, ParCoinBaseMerkle, AuxMerkleIndex) round-trip through
// Serialize/Deserialize: an attacker can re-encode one logical illegal block into
// unboundedly many raw byte strings, each with a distinct Hash(), bypassing the
// SpecialTxExists dedup set.
//
// When strictActive (evidence at/above StrictMoneyRangeHeight) this folds each evidence
// header by its logical identity (Header.Hash()) and canonically orders the two hashes,
// so every AuxPow encoding of one logical illegal block, and any reordering of the
// evidence pair, collapses to a single key. When !strictActive it returns the legacy
// raw Hash() unchanged so below-gate history serializes byte-identically. If either
// header fails to decode it falls back to the raw Hash() (a non-decodable header is
// rejected upstream anyway).
func (d *DPOSIllegalBlocks) DedupHash(strictActive bool) common.Uint256 {
	if !strictActive {
		return d.Hash()
	}
	h1, err1 := logicalHeaderHash(d.Evidence.Header)
	h2, err2 := logicalHeaderHash(d.CompareEvidence.Header)
	if err1 != nil || err2 != nil {
		return d.Hash()
	}
	// Canonical order, independent of the payload's raw-bytes evidence ordering.
	lo, hi := h1, h2
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	buf := new(bytes.Buffer)
	_ = common.WriteUint32(buf, uint32(d.CoinType))
	_ = common.WriteUint32(buf, d.BlockHeight)
	_ = lo.Serialize(buf)
	_ = hi.Serialize(buf)
	return common.Hash(buf.Bytes())
}

// logicalHeaderHash decodes a raw evidence-header byte string and returns its logical
// block identity (common2.Header.Hash() == SerializeNoAux, which excludes the AuxPow).
func logicalHeaderHash(raw []byte) (common.Uint256, error) {
	var hdr common2.Header
	if err := hdr.Deserialize(bytes.NewReader(raw)); err != nil {
		return common.Uint256{}, err
	}
	return hdr.Hash(), nil
}

// Domain tags for the logical illegal-evidence dedup keys, so the block, proposal and
// vote key spaces cannot collide with one another.
const (
	dedupDomainIllegalProposal = uint32(0x01)
	dedupDomainIllegalVote     = uint32(0x02)
)

// illegalEvidenceDedupKey folds one logical equivocation, an evidenced height plus the
// two evidence identities in canonical (order-independent) form, into a single dedup
// key. Shared by DPOSIllegalProposals.DedupHash and DPOSIllegalVotes.DedupHash, and
// deliberately shaped like DPOSIllegalBlocks.DedupHash.
func illegalEvidenceDedupKey(domain uint32, blockHeight uint32,
	h1, h2 common.Uint256) common.Uint256 {
	lo, hi := h1, h2
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	buf := new(bytes.Buffer)
	_ = common.WriteUint32(buf, domain)
	_ = common.WriteUint32(buf, blockHeight)
	_ = lo.Serialize(buf)
	_ = hi.Serialize(buf)
	return common.Hash(buf.Bytes())
}

// SpecialTxDedupKey returns the SpecialTxHashes dedup key for any DPOSIllegalData
// payload, given the coordinated StrictMoneyRangeHeight gate. At and above the gate,
// illegal-block evidence gets the AuxPow-independent logical key and illegal-proposal
// / illegal-vote evidence get the BlockHeader-independent logical key. Below the gate,
// and for the two remaining DPOSIllegalData types (SidechainIllegalData and
// InactiveArbitrators, which hash SerializeUnsigned only, so neither covers a raw
// header blob nor the arbiter signature set and neither has the malleability this fold
// exists to remove), the legacy raw payload Hash() is kept so below-gate history
// serializes byte-identically. The gate is read from the evidence's own BlockHeight so
// the read (State.SpecialTxExists) and write (State.recordSpecialTx) paths, and the
// block-level guard (blockchain.CheckSameBlockConflicts), always agree without
// threading an external height: read and write must flip together.
func SpecialTxDedupKey(d DPOSIllegalData, gateHeight uint32) common.Uint256 {
	switch p := d.(type) {
	case *DPOSIllegalBlocks:
		return p.DedupHash(p.BlockHeight >= gateHeight)
	case *DPOSIllegalProposals:
		return p.DedupHash(p.GetBlockHeight() >= gateHeight)
	case *DPOSIllegalVotes:
		return p.DedupHash(p.GetBlockHeight() >= gateHeight)
	}
	return d.Hash()
}
