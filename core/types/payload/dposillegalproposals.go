// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"io"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/elanet/pact"
)

const (
	IllegalProposalVersion byte = 0x00
)

type ProposalEvidence struct {
	Proposal    DPOSProposal
	BlockHeader []byte
	BlockHeight uint32
}

type DPOSIllegalProposals struct {
	Evidence        ProposalEvidence
	CompareEvidence ProposalEvidence

	hash *common.Uint256
}

func (d *ProposalEvidence) Serialize(w io.Writer) error {
	if err := d.Proposal.Serialize(w); err != nil {
		return err
	}

	if err := common.WriteVarBytes(w, d.BlockHeader); err != nil {
		return err
	}

	if err := common.WriteUint32(w, d.BlockHeight); err != nil {
		return err
	}

	return nil
}

func (d *ProposalEvidence) Deserialize(r io.Reader) (err error) {
	if err = d.Proposal.Deserialize(r); err != nil {
		return err
	}

	if d.BlockHeader, err = common.ReadVarBytes(r, pact.MaxBlockContextSize,
		"block header"); err != nil {
		return err
	}

	if d.BlockHeight, err = common.ReadUint32(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalProposals) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := d.Serialize(buf, version); err != nil {
		return []byte{0}
	}
	return buf.Bytes()
}

func (d *DPOSIllegalProposals) Serialize(w io.Writer, version byte) error {
	if err := d.Evidence.Serialize(w); err != nil {
		return err
	}

	if err := d.CompareEvidence.Serialize(w); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalProposals) Deserialize(r io.Reader, version byte) error {
	if err := d.Evidence.Deserialize(r); err != nil {
		return err
	}

	if err := d.CompareEvidence.Deserialize(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalProposals) Hash() common.Uint256 {
	if d.hash == nil {
		buf := new(bytes.Buffer)
		d.Serialize(buf, IllegalProposalVersion)
		hash := common.Hash(buf.Bytes())
		d.hash = &hash
	}
	return *d.hash
}

// DedupHash returns the SpecialTxHashes dedup key for illegal-proposal evidence.
//
// Without it DPOSIllegalProposals falls through to the raw payload Hash(), which
// serialises the whole ProposalEvidence including the raw BlockHeader blob. That blob
// is constrained only by header.Deserialize succeeding, header.Height ==
// evidence.BlockHeight and header.Hash().IsEqual(evidence.Proposal.BlockHash), and
// Header.Deserialize discards a trailing sentinel byte without asserting the buffer was
// consumed, so arbitrary trailing bytes survive into the stored blob and into Hash().
// One genuine, unforgeable equivocation therefore yields unboundedly many distinct
// dedup keys, defeating State.SpecialTxExists / recordSpecialTx and the
// CheckSameBlockConflicts illegal-evidence arm, and permanently growing SpecialTxHashes
// (which is serialized into every DPoS keyframe/checkpoint) with attacker-chosen input.
//
// At and above the gate this keys on the logical equivocation identity instead: the two
// DPOSProposal hashes in canonical order plus the evidenced BlockHeight, with the
// BlockHeader blob excluded entirely. DPOSProposal.Hash() is SerializeUnsigned (sponsor,
// block hash, view offset) so it is signature-malleability-proof too. Below the gate it
// returns the legacy raw Hash() unchanged, so below-gate history serializes
// byte-identically. Mirrors DPOSIllegalBlocks.DedupHash so the families stay symmetric.
// The domain tag keeps the proposal / vote / block key spaces disjoint.
//
// Retained history is untouched by the re-keying: there are 13
// IllegalProposalEvidence and 269 IllegalVoteEvidence transactions in all of
// history, and none of either at or above the gate.
func (d *DPOSIllegalProposals) DedupHash(strictActive bool) common.Uint256 {
	if !strictActive {
		return d.Hash()
	}
	return illegalEvidenceDedupKey(dedupDomainIllegalProposal, d.Evidence.BlockHeight,
		d.Evidence.Proposal.Hash(), d.CompareEvidence.Proposal.Hash())
}

func (d *DPOSIllegalProposals) GetBlockHeight() uint32 {
	return d.Evidence.BlockHeight
}

func (d *DPOSIllegalProposals) Type() IllegalDataType {
	return IllegalProposal
}
