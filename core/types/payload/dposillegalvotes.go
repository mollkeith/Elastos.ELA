// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

const (
	IllegalVoteVersion byte = 0x00
)

type VoteEvidence struct {
	ProposalEvidence
	Vote DPOSProposalVote
}

type DPOSIllegalVotes struct {
	Evidence        VoteEvidence
	CompareEvidence VoteEvidence

	hash *common.Uint256
}

func (d *VoteEvidence) Serialize(w io.Writer) error {
	if err := d.Vote.Serialize(w); err != nil {
		return err
	}

	if err := d.ProposalEvidence.Serialize(w); err != nil {
		return err
	}

	return nil
}

func (d *VoteEvidence) Deserialize(r io.Reader) (err error) {
	if err := d.Vote.Deserialize(r); err != nil {
		return err
	}

	if err := d.ProposalEvidence.Deserialize(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalVotes) Data(version byte) []byte {
	buf := new(bytes.Buffer)
	if err := d.Serialize(buf, version); err != nil {
		return []byte{0}
	}
	return buf.Bytes()
}

func (d *DPOSIllegalVotes) Serialize(w io.Writer, version byte) error {
	if err := d.Evidence.Serialize(w); err != nil {
		return err
	}

	if err := d.CompareEvidence.Serialize(w); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalVotes) Deserialize(r io.Reader, version byte) error {
	if err := d.Evidence.Deserialize(r); err != nil {
		return err
	}

	if err := d.CompareEvidence.Deserialize(r); err != nil {
		return err
	}

	return nil
}

func (d *DPOSIllegalVotes) Hash() common.Uint256 {
	if d.hash == nil {
		buf := new(bytes.Buffer)
		d.Serialize(buf, IllegalVoteVersion)
		hash := common.Hash(buf.Bytes())
		d.hash = &hash
	}
	return *d.hash
}

// DedupHash returns the SpecialTxHashes dedup key for illegal-vote evidence. Same
// defect and same fold as DPOSIllegalProposals.DedupHash (see the comment there): the
// raw payload Hash() carries the malleable BlockHeader blob, so one logical
// equivocation mints unbounded distinct dedup keys.
//
// The logical identity here is the pair of DPOSProposalVote hashes plus the evidenced
// BlockHeight. DPOSProposalVote.Hash() is SerializeUnsigned (proposal hash, signer,
// accept flag), so it excludes the vote signature and ECDSA signature malleability
// cannot move the key either, and it pins the proposal (and through it the block hash
// and height) by containing ProposalHash. Below the gate the legacy raw Hash() is
// returned unchanged for byte-identical replay.
func (d *DPOSIllegalVotes) DedupHash(strictActive bool) common.Uint256 {
	if !strictActive {
		return d.Hash()
	}
	return illegalEvidenceDedupKey(dedupDomainIllegalVote, d.Evidence.BlockHeight,
		d.Evidence.Vote.Hash(), d.CompareEvidence.Vote.Hash())
}

func (d *DPOSIllegalVotes) GetBlockHeight() uint32 {
	return d.Evidence.BlockHeight
}

func (d *DPOSIllegalVotes) Type() IllegalDataType {
	return IllegalVote
}
