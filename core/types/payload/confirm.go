// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA/common"
)

type Confirm struct {
	Proposal DPOSProposal
	Votes    []DPOSProposalVote
}

func (p *Confirm) TryAppend(v DPOSProposalVote) bool {
	if p.Proposal.Hash().IsEqual(v.ProposalHash) {
		p.Votes = append(p.Votes, v)
		return true
	}
	return false
}

// MaxDPOSProposalVotes bounds the per-confirm signature slice at decode time.
// Real values are the arbiter count (dozens); this is a DoS ceiling, not a
// consensus rule.
const MaxDPOSProposalVotes = 1024

func (p *Confirm) Serialize(w io.Writer) error {
	if err := p.Proposal.Serialize(w); err != nil {
		return err
	}

	if err := common.WriteUint64(w, uint64(len(p.Votes))); err != nil {
		return err
	}

	for _, sign := range p.Votes {
		if err := sign.Serialize(w); err != nil {
			return err
		}
	}

	return nil
}

func (p *Confirm) Deserialize(r io.Reader) error {
	if err := p.Proposal.Deserialize(r); err != nil {
		return err
	}

	signCount, err := common.ReadUint64(r)
	if err != nil {
		return err
	}
	// Decode-DoS guard: signCount is attacker-controlled from an untrusted p2p
	// message and drives an upfront allocation. A DPoS confirm carries at most one
	// vote per arbiter (dozens), so cap far above any real arbiter set but well
	// below the 2^64 that would crash/OOM the node before any consensus check.
	if signCount > MaxDPOSProposalVotes {
		return errors.New("confirm signCount exceeds maximum")
	}
	p.Votes = make([]DPOSProposalVote, signCount)

	for i := uint64(0); i < signCount; i++ {
		err := p.Votes[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	return nil
}
