// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Reorg revert-symmetry harness, CR proposal-manager edition. Drives the REAL
// dealProposal forward path so the REAL revert closure is Appended, commits it,
// rolls back through the REAL utils.History, and compares the COMPLETE proposal
// state -- not just the field under test.
package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/test/revsym"
	"github.com/elastos/Elastos.ELA/utils"
)

func revsymCROpts() revsym.Options {
	return revsym.NewOptions().SkipField("utils.History.commits")
}

// TestRevsym_F048_ChangeProposalOwner covers the ChangeProposalOwner branch of
// dealProposal. The pre-fix revert restored proposalState.ProposalOwner -- the owner
// of the CHANGE proposal -- into the TARGET proposal, so a reorg across the change
// block left the target proposal owned by the wrong key. The fix captures
// proposal.ProposalOwner, the object the forward actually mutates.
func TestRevsym_F048_ChangeProposalOwner(t *testing.T) {
	for _, withNewRecipient := range []bool{false, true} {
		const H = uint32(5000)
		history := utils.NewHistory(720)
		pm := &ProposalManager{
			ProposalKeyFrame: *NewProposalKeyFrame(),
			params:           &config.DefaultParams,
			history:          history,
		}

		targetHash := common.Uint256{0xA1, 0xA2}
		targetOwner := []byte{0x02, 0x11, 0x11, 0x11}
		targetRecipient := common.Uint168{0x21, 0x11}
		pm.Proposals[targetHash] = &ProposalState{
			Status:        Finished,
			ProposalOwner: targetOwner,
			Recipient:     targetRecipient,
		}

		changeOwner := []byte{0x02, 0x22, 0x22, 0x22}
		newOwner := []byte{0x02, 0x33, 0x33, 0x33}
		newRecipient := common.Uint168{0x21, 0x33}
		change := &ProposalState{
			// The CHANGE proposal's own owner differs from the target's: this is the
			// discriminator. The pristine revert wrote THIS key into the target.
			ProposalOwner: changeOwner,
			Proposal: payload.CRCProposalInfo{
				ProposalType:       payload.ChangeProposalOwner,
				TargetProposalHash: targetHash,
				NewOwnerPublicKey:  newOwner,
				OwnerPublicKey:     changeOwner,
			},
		}
		if withNewRecipient {
			change.Proposal.NewRecipient = newRecipient
		}

		history.Commit(H - 1) // the fork point: a committed parent block
		opt := revsymCROpts()
		before := revsym.Dump(pm, opt)

		unused := common.Fixed64(0)
		pm.dealProposal(change, &unused, H)
		history.Commit(H)

		if revsym.Diff(before, revsym.Dump(pm, opt), 1) == "" {
			t.Fatalf("withNewRecipient=%v: dealProposal changed NOTHING -- the case "+
				"reaches no closure", withNewRecipient)
		}
		if err := history.RollbackTo(H - 1); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if d := revsym.Diff(before, revsym.Dump(pm, opt), 25); d != "" {
			t.Errorf("F-048 (withNewRecipient=%v): REORG REVERT ASYMMETRY -- complete "+
				"proposal state after undo != state before:\n%s", withNewRecipient, d)
		}
	}
}
