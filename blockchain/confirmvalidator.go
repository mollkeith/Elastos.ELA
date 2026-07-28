// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	. "github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

func ConfirmSanityCheck(confirm *payload.Confirm) error {
	if err := ProposalSanityCheck(&confirm.Proposal); err != nil {
		return errors.New("[ConfirmSanityCheck] confirm contain invalid " +
			"proposal: " + err.Error())
	}

	proposalHash := confirm.Proposal.Hash()
	for _, vote := range confirm.Votes {
		if !vote.Accept {
			return errors.New("[ConfirmSanityCheck] confirm contains " +
				"reject vote")
		}

		if !proposalHash.IsEqual(vote.ProposalHash) {
			return errors.New("[ConfirmSanityCheck] confirm contains " +
				"invalid vote")
		}

		if err := VoteSanityCheck(&vote); err != nil {
			return errors.New("[ConfirmSanityCheck] confirm contain invalid " +
				"vote: " + err.Error())
		}
	}

	return nil
}

func IllegalConfirmContextCheck(confirm *payload.Confirm, blockHeight uint32,
	strictActive bool) error {
	signers := make(map[string]struct{})
	for _, vote := range confirm.Votes {
		if !vote.Accept {
			continue
		}
		signers[common.BytesToHexString(vote.Signer)] = struct{}{}
	}

	// At and above StrictMoneyRangeHeight, validate the confirm sponsor and every vote
	// signer against the DPoS arbiter set on duty at the evidenced height, which is the
	// correct voter universe and matches sibling illegal-proposal and illegal-vote
	// evidence (which use ProposalContextCheckByHeight / VoteContextCheckByHeight). The
	// legacy GetAllProducersPublicKey universe below admits signatures from any producer
	// that ever registered, not just the round's arbiters, so off-duty producers could be
	// counted toward the majority to fabricate evidence. Below the gate the legacy
	// universe is kept so historical evidence replays byte-identically.
	//
	// Fixing the voter universe alone leaves the threshold wrong, which makes the
	// function read sound while it is not. Two defects follow from that, and both are
	// closed here:
	//
	//  (1) Taking the majority count from GetArbitersMajorityCount(), that is 2/3 of
	//      len(a.CurrentArbitrators), measures the committee on duty now, while
	//      membership is checked against the committee at the evidenced height. Count
	//      and universe would be drawn from two different committees.
	//  (2) GetSnapshot returns a slice of frames (SnapshotByHeight appends on a force
	//      change, so one election key can hold a pre- and a post-force-change frame),
	//      and ProposalContextCheckByHeight / VoteContextCheckByHeight each accept a
	//      match in any frame, independently per signer. Nothing then binds the sponsor
	//      and the N votes to one coherent historical committee, so the admissible
	//      signer universe is the union of two committees while the bar is 2/3 of one,
	//      and a signer set that never simultaneously existed as a majority of any real
	//      committee could clear it.
	//
	// So one key frame is selected and used for both the count and the membership: the
	// sponsor and every vote signer must belong to the same frame, and the accepting
	// signer count must exceed 2/3 of that frame's size. Accept if any single frame
	// satisfies the whole conjunction. An empty ring fails closed, as it already did via
	// the by-height checks, but is rejected explicitly rather than incidentally.
	//
	// Applied to the strictActive branch only, so the legacy branch below and its
	// current-committee majority check are untouched for below-gate replay. No
	// IllegalBlockEvidence transaction exists anywhere in the retained chain, so
	// re-thresholding rejects no real history.
	if strictActive {
		frames := DefaultLedger.Arbitrators.GetSnapshot(blockHeight)
		if len(frames) == 0 {
			return errors.New("[IllegalConfirmContextCheck] no arbiter snapshot " +
				"retained for the evidenced height")
		}
		var lastErr error
		for _, frame := range frames {
			members := make(map[string]struct{}, len(frame.CurrentArbitrators))
			for _, a := range frame.CurrentArbitrators {
				members[common.BytesToHexString(a.GetNodePublicKey())] = struct{}{}
			}
			if _, ok := members[common.BytesToHexString(
				confirm.Proposal.Sponsor)]; !ok {
				lastErr = errors.New("[IllegalConfirmContextCheck] confirm contain " +
					"invalid proposal: current arbitrators verify error")
				continue
			}
			var badVote bool
			for _, vote := range confirm.Votes {
				if _, ok := members[common.BytesToHexString(vote.Signer)]; !ok {
					badVote = true
					break
				}
			}
			if badVote {
				lastErr = errors.New("[IllegalConfirmContextCheck] confirm contain " +
					"invalid vote: current arbitrators verify error")
				continue
			}
			// The threshold is 2/3 of THIS frame, computed exactly as
			// Arbiters.GetArbitersMajorityCount does for the current committee.
			threshold := int(float64(len(frame.CurrentArbitrators)) *
				state.MajoritySignRatioNumerator / state.MajoritySignRatioDenominator)
			if len(signers) <= threshold {
				lastErr = errors.New("[IllegalConfirmContextCheck] signers less than " +
					"majority count")
				continue
			}
			return nil
		}
		return lastErr
	}

	// Legacy (below-gate) path: unchanged, including its current-committee majority
	// count, so retained history replays byte-identically.
	if len(signers) <= DefaultLedger.Arbitrators.GetArbitersMajorityCount() {
		return errors.New("[IllegalConfirmContextCheck] signers less than " +
			"majority count")
	}

	if err := IllegalProposalContextCheck(&confirm.Proposal); err != nil {
		return errors.New("[IllegalConfirmContextCheck] confirm contain invalid " +
			"proposal: " + err.Error())
	}

	for _, vote := range confirm.Votes {
		if err := IllegalVoteContextCheck(&vote); err != nil {
			return errors.New("[IllegalConfirmContextCheck] confirm contain invalid " +
				"vote: " + err.Error())
		}
	}

	return nil
}

func ConfirmContextCheck(confirm *payload.Confirm) error {
	signers := make(map[string]struct{})
	for _, vote := range confirm.Votes {
		if !vote.Accept {
			continue
		}
		signers[common.BytesToHexString(vote.Signer)] = struct{}{}
	}

	if len(signers) <= DefaultLedger.Arbitrators.GetArbitersMajorityCount() {
		return errors.New("[ConfirmContextCheck] signers less than " +
			"majority count")
	}

	if err := ProposalContextCheck(&confirm.Proposal); err != nil {
		return errors.New("[ConfirmContextCheck] confirm contain invalid " +
			"proposal: " + err.Error())
	}

	for _, vote := range confirm.Votes {
		if err := VoteContextCheck(&vote); err != nil {
			return errors.New("[ConfirmContextCheck] confirm contain invalid " +
				"vote: " + err.Error())
		}
	}

	return nil
}

func checkBlockWithConfirmation(block *Block, confirm *payload.Confirm,
	manager *checkpoint.Manager, isPow bool) error {
	if block.Hash() != confirm.Proposal.BlockHash {
		return errors.New("[CheckBlockWithConfirmation] block " +
			"confirmation validate failed")
	}

	if err := ConfirmContextCheck(confirm); err != nil {
		// rollback to the state before this method
		if e := manager.OnRollbackTo(block.Height-1, isPow); e != nil {
			panic("rollback fail when check block with confirmation")
		}
		return err
	}

	return nil
}

func PreProcessSpecialTx(block *Block) error {

	inactivePayloads := make([]*payload.InactiveArbitrators, 0)
	for _, tx := range block.Transactions {
		switch tx.TxType() {
		case common2.InactiveArbitrators:
			// Gate on the block height, not the current tip, so replaying a below-gate
			// historical special tx during InitCheckpoint or fresh-from-genesis sync
			// stays structure-only and replay-safe.
			if err := CheckInactiveArbitrators(tx, block.Height); err != nil {
				return err
			}
			// InactiveArbitrators programs are arbiter-multisig, never Standard, Deposit or
			// CrossChain, so the gated guards on those branches do not apply here; pass the
			// block height and the real gate for a faithful, uniform signature.
			if err := checkTransactionSignature(tx, map[*common2.Input]common2.Output{},
				block.Height, DefaultLedger.Blockchain.chainParams.StrictMoneyRangeHeight); err != nil {
				return err
			}

			inactivePayloads = append(inactivePayloads,
				tx.Payload().(*payload.InactiveArbitrators))
			//case IllegalBlockEvidence:
			//	p, ok := tx.Payload.(*payload.DPOSIllegalBlocks)
			//	if !ok {
			//		return errors.New("invalid payload")
			//	}
			//	if err := CheckDPOSIllegalBlocks(p); err != nil {
			//		return err
			//	}
			//
			//	illegalBlocks = append(illegalBlocks, p)
		}
	}

	//if len(illegalBlocks) != 0 {
	//	for _, v := range illegalBlocks {
	//		if err := DefaultLedger.Arbitrators.ProcessSpecialTxPayload(
	//			v, block.Height-1); err != nil {
	//			return errors.New("force change fail when finding an " +
	//				"inactive arbitrators transaction")
	//		}
	//	}
	//}
	if len(inactivePayloads) != 0 {
		for _, v := range inactivePayloads {
			if err := DefaultLedger.Arbitrators.ProcessSpecialTxPayload(
				v, block.Height-1); err != nil {
				return errors.New("force change fail when finding an " +
					"inactive arbitrators transaction")
			}
		}
	}

	return nil
}

func ProposalCheck(proposal *payload.DPOSProposal) error {
	if err := ProposalSanityCheck(proposal); err != nil {
		return err
	}

	if err := ProposalContextCheck(proposal); err != nil {
		return err
	}

	return nil
}

func ProposalCheckByHeight(proposal *payload.DPOSProposal,
	height uint32) error {
	if err := ProposalSanityCheck(proposal); err != nil {
		return err
	}

	if err := ProposalContextCheckByHeight(proposal, height); err != nil {
		return err
	}

	return nil
}

func ProposalSanityCheck(proposal *payload.DPOSProposal) error {
	pubKey, err := crypto.DecodePoint(proposal.Sponsor)
	if err != nil {
		return err
	}
	err = crypto.Verify(*pubKey, proposal.Data(), proposal.Sign)
	if err != nil {
		return err
	}

	return nil
}

func IllegalProposalContextCheck(proposal *payload.DPOSProposal) error {
	arbiters := DefaultLedger.Arbitrators.GetAllProducersPublicKey()
	var isArbiter bool
	for _, a := range arbiters {
		pk, err := hex.DecodeString(a)
		if err != nil {
			continue
		}
		if bytes.Equal(pk, proposal.Sponsor) {
			isArbiter = true
			break
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error, sponsor:" +
			common.BytesToHexString(proposal.Sponsor))
	}

	return nil
}

func ProposalContextCheck(proposal *payload.DPOSProposal) error {
	arbiters := DefaultLedger.Arbitrators.GetArbitrators()
	var isArbiter bool
	for _, a := range arbiters {
		if !a.IsNormal {
			continue
		}
		if bytes.Equal(a.NodePublicKey, proposal.Sponsor) {
			isArbiter = true
			break
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error")
	}

	return nil
}

func ProposalContextCheckByHeight(proposal *payload.DPOSProposal,
	height uint32) error {
	var isArbiter bool
	keyFrames := DefaultLedger.Arbitrators.GetSnapshot(height)
out:
	for _, k := range keyFrames {
		for _, a := range k.CurrentArbitrators {
			if bytes.Equal(a.GetNodePublicKey(), proposal.Sponsor) {
				isArbiter = true
				break out
			}
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error")
	}

	return nil
}

func VoteCheck(vote *payload.DPOSProposalVote) error {
	if err := VoteSanityCheck(vote); err != nil {
		return err
	}

	if err := VoteContextCheck(vote); err != nil {
		log.Warn("[VoteContextCheck] error: ", err.Error())
		return err
	}

	return nil
}

func VoteCheckByHeight(vote *payload.DPOSProposalVote, height uint32) error {
	if err := VoteSanityCheck(vote); err != nil {
		return err
	}

	if err := VoteContextCheckByHeight(vote, height); err != nil {
		log.Warn("[VoteContextCheck] error: ", err.Error())
		return err
	}

	return nil
}

func VoteSanityCheck(vote *payload.DPOSProposalVote) error {
	pubKey, err := crypto.DecodePoint(vote.Signer)
	if err != nil {
		return err
	}
	err = crypto.Verify(*pubKey, vote.Data(), vote.Sign)
	if err != nil {
		return err
	}

	return nil
}

func IllegalVoteContextCheck(vote *payload.DPOSProposalVote) error {
	arbiters := DefaultLedger.Arbitrators.GetAllProducersPublicKey()
	var isArbiter bool
	for _, a := range arbiters {
		pk, err := hex.DecodeString(a)
		if err != nil {
			continue
		}
		if bytes.Equal(pk, vote.Signer) {
			isArbiter = true
			break
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error")
	}

	return nil
}

func VoteContextCheck(vote *payload.DPOSProposalVote) error {
	arbiters := DefaultLedger.Arbitrators.GetArbitrators()
	var isArbiter bool
	for _, a := range arbiters {
		if !a.IsNormal {
			continue
		}
		if bytes.Equal(a.NodePublicKey, vote.Signer) {
			isArbiter = true
			break
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error")
	}

	return nil
}

func VoteContextCheckByHeight(vote *payload.DPOSProposalVote,
	height uint32) error {
	var isArbiter bool
	keyFrames := DefaultLedger.Arbitrators.GetSnapshot(height)
out:
	for _, k := range keyFrames {
		for _, a := range k.CurrentArbitrators {
			if bytes.Equal(a.GetNodePublicKey(), vote.Signer) {
				isArbiter = true
				break out
			}
		}
	}
	if !isArbiter {
		return errors.New("current arbitrators verify error")
	}

	return nil
}
