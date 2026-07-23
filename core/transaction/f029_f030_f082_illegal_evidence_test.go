// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package transaction

import (
	"bytes"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// canonicalHeader returns a random block header at the given height whose AuxPow uses
// the single canonical encoding (ParMerkleIndex==0, ParentHash==ParBlockHeader.Hash()).
// The F-030 vectors below start from this canonical form so that the prior
// IsCanonical()+re-serialize fix would have accepted them -- proving the residual the
// logical-dedup-key fix closes.
func canonicalHeader(height uint32) *common2.Header {
	h := randomBlockHeader()
	h.Height = height
	h.AuxPow.ParMerkleIndex = 0
	h.AuxPow.ParentHash = h.AuxPow.ParBlockHeader.Hash()
	return h
}

// buildCanonicalIllegalBlocks assembles a fully valid ELA illegal-block evidence pair
// with two distinct canonical headers at the same height. confirmIdx and cmpIdx select
// the suite arbiters that sign the two confirms (and become the two evidences' Signers).
func (s *txValidatorSpecialTxTestSuite) buildCanonicalIllegalBlocks(
	height uint32, confirmIdx, cmpIdx []int) (
	*payload.DPOSIllegalBlocks, *payload.Confirm, *payload.Confirm,
	*payload.BlockEvidence, *payload.BlockEvidence, bool) {

	h1 := canonicalHeader(height)
	h2 := canonicalHeader(height)

	b1 := new(bytes.Buffer)
	h1.Serialize(b1)
	b2 := new(bytes.Buffer)
	h2.Serialize(b2)
	evidence := &payload.BlockEvidence{Header: b1.Bytes()}
	cmpEvidence := &payload.BlockEvidence{Header: b2.Bytes()}

	const viewOffset = uint32(1)
	confirm := s.buildConfirm(h1.Hash(), viewOffset, confirmIdx)
	cmpConfirm := s.buildConfirm(h2.Hash(), viewOffset, cmpIdx)

	for _, v := range confirm.Votes {
		evidence.Signers = append(evidence.Signers, v.Signer)
	}
	for _, v := range cmpConfirm.Votes {
		cmpEvidence.Signers = append(cmpEvidence.Signers, v.Signer)
	}

	asc := common.BytesToHexString(evidence.Header) <
		common.BytesToHexString(cmpEvidence.Header)
	illegalBlocks := &payload.DPOSIllegalBlocks{
		CoinType:    payload.ELACoin,
		BlockHeight: height,
	}
	s.updateIllegaBlocks(confirm, evidence, cmpConfirm, cmpEvidence, asc,
		illegalBlocks)
	return illegalBlocks, confirm, cmpConfirm, evidence, cmpEvidence, asc
}

// buildConfirm produces a Confirm proposing blockHash at viewOffset, sponsored by
// arbiter 0, with accept votes from the given suite arbiter indices.
func (s *txValidatorSpecialTxTestSuite) buildConfirm(blockHash common.Uint256,
	viewOffset uint32, idx []int) *payload.Confirm {
	confirm := &payload.Confirm{
		Proposal: payload.DPOSProposal{
			Sponsor:    s.arbitrators.CurrentArbitrators[0].GetNodePublicKey(),
			BlockHash:  blockHash,
			ViewOffset: viewOffset,
		},
	}
	confirm.Proposal.Sign, _ = crypto.Sign(s.arbitratorsPriKeys[0],
		confirm.Proposal.Data())
	for _, i := range idx {
		vote := payload.DPOSProposalVote{
			ProposalHash: confirm.Proposal.Hash(),
			Signer:       s.arbitrators.CurrentArbitrators[i].GetNodePublicKey(),
			Accept:       true,
		}
		vote.Sign, _ = crypto.Sign(s.arbitratorsPriKeys[i], vote.Data())
		confirm.Votes = append(confirm.Votes, vote)
	}
	return confirm
}

// TestF029IllegalBlockSignerSetEqualityGate: below the gate a padded Signers list
// (duplicate signer, real signer dropped) that keeps the count and stays a subset of the
// confirm votes is accepted; at/above the gate it is rejected.
func (s *txValidatorSpecialTxTestSuite) TestF029IllegalBlockSignerSetEqualityGate() {
	height := uint32(1000)

	// positive control: canonical, set-equal evidence passes strict validation.
	plOK, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(height,
		[]int{0, 1, 2, 3}, []int{1, 2, 3, 4})
	s.NoError(blockchain.CheckDPOSIllegalBlocks(plOK, true))

	pl, confirm, cmpConfirm, evidence, cmpEvidence, asc :=
		s.buildCanonicalIllegalBlocks(height, []int{0, 1, 2, 3}, []int{1, 2, 3, 4})
	// evidence.Signers was [arb0,arb1,arb2,arb3]; pad to [arb0,arb0,arb2,arb3]:
	// same count, still a subset of the confirm votes, but not the real set.
	evidence.Signers[1] = evidence.Signers[0]
	s.updateIllegaBlocks(confirm, evidence, cmpConfirm, cmpEvidence, asc, pl)

	// pristine (gate inactive) accepts the padded signer list.
	s.NoError(blockchain.CheckDPOSIllegalBlocks(pl, false))
	// strict (gate active) rejects the duplicate.
	s.EqualError(blockchain.CheckDPOSIllegalBlocks(pl, true),
		"duplicate signer within evidence")
}

// TestF030IllegalBlockDedupKeyCollapsesAuxPowEncodings: the SpecialTxExists dedup key
// (DPOSIllegalBlocks.Hash / DedupHash) folds the RAW evidence-header bytes, but two AuxPow
// encodings of ONE logical illegal block decode to the same block (Header.Hash() ==
// SerializeNoAux excludes the AuxPow). Below the gate each encoding yields a DISTINCT raw
// key (dedup bypass); at/above the gate DedupHash folds the LOGICAL header identity so
// both encodings collapse to ONE key. Probes the EXACT vectors the prior
// IsCanonical()+re-serialize fix missed: an AuxMerkleBranch mutation, and a
// ParBlockHeader.Nonce mutation with ParentHash recomputed (IsCanonical stays true) --
// both round-trip through Serialize/Deserialize and stay valid evidence.
func (s *txValidatorSpecialTxTestSuite) TestF030IllegalBlockDedupKeyCollapsesAuxPowEncodings() {
	height := uint32(2000)

	assertVector := func(name string, mutate func(*auxpow.AuxPow)) {
		// base canonical payload (encoding E1).
		pl1, confirm, cmpConfirm, evidence, cmpEvidence, _ :=
			s.buildCanonicalIllegalBlocks(height, []int{0, 1, 2, 3}, []int{1, 2, 3, 4})
		// E1 is valid evidence under strict validation (F-029/F-082 pass; F-030 no
		// longer rejects headers -- it only re-keys dedup).
		s.NoError(blockchain.CheckDPOSIllegalBlocks(pl1, true), name+": E1 must be valid")

		// Build encoding E2: the SAME logical CompareEvidence block, mutated AuxPow.
		mal := &common2.Header{}
		s.Require().NoError(mal.Deserialize(bytes.NewReader(cmpEvidence.Header)))
		mutate(&mal.AuxPow)
		// The prior fix's guards still pass on E2: IsCanonical stays true and E2's own
		// re-serialization is stable -- so the prior fix would NOT have caught this.
		s.True(mal.AuxPow.IsCanonical(), name+": E2 AuxPow must stay canonical")
		buf := new(bytes.Buffer)
		s.Require().NoError(mal.Serialize(buf))
		cmp2 := &payload.BlockEvidence{Header: buf.Bytes(), Signers: cmpEvidence.Signers}

		asc2 := common.BytesToHexString(evidence.Header) <
			common.BytesToHexString(cmp2.Header)
		pl2 := &payload.DPOSIllegalBlocks{CoinType: payload.ELACoin, BlockHeight: height}
		s.updateIllegaBlocks(confirm, evidence, cmpConfirm, cmp2, asc2, pl2)
		// E2 is also valid evidence -- the attacker can submit it.
		s.NoError(blockchain.CheckDPOSIllegalBlocks(pl2, true), name+": E2 must be valid")

		// The two logical hashes actually differ (E1 vs E2 are truly distinct byte-wise).
		s.NotEqual(cmpEvidence.Header, cmp2.Header, name+": raw headers must differ")

		// Legacy raw dedup key: DISTINCT -> the bypass exists pristine.
		s.NotEqual(pl1.DedupHash(false), pl2.DedupHash(false),
			name+": raw dedup keys must differ (bypass exists pristine)")
		// Strict logical dedup key: SAME -> the bypass is closed.
		s.Equal(pl1.DedupHash(true), pl2.DedupHash(true),
			name+": logical dedup keys must collapse to one")
	}

	// vector 1: append to AuxMerkleBranch -- round-trips; IsCanonical unaffected.
	assertVector("AuxMerkleBranch", func(ap *auxpow.AuxPow) {
		ap.AuxMerkleBranch = append(ap.AuxMerkleBranch,
			common.Uint256{0xde, 0xad, 0xbe, 0xef})
	})
	// vector 2: flip ParBlockHeader.Nonce and recompute ParentHash so IsCanonical
	// (ParentHash == ParBlockHeader.Hash()) STAYS true -- the exact case the prior fix
	// missed. Header.Hash() (SerializeNoAux) is unchanged, so the evidence stays valid.
	assertVector("ParBlockHeaderNonce", func(ap *auxpow.AuxPow) {
		ap.ParBlockHeader.Nonce = ap.ParBlockHeader.Nonce ^ 0x5a5a5a5a
		ap.ParentHash = ap.ParBlockHeader.Hash()
	})
}

// TestF082IllegalConfirmVoterUniverseGate: below the gate a confirm vote from a
// registered producer that was NOT on duty at the evidenced height is accepted (the
// all-producers universe); at/above the gate it is rejected against the round arbiter set
// at that height.
func (s *txValidatorSpecialTxTestSuite) TestF082IllegalConfirmVoterUniverseGate() {
	height := uint32(3000)

	// Shrink the on-duty arbiter snapshot to arbiters 0..3, while all 5 remain in the
	// legacy GetAllProducersPublicKey universe: arb[4] is a registered producer that was
	// not on duty at the evidenced height.
	origSnapshot := s.arbitrators.Snapshot
	defer func() { s.arbitrators.Snapshot = origSnapshot }()
	s.arbitrators.Snapshot = []*state.CheckPoint{{
		CurrentArbitrators: s.arbitrators.CurrentArbitrators[:4],
	}}

	// positive control: evidence signed only by on-duty arbiters passes strict.
	plOK, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(height,
		[]int{0, 1, 2, 3}, []int{0, 1, 2, 3})
	s.NoError(blockchain.CheckDPOSIllegalBlocks(plOK, true))

	// vulnerable payload: a compare-confirm vote comes from off-duty arb[4].
	pl, _, _, _, _, _ := s.buildCanonicalIllegalBlocks(height,
		[]int{0, 1, 2, 3}, []int{1, 2, 3, 4})
	// pristine accepts (arb[4] is in the all-producers universe).
	s.NoError(blockchain.CheckDPOSIllegalBlocks(pl, false))
	// strict rejects (arb[4] is not in the round arbiter set at the height).
	s.EqualError(blockchain.CheckDPOSIllegalBlocks(pl, true),
		"[IllegalConfirmContextCheck] confirm contain invalid vote: "+
			"current arbitrators verify error")
}
