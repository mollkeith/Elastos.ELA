// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

// NX-08 — the illegal-PROPOSAL / illegal-VOTE evidence dedup key is malleable.
//
// F-030 folded the SpecialTxHashes dedup key by logical identity for DPOSIllegalBlocks
// ONLY; the proposal and vote siblings fell through to the raw payload Hash(), which
// serialises the whole ProposalEvidence INCLUDING the raw BlockHeader blob. The blob is
// constrained only by header.Deserialize succeeding, header.Height == evidence.BlockHeight
// and header.Hash().IsEqual(evidence.Proposal.BlockHash) — and Header.Deserialize discards
// a trailing sentinel byte without asserting the buffer was consumed, so ARBITRARY
// trailing bytes survive into the stored blob and into Hash(). One genuine, unforgeable
// equivocation therefore minted unboundedly many distinct dedup keys: every copy passed
// State.SpecialTxExists, was relayed for free, and added a permanent 32-byte entry to
// SpecialTxHashes — which is serialized into every DPoS keyframe/checkpoint.
//
// These tests drive the REAL TRANSACTION path — IllegalProposalTransaction /
// IllegalVoteTransaction SpecialContextCheck -> BlockChain.GetState().SpecialTxExists ->
// payload.SpecialTxDedupKey — deliberately, because the illegal-evidence validators are
// DUPLICATED (core/transaction/illegalproposaltransaction.go for the tx path,
// blockchain/txvalidator.go for the DPoS-mesh path) and a test that drove only the
// blockchain copy would prove the mesh path and nothing else. The same-block arm is
// covered separately in blockchain/nx08_sameblock_evidence_test.go.
//
// Gate 1 (StrictMoneyRangeHeight), read from the evidence's OWN BlockHeight so the read
// (SpecialTxExists), the write (recordSpecialTx) and the block guard
// (CheckSameBlockConflicts) flip together — F-030's commit note requires exactly that.
// Census (PROVEN): 13 IllegalProposalEvidence and 269 IllegalVoteEvidence txs in
// 2,260,597 blocks, ZERO of either at or above the gate, so re-keying rejects zero real
// history.
//
// MUTATION PROOF: revert payload.SpecialTxDedupKey to the pristine
// `if blk, ok := d.(*DPOSIllegalBlocks); ok { ... }; return d.Hash()` form and these tests
// FAIL. See the batch report for the captured output.
package transaction

import (
	"bytes"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
)

// The one campaign gate. StrictMoneyRangeHeight on mainnet; the evidence's own BlockHeight
// is what selects the branch inside SpecialTxDedupKey.
const (
	nx08Gate      = uint32(2260451)
	nx08BelowGate = nx08Gate - 1
)

// nx08Equivocation builds ONE genuine equivocation at `height`: two canonical headers and
// two DPOSProposals from the SAME sponsor (suite arbiter 0) at the SAME view offset over
// two different block hashes, each correctly signed. Returns the two proposals and their
// serialized header blobs, already in the canonical evidence order the validator demands
// (Evidence.Proposal.Hash() <= CompareEvidence.Proposal.Hash()).
func (s *txValidatorSpecialTxTestSuite) nx08Equivocation(height uint32) (
	p1, p2 payload.DPOSProposal, raw1, raw2 []byte) {

	mk := func() (payload.DPOSProposal, []byte) {
		h := canonicalHeader(height)
		buf := new(bytes.Buffer)
		h.Serialize(buf)
		pr := payload.DPOSProposal{
			Sponsor:    s.arbitrators.CurrentArbitrators[0].GetNodePublicKey(),
			BlockHash:  h.Hash(),
			ViewOffset: 1,
		}
		pr.Sign, _ = crypto.Sign(s.arbitratorsPriKeys[0], pr.Data())
		return pr, buf.Bytes()
	}
	p1, raw1 = mk()
	p2, raw2 = mk()
	if p1.Hash().Compare(p2.Hash()) > 0 {
		p1, p2 = p2, p1
		raw1, raw2 = raw2, raw1
	}
	return
}

// nx08ProposalsPayload wraps one equivocation as DPOSIllegalProposals. `pad` bytes are
// appended to the FIRST evidence's raw header blob: the header still deserializes, its
// Height and Hash() are unchanged, validateProposalEvidence still accepts — but the raw
// payload Hash() (and therefore the pristine dedup key) changes.
func nx08ProposalsPayload(p1, p2 payload.DPOSProposal, raw1, raw2 []byte,
	height uint32, pad int) *payload.DPOSIllegalProposals {
	blob := append(append([]byte{}, raw1...), make([]byte, pad)...)
	for i := 0; i < pad; i++ {
		blob[len(raw1)+i] = byte(0xA0 + i)
	}
	return &payload.DPOSIllegalProposals{
		Evidence:        payload.ProposalEvidence{Proposal: p1, BlockHeader: blob, BlockHeight: height},
		CompareEvidence: payload.ProposalEvidence{Proposal: p2, BlockHeader: raw2, BlockHeight: height},
	}
}

// nx08VotesPayload wraps a VOTE equivocation as DPOSIllegalVotes. Above ChangeViewV1Height
// the validator requires BOTH evidences to carry the SAME proposal (illegalvotetransaction.go),
// so the equivocation here is one proposal with two contradictory votes from ONE signer
// (accept and reject) — the real shape of illegal-vote evidence at current heights.
// `pad` trailing bytes go on the first evidence's raw header blob.
func (s *txValidatorSpecialTxTestSuite) nx08VotesPayload(p1 payload.DPOSProposal,
	raw1 []byte, height uint32, pad int) *payload.DPOSIllegalVotes {
	mkVote := func(accept bool) payload.DPOSProposalVote {
		v := payload.DPOSProposalVote{
			ProposalHash: p1.Hash(),
			Signer:       s.arbitrators.CurrentArbitrators[1].GetNodePublicKey(),
			Accept:       accept,
		}
		v.Sign, _ = crypto.Sign(s.arbitratorsPriKeys[1], v.Data())
		return v
	}
	blob := append(append([]byte{}, raw1...), make([]byte, pad)...)
	for i := 0; i < pad; i++ {
		blob[len(raw1)+i] = byte(0xB0 + i)
	}
	// The PADDED blob rides on whichever evidence sorts first; the fold must ignore it
	// either way.
	vAccept, vReject := mkVote(true), mkVote(false)
	first, second := vAccept, vReject
	if first.Hash().Compare(second.Hash()) > 0 {
		first, second = second, first
	}
	return &payload.DPOSIllegalVotes{
		Evidence: payload.VoteEvidence{
			ProposalEvidence: payload.ProposalEvidence{
				Proposal: p1, BlockHeader: blob, BlockHeight: height},
			Vote: first,
		},
		CompareEvidence: payload.VoteEvidence{
			ProposalEvidence: payload.ProposalEvidence{
				Proposal: p1, BlockHeader: raw1, BlockHeight: height},
			Vote: second,
		},
	}
}

// nx08Tx wraps an illegal-evidence payload in a real zero-cost transaction (no inputs, no
// outputs, no attributes, no programs — what CheckAttributeProgram demands).
func (s *txValidatorSpecialTxTestSuite) nx08Tx(txType common2.TxType, version byte,
	pl interfaces.Payload) interfaces.Transaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09, txType, version, pl,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
	txn = CreateTransactionByType(txn, s.Chain)
	txn.SetParameters(&TransactionParameters{
		Transaction: txn,
		BlockHeight: nx08Gate,
		Config:      &config.DefaultParams,
		BlockChain:  s.Chain,
	})
	return txn
}

// nx08SeedDedupSet records `pl` in SpecialTxHashes EXACTLY as the production write path
// does — dpos/state/state.go's ProcessSpecialTx dispatch calls
// recordSpecialTx(payload.SpecialTxDedupKey(illegalData, s.ChainParams.StrictMoneyRangeHeight)).
// Read and write must use one key function; that is the invariant under test.
func (s *txValidatorSpecialTxTestSuite) nx08SeedDedupSet(pl payload.DPOSIllegalData) func() {
	st := s.Chain.GetState()
	key := payload.SpecialTxDedupKey(pl, config.DefaultParams.StrictMoneyRangeHeight)
	st.SpecialTxHashes[key] = struct{}{}
	return func() { st.RemoveSpecialTx(key) }
}

// TestNX08IllegalProposalDedupKeyIsNotMalleable is the fail-on-pristine test for the
// proposal family. On the pristine tree each trailing-byte re-encoding produces a fresh
// dedup key and every copy is admitted; with the NX-08 fold they all collapse to one key
// at and above gate 1, and the SECOND copy is rejected by the real transaction validator.
func (s *txValidatorSpecialTxTestSuite) TestNX08IllegalProposalDedupKeyIsNotMalleable() {
	p1, p2, raw1, raw2 := s.nx08Equivocation(nx08Gate)

	canonical := nx08ProposalsPayload(p1, p2, raw1, raw2, nx08Gate, 0)
	// POSITIVE CONTROL: the first copy is genuinely valid evidence — otherwise the
	// rejections below would prove nothing.
	errFirst, _ := s.nx08Tx(common2.IllegalProposalEvidence,
		payload.IllegalProposalVersion, canonical).SpecialContextCheck()
	s.Require().NoError(errFirst, "the canonical equivocation must be valid evidence")

	cleanup := s.nx08SeedDedupSet(canonical)
	defer cleanup()

	// The canonical copy is now a duplicate — baseline for the message asserted below.
	errDup, _ := s.nx08Tx(common2.IllegalProposalEvidence,
		payload.IllegalProposalVersion, canonical).SpecialContextCheck()
	s.Require().Error(errDup)
	s.Contains(errDup.Error(), "tx already exists")

	for _, pad := range []int{1, 4, 64} {
		variant := nx08ProposalsPayload(p1, p2, raw1, raw2, nx08Gate, pad)

		// The malleability precondition, asserted rather than assumed: the raw payload
		// hash — the pristine dedup key — genuinely differs.
		s.NotEqual(canonical.Hash(), variant.Hash(),
			"pad %d: the raw payload hash must differ (that IS the pristine bypass)", pad)
		// The logical key must NOT differ at/above the gate.
		s.Equal(
			payload.SpecialTxDedupKey(canonical, nx08Gate),
			payload.SpecialTxDedupKey(variant, nx08Gate),
			"pad %d: one logical equivocation must fold to ONE dedup key at/above the gate", pad)

		errVariant, _ := s.nx08Tx(common2.IllegalProposalEvidence,
			payload.IllegalProposalVersion, variant).SpecialContextCheck()
		s.Require().Error(errVariant,
			"pad %d: MALLEABLE KEY — a trailing-byte re-encoding of an already-recorded "+
				"equivocation was admitted by the real transaction validator", pad)
		s.Contains(errVariant.Error(), "tx already exists",
			"pad %d: the re-encoding must be rejected as a duplicate, not for some other reason", pad)
	}
}

// TestNX08IllegalProposalBelowGateKeepsTheLegacyKey is the replay guarantee. Below gate 1
// the raw payload Hash() must still be the dedup key, so retained history serializes
// byte-identically and an already-recorded below-gate evidence still does not collide with
// a re-encoding.
func (s *txValidatorSpecialTxTestSuite) TestNX08IllegalProposalBelowGateKeepsTheLegacyKey() {
	p1, p2, raw1, raw2 := s.nx08Equivocation(nx08BelowGate)

	canonical := nx08ProposalsPayload(p1, p2, raw1, raw2, nx08BelowGate, 0)
	variant := nx08ProposalsPayload(p1, p2, raw1, raw2, nx08BelowGate, 1)

	s.Equal(canonical.Hash(), payload.SpecialTxDedupKey(canonical, nx08Gate),
		"below the gate the dedup key must be the legacy raw payload hash")
	s.NotEqual(
		payload.SpecialTxDedupKey(canonical, nx08Gate),
		payload.SpecialTxDedupKey(variant, nx08Gate),
		"REPLAY BREAK: below-gate evidence must keep the legacy (malleable) key so retained "+
			"history serializes byte-identically")

	cleanup := s.nx08SeedDedupSet(canonical)
	defer cleanup()

	errVariant, _ := s.nx08Tx(common2.IllegalProposalEvidence,
		payload.IllegalProposalVersion, variant).SpecialContextCheck()
	s.NoError(errVariant,
		"REPLAY BREAK: below the gate the re-encoding must behave exactly as it did before")
}

// TestNX08IllegalVoteDedupKeyIsNotMalleable is the same fail-on-pristine proof for the
// vote family, which shares the ProposalEvidence blob and therefore the identical defect.
func (s *txValidatorSpecialTxTestSuite) TestNX08IllegalVoteDedupKeyIsNotMalleable() {
	p1, _, raw1, _ := s.nx08Equivocation(nx08Gate)

	canonical := s.nx08VotesPayload(p1, raw1, nx08Gate, 0)
	errFirst, _ := s.nx08Tx(common2.IllegalVoteEvidence,
		payload.IllegalVoteVersion, canonical).SpecialContextCheck()
	s.Require().NoError(errFirst, "the canonical vote equivocation must be valid evidence")

	cleanup := s.nx08SeedDedupSet(canonical)
	defer cleanup()

	for _, pad := range []int{1, 4, 64} {
		variant := s.nx08VotesPayload(p1, raw1, nx08Gate, pad)

		s.NotEqual(canonical.Hash(), variant.Hash(),
			"pad %d: the raw payload hash must differ (that IS the pristine bypass)", pad)
		s.Equal(
			payload.SpecialTxDedupKey(canonical, nx08Gate),
			payload.SpecialTxDedupKey(variant, nx08Gate),
			"pad %d: one logical vote equivocation must fold to ONE dedup key", pad)

		errVariant, _ := s.nx08Tx(common2.IllegalVoteEvidence,
			payload.IllegalVoteVersion, variant).SpecialContextCheck()
		s.Require().Error(errVariant,
			"pad %d: MALLEABLE KEY — a trailing-byte re-encoding of an already-recorded "+
				"vote equivocation was admitted by the real transaction validator", pad)
		s.Contains(errVariant.Error(), "tx already exists", "pad %d", pad)
	}
}

// TestNX08DedupKeySpacesAreDisjoint pins the domain separation. Without a domain tag a
// proposal fold and a vote fold over the same height and the same two hashes would
// produce the SAME key, so one family could suppress the other's evidence.
func (s *txValidatorSpecialTxTestSuite) TestNX08DedupKeySpacesAreDisjoint() {
	p1, p2, raw1, raw2 := s.nx08Equivocation(nx08Gate)
	props := nx08ProposalsPayload(p1, p2, raw1, raw2, nx08Gate, 0)
	votes := s.nx08VotesPayload(p1, raw1, nx08Gate, 0)

	s.NotEqual(
		payload.SpecialTxDedupKey(props, nx08Gate),
		payload.SpecialTxDedupKey(votes, nx08Gate),
		"proposal and vote dedup key spaces must be disjoint")

	// And a DIFFERENT logical equivocation must still get its own key — the fold must not
	// over-collapse and swallow genuine second offences.
	q1, q2, qraw1, qraw2 := s.nx08Equivocation(nx08Gate)
	other := nx08ProposalsPayload(q1, q2, qraw1, qraw2, nx08Gate, 0)
	s.NotEqual(
		payload.SpecialTxDedupKey(props, nx08Gate),
		payload.SpecialTxDedupKey(other, nx08Gate),
		"two DISTINCT logical equivocations must keep distinct dedup keys")
}
