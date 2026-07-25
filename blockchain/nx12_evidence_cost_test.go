// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-12 — unauthenticated zero-cost EC-verification amplifier.
//
// IllegalBlockEvidence is a zero-input, zero-output, zero-program, zero-fee
// transaction behind NO height gate, so any peer can send one. Pristine
// checkDPOSElaIllegalBlockConfirms ran ConfirmSanityCheck (1 crypto.Verify for the
// proposal + crypto.DecodePoint and crypto.Verify per vote, membership checked
// NOWHERE, no short-circuit) BEFORE IllegalConfirmContextCheck, the first
// membership test. A payload carrying MaxDPOSProposalVotes = 1024 self-signed votes
// from throwaway keypairs therefore bought ~1025 EC verifications on the shared
// block-processing goroutine before it could be rejected.
//
// FAIL-ON-PRISTINE, driving the PRODUCTION entry point CheckDPOSIllegalBlocks (what
// IllegalBlockEvidenceTransaction.SpecialContextCheck calls via
// blockchain/txvalidator.go:1305,1312) — not the function that was edited:
//
//	the test measures ConfirmSanityCheck on the SAME payload as its own calibration,
//	then requires the production path to cost a small fraction of it. Pristine
//	ordering makes the production path do exactly that signature work, so the ratio
//	is ~1 and the test fails. No absolute timing is asserted, so the test does not
//	depend on how fast the box is.
package blockchain

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// nx12Confirm builds a fully self-consistent confirm with `votes` accept votes, each
// signed by its own freshly generated keypair. Every signature is genuine, so
// ConfirmSanityCheck accepts it in full: that is the whole point — signature validity
// carries no authorization, and the pristine ordering paid for all of it first.
func nx12Confirm(t *testing.T, blockHash common.Uint256, votes int) *payload.Confirm {
	t.Helper()

	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	pubBuf, err := pub.EncodePoint(true)
	if err != nil {
		t.Fatalf("encode point: %v", err)
	}

	confirm := &payload.Confirm{
		Proposal: payload.DPOSProposal{
			Sponsor:    pubBuf,
			BlockHash:  blockHash,
			ViewOffset: 0,
		},
	}
	if confirm.Proposal.Sign, err = crypto.Sign(priv, confirm.Proposal.Data()); err != nil {
		t.Fatalf("sign proposal: %v", err)
	}
	proposalHash := confirm.Proposal.Hash()

	for i := 0; i < votes; i++ {
		vpriv, vpub, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("generate vote key pair: %v", err)
		}
		vbuf, err := vpub.EncodePoint(true)
		if err != nil {
			t.Fatalf("encode vote point: %v", err)
		}
		vote := payload.DPOSProposalVote{
			ProposalHash: proposalHash,
			Signer:       vbuf,
			Accept:       true,
		}
		if vote.Sign, err = crypto.Sign(vpriv, vote.Data()); err != nil {
			t.Fatalf("sign vote: %v", err)
		}
		confirm.Votes = append(confirm.Votes, vote)
	}
	return confirm
}

// nx12Evidence serializes one BlockEvidence leg: a header at `height` distinguished
// by `nonce`, the confirm blob, and a Signers slice sized to match the vote count so
// the O(1) structural test cannot be what rejects the payload.
func nx12Evidence(t *testing.T, height, nonce uint32, confirm *payload.Confirm) payload.BlockEvidence {
	t.Helper()

	hdr := common2.Header{Height: height, Nonce: nonce}
	hbuf := new(bytes.Buffer)
	if err := hdr.Serialize(hbuf); err != nil {
		t.Fatalf("serialize header: %v", err)
	}
	cbuf := new(bytes.Buffer)
	if err := confirm.Serialize(cbuf); err != nil {
		t.Fatalf("serialize confirm: %v", err)
	}
	signers := make([][]byte, 0, len(confirm.Votes))
	for _, v := range confirm.Votes {
		signers = append(signers, v.Signer)
	}
	return payload.BlockEvidence{
		Header:       hbuf.Bytes(),
		BlockConfirm: cbuf.Bytes(),
		Signers:      signers,
	}
}

// nx12Ledger installs an arbiters mock with an empty arbiter set and a small majority
// count, so 1024 distinct attacker signers clear the count gate and are then rejected
// on MEMBERSHIP — which is exactly the O(1) rejection the reorder is meant to reach.
func nx12Ledger(t *testing.T) func() {
	t.Helper()
	prev := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: &state.ArbitratorsMock{MajorityCount: 24}}
	return func() { DefaultLedger = prev }
}

// nx12MemberMock installs every signer of both confirms as a current arbiter, so the
// membership gate passes and the signature check becomes the deciding conjunct.
func nx12MemberMock(t *testing.T, confirms ...*payload.Confirm) *state.ArbitratorsMock {
	t.Helper()
	mock := &state.ArbitratorsMock{
		CurrentArbitrators: make([]state.ArbiterMember, 0),
		MajorityCount:      5,
	}
	add := func(key []byte) {
		ar, err := state.NewOriginArbiter(key)
		if err != nil {
			t.Fatalf("build arbiter member: %v", err)
		}
		mock.CurrentArbitrators = append(mock.CurrentArbitrators, ar)
	}
	for _, c := range confirms {
		add(c.Proposal.Sponsor)
		for _, v := range c.Votes {
			add(v.Signer)
		}
	}
	return mock
}

// TestNX12IllegalEvidenceRejectedBeforeSignatureWork is the cost proof.
func TestNX12IllegalEvidenceRejectedBeforeSignatureWork(t *testing.T) {
	if testing.Short() {
		t.Skip("generates 1024 keypairs and times the validator; skipped under -short")
	}
	defer nx12Ledger(t)()

	const height = uint32(2_260_500)
	const votes = 1024 // MaxDPOSProposalVotes

	a := nx12Confirm(t, common.Uint256{1}, votes)
	b := nx12Confirm(t, common.Uint256{2}, votes)

	d := &payload.DPOSIllegalBlocks{
		CoinType:    payload.ELACoin,
		BlockHeight: height,
		Evidence:    nx12Evidence(t, height, 1, a),
		// nonce 2 > nonce 1 keeps the "evidence order error" precondition satisfied
		// (headers are compared as hex strings).
		CompareEvidence: nx12Evidence(t, height, 2, b),
	}

	// Both quantities are measured as the MINIMUM of several rounds rather than from a
	// single sample. A one-shot wall-clock reading is not a safe basis for a CI
	// assertion: measured on this box, the single-sample form PASSED when this test ran
	// alone under -race and FAILED inside the full -race ./blockchain/ suite, where the
	// box is saturated and any one sample can be inflated several fold. Both functions
	// are PURE over an immutable payload -- ConfirmSanityCheck verifies signatures and
	// CheckDPOSIllegalBlocks only reads the ledger mock -- so repeating them has no side
	// effects, and the minimum is the sample least contaminated by descheduling.
	const nx12Rounds = 5
	measure := func(f func()) time.Duration {
		best := time.Duration(1) << 62
		for i := 0; i < nx12Rounds; i++ {
			start := time.Now()
			f()
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	// Calibration on THIS box, using the same payload: what the pristine ordering
	// spends before it can reject.
	var sanityErr error
	sanityCost := measure(func() { sanityErr = ConfirmSanityCheck(a) })
	if sanityErr != nil {
		t.Fatalf("the attacker payload must be signature-VALID for this test to mean "+
			"anything; ConfirmSanityCheck rejected it: %v", sanityErr)
	}
	if sanityCost <= 0 {
		t.Skip("timer resolution too coarse to calibrate")
	}

	for _, strict := range []bool{false, true} {
		name := "legacy"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			var err error
			cost := measure(func() { err = CheckDPOSIllegalBlocks(d, strict) })

			if err == nil {
				t.Fatal("NX-12: a fully synthetic illegal-block evidence payload signed by " +
					"1024 throwaway keypairs was ACCEPTED")
			}
			// The whole payload is TWO confirms, so pristine spends ~2x sanityCost
			// before rejecting. A quarter of ONE confirm's cost is a wide margin that
			// still cannot be reached by any ordering that verifies 1024 signatures.
			if cost > sanityCost/4 {
				t.Fatalf("NX-12: CheckDPOSIllegalBlocks spent %v rejecting a payload whose "+
					"signature check alone costs %v -- membership is still being tested "+
					"AFTER ~1025 EC verifications, so an unauthenticated peer can buy that "+
					"CPU on the block-processing goroutine for %d bytes and no fee",
					cost, sanityCost, len(d.Evidence.BlockConfirm))
			}
		})
	}
}

// TestNX12AcceptanceIsUnchangedByTheReorder pins the property that makes the reorder
// shippable UNGATED: both predicates are conjuncts over the same immutable payload,
// so every payload rejected before is still rejected. The legs below cover each
// rejection reason independently of ordering.
func TestNX12AcceptanceIsUnchangedByTheReorder(t *testing.T) {
	defer nx12Ledger(t)()

	const height = uint32(2_260_500)

	t.Run("mismatched signer count is still rejected", func(t *testing.T) {
		a := nx12Confirm(t, common.Uint256{1}, 30)
		b := nx12Confirm(t, common.Uint256{2}, 30)
		d := &payload.DPOSIllegalBlocks{
			CoinType:        payload.ELACoin,
			BlockHeight:     height,
			Evidence:        nx12Evidence(t, height, 1, a),
			CompareEvidence: nx12Evidence(t, height, 2, b),
		}
		d.Evidence.Signers = nil // the Signers: nil that defeated the O(1) test
		if err := CheckDPOSIllegalBlocks(d, false); err == nil {
			t.Fatal("NX-12: a payload whose Signers count does not match its votes was accepted")
		}
	})

	t.Run("invalid signature is still rejected once membership passes", func(t *testing.T) {
		// This is the leg that proves the reorder DEFERS the signature check rather
		// than dropping it: every signer here is a member, so IllegalConfirmContextCheck
		// passes and ConfirmSanityCheck is the only thing left that can reject.
		a := nx12Confirm(t, common.Uint256{1}, 30)
		b := nx12Confirm(t, common.Uint256{2}, 30)

		prev := DefaultLedger
		DefaultLedger = &Ledger{Arbitrators: nx12MemberMock(t, a, b)}
		defer func() { DefaultLedger = prev }()

		d := &payload.DPOSIllegalBlocks{
			CoinType:        payload.ELACoin,
			BlockHeight:     height,
			Evidence:        nx12Evidence(t, height, 1, a),
			CompareEvidence: nx12Evidence(t, height, 2, b),
		}
		// Positive control: with every signature intact the payload gets PAST both
		// confirm checks (it is rejected later, on the header/hash rules), so the
		// negative below is attributable to the signature alone.
		clean := CheckDPOSIllegalBlocks(d, false)
		if clean != nil && strings.Contains(clean.Error(), "ConfirmSanityCheck") {
			t.Fatalf("positive control failed: a fully valid confirm was rejected by "+
				"ConfirmSanityCheck: %v", clean)
		}

		a.Votes[0].Sign = []byte{0x00}
		d.Evidence = nx12Evidence(t, height, 1, a)
		err := CheckDPOSIllegalBlocks(d, false)
		if err == nil {
			t.Fatal("NX-12: a payload carrying an invalid vote signature was accepted -- " +
				"the reorder must not skip ConfirmSanityCheck, only defer it")
		}
		if !strings.Contains(err.Error(), "ConfirmSanityCheck") {
			t.Fatalf("NX-12: expected the signature check to reject, got: %v", err)
		}
	})
}
