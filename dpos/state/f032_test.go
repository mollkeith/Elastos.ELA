// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/assert"
)

// TestF032RecordSponsorBinding proves F-032 (Class B reward misdirection, conserved / no
// inflation): the deferred DPoS sponsor-reward is paid from LastDPoSRewards[recordedSponsor]
// where recordedSponsor is the block producer's attacker-packable RecordSponsor tx payload,
// validated (recordsponsortransaction.go SpecialContextCheck) only for arbiter-membership.
// The gated bind rejects a RecordSponsor tx that names anyone other than the confirmed
// previous block's true (override-aware) sponsor, at/above RevisedDPoSRewardHeight, while
// leaving pre-gate history byte-identical.
//
// Fail-on-pristine: neutralize the `if !bytes.Equal(...)` guard in
// dpos/state/arbitrators.go CheckRecordSponsorBinding and the at/above-gate mismatch
// assertion flips to accepted (the latent misdirection), so this test depends on the fix.
func TestF032RecordSponsorBinding(t *testing.T) {
	const gate = uint32(100)
	const lastH = uint32(99)

	realSponsor := []byte{0x02, 0xAA, 0xAA}
	wrongSponsor := []byte{0x02, 0xBB, 0xBB} // some other current/last arbiter
	overrideSponsor := []byte{0x02, 0xCC, 0xCC}

	newArb := func(override map[uint32][]byte) *Arbiters {
		return &Arbiters{
			ChainParams:                  &config.Configuration{RevisedDPoSRewardHeight: gate},
			BlockConfirmProposalSponsors: override,
		}
	}

	// BELOW the gate: retained-history behavior -- a mismatched sponsor is accepted
	// (the latent misdirection), byte-identical.
	a := newArb(map[uint32][]byte{})
	assert.NoError(t, a.CheckRecordSponsorBinding(wrongSponsor, lastH, realSponsor, gate-1),
		"below gate the bind must be a no-op (history byte-identical)")

	// AT/ABOVE the gate, matching the confirmed sponsor -> accepted.
	assert.NoError(t, a.CheckRecordSponsorBinding(realSponsor, lastH, realSponsor, gate),
		"a truthful RecordSponsor must pass at/above the gate")

	// AT/ABOVE the gate, naming a DIFFERENT arbiter -> rejected (misdirection blocked).
	err := a.CheckRecordSponsorBinding(wrongSponsor, lastH, realSponsor, gate)
	assert.Error(t, err, "a mismatched RecordSponsor must be rejected at/above the gate")
	if err != nil {
		assert.Contains(t, err.Error(), "record sponsor does not match")
	}

	// Override-aware: an operator "sponsors file" entry for lastH makes the override the
	// truth; the confirm's own sponsor must then NOT be accepted, and the override must.
	ao := newArb(map[uint32][]byte{lastH: overrideSponsor})
	assert.NoError(t, ao.CheckRecordSponsorBinding(overrideSponsor, lastH, realSponsor, gate),
		"the override sponsor must be accepted when present")
	assert.Error(t, ao.CheckRecordSponsorBinding(realSponsor, lastH, realSponsor, gate),
		"with an override present, the raw confirm sponsor must be rejected")
}
