// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"encoding/hex"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// fv10State builds the smallest State that drives the PRODUCTION call path
// countArbitratorsInactivityV3 -> updateCRMemberInactiveCountV2, and returns the CR
// member plus counters for the injected penalty hooks.
//
// Every collaborator countArbitratorsInactivityV3 reaches is a function field on
// State, so the whole path runs for real -- this is not a direct call to the edited
// function.
func fv10State(t *testing.T, memberKey []byte, sponsorKey []byte,
	member *crstate.CRMember) (*State, *int, *int) {
	t.Helper()

	params := &config.Configuration{}
	// DPoSV2 accounting active, and the CR penalty branch reachable.
	params.DPoSV2StartHeight = 0
	params.CRConfiguration.ChangeCommitteeNewCRHeight = 0
	// lastPosition == (dutyIndex == NormalArbitratorsCount+len(CRCArbiters)-1) == 0.
	params.DPoSConfiguration.NormalArbitratorsCount = 1
	params.DPoSConfiguration.CRCArbiters = nil

	applied, reverted := 0, 0
	s := &State{
		StateKeyFrame: NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   params,
	}
	s.GetArbiters = func() []*ArbiterInfo {
		return []*ArbiterInfo{{NodePublicKey: memberKey, IsNormal: true}}
	}
	s.getCurrentCRMembers = func() []*crstate.CRMember { return []*crstate.CRMember{member} }
	s.isInElectionPeriod = func() bool { return true }
	s.updateCRInactivePenalty = func(cid common.Uint168, height uint32) { applied++ }
	s.revertUpdateCRInactivePenalty = func(cid common.Uint168, height uint32) { reverted++ }
	// Sponsor is a DIFFERENT key, so needReset stays false for our member.
	_ = sponsorKey
	return s, &applied, &reverted
}

// fv10Member builds a CR member whose claimed-DPoS key is memberKey.
// getClaimedCRMembersMap keys members by hex(Info.Code[1:len-1]), and
// getProducerKey(NodePublicKey) falls through to hex(NodePublicKey) when the node
// key is not in any owner map -- so the two must agree for the member to be found.
func fv10Member(memberKey []byte) *crstate.CRMember {
	code := append([]byte{byte(len(memberKey))}, memberKey...)
	code = append(code, 0xAC)
	return &crstate.CRMember{
		Info:            payload.CRInfo{Code: code, CID: common.Uint168{1, 2, 3}},
		MemberState:     crstate.MemberElected,
		DPOSPublicKey:   memberKey,
		InactiveCountV2: 2, // one increment away from the threshold
		WorkedInRound:   false,
	}
}

// TestFV10CRMemberInactivityRollbackRestores is the fail-on-pristine proof of FV-10:
// the CR twin of F-064 was never given F-064's `fired` capture, so its undo guard
// re-read member.InactiveCountV2 -- which the forward ZEROES on firing -- and
// `>= 3` was false in every reachable state.
//
// The consequence is not cosmetic: MemberInactive removes the member from the CRC
// arbiter set (12 of the 36 seats, and the multisig quorum for InactiveArbitrators /
// illegal-evidence acceptance), and the CR inactivity penalty against its deposit is
// likewise never reverted. A node that reorgs across the firing block diverges
// permanently and recovers only by full resync.
//
// FAIL-ON-PRISTINE: with the shipped guard
// (`if member.MemberState == MemberInactive && member.InactiveCountV2 >= 3`) the
// post-rollback assertions fail -- the member stays MemberInactive and the penalty
// is never reverted.
func TestFV10CRMemberInactivityRollbackRestores(t *testing.T) {
	memberKey, _ := common.HexStringToBytes(
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a")
	sponsorKey, _ := common.HexStringToBytes(
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9")

	member := fv10Member(memberKey)
	s, applied, reverted := fv10State(t, memberKey, sponsorKey, member)

	const H = uint32(1000)

	// Sanity: the production path really reaches our member (a silent miss here would
	// make every assertion below vacuous).
	if _, ok := s.getClaimedCRMembersMap()[hex.EncodeToString(memberKey)]; !ok {
		t.Fatal("harness: the CR member is not reachable through getClaimedCRMembersMap")
	}

	// PRODUCTION CALL PATH: the round's last position, member did not work.
	s.countArbitratorsInactivityV3(H, sponsorKey, 0)
	s.History.Commit(H)

	assert.Equal(t, crstate.MemberInactive, member.MemberState,
		"sanity: crossing InactiveCountV2>=3 must set the member Inactive")
	assert.Equal(t, uint32(0), member.InactiveCountV2, "sanity: the count is zeroed on firing")
	assert.Equal(t, 1, *applied, "sanity: the CR inactivity penalty was applied")

	// Reorg across the firing block.
	if err := s.History.RollbackTo(H - 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	assert.Equal(t, crstate.MemberElected, member.MemberState,
		"FV-10: rollback must restore the CR member to its captured pre-block state "+
			"(pristine leaves it stuck MemberInactive, i.e. out of the CRC arbiter set)")
	assert.Equal(t, 1, *reverted,
		"FV-10: the CR inactivity penalty against the member's deposit must be reverted "+
			"(pristine never calls revertUpdateCRInactivePenalty)")
	assert.Equal(t, uint32(2), member.InactiveCountV2,
		"InactiveCountV2 must be restored to the pre-block value")
}

// TestFV10CRMemberNonFiringRollbackIsNoop is the negative control: below the
// threshold the forward must not fire, and the undo must not revert a penalty that
// was never applied. Without this arm a fix that reverted unconditionally would also
// turn the first test green.
func TestFV10CRMemberNonFiringRollbackIsNoop(t *testing.T) {
	memberKey, _ := common.HexStringToBytes(
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a")
	sponsorKey, _ := common.HexStringToBytes(
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9")

	member := fv10Member(memberKey)
	member.InactiveCountV2 = 0 // 0 -> 1, nowhere near the threshold
	s, applied, reverted := fv10State(t, memberKey, sponsorKey, member)

	const H = uint32(1000)
	s.countArbitratorsInactivityV3(H, sponsorKey, 0)
	s.History.Commit(H)

	assert.Equal(t, crstate.MemberElected, member.MemberState)
	assert.Equal(t, uint32(1), member.InactiveCountV2)
	assert.Equal(t, 0, *applied)

	if err := s.History.RollbackTo(H - 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	assert.Equal(t, crstate.MemberElected, member.MemberState)
	assert.Equal(t, uint32(0), member.InactiveCountV2)
	assert.Equal(t, 0, *reverted,
		"a non-firing forward must not revert a penalty it never applied")
}
