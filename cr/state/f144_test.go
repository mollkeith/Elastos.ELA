// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// newBareCommittee builds a minimal, real Committee without NewCommittee (which
// parses a secretary-general public key). It carries exactly the fields the
// checkpoint reset/rollback recovery path touches.
func newBareCommittee(params *config.Configuration) *Committee {
	c := &Committee{
		state:                NewState(params),
		Params:               params,
		KeyFrame:             *NewKeyFrame(),
		manager:              NewProposalManager(params),
		firstHistory:         utils.NewHistory(maxHistoryCapacity),
		inactiveCRHistory:    utils.NewHistory(maxHistoryCapacity),
		committeeHistory:     utils.NewHistory(maxHistoryCapacity),
		appropriationHistory: utils.NewHistory(maxHistoryCapacity),
	}
	c.state.SetManager(c.manager)
	return c
}

// assertBoundToRealCommittee drives the real returnDeposit consumer path: after a
// reset/deep-rollback recovery, changeCommittee reassigns c.HistoryMembers to a
// FRESH map (committee.go:656). Reproduce that reassignment, then invoke the
// registered getHistoryMember (state.go:458). Pre-fix it is bound to the throwaway
// local committee whose frozen map never sees this member -> 0 results.
func assertBoundToRealCommittee(t *testing.T, committee *Committee, ctx string) {
	code := []byte{0x21, 0xaa, 0xbb, 0xcc, 0xdd, 0xac}
	member := &CRMember{
		Info:        payload.CRInfo{Code: code, CID: common.Uint168{0x11}},
		MemberState: MemberElected,
	}
	// Mimic changeCommittee reassigning the live map on the REAL committee.
	committee.HistoryMembers = map[uint64]map[common.Uint168]*CRMember{
		1: {common.Uint168{0x11}: member},
	}

	got := committee.state.getHistoryMember(code)
	assert.Equal(t, 1, len(got),
		"F-144 (%s): the registered GetHistoryMember must resolve against the REAL "+
			"live committee; pre-fix it was bound to a throwaway empty committee -> 0", ctx)
	if len(got) == 1 {
		assert.Equal(t, member, got[0], "F-144 (%s): must return the real member", ctx)
	}
}

// TestF144OnResetBindsHistoryMemberToRealCommittee proves F-144 for the OnReset
// (recover-from-genesis) recovery branch fired on a >=720-block reorg
// (blockchain.go:1438). Pre-fix binds state.getHistoryMember to a throwaway local
// committee; post-fix binds to the real committee.
func TestF144OnResetBindsHistoryMemberToRealCommittee(t *testing.T) {
	committee := newBareCommittee(&config.Configuration{})
	cp := NewCheckpoint(committee)

	assert.NoError(t, cp.OnReset())
	assertBoundToRealCommittee(t, committee, "OnReset")
}

// TestF144OnRollbackToDeepBindsHistoryMemberToRealCommittee proves F-144 for the
// deep OnRollbackTo branch (height < CRVotingStartHeight), reached when a reorg
// detach rolls state below the CR voting start height (blockchain.go:1421).
func TestF144OnRollbackToDeepBindsHistoryMemberToRealCommittee(t *testing.T) {
	params := &config.Configuration{}
	params.CRConfiguration.CRVotingStartHeight = 100
	committee := newBareCommittee(params)
	cp := NewCheckpoint(committee)

	// height < StartHeight() takes the reset-style rebind branch.
	assert.NoError(t, cp.OnRollbackTo(50))
	assertBoundToRealCommittee(t, committee, "OnRollbackTo-deep")
}
