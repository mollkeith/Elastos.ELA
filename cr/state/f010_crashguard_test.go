// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-010 crash-hardening, previously UNTESTED (commit 509d9ce).
package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/utils"
)

// f010State returns a CR State with no candidates registered, so GetCandidate returns nil
// for any cid — the "candidate was removed" case the guard exists for.
func f010State() *State {
	return &State{
		StateKeyFrame: *NewStateKeyFrame(),
		History:       utils.NewHistory(maxHistoryCapacity),
		params:        &config.Configuration{},
	}
}

// TestF010VoteCRCUnknownCandidateDoesNotPanic drives the REAL processVoteCRC and
// processCancelVoteCRC for a candidate that is NOT registered. The pre-fix guard tested
// the []byte parameter (always non-nil at this point) instead of the GetCandidate result,
// so a nil candidate was Appended into a History closure and nil-dereferenced when the
// block committed — a node halt on a vote for a removed candidate.
//
// Fail-on-pristine: restore `if candidate == nil` and this test PANICS on Commit.
func TestF010VoteCRCUnknownCandidateDoesNotPanic(t *testing.T) {
	// A syntactically valid but unregistered CID.
	var cid common.Uint168
	cid[0] = byte(contract.PrefixCRDID)
	for i := 1; i < len(cid); i++ {
		cid[i] = byte(i)
	}

	const H = uint32(500)

	s := f010State()
	s.processVoteCRC(H, cid[:], 100)
	s.History.Commit(H) // pristine nil-derefs here

	s2 := f010State()
	s2.processCancelVoteCRC(H, cid[:], 100)
	s2.History.Commit(H) // pristine nil-derefs here

	// And a rollback across the same block must be clean too.
	if err := s.History.RollbackTo(H - 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}
