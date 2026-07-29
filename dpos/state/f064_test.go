// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// TestF064InactiveCountV2RollbackRestores proves F-064 (Class E reorg revert-symmetry):
// updateInactiveCountV2's forward closure zeroes inactiveCountV2 when it crosses the
// threshold and sets the producer Inactive; the pre-fix revert guard re-read the (now
// zeroed) count as `>= 3`, so on rollback revertSettingInactiveProducer never ran and the
// producer stayed stuck Inactive. The fix drives the undo off a captured `fired` flag.
//
// Fail-on-pristine: with the pre-fix guard, the final assertion (producer restored to
// Active after rollback) fails — the producer is left Inactive.
func TestF064InactiveCountV2RollbackRestores(t *testing.T) {
	s := &State{
		StateKeyFrame: &StateKeyFrame{
			ActivityProducers: map[string]*Producer{},
			InactiveProducers: map[string]*Producer{},
		},
		History:     utils.NewHistory(maxHistoryCapacity),
		ChainParams: &config.Configuration{},
	}
	const key = "p0"
	const H = uint32(1000)
	p := &Producer{state: Active, inactiveCountV2: 2} // one increment away from the threshold
	s.ActivityProducers[key] = p

	// Cross the threshold: 2 -> 3 fires setInactiveProducer and resets the count to 0.
	s.updateInactiveCountV2(true, false, false, p, H, key)
	s.History.Commit(H)

	assert.Equal(t, Inactive, p.state, "crossing inactiveCountV2>=3 must set the producer Inactive")
	assert.Equal(t, uint32(0), p.inactiveCountV2, "count is zeroed on firing")
	if _, ok := s.ActivityProducers[key]; ok {
		t.Fatal("producer must be removed from ActivityProducers when set Inactive")
	}
	if _, ok := s.InactiveProducers[key]; !ok {
		t.Fatal("producer must be in InactiveProducers when set Inactive")
	}

	// Reorg across the threshold block.
	if err := s.History.RollbackTo(H - 1); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	// The fix: the producer is fully restored. Pristine leaves it stuck Inactive.
	assert.Equal(t, Active, p.state,
		"F-064: rollback must restore the producer to Active (pristine leaves it stuck Inactive)")
	assert.Equal(t, uint32(2), p.inactiveCountV2, "inactiveCountV2 restored to the pre-block value")
	if _, ok := s.ActivityProducers[key]; !ok {
		t.Fatal("F-064: producer must be restored to ActivityProducers on rollback")
	}
	if _, ok := s.InactiveProducers[key]; ok {
		t.Fatal("F-064: producer must be removed from InactiveProducers on rollback")
	}
}
