// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-171 crash-hardening, previously UNTESTED (commit 509d9ce).
package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils"
)

// TestF171GetSnapshotEmptyRingDoesNotPanic drives the REAL Arbiters.GetSnapshot on an
// Arbiters whose snapshot ring is empty — the state a freshly started node is in, and
// the state F-109's rollback prune can now legitimately produce. getSnapshot indexed
// SnapshotKeysDesc[len-1] unconditionally.
//
// Fail-on-pristine: remove the `if len(a.SnapshotKeysDesc) == 0` guard and this test
// PANICS (index out of range).
func TestF171GetSnapshotEmptyRingDoesNotPanic(t *testing.T) {
	params := &config.Configuration{}
	a := &Arbiters{
		State: &State{
			StateKeyFrame: NewStateKeyFrame(),
			History:       utils.NewHistory(maxHistoryCapacity),
			ChainParams:   params,
		},
		ChainParams:      params,
		History:          utils.NewHistory(maxHistoryCapacity),
		degradation:      &degradation{},
		Snapshots:        map[uint32][]*CheckPoint{},
		SnapshotKeysDesc: []uint32{},
	}
	// The exported entry point consults bestHeight before delegating to getSnapshot.
	a.RegisterFunction(func() uint32 { return 1_000_000 }, nil, nil, nil)

	for _, h := range []uint32{0, 1, 1000, 999_999} {
		got := a.GetSnapshot(h)
		if len(got) != 0 {
			t.Fatalf("F-171: an empty snapshot ring must answer with an empty result at "+
				"height %d, got %d entries", h, len(got))
		}
	}
}

// TestF171GetSnapshotAfterRollbackPrune ties F-171 to F-109: the rollback prune can empty
// the ring, and the very next snapshot lookup must not halt the node.
func TestF171GetSnapshotAfterRollbackPrune(t *testing.T) {
	params := &config.Configuration{}
	a := &Arbiters{
		State: &State{
			StateKeyFrame: NewStateKeyFrame(),
			History:       utils.NewHistory(maxHistoryCapacity),
			ChainParams:   params,
		},
		ChainParams:      params,
		History:          utils.NewHistory(maxHistoryCapacity),
		degradation:      &degradation{},
		Snapshots:        map[uint32][]*CheckPoint{},
		SnapshotKeysDesc: []uint32{},
	}
	a.RegisterFunction(func() uint32 { return 1_000_000 }, nil, nil, nil)
	// Every snapshot sits ABOVE the rollback target, so F-109's prune empties the ring.
	for _, h := range []uint32{200, 150, 120} {
		a.SnapshotKeysDesc = append(a.SnapshotKeysDesc, h)
		a.Snapshots[h] = []*CheckPoint{{}}
	}
	if err := a.RollbackTo(100); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if len(a.SnapshotKeysDesc) != 0 {
		t.Fatalf("F-109 precondition: the prune must empty the ring, got %v", a.SnapshotKeysDesc)
	}
	if got := a.GetSnapshot(100); len(got) != 0 {
		t.Fatalf("F-171: lookup on the emptied ring must return empty, got %d", len(got))
	}
}
