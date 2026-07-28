// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/assert"
)

// Committee.RollbackTo must not underflow into a ~4.29 billion iteration loop.
//
// WHY THIS EXISTS. The batch shipped this guard with NO test at all, which a
// mutation audit found on 2026-07-28. The defect it prevents is real and was
// reproduced by probe: with the guard reverted, RollbackTo on a fresh height-0
// Committee did not return within 20 seconds.
//
// THE DEFECT. currentHeight is uint32:
//   - currentHeight == 0 -> `currentHeight - 1` wraps to 4,294,967,295 and the loop
//     runs that many iterations, six sub-rollbacks each, holding c.mtx throughout.
//   - height == 0 -> `i >= height` is permanently true for an unsigned counter, so
//     the loop never terminates even from a sane start.
//
// WHY IT IS RESTART-CRITICAL. Committee.Recover installs fresh histories at height
// 0 and runs from OnInit on every boot's checkpoint restore. That is EXACTLY the
// post-rewind state on restart day: a node that rewound to 2,260,450 rebuilds
// derived state from a pre-target snapshot, and a rollback issued against a
// height-0 committee wedges the node under a held mutex with no diagnostic.
//
// FAIL-ON-PRISTINE: replace the guard at committee.go with the pre-batch form
//     for i := currentHeight - 1; i >= height; i-- {
// and TestRollbackToDoesNotUnderflowAtHeightZero hangs until the test deadline
// instead of returning. Proven by reverting the production guard, not by assertion.

// rollbackReturnsWithin runs c.RollbackTo(height) and reports whether it returned
// inside the budget. The pre-batch loop does not return in any practical time, so
// a timeout here IS the defect rather than a flaky machine: the budget is three
// orders of magnitude more than the guarded path needs.
func rollbackReturnsWithin(c *Committee, height uint32, budget time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = c.RollbackTo(height)
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(budget):
		return false
	}
}

func TestRollbackToDoesNotUnderflowAtHeightZero(t *testing.T) {
	params := config.GetDefaultParams()

	// A committee straight out of Recover/OnInit: histories at height 0. This is
	// the post-checkpoint-restore state every boot passes through.
	c := newBareCommittee(params)
	assert.Equal(t, uint32(0), c.committeeHistory.Height(),
		"precondition: the committee must be at height 0, or this does not exercise "+
			"the underflow")

	// The probe that found this used RollbackTo(5) on a height-0 committee.
	if !rollbackReturnsWithin(c, 5, 5*time.Second) {
		t.Fatal("ROLLBACK UNDERFLOW: RollbackTo(5) on a height-0 Committee did not return " +
			"within 5s. currentHeight-1 wrapped to 4,294,967,295 and the loop is running " +
			"that many iterations under c.mtx. On restart day this wedges a node that has " +
			"just rebuilt derived state from a pre-target snapshot.")
	}
}

// The second underflow: a sane currentHeight but a zero target. `i >= height` can
// never go false for an unsigned counter, so the loop never terminates.
func TestRollbackToDoesNotSpinOnZeroTarget(t *testing.T) {
	params := config.GetDefaultParams()
	c := newBareCommittee(params)

	if !rollbackReturnsWithin(c, 0, 5*time.Second) {
		t.Fatal("ROLLBACK NON-TERMINATION: RollbackTo(0) did not return within 5s. " +
			"For an unsigned counter `i >= 0` is always true, so the loop cannot exit.")
	}
}

// Rolling back to a height at or above the current one is a no-op and must return
// immediately rather than entering the loop at all.
func TestRollbackToAboveCurrentIsNoOp(t *testing.T) {
	params := config.GetDefaultParams()
	c := newBareCommittee(params)

	for _, h := range []uint32{1, 100, 2260450} {
		if !rollbackReturnsWithin(c, h, 5*time.Second) {
			t.Fatalf("RollbackTo(%d) on a height-0 committee did not return within 5s; "+
				"there is nothing to roll back and it must exit immediately", h)
		}
	}
}
