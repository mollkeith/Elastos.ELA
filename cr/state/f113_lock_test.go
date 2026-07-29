// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
)

// TestF113CRMemberMutatorsTakeWriteLock proves F-113: the six Committee entry
// points that MUTATE CR member state (MemberState, InactiveCount,
// InactiveCountingHeight and the deposit Penalty reached through c.state) used to
// acquire c.mtx.RLock() - a READ lock - so they raced every concurrent reader
// (each Committee getter holds exactly the RLock this test holds).
//
// The probe is deterministic and needs no race detector: a reader holds
// mtx.RLock() and the mutator is called on another goroutine. A read lock is
// shared, so the pristine code sails straight through and the test FAILS; a
// write lock must wait for the reader to leave, so the fixed code blocks until
// RUnlock and the test PASSES.
func TestF113CRMemberMutatorsTakeWriteLock(t *testing.T) {
	const readerHold = 250 * time.Millisecond

	cases := []struct {
		name string
		call func(c *Committee)
	}{
		{"TryUpdateCRMemberInactivity", func(c *Committee) {
			c.TryUpdateCRMemberInactivity(common.Uint168{}, false, 1)
		}},
		{"TryRevertCRMemberInactivity", func(c *Committee) {
			c.TryRevertCRMemberInactivity(common.Uint168{}, MemberElected, 0, 1)
		}},
		{"TryUpdateCRMemberIllegal", func(c *Committee) {
			c.TryUpdateCRMemberIllegal(common.Uint168{}, 1, 0)
		}},
		{"TryRevertCRMemberIllegal", func(c *Committee) {
			c.TryRevertCRMemberIllegal(common.Uint168{}, MemberElected, 1, 0)
		}},
		{"UpdateCRInactivePenalty", func(c *Committee) {
			c.UpdateCRInactivePenalty(common.Uint168{}, 1)
		}},
		{"RevertUpdateCRInactivePenalty", func(c *Committee) {
			c.RevertUpdateCRInactivePenalty(common.Uint168{}, 1)
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := &Committee{state: &State{}}

			// Stand in for any concurrent Committee reader.
			c.mtx.RLock()

			done := make(chan struct{})
			go func() {
				tc.call(c)
				close(done)
			}()

			select {
			case <-done:
				c.mtx.RUnlock()
				t.Fatalf("%s returned while a reader still held mtx.RLock: "+
					"it mutates CR member state under a READ lock (F-113)", tc.name)
			case <-time.After(readerHold):
				// Correct: the mutator is waiting for the write lock.
			}

			c.mtx.RUnlock()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s never completed after the reader released mtx", tc.name)
			}
		})
	}
}
