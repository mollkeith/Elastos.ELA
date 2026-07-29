// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"
)

// TestF179IsSameWithNextArbitrators proves F-179: the comparison loop inside
// IsSameWithNextArbitrators was fully inverted - it returned "not the same" as
// soon as it found a node public key that WAS equal, so two identical arbiter
// sets reported different and two sets differing only after position 0 reported
// identical. The function has no caller today (dead code, hence no acceptance
// impact), but the truth table below is what any future caller would rely on.
func TestF179IsSameWithNextArbitrators(t *testing.T) {
	mk := func(keys ...byte) []ArbiterMember {
		res := make([]ArbiterMember, 0, len(keys))
		for _, k := range keys {
			res = append(res, &originArbiter{key: []byte{k}})
		}
		return res
	}

	a := &Arbiters{}

	// 1. Identical sets must report same. Pristine returns false here.
	a.CurrentArbitrators = mk(0x01, 0x02, 0x03)
	a.nextArbitrators = mk(0x01, 0x02, 0x03)
	if !a.IsSameWithNextArbitrators() {
		t.Fatal("identical arbiter sets reported as different (F-179 inversion)")
	}

	// 2. A single differing key must report not-same.
	a.nextArbitrators = mk(0x01, 0x09, 0x03)
	if a.IsSameWithNextArbitrators() {
		t.Fatal("arbiter sets differing at index 1 reported as the same")
	}

	// 3. A differing FIRST key must report not-same. Pristine gets this
	// "right" only by accident - it bails on the first equal key instead.
	a.nextArbitrators = mk(0x09, 0x02, 0x03)
	if a.IsSameWithNextArbitrators() {
		t.Fatal("arbiter sets differing at index 0 reported as the same")
	}

	// 4. Different lengths must report not-same.
	a.nextArbitrators = mk(0x01, 0x02)
	if a.IsSameWithNextArbitrators() {
		t.Fatal("arbiter sets of different length reported as the same")
	}

	// 5. Two empty sets are trivially the same.
	a.CurrentArbitrators = mk()
	a.nextArbitrators = mk()
	if !a.IsSameWithNextArbitrators() {
		t.Fatal("two empty arbiter sets reported as different")
	}
}
