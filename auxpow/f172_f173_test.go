// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package auxpow

import "testing"

// TestF173GetExpectedIndexNoDivZero — F-173: GetExpectedIndex does
// `rand % (1 << uint32(h))`; for h >= 32 the uint32 shift overflows to 0 -> `rand % 0`
// integer divide-by-zero panic. h is attacker-controlled (len(AuxMerkleBranch) via
// ReadVarUint), reached pre-PoW. Drives the REAL GetExpectedIndex: h >= 32 returns -1
// (guarded), valid h returns a bounded index. Pre-fix, h >= 32 panics "integer divide by
// zero".
func TestF173GetExpectedIndexNoDivZero(t *testing.T) {
	for _, h := range []int{32, 33, 40, 63, 64, 255, -1} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("F-173: GetExpectedIndex(h=%d) panicked (must return -1): %v", h, r)
				}
			}()
			if got := GetExpectedIndex(1, 1224, h); got != -1 {
				t.Fatalf("F-173: GetExpectedIndex(h=%d) must return -1 (guarded), got %d", h, got)
			}
		}()
	}
	// Valid heights still compute a bounded index in [0, 1<<h).
	for _, h := range []int{0, 1, 4, 16, 31} {
		got := GetExpectedIndex(1, 1224, h)
		if got < 0 || (h < 31 && got >= (1<<uint(h))) {
			t.Fatalf("F-173: GetExpectedIndex(h=%d) = %d out of range [0,%d)", h, got, 1<<uint(h))
		}
	}
}
