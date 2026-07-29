// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
)

// TestF058_NextArbitratorsSameV1_ShortCRPublicKeys is a fail-on-pristine
// crash-harden guard for F-058.
//
// isNextArbitratorsSameV1 length-checks ONLY the DPoS leg. Its CRC loop ranges
// over nextCRCArbitrators (a node-local, attacker-independent list) while
// indexing the attacker-supplied nextTurnDPOSInfo.CRPublicKeys[i]. A payload
// whose CRPublicKeys slice is shorter than the node CRC-arbiter count indexes
// out of range and panics.
//
// The DPoS leg is kept empty so the DPoS loop performs zero iterations and the
// function never dereferences blockchain.DefaultLedger before reaching the CRC
// leg, isolating the CRC out-of-bounds path.
//
// PRISTINE: the CRC loop panics with index out of range -> recover() fires ->
// t.Fatalf -> test FAILS.
// FIXED: the added len(CRPublicKeys) < len(nextCRCArbitrators) guard returns
// false without indexing -> test PASSES.
func TestF058_NextArbitratorsSameV1_ShortCRPublicKeys(t *testing.T) {
	// Empty DPoS leg: length check passes (0 == 0) and the DPoS loop is a no-op,
	// so DefaultLedger is never touched.
	info := &payload.NextTurnDPOSInfo{
		CRPublicKeys:   [][]byte{}, // shorter than the node CRC list below
		DPOSPublicKeys: [][]byte{},
	}
	var nextArbitrators []*state.ArbiterInfo // len 0, matches DPOSPublicKeys

	// Node-local CRC arbiter list longer than the attacker CRPublicKeys slice.
	nextCRCArbitrators := [][]byte{
		{0x02, 0xaa},
		{0x03, 0xbb},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("F-058: isNextArbitratorsSameV1 panicked on short CRPublicKeys "+
				"(pristine out-of-bounds index): %v", r)
		}
	}()

	got := isNextArbitratorsSameV1(info, nextArbitrators, nextCRCArbitrators)
	if got != false {
		t.Fatalf("F-058: expected isNextArbitratorsSameV1 to reject a short "+
			"CRPublicKeys slice (want false), got %v", got)
	}
}
