// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF170SnapshotCopiesEveryPersistedField is the fail-on-pristine test for F-170.
//
// StateKeyFrame.snapshot() is meant to return a copy of the frame it is taken from.
// Pristine, it copied the maps and the single scalar DPoSV2ActiveHeight, left a
// "//todo add DPOSStartHeight and so on" behind, and silently dropped the
// EmergencyInactiveArbiters set plus the fourteen remaining scalars -- exactly the
// field set StateKeyFrame.Serialize writes after the map block
// (SerializeStringSet(EmergencyInactiveArbiters), WriteVarString of
// LastRandomCandidateOwner, and the fourteen WriteElements). A snapshot was therefore
// a frame with a NIL map and zeroed scalars.
//
// Every assertion below except the DPoSV2ActiveHeight one FAILS on pristine and
// PASSES with the fix. The copy is a deep copy: mutating the source set afterwards
// must not reach the snapshot.
func TestF170SnapshotCopiesEveryPersistedField(t *testing.T) {
	kf := NewStateKeyFrame()

	kf.EmergencyInactiveArbiters["emergency-arbiter-1"] = struct{}{}
	kf.EmergencyInactiveArbiters["emergency-arbiter-2"] = struct{}{}
	kf.LastRandomCandidateOwner = "0303c43d9c0e5e6f1c6d0b4b2f0f39d0f6ba5a11"
	kf.VersionStartHeight = 111
	kf.VersionEndHeight = 222
	kf.LastRandomCandidateHeight = 333
	kf.DPOSWorkHeight = 444
	kf.ConsensusAlgorithm = POW
	kf.LastBlockTimestamp = 555
	kf.NeedRevertToDPOSTX = true
	kf.NeedNextTurnDPOSInfo = true
	kf.NoProducers = true
	kf.NoClaimDPOSNode = true
	kf.RevertToPOWBlockHeight = 666
	kf.LastIrreversibleHeight = 777
	kf.DPOSStartHeight = 888
	kf.DPoSV2ActiveHeight = 999

	snap := kf.snapshot()

	// The EmergencyInactiveArbiters set: pristine leaves it nil (the struct literal in
	// snapshot() never allocated it and nothing ever copied it).
	assert.NotNil(t, snap.EmergencyInactiveArbiters,
		"F-170: snapshot must carry an allocated EmergencyInactiveArbiters set, not nil")
	assert.Equal(t, kf.EmergencyInactiveArbiters, snap.EmergencyInactiveArbiters,
		"F-170: snapshot must copy EmergencyInactiveArbiters")

	// Deep copy, not aliasing: a later mutation of the source must not be visible.
	kf.EmergencyInactiveArbiters["emergency-arbiter-3"] = struct{}{}
	assert.Len(t, snap.EmergencyInactiveArbiters, 2,
		"F-170: snapshot must hold its own EmergencyInactiveArbiters map")

	assert.Equal(t, "0303c43d9c0e5e6f1c6d0b4b2f0f39d0f6ba5a11", snap.LastRandomCandidateOwner,
		"F-170: snapshot must copy LastRandomCandidateOwner")
	assert.Equal(t, uint32(111), snap.VersionStartHeight, "F-170: VersionStartHeight")
	assert.Equal(t, uint32(222), snap.VersionEndHeight, "F-170: VersionEndHeight")
	assert.Equal(t, uint32(333), snap.LastRandomCandidateHeight, "F-170: LastRandomCandidateHeight")
	assert.Equal(t, uint32(444), snap.DPOSWorkHeight, "F-170: DPOSWorkHeight")
	assert.Equal(t, POW, snap.ConsensusAlgorithm, "F-170: ConsensusAlgorithm")
	assert.Equal(t, uint32(555), snap.LastBlockTimestamp, "F-170: LastBlockTimestamp")
	assert.True(t, snap.NeedRevertToDPOSTX, "F-170: NeedRevertToDPOSTX")
	assert.True(t, snap.NeedNextTurnDPOSInfo, "F-170: NeedNextTurnDPOSInfo")
	assert.True(t, snap.NoProducers, "F-170: NoProducers")
	assert.True(t, snap.NoClaimDPOSNode, "F-170: NoClaimDPOSNode")
	assert.Equal(t, uint32(666), snap.RevertToPOWBlockHeight, "F-170: RevertToPOWBlockHeight")
	assert.Equal(t, uint32(777), snap.LastIrreversibleHeight, "F-170: LastIrreversibleHeight")
	assert.Equal(t, uint32(888), snap.DPOSStartHeight, "F-170: DPOSStartHeight")

	// Copied on pristine too - present as a control.
	assert.Equal(t, uint32(999), snap.DPoSV2ActiveHeight, "DPoSV2ActiveHeight (control)")
}
