// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TEST — F-096 CAPTURE side.
//
// The blocker: severing the capture so every checkpoint records DSNormal — i.e. exactly
// the pre-fix bug —
//
//	c.DegradationState = byte(DSNormal)
//	c.UnderstaffedSince = 0
//
// left the entire suite green at HEAD, INCLUDING the test that was added specifically to
// "drive the real production path end to end". That test hand-builds a *CheckPoint with
// the degradation fields already populated, so it only ever exercised the RESTORE side.
//
// This test starts from an Arbiters that is actually degraded and drives the REAL
// production capture path — (*CheckPoint).Snapshot(), which is what checkpoint.Manager
// calls on save: initFromArbitrators -> Serialize -> Deserialize — then restores into a
// fresh Arbiters. Sever the capture and the restored node comes back DSNormal.
package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

// degradedArbiters returns an Arbiters that is genuinely in the degraded (DSInactive)
// mode, with a non-empty processed-inactive-tx dedup set.
func degradedArbiters(txs map[common.Uint256]interface{}) *Arbiters {
	params := &config.Configuration{}
	return &Arbiters{
		State: &State{
			StateKeyFrame: NewStateKeyFrame(),
			History:       utils.NewHistory(maxHistoryCapacity),
			ChainParams:   params,
		},
		ChainParams: params,
		History:     utils.NewHistory(maxHistoryCapacity),
		degradation: &degradation{
			state:             DSInactive,
			understaffedSince: 100,
			inactivateHeight:  200,
			inactiveTxs:       txs,
		},
		Snapshots:        map[uint32][]*CheckPoint{},
		SnapshotKeysDesc: []uint32{},
	}
}

// TestF096CaptureWiringSnapshotPreservesDegradation is the F-096 capture-side wiring proof.
//
// MUTATION PROOF: replace the capture in initFromArbitrators with the pre-fix constants
// (DegradationState = DSNormal, UnderstaffedSince = 0) -> the restored Arbiters comes back
// DSNormal -> this test FAILS. The pre-existing F-096 tests all still pass under that
// mutation because they build the checkpoint by hand.
func TestF096CaptureWiringSnapshotPreservesDegradation(t *testing.T) {
	txs := f096Hashes(3)
	a := degradedArbiters(txs)

	// REAL production capture path: Manager.onBlockSaved -> ICheckPoint.Snapshot().
	cp := NewCheckpoint(a)
	snapshot := cp.Snapshot()
	if snapshot == nil {
		t.Fatal("harness bug: Snapshot() returned nil (serialize/deserialize failed)")
	}
	restoredPoint, ok := snapshot.(*CheckPoint)
	if !ok {
		t.Fatalf("harness bug: Snapshot() returned %T", snapshot)
	}

	// Restore into a fresh node, exactly as OnInit does after a cold restart.
	fresh := &Arbiters{State: &State{}, degradation: &degradation{}}
	fresh.RecoverFromCheckPoints(restoredPoint)

	assert.Equal(t, DSInactive, fresh.degradation.state,
		"F-096 CAPTURE SEVERED: a degraded node checkpointed and restarted came back DSNormal — "+
			"the checkpoint never recorded the degradation, so InitCheckpoint's dedup is empty "+
			"and the node re-triggers a spurious ForceChange")
	assert.Equal(t, uint32(100), fresh.degradation.understaffedSince,
		"F-096 CAPTURE SEVERED: understaffedSince was not captured")
	assert.Equal(t, uint32(200), fresh.degradation.inactivateHeight,
		"F-096 CAPTURE SEVERED: inactivateHeight was not captured")
	assert.Equal(t, len(txs), len(fresh.degradation.inactiveTxs),
		"F-096 CAPTURE SEVERED: the processed-inactive-tx dedup set was not captured")
	for k := range txs {
		_, present := fresh.degradation.inactiveTxs[k]
		assert.Truef(t, present, "processed-inactive-tx %s must survive capture -> restart -> restore", k)
	}
}

// TestF096CaptureWiringNewCheckpointCapturesDegradation pins the OTHER capture entry
// point: NewCheckpoint (used by the two checkpoint rebuild sites) must read the live
// degradation rather than defaulting it.
func TestF096CaptureWiringNewCheckpointCapturesDegradation(t *testing.T) {
	txs := f096Hashes(2)
	cp := NewCheckpoint(degradedArbiters(txs))

	assert.Equal(t, byte(DSInactive), cp.DegradationState,
		"F-096 CAPTURE SEVERED: NewCheckpoint did not read Arbiters.degradation.state")
	assert.Equal(t, uint32(100), cp.UnderstaffedSince)
	assert.Equal(t, uint32(200), cp.InactivateHeight)
	assert.Equal(t, len(txs), len(cp.InactiveTxs))
}

// TestF096CaptureWiringNilDegradationStillDefaults keeps the documented back-compat leg
// honest: a nil degradation must capture as the legacy default, not panic.
func TestF096CaptureWiringNilDegradationStillDefaults(t *testing.T) {
	a := degradedArbiters(nil)
	a.degradation = nil

	cp := NewCheckpoint(a)
	assert.Equal(t, byte(DSNormal), cp.DegradationState,
		"a nil degradation must capture as the pre-F-096 legacy default")
	assert.NotNil(t, cp.InactiveTxs)
	assert.Equal(t, 0, len(cp.InactiveTxs))
}
