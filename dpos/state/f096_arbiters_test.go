// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF096ArbitersRestoreDegradation is the Arbiters-level integration test the
// safety re-verification asked for: it drives the REAL capture -> cold-restart
// serialize/deserialize -> recoverFromCheckPoints path and asserts the degradation
// state survives. This is the behavior the fix exists for — a restored node stays
// DSInactive with its processed-inactive-tx set intact, so InitCheckpoint's dedup
// skips the spurious ForceChange that a pristine (state-losing) node would
// re-trigger.
func TestF096ArbitersRestoreDegradation(t *testing.T) {
	txs := f096Hashes(3)
	point := &CheckPoint{
		StateKeyFrame:     *NewStateKeyFrame(),
		DegradationState:  byte(DSInactive),
		UnderstaffedSince: 100,
		InactivateHeight:  200,
		InactiveTxs:       txs,
	}

	// Cold restart: the checkpoint is serialized to disk and read back.
	var buf bytes.Buffer
	assert.NoError(t, point.Serialize(&buf))
	restored := &CheckPoint{}
	assert.NoError(t, restored.Deserialize(bytes.NewReader(buf.Bytes())))

	// InitCheckpoint applies the restored checkpoint to a fresh Arbiters.
	a := &Arbiters{State: &State{}, degradation: &degradation{}}
	a.RecoverFromCheckPoints(restored)

	// The degradation mode + dedup set are restored -> no spurious re-ForceChange.
	assert.Equal(t, DSInactive, a.degradation.state,
		"restored node stays DSInactive; InitCheckpoint dedup then skips re-ForceChange")
	assert.Equal(t, uint32(100), a.degradation.understaffedSince)
	assert.Equal(t, uint32(200), a.degradation.inactivateHeight)
	assert.Equal(t, len(txs), len(a.degradation.inactiveTxs))
	for k := range txs {
		_, ok := a.degradation.inactiveTxs[k]
		assert.True(t, ok, "each processed-inactive-tx hash survives capture->restart->restore")
	}
}

// TestF096ArbitersLegacyCheckpointDefaults proves back-compat at the Arbiters
// level: a legacy checkpoint (no trailing DEGR block) restores a fresh Arbiters
// to DSNormal with an empty dedup set — the pristine behavior, not a forced state.
func TestF096ArbitersLegacyCheckpointDefaults(t *testing.T) {
	// A legacy checkpoint deserializes with no DEGR block -> DSNormal + empty map.
	legacy := &CheckPoint{}
	assert.NoError(t, legacy.deserializeDegradation(bytes.NewReader(nil)))

	a := &Arbiters{State: &State{}, degradation: &degradation{}}
	a.RecoverFromCheckPoints(legacy)

	assert.Equal(t, DSNormal, a.degradation.state,
		"legacy checkpoint restores DSNormal (back-compat, no forced state)")
	assert.NotNil(t, a.degradation.inactiveTxs)
	assert.Equal(t, 0, len(a.degradation.inactiveTxs))
}
