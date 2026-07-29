// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/stretchr/testify/assert"
)

// f096Hashes builds n distinct processed-inactive-tx hashes.
func f096Hashes(n int) map[common.Uint256]interface{} {
	m := make(map[common.Uint256]interface{})
	for i := 0; i < n; i++ {
		var h common.Uint256
		h[0] = byte(i + 1)
		h[15] = byte(i*3 + 2)
		h[31] = byte(i*7 + 5)
		m[h] = nil
	}
	return m
}

// TestF096DegradationRoundTrip proves the trailing degradation block written by
// serializeDegradation is read back identically by deserializeDegradation across
// >20 combinations of state / heights / inactive-tx sets.
func TestF096DegradationRoundTrip(t *testing.T) {
	states := []degradationState{DSNormal, DSUnderstaffed, DSInactive}
	cases := 0
	for si, st := range states {
		for _, us := range []uint32{0, 1, 12345, 2260451} {
			for _, txn := range []int{0, 1, 5} {
				c := &CheckPoint{
					DegradationState:  byte(st),
					UnderstaffedSince: us,
					InactivateHeight:  us + uint32(si)*10 + 7,
					InactiveTxs:       f096Hashes(txn),
				}
				var buf bytes.Buffer
				assert.NoError(t, c.serializeDegradation(&buf))

				c2 := &CheckPoint{}
				assert.NoError(t, c2.deserializeDegradation(&buf))

				assert.Equal(t, c.DegradationState, c2.DegradationState)
				assert.Equal(t, c.UnderstaffedSince, c2.UnderstaffedSince)
				assert.Equal(t, c.InactivateHeight, c2.InactivateHeight)
				assert.Equal(t, len(c.InactiveTxs), len(c2.InactiveTxs))
				for k := range c.InactiveTxs {
					_, ok := c2.InactiveTxs[k]
					assert.True(t, ok, "inactive-tx hash must round-trip")
				}
				cases++
			}
		}
	}
	assert.GreaterOrEqual(t, cases, 20, "need >=20 round-trip scenarios")
}

// TestF096BackCompatLegacyCheckpoint proves a legacy checkpoint (which ends right
// after StateKeyFrame, with no trailing DEGR block) deserializes gracefully: the
// degradation state defaults to DSNormal instead of erroring.
func TestF096BackCompatLegacyCheckpoint(t *testing.T) {
	c := &CheckPoint{}
	assert.NoError(t, c.deserializeDegradation(bytes.NewReader(nil)))
	assert.Equal(t, byte(DSNormal), c.DegradationState)
	assert.NotNil(t, c.InactiveTxs)
	assert.Equal(t, 0, len(c.InactiveTxs))
	assert.Equal(t, uint32(0), c.UnderstaffedSince)
	assert.Equal(t, uint32(0), c.InactivateHeight)
}

// TestF096InvalidTagRejected proves a corrupt trailing block (present but not the
// DEGR tag) is rejected rather than silently ignored.
func TestF096InvalidTagRejected(t *testing.T) {
	c := &CheckPoint{}
	err := c.deserializeDegradation(bytes.NewReader([]byte{'X', 'X', 'X', 'X'}))
	assert.Error(t, err)
}

// TestF096FullCheckpointRoundTrip exercises the REAL CheckPoint.Serialize /
// Deserialize end to end and confirms the degradation state survives (the pristine
// code omitted it entirely, losing DSInactive + the inactive-tx set on restart).
func TestF096FullCheckpointRoundTrip(t *testing.T) {
	c := &CheckPoint{
		StateKeyFrame:     *NewStateKeyFrame(),
		Height:            2260500,
		DegradationState:  byte(DSInactive),
		UnderstaffedSince: 2260480,
		InactivateHeight:  2260490,
		InactiveTxs:       f096Hashes(3),
	}

	var buf bytes.Buffer
	assert.NoError(t, c.Serialize(&buf))

	c2 := &CheckPoint{}
	assert.NoError(t, c2.Deserialize(bytes.NewReader(buf.Bytes())))

	assert.Equal(t, byte(DSInactive), c2.DegradationState)
	assert.Equal(t, uint32(2260480), c2.UnderstaffedSince)
	assert.Equal(t, uint32(2260490), c2.InactivateHeight)
	assert.Equal(t, 3, len(c2.InactiveTxs))
	for k := range c.InactiveTxs {
		_, ok := c2.InactiveTxs[k]
		assert.True(t, ok, "inactive-tx hash must survive full checkpoint round-trip")
	}
}
