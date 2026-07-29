package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"

	"github.com/stretchr/testify/assert"
)

// writeCheckpointWithHeight writes a minimal checkpoint file whose first four bytes
// are the height, which is how every consensus checkpoint serialises it. The reader
// under test deliberately does not deserialise the body.
func writeCheckpointWithHeight(t *testing.T, dir, key string, height uint32, ext string) {
	t.Helper()
	sub := filepath.Join(dir, "checkpoints", key)
	assert.NoError(t, os.MkdirAll(sub, 0o755))
	buf := []byte{
		byte(height), byte(height >> 8), byte(height >> 16), byte(height >> 24),
		0xde, 0xad, 0xbe, 0xef, // body the reader must not need
	}
	assert.NoError(t, os.WriteFile(filepath.Join(sub, "default"+ext), buf, 0o644))
}

// TestOpen1EarlyGateSeesAnAboveTargetCheckpoint is the property the early gate in
// main.go depends on: the on-disk checkpoint height must be readable BEFORE any
// restore, so the node can refuse before arbitrator.Start() puts it on the DPoS mesh.
func TestOpen1EarlyGateSeesAnAboveTargetCheckpoint(t *testing.T) {
	const target = uint32(2260450)
	dir := t.TempDir()

	// One snapshot safely pre-target, one that drifted past it.
	writeCheckpointWithHeight(t, dir, "cp_cr", 2259577, ".cr")
	writeCheckpointWithHeight(t, dir, "cp_dpos", target+7, ".dpos")

	mh, detail := blockchain.PredictRestoredCheckpointMaxHeight(dir)

	assert.GreaterOrEqual(t, mh, target,
		"an above-target checkpoint must be visible BEFORE restore, or the node "+
			"joins the DPoS mesh with exploit-era derived state and only refuses afterwards")
	assert.NotEmpty(t, detail, "the operator must be told which checkpoint tripped it")
	t.Logf("max on-disk checkpoint height %d vs target %d, detail %v", mh, target, detail)
}

// TestOpen1EarlyGateStaysQuietOnACleanNode is the false-positive control. Without
// it, a gate that refused unconditionally would also "pass" the test above.
func TestOpen1EarlyGateStaysQuietOnACleanNode(t *testing.T) {
	const target = uint32(2260450)
	dir := t.TempDir()

	writeCheckpointWithHeight(t, dir, "cp_cr", 2259577, ".cr")
	writeCheckpointWithHeight(t, dir, "cp_dpos", 2259577, ".dpos")

	mh, _ := blockchain.PredictRestoredCheckpointMaxHeight(dir)

	assert.Less(t, mh, target,
		"a node whose snapshots are strictly pre-target must NOT be refused")
	t.Logf("clean node: max on-disk checkpoint height %d < target %d", mh, target)
}

// TestOpen1EarlyGateIgnoresTheTxPoolCheckpoint pins the one exclusion that matters:
// the tx-pool checkpoint tracks the tip and is routinely above the target. Counting
// it would refuse every node.
func TestOpen1EarlyGateIgnoresTheTxPoolCheckpoint(t *testing.T) {
	const target = uint32(2260450)
	dir := t.TempDir()

	writeCheckpointWithHeight(t, dir, "cp_cr", 2259577, ".cr")
	writeCheckpointWithHeight(t, dir, "cp_txPool", 2260594, ".txpcp")

	mh, detail := blockchain.PredictRestoredCheckpointMaxHeight(dir)

	assert.Less(t, mh, target,
		"the tx-pool checkpoint tracks the tip and must be excluded, exactly as "+
			"CkpManager.MaxHeight() excludes it; counting it refuses every healthy node")
	t.Logf("txPool excluded: max %d < target %d, detail %v", mh, target, detail)
}
