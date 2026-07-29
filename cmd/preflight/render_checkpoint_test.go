// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package preflight

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"

	"github.com/stretchr/testify/assert"
)

// TestRenderShowsTheRestoredCheckpointHeight pins that the store section states the
// height main.go's post-restore gate will compare, per checkpoint, and says in words
// whether that gate runs on this start. Printing the number alone would leave the
// operator to work out whether it can stop them.
func TestRenderShowsTheRestoredCheckpointHeight(t *testing.T) {
	out := RenderText(&blockchain.PreflightReport{
		Version:  "v1.0.0",
		Outcome:  blockchain.PreflightWillRewind,
		Headline: "This node WILL REWIND on start.",
		Cell:     "A-or-E/holds-the-chain-the-recovery-removes",
		Store: blockchain.PreflightStoreState{
			DataDir:                     "/home/ela/node/data",
			Tip:                         2260594,
			RestoredCheckpointMaxHeight: 2259577,
			CheckpointGateEvaluated:     true,
			RestoredCheckpoints: []blockchain.RestoredCheckpoint{
				{Key: "cp_cr", File: "default.ccp", Height: 2259577, CountedInMaxHeight: true},
				{Key: "cp_dpos", File: "default.dcp", Height: 2259577, CountedInMaxHeight: true},
				{Key: "cp_txPool", File: "default.txpcp", Height: 2260594},
			},
		},
	})

	assert.Contains(t, out, "restored checkpoint height  2259577")
	assert.Contains(t, out, "cp_cr", "each checkpoint must be shown, not just the max")
	assert.Contains(t, out, "cp_dpos")
	assert.Contains(t, out, "[not counted]",
		"cp_txPool is excluded from the gate and the output must say so")
	assert.Contains(t, out, "RUNS on this start")
	assert.Contains(t, out, "upper bound",
		"the number must carry its own caveat where it is printed")

	// And when the gate cannot fire, the tool says that instead of staying silent.
	quiet := RenderText(&blockchain.PreflightReport{
		Version: "v1.0.0",
		Outcome: blockchain.PreflightNothingToDo,
		Store: blockchain.PreflightStoreState{
			RestoredCheckpointMaxHeight: 2261000,
			CheckpointGateEvaluated:     false,
		},
	})
	assert.Contains(t, quiet, "does not apply to this start")
	assert.NotContains(t, quiet, "RUNS on this start")

	if testing.Verbose() {
		t.Log("\n" + out[strings.Index(out, "STORE --"):])
	}
}
