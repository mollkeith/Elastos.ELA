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

// TestRenderPutsThePredictionFirst pins the layout an operator actually reads.
//
// On restart day the top of the output is what gets read. A report whose first
// screen is identity and store detail buries the one sentence the command exists
// to produce.
func TestRenderPutsThePredictionFirst(t *testing.T) {
	out := RenderText(&blockchain.PreflightReport{
		Version:  "v1.0.0",
		Outcome:  blockchain.PreflightWillRewind,
		Headline: "This node WILL REWIND on start: from tip 2260594 down to 2260450.",
		Cell:     "A-or-E/holds-the-chain-the-recovery-removes",
		Estimate: blockchain.PreflightEstimate{
			FullStoreScans: 3, LowSeconds: 64, HighSeconds: 72,
			Basis: "ESTIMATE. MEASURED: an armed boot on a 25 GiB store took 66-73 s.",
		},
	})

	headlineAt := strings.Index(out, "WILL REWIND on start")
	identityAt := strings.Index(out, "IDENTITY")
	storeAt := strings.Index(out, "STORE --")
	assert.Greater(t, headlineAt, -1, "the headline must be rendered")
	assert.Less(t, headlineAt, identityAt, "the prediction must precede identity")
	assert.Less(t, headlineAt, storeAt, "the prediction must precede store detail")
	assert.Contains(t, out, "WILL-REWIND")
	assert.Contains(t, out, "64-72 seconds (3 full store scan(s))")
	assert.Contains(t, out, "MEASURED", "the estimate must show what it rests on")
}

// TestRenderPrintsTheBlockingErrorVerbatim pins that a refusal shows the node's
// OWN words. The remedy is inside that text; paraphrasing it would drop the part
// the operator has to act on.
func TestRenderPrintsTheBlockingErrorVerbatim(t *testing.T) {
	const blocker = "forced rollback: the targeted block is still in the persisted " +
		"store. Remedy: restore a pre-rollback backup of the data directory."
	out := RenderText(&blockchain.PreflightReport{
		Version:  "v1.0.0",
		Outcome:  blockchain.PreflightWillRefuse,
		Headline: "This node will REFUSE to start.",
		Blocking: []string{blocker},
	})
	assert.Contains(t, out, "BLOCKING")
	// The renderer wraps, so compare on collapsed whitespace.
	assert.Contains(t, collapse(out), collapse(blocker))
	assert.Contains(t, out, "and then exit",
		"the section must say the node exits, not merely that something is wrong")
}

// TestRenderSaysWarningsDoNotChangeTheExitCode pins the one thing that could make
// a warning misread as a failure -- or, worse, make a real failure look like a
// warning.
func TestRenderSaysWarningsDoNotChangeTheExitCode(t *testing.T) {
	out := RenderText(&blockchain.PreflightReport{
		Version:  "v1.0.0",
		Outcome:  blockchain.PreflightWillRewind,
		Headline: "This node WILL REWIND on start.",
		Warnings: []string{"THE STORE CANNOT TELL YOU whether this is stale data."},
	})
	assert.Contains(t, out, "do NOT stop the node")
	assert.Contains(t, out, "do not change the exit code")
	assert.Contains(t, collapse(out), "THE STORE CANNOT TELL YOU")
}

// TestRenderNamesTheDisabledSentinelInWords pins that an operator never has to
// recognise 4294967295 as "off".
func TestRenderNamesTheDisabledSentinelInWords(t *testing.T) {
	out := RenderText(&blockchain.PreflightReport{
		Version:  "v1.0.0",
		Outcome:  blockchain.PreflightNothingToDo,
		Headline: "No forced rollback is configured.",
		Gates: blockchain.PreflightGates{
			ActiveNet:              "",
			StrictMoneyRangeHeight: 4294967295,
			ForcedRollbackHeight:   4294967295,
			ForcedRollbackTrigger:  "",
		},
	})
	assert.Contains(t, out, "disabled (max uint32)")
	assert.NotContains(t, out, "4294967295")
	assert.Contains(t, out, `"" (mainnet)`,
		"an empty ActiveNet means mainnet and must not render as a blank")
	assert.Contains(t, out, "(none -- forced rollback disabled)")
}

// TestExitCodesAreDistinctAndDocumented pins the command's scripted API: node.sh
// and the operator script branch on these, so no two may mean the same thing and
// every one must appear in the help text.
func TestExitCodesAreDistinctAndDocumented(t *testing.T) {
	named := map[string]int{
		"ready": ExitReady, "usage": ExitUsage, "store-unreadable": ExitStoreUnreadable,
		"node-running": ExitNodeRunning, "will-refuse": ExitWillRefuse,
		"internal": ExitInternal,
	}
	seen := map[int]string{}
	for name, code := range named {
		if prev, dup := seen[code]; dup {
			t.Fatalf("exit code %d means both %q and %q", code, prev, name)
		}
		seen[code] = name
	}
	assert.Len(t, seen, 6)

	help := NewCommand().Description
	for _, code := range []string{"0", "1", "2", "3", "4", "5"} {
		assert.Containsf(t, help, code+" ",
			"exit code %s is not documented in the command description", code)
	}
	assert.Contains(t, help, "It NEVER writes",
		"the description must state the guarantee the command rests on")
	assert.Contains(t, NewCommand().Usage, "READ-ONLY",
		"the one-line usage must carry the guarantee too -- it is what `ela-cli "+
			"--help` shows")
}

// collapse squeezes runs of whitespace so wrapped output can be compared with the
// unwrapped source string.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
