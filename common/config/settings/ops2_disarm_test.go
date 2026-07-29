// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// OPS2 item 2 -- the settings half: an override this node DISCARDS must be announced.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 8e78ce3): on mainnet,
// enforceStrictMoneyAndRollbackHeights assigns the compiled-in forced-rollback height
// and trigger unconditionally, so a --forcedrollbacktrigger / --forcedrollbackheight
// supplied on the command line or in config.json is overwritten with nothing written
// anywhere. The operator's mental model ("I disarmed this node") and the binary's
// behaviour ("this node is armed") then disagree in total silence -- and the node's
// OWN error text told the operator to do exactly that (see the blockchain-side test).
//
// The Schnorr pin four functions further down already announces its discards on
// stderr, so this is the same treatment applied to the one pin an operator is
// actually told to touch on restart day.
package settings

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/assert"
)

// ops2CaptureStderr runs fn with os.Stderr replaced by a pipe and returns what was
// written to it. Stderr is the only channel available here: SetupConfig runs before
// setupLog, so common/log's package logger is still nil and any log call would panic
// -- which is why the Schnorr pin writes to os.Stderr directly too.
func ops2CaptureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	real := os.Stderr
	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); io.Copy(&buf, r) }()

	os.Stderr = w
	func() {
		defer func() {
			os.Stderr = real
			w.Close()
		}()
		fn()
	}()
	wg.Wait()
	return buf.String()
}

// ops2TriggerOverride is a syntactically valid but WRONG trigger hash: what a
// mistyped or copy-pasted --forcedrollbacktrigger looks like.
const ops2TriggerOverride = "00000000000000000000000000000000000000000000000000000000deadbeef"

// ops2RollbackOverride is a wrong forced-rollback height.
const ops2RollbackOverride = uint32(4294967295)

// TestOps2DiscardedRollbackOverrideIsAnnounced is the item-2 settings proof.
//
// FAILS ON PRISTINE: the mainnet arm assigns the pinned values and returns; stderr is
// empty.
func TestOps2DiscardedRollbackOverrideIsAnnounced(t *testing.T) {
	for _, activeNet := range []string{"", "mainnet", "MainNet", " main "} {
		t.Run("net="+activeNet, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = activeNet
			c.ForcedRollbackTrigger = ops2TriggerOverride
			c.ForcedRollbackHeight = ops2RollbackOverride

			out := ops2CaptureStderr(t, func() {
				enforceCoordinatedMainnetParameters(c)
			})

			// The pin itself is unchanged: this is about loudness only.
			assert.Equal(t, config.MainNetForcedRollbackTrigger, c.ForcedRollbackTrigger)
			assert.Equal(t, config.MainNetForcedRollbackHeight, c.ForcedRollbackHeight)

			assert.Contains(t, out, "forcedrollbacktrigger",
				"a discarded trigger override was swallowed silently")
			assert.Contains(t, out, "forcedrollbackheight",
				"a discarded height override was swallowed silently")
			assert.Contains(t, out, config.MainNetForcedRollbackTrigger,
				"the announcement must name the value that WON, so the operator can "+
					"see what this node is actually armed for")
		})
	}
}

// TestOps2CorrectlyConfiguredMainnetNodeSaysNothing keeps the announcement from
// becoming boilerplate every operator learns to ignore: a node that supplied no
// override -- i.e. every node in the fleet on restart day -- must print nothing.
func TestOps2CorrectlyConfiguredMainnetNodeSaysNothing(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"

	out := ops2CaptureStderr(t, func() {
		enforceCoordinatedMainnetParameters(c)
	})

	assert.NotContains(t, out, "forcedrollback",
		"a correctly configured mainnet node must not be told about a pin it never fought")
}

// TestOps2MainNetActiveNetAgreesWithThePin is the anti-drift guard for
// config.IsMainNetActiveNet, which the blockchain-side remedy text switches on.
//
// The remedy the node prints ("unsetting the trigger will / will not let this node
// start") is only true if that predicate agrees, label for label, with the pin that
// actually discards the trigger. Rather than sharing a literal, this asserts the
// agreement against the REAL production pin: for every label, arm the pin and check
// whether the supplied trigger survived.
func TestOps2MainNetActiveNetAgreesWithThePin(t *testing.T) {
	labels := []string{"", "mainnet", "main", "MAINNET", " Main ", "testnet", "test",
		"regnet", "regtest", "reg", "mainet", "production", "private"}

	for _, label := range labels {
		t.Run("net="+label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label
			c.ForcedRollbackTrigger = ops2TriggerOverride

			ops2CaptureStderr(t, func() {
				enforceCoordinatedMainnetParameters(c)
			})

			// The question the remedy text must answer is not "was my value
			// discarded" but "will this node be armed no matter what I supply".
			// On mainnet the pin re-installs the coordinated trigger; everywhere
			// else the forced rollback is either disabled outright or (with
			// ArmIncidentGates) left in the operator's hands.
			forceArmed := c.ForcedRollbackTrigger == config.MainNetForcedRollbackTrigger
			assert.Equal(t, forceArmed, config.IsMainNetActiveNet(label),
				"IsMainNetActiveNet(%q)=%v but the production pin left the trigger %q; "+
					"the remedy text would tell the operator to do something that does "+
					"not work", label, config.IsMainNetActiveNet(label),
				c.ForcedRollbackTrigger)
		})
	}
}
