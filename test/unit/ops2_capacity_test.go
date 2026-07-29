// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- OPS2 item 2, the blockchain half: our own error text must not
// instruct an impossible action.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 8e78ce3): the capacity refusal --
// the refusal a node further than the incremental rewind window past the target
// meets, and the one 48/48 rehearsal nodes met -- ended with "Unsetting
// --forcedrollbacktrigger also lets this node start". On mainnet that is false:
// settings.enforceStrictMoneyAndRollbackHeights discards both the flag and the
// config.json field and re-pins the coordinated values. An operator who followed
// the instruction got a node that still did not start and an error that still
// said the same thing.
package unit

import (
	"strings"
	"testing"
)

// ops2CapacityRefusal drives the production capacity refusal on a chain built far
// enough past the target that ForceRollback declines, and returns its message.
func ops2CapacityRefusal(t *testing.T, activeNet string) string {
	t.Helper()
	const target = uint32(5)
	dir := t.TempDir()
	params := t1Params(target)
	params.ActiveNet = activeNet
	t1BuildChain(t, dir, params, target+b1b5CapacityDepth)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	err := chain.ForceRollback(nil)
	if err == nil {
		t.Fatal("harness is wrong: the capacity refusal did not fire")
	}
	return err.Error()
}

// TestOps2CapacityRefusalDoesNotPrescribeAnImpossibleDisarm is the item-2 proof.
//
// FAILS ON PRISTINE on the mainnet labels: the pristine text always offers the
// disarm.
func TestOps2CapacityRefusalDoesNotPrescribeAnImpossibleDisarm(t *testing.T) {
	for _, activeNet := range []string{"", "mainnet", "main", "MainNet"} {
		t.Run("mainnet/"+activeNet, func(t *testing.T) {
			msg := ops2CapacityRefusal(t, activeNet)
			if strings.Contains(msg, "Unsetting --forcedrollbacktrigger also lets this "+
				"node start") {
				t.Errorf("the refusal prescribes a disarm that this node discards.\n"+
					"full message:\n%s", msg)
			}
			if !strings.Contains(msg, "NO disarm on mainnet") {
				t.Errorf("the refusal does not tell the operator that the disarm is "+
					"unavailable here.\nfull message:\n%s", msg)
			}
		})
	}
}

// TestOps2CapacityRefusalKeepsTheRealDisarmOffMainnet is the negative control: on a
// net where unsetting the trigger DOES work -- a private or forked chain running this
// binary -- the operator must still be told so. A fix that simply deleted the sentence
// would pass the test above and take a working remedy away from those nodes.
func TestOps2CapacityRefusalKeepsTheRealDisarmOffMainnet(t *testing.T) {
	for _, activeNet := range []string{"testnet", "regnet", "privatenet"} {
		t.Run("other/"+activeNet, func(t *testing.T) {
			msg := ops2CapacityRefusal(t, activeNet)
			if !strings.Contains(msg, "Unsetting --forcedrollbacktrigger") {
				t.Errorf("a net where the disarm works was not told about it.\n"+
					"full message:\n%s", msg)
			}
			if strings.Contains(msg, "NO disarm on mainnet") {
				t.Errorf("a non-mainnet node was told the mainnet story.\n"+
					"full message:\n%s", msg)
			}
		})
	}
}
