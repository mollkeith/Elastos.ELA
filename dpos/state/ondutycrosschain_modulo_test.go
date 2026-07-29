// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/assert"
)

// GetOnDutyCrossChainArbitrator must not divide by zero when the CRC arbiter
// collections are empty.
//
// WHY THIS EXISTS. The batch shipped both modulo guards in this function with NO
// test -- nothing in the tree referenced GetOnDutyCrossChainArbitrator at all. A
// mutation audit found that on 2026-07-28: reverting only these two guards left
// dpos/state, test/unit, blockchain and mempool all green, while a throwaway probe
// panicked with "runtime error: integer divide by zero".
//
// THE DEFECT, and why the second branch is the serious one.
//   - Branch A, heights in [CRCOnlyDPOSHeight-1, CRClaimDPOSNodeStartHeight):
//     `% len(crcArbiters)` on an empty slice. Retained history on mainnet, so it
//     runs on every full resync from genesis.
//   - Branch B, heights below DPOSNodeCrossChainHeight: `a.DutyIndex %
//     len(a.CurrentCRCArbitersMap)`. CurrentCRCArbitersMap is never allocated by
//     initArbitrators, and mainnet sets DPOSNodeCrossChainHeight = MaxUint32, so
//     the enclosing condition holds at EVERY real height. The fix's own comment
//     calls this the LIVE mainnet branch, and it is reachable from a relayed
//     SideChainPow transaction -- i.e. from any peer.
//
// A panic here takes the node down. During the PoW window that is a node the
// restart depends on.
//
// FAIL-ON-PRISTINE: remove either guard and the matching subtest panics with
// "integer divide by zero" instead of returning nil. Proven by reverting the
// production guards, not by assertion.

// bareArbitersAtHeight builds the minimum Arbiters this function touches, with
// EMPTY CRC collections -- the state initArbitrators actually leaves behind.
func bareArbitersAtHeight(params *config.Configuration, height uint32) *Arbiters {
	a := &Arbiters{
		State:       &State{},
		degradation: &degradation{},
		ChainParams: params,
		// Left NIL on purpose: initArbitrators never allocates
		// CurrentCRCArbitersMap, so nil is the real production state, not a
		// contrived one.
		CurrentCRCArbitersMap: nil,
		CurrentArbitrators:    nil,
	}
	a.bestHeight = func() uint32 { return height }
	return a
}

func TestOnDutyCrossChainArbitratorNoDivideByZero(t *testing.T) {
	params := config.GetDefaultParams()

	cases := []struct {
		name   string
		height uint32
	}{
		{
			// Branch B: the LIVE mainnet branch. DPOSNodeCrossChainHeight is
			// MaxUint32 on mainnet, so every real height lands here.
			name:   "live mainnet branch (DutyIndex %% empty CurrentCRCArbitersMap)",
			height: 2260450,
		},
		{
			// Branch B again, at the restart tip itself.
			name:   "at the restart tip",
			height: 2260451,
		},
		{
			// Branch A: retained history, exercised on every resync from genesis.
			name:   "retained-history branch (%% empty crcArbiters)",
			height: params.CRCOnlyDPOSHeight,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := bareArbitersAtHeight(params, c.height)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DIVIDE BY ZERO at height %d: %v.\n"+
						"  GetOnDutyCrossChainArbitrator took a modulo against an empty CRC\n"+
						"  collection. This is reachable from a relayed SideChainPow\n"+
						"  transaction, so any peer can crash the node.", c.height, r)
				}
			}()
			got := a.GetOnDutyCrossChainArbitrator()
			assert.Nil(t, got,
				"with no CRC arbiters the function must return a defined nil, not a value")
		})
	}
}

// Guard the premise the live branch depends on: mainnet really does set
// DPOSNodeCrossChainHeight to MaxUint32, which is why branch B is live at every
// height rather than a historical curiosity.
func TestMainnetKeepsCrossChainBranchLiveAtEveryHeight(t *testing.T) {
	params := config.GetDefaultParams()
	assert.Equal(t, uint32(math.MaxUint32),
		params.DPoSConfiguration.DPOSNodeCrossChainHeight,
		"if this is ever lowered, the live-branch reasoning in the guard comment and "+
			"in this test needs revisiting")
}
