// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
)

// hashAt builds a deterministic distinct hash for a synthetic height.
func hashAt(h byte) *common.Uint256 {
	var u common.Uint256
	u[0] = h
	return &u
}

func armChain(t *testing.T, tipHeight int, target uint32, trigger string) *BlockChain {
	t.Helper()
	params := config.GetDefaultParams()
	params.ForcedRollbackHeight = target
	params.ForcedRollbackTrigger = trigger

	nodes := make([]*BlockNode, tipHeight+1)
	for i := range nodes {
		nodes[i] = &BlockNode{Hash: hashAt(byte(i))}
	}
	return &BlockChain{chainParams: params, Nodes: nodes}
}

// TestForcedRollbackArmsOnlyOnTheTargetedChain is the safety property: the
// rollback must fire ONLY when this node actually holds the targeted block.
func TestForcedRollbackArmsOnlyOnTheTargetedChain(t *testing.T) {
	// block at target+1 == trigger -> armed
	b := armChain(t, 20, 10, hashAt(11).ReversedString())
	armed, err := b.ForcedRollbackArmed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !armed {
		t.Fatal("must arm when the chain holds the targeted block")
	}

	// block at target+1 is a DIFFERENT hash -> must NOT arm. This is the case
	// that protects a node on a clean chain from being rewound.
	b = armChain(t, 20, 10, hashAt(99).ReversedString())
	if armed, _ := b.ForcedRollbackArmed(); armed {
		t.Fatal("must NOT arm when the block above target does not match the trigger")
	}
}

// TestForcedRollbackIsIdempotent: once the tip is at or below the target there is
// nothing to do, so a second restart is a no-op.
func TestForcedRollbackIsIdempotent(t *testing.T) {
	b := armChain(t, 10, 10, hashAt(11).ReversedString())
	if armed, _ := b.ForcedRollbackArmed(); armed {
		t.Fatal("must not arm when tip is already at the target")
	}
	b = armChain(t, 5, 10, hashAt(11).ReversedString())
	if armed, _ := b.ForcedRollbackArmed(); armed {
		t.Fatal("must not arm when tip is below the target (fresh node)")
	}
}

// TestForcedRollbackDisabledByDefault: networks without a configured trigger
// must never rewind.
func TestForcedRollbackDisabledByDefault(t *testing.T) {
	b := armChain(t, 20, 10, "")
	if armed, _ := b.ForcedRollbackArmed(); armed {
		t.Fatal("must not arm with an empty trigger")
	}
}

// TestForcedRollbackRejectsBadTrigger surfaces a misconfigured hash loudly
// instead of silently not arming.
func TestForcedRollbackRejectsBadTrigger(t *testing.T) {
	b := armChain(t, 20, 10, "not-a-hash")
	if _, err := b.ForcedRollbackArmed(); err == nil {
		t.Fatal("a malformed trigger hash must be reported, not silently ignored")
	}
}
