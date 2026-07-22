package netsync

import (
	"encoding/binary"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p/msg"
)

// TestF077LimitMapCapsPerPeerMap proves the mechanism of the F-077 TX-map fix: the
// exact function + constant the fix applies (sm.limitMap(state.requestedTxns,
// maxRequestedTxns)) bounds a per-peer-style map to maxRequestedTxns even under a
// flood of distinct hashes far exceeding the cap. Pre-fix the per-peer map had no
// such call and grew unbounded (the global map at the same site was already capped).
//
// NOTE: the end-to-end flood through handleInvMsg needs a full SyncManager + peer +
// chain harness and is deferred (see INFERRED-ITEMS F-077). This test verifies the
// capping mechanism against the real limitMap and the real maxRequestedTxns constant.
func TestF077LimitMapCapsPerPeerMap(t *testing.T) {
	if maxRequestedTxns != msg.MaxInvPerMsg {
		t.Fatalf("maxRequestedTxns drifted: got %d want %d", maxRequestedTxns, msg.MaxInvPerMsg)
	}

	sm := &SyncManager{}
	perPeer := make(map[common.Uint256]struct{})

	const flood = maxRequestedTxns * 4
	for i := 0; i < flood; i++ {
		var h common.Uint256
		binary.LittleEndian.PutUint64(h[:], uint64(i))
		perPeer[h] = struct{}{}
		sm.limitMap(perPeer, maxRequestedTxns)
	}

	if len(perPeer) > maxRequestedTxns {
		t.Fatalf("per-peer tx map not capped: got %d want <= %d", len(perPeer), maxRequestedTxns)
	}
}
