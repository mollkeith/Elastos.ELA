// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package elanet

import (
	"testing"

	elapeer "github.com/elastos/Elastos.ELA/elanet/peer"
	"github.com/elastos/Elastos.ELA/p2p/msg"
)

// TestF054OnInvIsMetered drives the REAL OnInv handler and proves an inventory
// announcement is charged a decaying ban score, exactly as OnGetData already
// is. Each announced hash costs us a haveInventory lookup, and for an
// InvTypeConfirmedBlock that used to mean a full flat-file block read behind a
// two-entry cache -- 33 bytes of inv buying an unbounded disk read, with no ban
// score anywhere on the inv path.
//
// The handler is driven with a nil SyncManager behind it, so it panics once it
// gets past the metering (server.SyncManager.QueueInv). That is exactly what
// this test needs to observe: the score has to be charged BEFORE the work is
// dispatched. banScoreRecorder is shared with f214_banscore_test.go.
//
// FAIL-ON-PRISTINE: revert the OnInv hunk (drop the AddBanScore line) and the
// handler panics on the nil SyncManager before charging anything, so the
// recorder stays at zero and the assertion fails.
func TestF054OnInvIsMetered(t *testing.T) {
	recorder := &banScoreRecorder{}
	sp := &ServerPeer{
		Peer:   &elapeer.Peer{IPeer: recorder},
		server: &NetServer{},
	}

	// 2000 hashes: 2000*99/MaxInvPerMsg = 3 (> 0). An honest getblocks answer
	// (<= 500) or a relay inv (far smaller) truncates to 0.
	inv := &msg.Inv{}
	for i := 0; i < 2000; i++ {
		inv.InvList = append(inv.InvList, &msg.InvVect{})
	}

	func() {
		defer func() { recover() }()
		sp.OnInv(nil, inv)
	}()

	if recorder.transient == 0 {
		t.Fatalf("FAIL(F-054): a %d-entry inv announcement was charged no ban "+
			"score; the inv path is unmetered even though each hash can trigger a "+
			"block-store lookup", len(inv.InvList))
	}
	if recorder.persistent != 0 {
		t.Fatalf("unexpected persistent ban score %d charged by %v",
			recorder.persistent, recorder.reasons)
	}
}

// TestOnInvHonestAnnouncementNotMetered guards the metering against
// over-reach: an announcement of the size an honest peer actually sends (a
// getblocks answer is capped at pact.MaxBlocksPerMsg = 500) must be charged
// nothing. This holds on both trees, so it is a guard, not a discrimination
// proof.
func TestOnInvHonestAnnouncementNotMetered(t *testing.T) {
	recorder := &banScoreRecorder{}
	sp := &ServerPeer{
		Peer:   &elapeer.Peer{IPeer: recorder},
		server: &NetServer{},
	}

	inv := &msg.Inv{}
	for i := 0; i < 500; i++ {
		inv.InvList = append(inv.InvList, &msg.InvVect{})
	}

	func() {
		defer func() { recover() }()
		sp.OnInv(nil, inv)
	}()

	if recorder.transient != 0 {
		t.Fatalf("an honest %d-entry announcement was charged a ban score of %d",
			len(inv.InvList), recorder.transient)
	}
}
