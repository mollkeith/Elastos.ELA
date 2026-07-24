// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package routes

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	dp "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	ep "github.com/elastos/Elastos.ELA/elanet/peer"
	"github.com/elastos/Elastos.ELA/p2p/msg"
	p2ppeer "github.com/elastos/Elastos.ELA/p2p/peer"
)

// newRoutesState builds the same state addrHandler builds, without touching the
// network.
func newRoutesState() *state {
	return &state{
		dposPeers: make(map[dp.PID]struct{}),
		crPeers:   make(map[dp.PID]struct{}),
		requested: make(map[common.Uint256]struct{}),
		peerCache: make(map[*ep.Peer]*cache),
	}
}

// newOfflinePeer builds an elanet peer that is fully usable for the inv/teardown
// bookkeeping (known-inventory cache, QueueMessage) but never connects.
func newOfflinePeer() *ep.Peer {
	return mockPeer(p2ppeer.NewInboundPeer(&p2ppeer.Config{}))
}

// invFor builds an address inventory message for the given hashes.
func invFor(hashes ...common.Uint256) *msg.Inv {
	inv := msg.NewInv()
	for i := range hashes {
		h := hashes[i]
		inv.AddInvVect(msg.NewInvVect(msg.InvTypeAddress, &h))
	}
	return inv
}

// TestF148_DonePeerReleasesGlobalRequested drives the exact production sequence:
// a peer announces an address inventory (handleInv records the hash in the
// per-peer AND the global requested map), then disconnects without ever
// delivering the DAddr.
//
// FAIL-ON-PRISTINE: unpatched, handleDonePeer drains only c.requested -- a map
// that is already unreachable garbage the moment s.peerCache[p] is deleted --
// and leaves the hash in s.requested forever.  Assertion 1 below fails on the
// unpatched tree.
func TestF148_DonePeerReleasesGlobalRequested(t *testing.T) {
	r := &Routes{}
	s := newRoutesState()

	var hash common.Uint256
	hash[0] = 0xA1

	p1 := newOfflinePeer()
	r.handleNewPeer(s, p1)
	r.handleInv(s, p1, invFor(hash))

	if _, ok := s.requested[hash]; !ok {
		t.Fatalf("precondition: handleInv did not record %s in the global "+
			"requested map", hash)
	}

	// The peer goes away with the request still outstanding.
	r.handleDonePeer(s, p1)

	// Assertion 1 -- the leak itself.
	if _, ok := s.requested[hash]; ok {
		t.Fatalf("F-148: %s is still marked in-flight in the GLOBAL requested map "+
			"after the only peer that requested it disconnected", hash)
	}

	// Assertion 2 -- the consequence.  handleInv skips any hash already present
	// in s.requested, so a leaked entry permanently suppresses re-requesting that
	// DPoS address from every future peer.
	p2 := newOfflinePeer()
	r.handleNewPeer(s, p2)
	r.handleInv(s, p2, invFor(hash))

	if _, ok := s.peerCache[p2].requested[hash]; !ok {
		t.Fatalf("F-148: the DPoS address %s can never be re-requested -- a stale "+
			"global entry from a departed peer suppresses it permanently", hash)
	}
	if _, ok := s.requested[hash]; !ok {
		t.Fatalf("F-148: re-request was not recorded globally for the new peer")
	}
}

// TestF148_DonePeerLeavesOtherPeersRequestsAlone is the non-regression half: the
// teardown must release only the hashes the departing peer actually held.  A
// hash is inserted only when the global map has no entry for it, so at most one
// peer holds a given hash in flight -- the fix must not disturb the others.
func TestF148_DonePeerLeavesOtherPeersRequestsAlone(t *testing.T) {
	r := &Routes{}
	s := newRoutesState()

	var mine, theirs common.Uint256
	mine[0] = 0xB1
	theirs[0] = 0xB2

	p1 := newOfflinePeer()
	p2 := newOfflinePeer()
	r.handleNewPeer(s, p1)
	r.handleNewPeer(s, p2)

	r.handleInv(s, p1, invFor(mine))
	r.handleInv(s, p2, invFor(theirs))

	r.handleDonePeer(s, p1)

	if _, ok := s.requested[mine]; ok {
		t.Fatalf("F-148: departing peer's hash %s was not released", mine)
	}
	if _, ok := s.requested[theirs]; !ok {
		t.Fatalf("F-148: teardown wrongly released %s, which is still in flight "+
			"on another peer", theirs)
	}
	if _, ok := s.peerCache[p2]; !ok {
		t.Fatalf("F-148: teardown wrongly evicted the surviving peer")
	}
}
