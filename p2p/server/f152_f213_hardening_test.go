// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/p2p"
	"github.com/elastos/Elastos.ELA/p2p/peer"
)

// closedPortAddr returns a loopback address that is guaranteed to have nothing
// listening on it.
func closedPortAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestFromDNSReleasesSeedingOnDialFailure proves a DNS seed that cannot be
// dialled is not disabled for the lifetime of the process (F-152).
//
// On the pristine tree discover returns on a dial error without ever writing
// to addrChan, so the fromDNS goroutine blocks on the receive for ever and the
// LoadOrStore entry that marks the host as being seeded is never deleted -
// every later fromDNS call skips that host.
func TestFromDNSReleasesSeedingOnDialFailure(t *testing.T) {
	host := closedPortAddr(t)
	s := &seed{cfg: &Config{DNSSeeds: []string{host}}}

	s.fromDNS()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, seeding := s.seeding.Load(host); !seeding {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("DNS seed is still marked as being seeded after the dial failed: " +
		"the seeding entry is never released so this seed is disabled for " +
		"the lifetime of the process (F-152)")
}

// newConnectedInboundPeer returns an inbound serverPeer that is associated
// with a live (piped) connection so Connected() reports true.
func newConnectedInboundPeer(t *testing.T, s *server, port int) (*serverPeer, func()) {
	t.Helper()

	sp := newServerPeer(s, false)
	sp.Peer = peer.NewInboundPeer(&peer.Config{
		Magic:           123123,
		ProtocolVersion: 1,
		DefaultPort:     20338,
		BestHeight:      func() uint64 { return 0 },
		MessageFunc:     func(*peer.Peer, p2p.Message) {},
	})
	sp.Peer.SetAddr(fmt.Sprintf("127.0.0.1:%d", port))

	local, remote := net.Pipe()
	sp.Peer.AssociateConnection(local)
	for i := 0; i < 200 && !sp.Connected(); i++ {
		time.Sleep(time.Millisecond)
	}
	if !sp.Connected() {
		t.Fatal("test peer did not become connected")
	}

	return sp, func() {
		sp.Disconnect()
		remote.Close()
	}
}

// TestInboundPeersCannotOccupyEverySlot proves inbound connections cannot fill
// every peer slot and lock the connection manager out of making outbound
// connections (F-213).
//
// On the pristine tree the only limit is the total MaxPeers count and the
// newcomer - never an existing peer - is the one that gets disconnected, so an
// attacker that holds all MaxPeers inbound slots eclipses the node.
func TestInboundPeersCannotOccupyEverySlot(t *testing.T) {
	s := &server{cfg: Config{MaxPeers: 10, TargetOutbound: 2}}
	state := &peerState{
		inboundPeers:    make(map[uint64]*serverPeer),
		outboundPeers:   make(map[uint64]*serverPeer),
		persistentPeers: make(map[uint64]*serverPeer),
		banned:          make(map[string]time.Time),
		outboundGroups:  make(map[string]int),
	}

	// MaxPeers 10 with 2 outbound slots reserved leaves 8 inbound slots.
	const wantInbound = 8
	for i := 0; i < wantInbound; i++ {
		sp, cleanup := newConnectedInboundPeer(t, s, 30000+i)
		defer cleanup()
		// Use explicit keys, every unnegotiated peer reports ID 0.
		state.inboundPeers[uint64(100+i)] = sp
	}

	newcomer, cleanup := newConnectedInboundPeer(t, s, 40000)
	defer cleanup()

	s.handleAddPeerMsg(state, newcomer)

	if len(state.inboundPeers) != wantInbound {
		t.Fatalf("inbound peer count is %d, want %d: there is no inbound sub "+
			"cap so inbound connections can occupy every one of the %d peer "+
			"slots and lock out all outbound connections (F-213)",
			len(state.inboundPeers), wantInbound, s.cfg.MaxPeers)
	}
}
