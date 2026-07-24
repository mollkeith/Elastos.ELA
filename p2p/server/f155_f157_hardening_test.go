// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package server

import (
	"net"
	"testing"

	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/p2p"
)

// TestKnownAddressesAreBounded proves the per peer known address set cannot
// grow without bound (F-155).  Only the address count of a single addr message
// is bounded by the protocol, not the number of addr messages a peer may send,
// so on the pristine tree one peer grows this map for ever.
func TestKnownAddressesAreBounded(t *testing.T) {
	sp := newServerPeer(nil, false)

	ip := net.ParseIP("10.11.12.13")
	first := p2p.NewNetAddressIPPort(ip, 1, 0)
	sp.addKnownAddresses([]*p2p.NetAddress{first})
	if !sp.addressKnown(first) {
		t.Fatal("the address just added is not known")
	}

	// Flood well past any sane limit.
	for port := 1000; port < 21000; port++ {
		sp.addKnownAddresses([]*p2p.NetAddress{
			p2p.NewNetAddressIPPort(ip, uint16(port), 0),
		})
	}

	if sp.addressKnown(first) {
		t.Fatal("the oldest known address survived 20000 further addresses: " +
			"the known address set never evicts, so an addr flood from a " +
			"single peer grows it without bound (F-155)")
	}
}

// TestCheckAddrDoesNotMutateProtocolVersion proves the address probe does not
// write to the shared server configuration (F-157).  checkAddr runs on the
// address manager's expirePeers goroutine while newPeerConfig reads
// cfg.ProtocolVersion for every new peer, so the assignment was both a data
// race and a global side effect.
func TestCheckAddrDoesNotMutateProtocolVersion(t *testing.T) {
	const localVersion = uint32(10)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	s := &server{cfg: Config{
		MagicNumber:      123123,
		ProtocolVersion:  localVersion,
		DefaultPort:      20338,
		NodeVersion:      "v0.9.9.7",
		NewVersionHeight: 100,
		BestHeight:       func() uint64 { return 200 },
	}}

	// The probe is expected to fail, the listener closes straight away.  What
	// matters is what it leaves behind.
	_ = s.checkAddr(ln.Addr().String())

	if s.cfg.ProtocolVersion != localVersion {
		t.Fatalf("checkAddr changed the shared server protocol version to %d, "+
			"want it left at %d (pact.CRProposalVersion is %d) (F-157)",
			s.cfg.ProtocolVersion, localVersion, pact.CRProposalVersion)
	}
}
