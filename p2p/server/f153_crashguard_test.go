// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 — F-153 crash-hardening, previously UNTESTED (commit 509d9ce).
package server

import (
	"errors"
	"net"
	"testing"

	"github.com/elastos/Elastos.ELA/p2p/addrmgr"
	"github.com/elastos/Elastos.ELA/p2p/connmgr"
)

// badAddr is a net.Addr whose String() is not a valid host:port, so
// peer.NewOutboundPeer fails early and returns a NIL peer.
type badAddr struct{}

func (badAddr) Network() string { return "tcp" }
func (badAddr) String() string  { return "this-is-not-a-host-port" }

// TestF153OutboundPeerConnectedBailsOutOnFailedPeer drives the REAL
// (*server).outboundPeerConnected down its error branch. peer.NewOutboundPeer returns
// (nil, err); without the F-153 `return` the function fell through to
// sp.AssociateConnection(conn) on a serverPeer whose embedded *peer.Peer is nil, which
// panics — a remote peer that offers a malformed address halts the node.
//
// Fail-on-pristine: delete the `return` after s.connManager.Disconnect and this test
// PANICS (nil pointer dereference).
func TestF153OutboundPeerConnectedBailsOutOnFailedPeer(t *testing.T) {
	cm, err := connmgr.New(&connmgr.Config{
		Dial: func(net.Addr) (net.Conn, error) { return nil, errors.New("no dial") },
	})
	if err != nil {
		t.Fatalf("connmgr.New: %v", err)
	}
	// Stopped, so Disconnect returns immediately instead of blocking on the request
	// channel of a manager that is not running.
	cm.Stop()

	s := &server{
		cfg:         Config{MagicNumber: 123123, DefaultPort: 20338},
		addrManager: addrmgr.New("", nil),
		connManager: cm,
	}

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	// Must return normally. Pristine panics inside AssociateConnection.
	s.outboundPeerConnected(&connmgr.ConnReq{Addr: badAddr{}}, local)
}
