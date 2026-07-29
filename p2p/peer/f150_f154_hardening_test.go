// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package peer

import (
	"net"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/p2p"
	"github.com/elastos/Elastos.ELA/p2p/msg"
)

// newTestPeerConfig returns a peer config that is good enough to associate a
// connection with, no message is ever exchanged by these tests.
func newTestPeerConfig() *Config {
	return &Config{
		Magic:           123123,
		ProtocolVersion: 1,
		DefaultPort:     20338,
		Services:        0,
		BestHeight:      func() uint64 { return 0 },
		MessageFunc:     func(*Peer, p2p.Message) {},
	}
}

// TestQueueMessageDoesNotWedgeCaller proves that a full output queue cannot
// block the caller forever (F-150 / F-116).
//
// AssociateConnection marks the peer connected and the server registers it
// with peerState while the protocol negotiation is still running, but
// queueHandler - the only drainer of outputQueue - is not started until the
// negotiation completes.  A peer that never speaks therefore lets the queue
// fill up, and on the pristine tree the unguarded 'p.outputQueue <- ...' send
// never returns, not even after the peer is disconnected, because queueHandler
// never runs to drain it.  The caller is usually the single peerHandler
// goroutine (handleBroadcastMsg), so that wedge stops all peer management.
func TestQueueMessageDoesNotWedgeCaller(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()

	p := NewInboundPeer(newTestPeerConfig())
	p.SetAddr("127.0.0.1:20338")

	// Associate the connection.  The negotiation goroutine blocks reading the
	// remote version message, so queueHandler is never started.
	p.AssociateConnection(local)
	for i := 0; i < 200 && !p.Connected(); i++ {
		time.Sleep(time.Millisecond)
	}
	if !p.Connected() {
		t.Fatal("peer did not become connected")
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < outputBufferSize+5; i++ {
			p.QueueMessage(msg.NewPing(0), nil)
		}
		close(done)
	}()

	// The sender is expected to be stuck at this point, nothing drains the
	// output queue before the negotiation completes.
	select {
	case <-done:
		t.Log("sender was not blocked, the queue absorbed every message")
	case <-time.After(250 * time.Millisecond):
	}

	// Disconnecting the peer must release the sender.
	p.Disconnect()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("QueueMessage is still blocked 5s after Disconnect: a full " +
			"output queue with no drainer wedges the caller forever (F-150)")
	}
}

// TestLocalVersionMsgUsesConfiguredNonce proves the version nonce comes from
// the configured provider (F-154).  On the pristine tree localVersionMsg
// generated a private random nonce, so the caller's sent nonce cache stayed
// empty for ever and IsSelfConnection could never return true.
func TestLocalVersionMsgUsesConfiguredNonce(t *testing.T) {
	const wantNonce = uint64(0x0123456789abcdef)

	var calls int
	cfg := newTestPeerConfig()
	cfg.GetVersionNonce = func() uint64 {
		calls++
		return wantNonce
	}

	p := NewInboundPeer(cfg)
	m, err := p.localVersionMsg()
	if err != nil {
		t.Fatalf("localVersionMsg failed: %v", err)
	}

	if calls != 1 {
		t.Fatalf("GetVersionNonce called %d times, want 1: the sent nonce "+
			"cache is never populated so self connection detection is inert "+
			"(F-154)", calls)
	}
	if m.Nonce != wantNonce {
		t.Fatalf("version nonce is %#x, want the configured %#x (F-154)",
			m.Nonce, wantNonce)
	}
}
