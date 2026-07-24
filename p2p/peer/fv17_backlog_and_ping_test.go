// Copyright (c) 2017-2020 The Elastos Foundation
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

// FAIL-ON-PRISTINE for FV-17.
//
// outputQueue is bounded, but queueHandler drains it into pendingMsgs, a
// list.List with NO cap, and pendingMsgs is only drained when outHandler
// completes a socket write. On the pristine tree a peer that completes a
// handshake and then stops reading accumulates every message we want to send
// it, in RAM, for the whole write deadline -- which was p2p.WriteMessageTimeOut,
// ten minutes. ping is the amplifier: handled in this generic layer, so it never
// reaches elanet's ban scorer (a census of AddBanScore in elanet/server.go
// covers mempool, inv, notfound, getdata, getblocks and filterload, and nothing
// for ping), a guaranteed 1:1 response, and tiny in both directions.
//
// The reviewer led with the 30s QueueMessage block; that half is a startup race
// F-150 already bounded. These tests are aimed at the unbounded list.

// stalledPeer returns a connected peer whose queueHandler is running and whose
// outHandler is NOT, which is exactly the state a peer that has stopped reading
// puts us in: sendQueue (capacity 1) absorbs the first message and every
// subsequent one lands in pendingMsgs.
//
// AssociateConnection is used for the connection and the connected flag; its
// negotiation goroutine blocks reading the pipe, so start() never runs and
// never launches a second queueHandler.
func stalledPeer(t *testing.T) (*Peer, func()) {
	t.Helper()

	local, remote := net.Pipe()

	p := NewInboundPeer(newTestPeerConfig())
	p.SetAddr("127.0.0.1:20338")
	p.AssociateConnection(local)

	for i := 0; i < 500 && !p.Connected(); i++ {
		time.Sleep(time.Millisecond)
	}
	if !p.Connected() {
		remote.Close()
		t.Fatal("peer did not become connected")
	}

	go p.queueHandler()

	return p, func() { remote.Close() }
}

// TestFV17PendingBacklogIsBounded is the primary discriminator. Every message
// goes in through the production QueueMessage and is handled by the production
// queueHandler. On the pristine tree the peer stays connected no matter how
// many messages pile up; with the cap it is disconnected once the backlog is
// unmistakably a peer that is not reading.
func TestFV17PendingBacklogIsBounded(t *testing.T) {
	p, cleanup := stalledPeer(t)
	defer cleanup()

	go func() {
		for i := 0; i < maxPendingMsgs*4; i++ {
			p.QueueMessage(msg.NewPing(uint64(i)), nil)
		}
	}()

	deadline := time.After(15 * time.Second)
	for {
		if !p.Connected() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("FV-17: %d messages were queued for a peer that is not "+
				"reading and the peer is still connected -- pendingMsgs has no "+
				"ceiling, so the node's retained bytes grow at the attacker's "+
				"line rate for the whole write deadline",
				maxPendingMsgs*4)
		default:
			time.Sleep(2 * time.Millisecond)
		}
	}
}

// TestFV17ModestBacklogIsNotPunished is the over-reach guard: a burst well
// inside the cap must not cost a peer its connection. Bursts do happen -- a
// getdata batch, an inv fan-out during a reorg -- and disconnecting on them
// would turn a memory fix into a churn bug.
func TestFV17ModestBacklogIsNotPunished(t *testing.T) {
	p, cleanup := stalledPeer(t)
	defer cleanup()

	for i := 0; i < maxPendingMsgs/2; i++ {
		p.QueueMessage(msg.NewPing(uint64(i)), nil)
	}

	time.Sleep(250 * time.Millisecond)
	if !p.Connected() {
		t.Fatalf("FV-17 OVER-REACH: a backlog of %d messages -- half the cap "+
			"-- disconnected the peer", maxPendingMsgs/2)
	}
}

// TestFV17DroppedMessageReleasesItsWaiter proves the shed message does not
// strand its caller. OnGetData waits on a done channel every five messages
// precisely so it does not queue more than it can send; if the cap dropped such
// a message silently, that handler would block forever and the fix would be
// worse than the defect.
func TestFV17DroppedMessageReleasesItsWaiter(t *testing.T) {
	p, cleanup := stalledPeer(t)
	defer cleanup()

	// Fill the backlog past the cap, then send one more with a done channel.
	for i := 0; i < maxPendingMsgs+8; i++ {
		p.QueueMessage(msg.NewPing(uint64(i)), nil)
	}

	done := make(chan struct{}, 1)
	p.QueueMessage(msg.NewPing(0), done)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("FV-17: a message dropped by the backlog cap never signalled " +
			"its done channel; the sender is stranded")
	}
}

// TestFV17PingResponseIsMetered proves the amplifier is metered on the
// production path. handlePingMsg is what inHandler dispatches CmdPing to, and
// on the pristine tree every single ping queues a pong unconditionally.
//
// queueHandler is deliberately NOT started here, so the pongs stay in
// outputQueue where they can be counted.
func TestFV17PingResponseIsMetered(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()

	p := NewInboundPeer(newTestPeerConfig())
	p.SetAddr("127.0.0.1:20338")
	p.AssociateConnection(local)
	for i := 0; i < 500 && !p.Connected(); i++ {
		time.Sleep(time.Millisecond)
	}
	if !p.Connected() {
		t.Fatal("peer did not become connected")
	}

	const flood = 20
	for i := 0; i < flood; i++ {
		p.handlePingMsg(msg.NewPing(uint64(i)))
	}

	var pongs int
drain:
	for {
		select {
		case m := <-p.outputQueue:
			if m.msg.CMD() == p2p.CmdPong {
				pongs++
			}
		default:
			break drain
		}
	}

	if pongs > pingResponseBurst {
		t.Fatalf("FV-17: %d pings queued %d pongs back to back; ping accrues "+
			"no ban score anywhere in the stack, so this is a free 1:1 "+
			"amplifier. Want at most %d.", flood, pongs, pingResponseBurst)
	}
	if pongs == 0 {
		t.Fatalf("FV-17 OVER-REACH: not a single ping was answered")
	}
}

// TestFV17HonestPingCadenceIsNeverThrottled is the second over-reach guard.
// The protocol pings every pingInterval; the meter must be invisible at that
// rate, forever, or the fix silently breaks liveness measurement between honest
// peers. The clock is supplied here because handlePingMsg reads the real one.
func TestFV17HonestPingCadenceIsNeverThrottled(t *testing.T) {
	p := NewInboundPeer(newTestPeerConfig())

	now := time.Now()
	for i := 0; i < 500; i++ {
		p.statsMtx.Lock()
		allowed := p.allowPingResponseLocked(now)
		p.statsMtx.Unlock()
		if !allowed {
			t.Fatalf("FV-17 OVER-REACH: ping %d at the protocol's own %v "+
				"cadence was throttled", i, pingInterval)
		}
		now = now.Add(pingInterval)
	}
}

// TestFV17PeerWriteTimeoutIsBounded pins the retention window itself. The cap
// bounds how much is held; this bounds for how long, and the ten minute value
// it replaces is the whole reason a stalled peer was worth attacking.
func TestFV17PeerWriteTimeoutIsBounded(t *testing.T) {
	if peerWriteTimeout >= p2p.WriteMessageTimeOut {
		t.Fatalf("FV-17: the peer write path still uses a %v deadline; a peer "+
			"that stops reading holds the connection and everything queued "+
			"behind it for that long", peerWriteTimeout)
	}
	if peerWriteTimeout > 2*time.Minute {
		t.Fatalf("FV-17: peer write deadline %v is too generous to bound the "+
			"retention window", peerWriteTimeout)
	}
	if peerWriteTimeout < 30*time.Second {
		t.Fatalf("FV-17 OVER-REACH: a %v write deadline would drop honest "+
			"peers mid block", peerWriteTimeout)
	}
}
