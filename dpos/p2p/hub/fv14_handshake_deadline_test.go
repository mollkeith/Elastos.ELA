// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package hub

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/p2p"
)

// deadlineConn records every deadline WrapConn sets on the wrapped connection.
type deadlineConn struct {
	net.Conn

	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()

	return c.Conn.SetDeadline(t)
}

// writeVersion writes a well-formed DPoS version message, header and checksum
// included, so WrapConn takes its success path.
func writeVersion(c net.Conn) error {
	v := &msg.Version{Port: 20339}
	buf := new(bytes.Buffer)
	if err := v.Serialize(buf); err != nil {
		return err
	}
	payload := buf.Bytes()

	hdr, err := p2p.BuildHeader(123123, v.CMD(), payload).Serialize()
	if err != nil {
		return err
	}
	if _, err = c.Write(hdr); err != nil {
		return err
	}
	_, err = c.Write(payload)

	return err
}

// FAIL-ON-PRISTINE for FV-14.
//
// Intercept is the FIRST thing dpos/p2p/server.inboundPeerConnected does with
// an accepted connection -- before the PID/allowlist check and before the
// MaxNodePerHost accounting -- and it calls WrapConn, which does raw
// io.ReadFull. There is no SetReadDeadline anywhere in production dpos/p2p, the
// hub bypasses p2p.ReadMessage entirely, and the pipe's idleTimer cannot help
// because no pipe exists yet. On the pristine tree the goroutine below never
// returns: one IP can hold every descriptor the process is allowed and starve
// an arbiter of DPoS connections.
//
// This is NOT a memory test. The reviewer's 32 MiB-per-connection premise was
// measured and refuted (200 untouched 32 MiB allocations moved RSS by ~10 MB);
// the defect is goroutine/fd exhaustion, and the deadline is the fix.

// TestFV14InterceptDropsASilentConnection drives the production entry point.
func TestFV14InterceptDropsASilentConnection(t *testing.T) {
	restore := handshakeTimeout
	handshakeTimeout = 150 * time.Millisecond
	defer func() { handshakeTimeout = restore }()

	client, server := net.Pipe()
	defer client.Close()

	h := &Hub{}
	returned := make(chan net.Conn, 1)
	go func() { returned <- h.Intercept(server) }()

	select {
	case c := <-returned:
		if c != nil {
			t.Fatalf("FV-14: Intercept returned a usable connection for a "+
				"peer that never sent a version message: %v", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("FV-14: Intercept never returned for a peer that connected "+
			"and then sent nothing -- the goroutine and the file descriptor "+
			"are pinned, and this happens before MaxNodePerHost applies")
	}

	// The connection must also be closed, not merely abandoned.
	if _, err := server.Write([]byte{0}); err == nil {
		t.Fatalf("FV-14: the timed-out connection was left open")
	}
}

// TestFV14PartialHeaderDoesNotHoldTheConnection covers the slower variant: a
// peer that dribbles part of a header and then stops. io.ReadFull blocks on the
// remainder, so without a deadline this is the same pin, reached from a
// connection that looks alive.
func TestFV14PartialHeaderDoesNotHoldTheConnection(t *testing.T) {
	restore := handshakeTimeout
	handshakeTimeout = 150 * time.Millisecond
	defer func() { handshakeTimeout = restore }()

	client, server := net.Pipe()
	defer client.Close()

	h := &Hub{}
	returned := make(chan net.Conn, 1)
	go func() { returned <- h.Intercept(server) }()

	// Fewer bytes than a header, then silence.
	go func() {
		partial := make([]byte, p2p.HeaderSize-1)
		_, _ = client.Write(partial)
	}()

	select {
	case c := <-returned:
		if c != nil {
			t.Fatalf("FV-14: Intercept accepted a truncated handshake: %v", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("FV-14: a peer that sent %d of %d header bytes and then "+
			"stopped pinned Intercept forever", p2p.HeaderSize-1, p2p.HeaderSize)
	}
}

// TestFV14DeadlineIsClearedOnSuccess is the over-reach guard. The handshake
// deadline is an absolute time, so leaving it set would kill every established
// DPoS connection handshakeTimeout after it was accepted -- which would be a
// far worse bug than the one being fixed. deadlineConn records what WrapConn
// asks for; the final call must clear it.
func TestFV14DeadlineIsClearedOnSuccess(t *testing.T) {
	restore := handshakeTimeout
	handshakeTimeout = 30 * time.Second
	defer func() { handshakeTimeout = restore }()

	client, server := net.Pipe()
	defer client.Close()
	recorder := &deadlineConn{Conn: server}

	done := make(chan error, 1)
	go func() {
		_, err := WrapConn(recorder)
		done <- err
	}()

	go func() { _ = writeVersion(client) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WrapConn rejected a well-formed version message: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("WrapConn did not complete a well-formed handshake")
	}

	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.deadlines) < 2 {
		t.Fatalf("FV-14: WrapConn set %d deadlines; want a handshake deadline "+
			"and a clearing one", len(recorder.deadlines))
	}
	if !recorder.deadlines[len(recorder.deadlines)-1].IsZero() {
		t.Fatalf("FV-14 OVER-REACH: the handshake deadline was left set on a "+
			"successful handshake, so every established DPoS connection would "+
			"die %v after it was accepted", handshakeTimeout)
	}
}
