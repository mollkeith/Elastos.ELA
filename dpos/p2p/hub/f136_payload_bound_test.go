// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package hub

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/p2p"
)

// writeAll pushes b into the (unbuffered) pipe from a goroutine and then closes
// the writing end, so the reader side always sees a clean EOF after b.
func writeAll(c net.Conn, b []byte) {
	go func() {
		_, _ = c.Write(b)
		_ = c.Close()
	}()
}

// headerFor builds a wire header claiming the given command and payload length.
// The checksum is deliberately irrelevant here: the point of F-136 is that the
// length is trusted (and acted upon) long before anything is verified.
func headerFor(cmd string, length uint32) []byte {
	hdr := p2p.Header{Magic: 123123, Length: length}
	copy(hdr.CMD[:len(cmd)], cmd)
	raw, err := hdr.Serialize()
	if err != nil {
		panic(err)
	}
	return raw
}

// TestF136_WrapConnBoundsPayloadBeforeAllocating proves the hub handshake no
// longer sizes a heap buffer from an unauthenticated wire integer.
//
// FAIL-ON-PRISTINE: on the unpatched tree WrapConn runs
// `payload := make([]byte, hdr.Length)` before any allowlist / PID check, so a
// single inbound TCP connection that claims 64 MB gets 64 MB of heap (and a
// uint32 claim gets ~4 GiB).  Unpatched, this test fails twice over: the
// returned error is io.ErrUnexpectedEOF / io.EOF instead of
// p2p.ErrMsgSizeExceeded, and TotalAlloc grows by the claimed size.
func TestF136_WrapConnBoundsPayloadBeforeAllocating(t *testing.T) {
	// Comfortably above p2p.MaxMessagePayload (32 MB), small enough that the
	// unpatched allocation is survivable on a test box.
	const claimed = 64 * 1024 * 1024

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	writeAll(client, headerFor(p2p.CmdVersion, claimed))

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	conn, err := WrapConn(server)
	runtime.ReadMemStats(&after)

	if conn != nil {
		t.Fatalf("F-136: WrapConn returned a connection for an over-sized payload")
	}
	if !errors.Is(err, p2p.ErrMsgSizeExceeded) {
		t.Fatalf("F-136: WrapConn accepted a %d byte payload claim and failed only "+
			"later with %v; the length must be bounded BEFORE allocating",
			claimed, err)
	}

	grew := after.TotalAlloc - before.TotalAlloc
	if grew > 8*1024*1024 {
		t.Fatalf("F-136: WrapConn allocated %d bytes for a %d byte claim from an "+
			"unauthenticated peer", grew, claimed)
	}
}

// TestF136_WrapConnStillAcceptsLegitimateVersion is the non-regression half:
// the bound must not reject anything a conforming peer can actually send.
func TestF136_WrapConnStillAcceptsLegitimateVersion(t *testing.T) {
	var pid, target [33]byte
	pid[0] = 0x02
	target[0] = 0x03

	v := msg.Version{PID: pid, Target: PIDTo16(target), Port: 20338,
		Timestamp: time.Unix(0, 0)}
	buf := new(bytes.Buffer)
	if err := v.Serialize(buf); err != nil {
		t.Fatal(err)
	}
	payload := buf.Bytes()

	hdr, err := p2p.BuildHeader(123123, v.CMD(), payload).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	writeAll(client, append(hdr, payload...))

	conn, err := WrapConn(server)
	if err != nil {
		t.Fatalf("F-136 bound rejected a legitimate version message: %v", err)
	}
	if conn.PID() != pid {
		t.Fatalf("unexpected PID %x", conn.PID())
	}
	if conn.Magic() != 123123 {
		t.Fatalf("unexpected magic %d", conn.Magic())
	}
}

// TestF136_PipeBoundsRelayedPayload covers the SECOND allocation site: the hub
// pipe, which reads a header/length pair for every message it relays between an
// inbound connection and the local service.
//
// FAIL-ON-PRISTINE: unpatched, pipe.flow runs `make([]byte, hdr.Length)` for
// every relayed message, so one length claim forces the allocation before a
// single payload byte has been read (let alone checksummed).  TotalAlloc grows
// by the claimed size on the unpatched tree and stays flat on the patched one.
func TestF136_PipeBoundsRelayedPayload(t *testing.T) {
	const claimed = 64 * 1024 * 1024

	client, server := net.Pipe()
	writeAll(client, headerFor(p2p.CmdPing, claimed))

	sink, drain := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, drain) }()
	defer func() { _ = drain.Close() }()

	p := &pipe{inlet: server, outlet: sink}
	connChan := make(chan bool, 4)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	// nil AddrManager is fine: it is only consulted for CmdDAddr.
	p.flow(nil, server, sink, connChan)
	runtime.ReadMemStats(&after)

	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8*1024*1024 {
		t.Fatalf("F-136: the hub pipe allocated %d bytes for a %d byte length "+
			"claim from an unauthenticated peer", grew, claimed)
	}
}

// TestF136_BoundIsExactlyMaxMessagePayload closes the FV-25 boundary gap: the shipped
// tests only ever proved that an OVER-limit claim is refused, so a bound written as
// `>=` instead of `>` -- which would reject the largest message a conforming peer may
// legitimately send -- passed them all.
//
// The probe writes only the header and then closes, so nothing 32 MB is allocated:
// at the limit readPayload must get PAST the bound and fail later on the truncated
// body (io.ErrUnexpectedEOF), while one byte above it must fail ON the bound.
func TestF136_BoundIsExactlyMaxMessagePayload(t *testing.T) {
	atLimit := func(length uint32) error {
		client, server := net.Pipe()
		defer func() { _ = server.Close() }()
		writeAll(client, headerFor(p2p.CmdVersion, length))
		_, err := WrapConn(server)
		return err
	}

	if err := atLimit(p2p.MaxMessagePayload); errors.Is(err, p2p.ErrMsgSizeExceeded) {
		t.Fatalf("F-136/FV-25: a payload of EXACTLY p2p.MaxMessagePayload (%d) was "+
			"rejected by the bound. That is the largest message p2p.WriteMessage will "+
			"emit, so the bound is off by one and conforming peers are refused.",
			p2p.MaxMessagePayload)
	}
	if err := atLimit(p2p.MaxMessagePayload + 1); !errors.Is(err, p2p.ErrMsgSizeExceeded) {
		t.Fatalf("F-136: a payload one byte ABOVE p2p.MaxMessagePayload must be refused "+
			"by the bound, got %v", err)
	}
}
