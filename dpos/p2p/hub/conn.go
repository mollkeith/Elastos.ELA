// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

/*
Conn is a wrapper of the origin network connection.  It resolves the handshake
information from the first version message including magic number, PID, network
address etc.
*/
package hub

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/p2p"
)

// handshakeTimeout bounds how long an accepted DPoS connection may take to
// deliver its version message.
//
// FV-14: there is NO read deadline anywhere in production dpos/p2p. WrapConn
// runs at the very top of server.inboundPeerConnected -- BEFORE the PID/
// allowlist check and BEFORE the MaxNodePerHost accounting -- and does raw
// io.ReadFull, bypassing p2p.ReadMessage and its ReadMessageTimeOut entirely.
// The hub pipe's own idleTimer (pipeTimeout) cannot help either, because no
// pipe exists yet. A peer that completes the TCP handshake and then sends
// nothing therefore pinned a goroutine and a file descriptor FOREVER, with no
// per-host limit yet in force, so a single IP could hold every descriptor the
// process is allowed and starve an arbiter of DPoS connections.
//
// NOT a memory-amplification fix: an untouched Go allocation of the 32 MiB
// readPayload ceiling costs tens of KB of RSS, so lowering that ceiling would
// buy nothing. The deadline is the fix.
//
// 30s matches p2p/peer's negotiateTimeout, the equivalent bound on the
// mainchain side.
//
// A var rather than a const ONLY so the fail-on-pristine test can shorten it;
// nothing in production ever assigns to it.
var handshakeTimeout = 30 * time.Second

// Conn is a wrapper of the origin network connection.
type Conn struct {
	net.Conn // The origin network connection.
	buf      *bytes.Buffer
	magic    uint32
	pid      [33]byte
	target   [16]byte
	addr     net.Addr
}

// Magic returns the magic number resolved from message header.
func (c *Conn) Magic() uint32 {
	return c.magic
}

// PID returns the PID resolved from the version message.  It represents who
// is connecting.
func (c *Conn) PID() [33]byte {
	return c.pid
}

// Target returns the Target PID resolved from the version message.  It used
// when a service behind the hub want to connect to another service,
// representing who the service is going to connect.
func (c *Conn) Target() [16]byte {
	return c.target
}

// NetAddr returns the network address resolve from the origin connection and
// the version message.
func (c *Conn) NetAddr() net.Addr {
	return c.addr
}

// Read warps the origin Read method without knowing we have intercepted the
// version message.
func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.buf.Read(b)
	if n > 0 {
		return n, err
	}
	return c.Conn.Read(b)
}

// readPayload reads the message payload described by hdr into a freshly
// allocated buffer, refusing to allocate for a length no conforming sender
// could ever have produced.
//
// F-136: hdr.Length is an attacker-controlled uint32 taken straight off the
// wire, and both the hub handshake (WrapConn) and the hub pipe read it BEFORE
// any allowlist / PID check has run.  A bare make([]byte, hdr.Length) therefore
// let a single unauthenticated inbound TCP connection force a ~4 GiB
// allocation.  p2p.MaxMessagePayload (32 MB) is the exact ceiling that
// p2p.WriteMessage already enforces on every outgoing message, so a payload
// above it can only come from a non-conforming peer -- bounding here rejects
// nothing that was previously routable and changes no acceptance decision.
func readPayload(r io.Reader, hdr *p2p.Header) ([]byte, error) {
	if hdr.Length > p2p.MaxMessagePayload {
		return nil, p2p.ErrMsgSizeExceeded
	}
	payload := make([]byte, hdr.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WrapConn warps the origin network connection and returns a hub connection
// with the handshake information resolved from version message.
func WrapConn(c net.Conn) (conn *Conn, err error) {
	// FV-14: bound the whole pre-identity handshake. The deadline is cleared
	// again on success so the connection's normal lifetime is governed by
	// whoever takes it over -- p2p.ReadMessage's own deadline on the peer path,
	// or the hub pipe's idleTimer on the pipe path -- exactly as before.
	if derr := c.SetDeadline(time.Now().Add(handshakeTimeout)); derr != nil {
		return nil, derr
	}
	defer func() {
		if err == nil {
			_ = c.SetDeadline(time.Time{})
		}
	}()

	// Read message header
	var headerBytes [p2p.HeaderSize]byte
	if _, err = io.ReadFull(c, headerBytes[:]); err != nil {
		return
	}

	// Deserialize message header
	var hdr p2p.Header
	if err = hdr.Deserialize(headerBytes[:]); err != nil {
		return
	}

	if hdr.GetCMD() != p2p.CmdVersion {
		err = fmt.Errorf("invalid message %s, expecting version",
			hdr.GetCMD())
		return
	}

	// Read payload
	payload, err := readPayload(c, &hdr)
	if err != nil {
		return
	}

	// Verify checksum
	if err = hdr.Verify(payload); err != nil {
		return
	}

	v := &msg.Version{}
	err = v.Deserialize(bytes.NewReader(payload))
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(headerBytes[:])
	buf.Write(payload)

	conn = &Conn{
		Conn:   c,
		buf:    buf,
		magic:  hdr.Magic,
		pid:    v.PID,
		target: v.Target,
		addr:   newNetAddr(c.RemoteAddr(), v.Port),
	}
	return
}

// newNetAddr creates a net.Addr with the origin net.Addr and port.
func newNetAddr(addr net.Addr, port uint16) net.Addr {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return &net.TCPAddr{IP: tcpAddr.IP, Port: int(port)}
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return &net.TCPAddr{IP: net.ParseIP(host), Port: int(port)}
}
