// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Fail-on-pristine tests for the websocket half of the RPC surface hardening:
// F-161 (no SetReadLimit anywhere in the tree) and F-162 (the websocket
// http.Server set no deadline of any kind). Everything in this file is written
// against identifiers that exist before the fix as well, so reverting the fix
// makes these tests fail rather than fail to build.
package httpwebsocket

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/servers"

	"github.com/gorilla/websocket"
)

// the package logger is nil in a bare test binary; the connection handler logs.
func init() { log.NewDefault(t_logPath, 0, 0, 0) }

const t_logPath = "/tmp/f161-ws-test-logs"

// f161ExpectedMessageLimit is the inbound message bound this test requires. It
// is spelled out rather than taken from the server so the test still compiles -
// and fails - against the unfixed server.
const f161ExpectedMessageLimit = 1024 * 1024 * 8

// f162SlowlorisBudget is how long the test waits for the server to hang up on a
// request whose headers never end.
const f162SlowlorisBudget = 30 * time.Second

// freeLocalPort returns a port nothing is listening on, avoiding the value that
// would send the server down its TLS branch.
func freeLocalPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 16; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if port%1000 != servers.TlsPort && port != 0 {
			return port
		}
	}
	t.Fatal("could not find a usable local port")
	return 0
}

// waitForWSServer blocks until the server accepts TCP on addr.
func waitForWSServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("websocket server never came up on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startWSServerWithCap brings up a websocket server on a free local port with
// the given session cap (0 disables the cap) and returns it with its dial
// address.
//
// The server goroutine reads config.Parameters inside Start(). The cleanup
// therefore shuts the server down and JOINS its goroutine before it restores
// the global, so the restore can never race the server's read of it - that
// unsynchronised overlap is exactly what -race used to flag here. Session
// connections opened by callers register their own t.Cleanup after this one,
// so LIFO cleanup order closes them first and Shutdown returns promptly.
func startWSServerWithCap(t *testing.T, limit int) (*Server, string) {
	t.Helper()
	port := freeLocalPort(t)

	orig := config.Parameters
	config.Parameters = &config.Configuration{HttpWsPort: port}

	s := &Server{
		Upgrader:    websocket.Upgrader{},
		sessions:    &sessions{},
		maxSessions: limit,
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		s.Start()
	}()

	addr := "127.0.0.1:" + strconv.Itoa(port)
	waitForWSServer(t, addr)

	t.Cleanup(func() {
		s.Stop()  // graceful shutdown -> Serve returns -> Start returns
		<-stopped // join: the goroutine has finished reading config.Parameters
		config.Parameters = orig
	})
	return s, addr
}

// startTestWSServer brings up a websocket server on a free local port with no
// session cap, and returns its dial address.
func startTestWSServer(t *testing.T) string {
	t.Helper()
	_, addr := startWSServerWithCap(t, 0)
	return addr
}

// TestF161OversizedMessageIsRejected proves one inbound message can no longer
// make the node allocate without bound.
//
// Fail-on-pristine: pre-fix SetReadLimit was called nowhere in the tree, so the
// server read the whole 9MB message into memory and answered it.
func TestF161OversizedMessageIsRejected(t *testing.T) {
	addr := startTestWSServer(t)

	conn, _, err := websocket.DefaultDialer.Dial("ws://"+addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	oversized := make([]byte, f161ExpectedMessageLimit+1024*1024)
	for i := range oversized {
		oversized[i] = 'a'
	}
	if err := conn.WriteMessage(websocket.TextMessage, oversized); err != nil {
		// the server tore the connection down mid-write: the limit fired.
		return
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("server read and answered an oversized websocket message")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server neither answered nor closed the connection: %v", err)
	}
}

// TestF162WSServerClosesSlowlorisConnection proves the websocket server hangs up
// on a request whose headers never arrive.
//
// Fail-on-pristine: pre-fix the http.Server had no ReadHeaderTimeout (nor any
// other deadline), so the connection and its goroutine were held indefinitely.
func TestF162WSServerClosesSlowlorisConnection(t *testing.T) {
	addr := startTestWSServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// An upgrade request whose header section is never terminated.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n" +
		"Upgrade: websocket\r\n")); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(f162SlowlorisBudget)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("server held a half-sent request open for %v with no header "+
			"timeout (Slowloris)", time.Since(start))
	}
}

// TestF161ExactlyAtLimitMessageIsAccepted closes the FV-25 boundary gap: the shipped
// F-161 test only ever proved that an OVER-limit message is refused, so a read limit
// written one byte too tight -- rejecting the largest message a client may legitimately
// send -- passed it. gorilla closes the connection with close code 1009 the moment a
// message EXCEEDS SetReadLimit, so "the connection is still usable" is the exact
// discriminator.
//
// Deliberately tolerant of whether the server ANSWERS the payload: the message is not
// valid JSON, and what is under test is the read limit, not the request router. A read
// TIMEOUT therefore passes (the limit did not fire); only a close/protocol error fails.
func TestF161ExactlyAtLimitMessageIsAccepted(t *testing.T) {
	addr := startTestWSServer(t)

	conn, _, err := websocket.DefaultDialer.Dial("ws://"+addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	atLimit := make([]byte, f161ExpectedMessageLimit)
	for i := range atLimit {
		atLimit[i] = 'a'
	}
	if err := conn.WriteMessage(websocket.TextMessage, atLimit); err != nil {
		t.Fatalf("F-161/FV-25: the server tore the connection down while receiving a "+
			"message of EXACTLY the %d byte limit; the bound is off by one: %v",
			f161ExpectedMessageLimit, err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err = conn.ReadMessage()
	if err == nil {
		return // the server answered: the message was accepted in full
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return // no answer, but no close either: the read limit did not fire
	}
	t.Fatalf("F-161/FV-25: a message of EXACTLY the %d byte limit must be accepted; the "+
		"server closed the connection instead: %v", f161ExpectedMessageLimit, err)
}
