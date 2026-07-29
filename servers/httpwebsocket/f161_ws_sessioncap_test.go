// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// F-161, session cap half. The cap cannot be expressed without the field it
// lives on, so this file does not compile against the unfixed server; the
// control arm below is what demonstrates the behaviour difference directly - a
// server with the cap disabled accepts an unbounded number of sessions, which
// is exactly what every pre-fix server did.
package httpwebsocket

import (
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startCappedWSServer brings up a websocket server with the given session cap
// (0 disables the cap) and returns it with its dial address. It shares
// startWSServerWithCap's stop-and-join cleanup, so restoring config.Parameters
// never races the server goroutine's read of it.
func startCappedWSServer(t *testing.T, limit int) (*Server, string) {
	t.Helper()
	return startWSServerWithCap(t, limit)
}

// fillSessions opens n websocket sessions and waits for the server to register
// them all.
func fillSessions(t *testing.T, s *Server, addr string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		conn, _, err := websocket.DefaultDialer.Dial("ws://"+addr, nil)
		if err != nil {
			t.Fatalf("connection %d refused: %v", i, err)
		}
		t.Cleanup(func() { conn.Close() })
	}
	// the handler registers a session only after the handshake completes.
	deadline := time.Now().Add(10 * time.Second)
	for s.sessions.Count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d sessions registered", s.sessions.Count(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestF161SessionCountIsCapped proves concurrent websocket sessions are bounded.
func TestF161SessionCountIsCapped(t *testing.T) {
	const limit = 2
	s, addr := startCappedWSServer(t, limit)
	fillSessions(t, s, addr, limit)

	conn, resp, err := websocket.DefaultDialer.Dial("ws://"+addr, nil)
	if err == nil {
		conn.Close()
		t.Fatalf("session %d was accepted with a cap of %d", limit+1, limit)
	}
	if resp == nil || resp.StatusCode != 503 {
		t.Fatalf("expected 503 over the session cap, got %v (%v)", resp, err)
	}
}

// TestF161UncappedServerAcceptsUnboundedSessions is the control arm: it is the
// pre-fix behaviour, reproduced on demand.
func TestF161UncappedServerAcceptsUnboundedSessions(t *testing.T) {
	const limit = 2
	s, addr := startCappedWSServer(t, 0)
	fillSessions(t, s, addr, limit)

	conn, _, err := websocket.DefaultDialer.Dial("ws://"+addr, nil)
	if err != nil {
		t.Fatalf("uncapped server refused a session: %v", err)
	}
	conn.Close()
}
