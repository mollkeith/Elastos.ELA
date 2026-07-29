// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Fail-on-pristine tests for the REST half of the RPC surface hardening:
// F-149 (the POST handler read the request body unbounded and discarded the
// read error) and F-162 (the REST http.Server set no deadline of any kind).
package httprestful

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/servers"
)

// f149ExpectedBodyLimit is the bound this test requires of the POST handler. It
// is spelled out rather than taken from the server so the test still compiles -
// and fails - against the unfixed server.
const f149ExpectedBodyLimit = 1024 * 1024 * 8

// f162SlowlorisBudget is how long the test waits for the server to hang up on a
// request whose headers never end.
const f162SlowlorisBudget = 30 * time.Second

// countingBody is a request body of a fixed length that records how much of
// itself was actually consumed.
type countingBody struct {
	remaining int64
	read      int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > c.remaining {
		n = c.remaining
	}
	for i := range p[:n] {
		p[i] = 'a'
	}
	c.remaining -= n
	c.read += n
	return int(n), nil
}

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

// waitForRestServer blocks until the server accepts TCP on addr.
func waitForRestServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rest server never came up on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// startTestRestServer brings up a REST server on a free local port and returns
// it with its dial address.
//
// The server goroutine reads config.Parameters inside Start(). The cleanup
// therefore shuts the server down and JOINS its goroutine before it restores
// the global, so the restore can never race the server's read of it - that
// unsynchronised overlap is exactly what -race used to flag here.
func startTestRestServer(t *testing.T) (*restServer, string) {
	t.Helper()
	port := freeLocalPort(t)

	orig := config.Parameters
	config.Parameters = &config.Configuration{HttpRestPort: port}

	rt := InitRestServer().(*restServer)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rt.Start()
	}()

	addr := "127.0.0.1:" + strconv.Itoa(port)
	waitForRestServer(t, addr)

	t.Cleanup(func() {
		rt.Stop() // graceful shutdown -> Serve returns -> Start returns
		<-stopped // join: the goroutine has finished reading config.Parameters
		config.Parameters = orig
	})
	return rt, addr
}

// TestF149RestPostBodyIsBounded proves the REST POST handler stops reading.
//
// Fail-on-pristine: pre-fix the handler was ioutil.ReadAll(r.Body) with the
// error thrown away, so it consumed every byte offered - here 64MB from a
// single unauthenticated request.
func TestF149RestPostBodyIsBounded(t *testing.T) {
	rt := InitRestServer().(*restServer)
	handler, _, err := rt.router.Try(ApiSendRawTransaction, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}

	body := &countingBody{remaining: 64 * 1024 * 1024}
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodPost, ApiSendRawTransaction, body))

	if body.read > f149ExpectedBodyLimit+4096 {
		t.Fatalf("REST POST consumed %d bytes of request body; it must stop at %d",
			body.read, f149ExpectedBodyLimit)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", w.Code)
	}
}

// TestF162RestServerClosesSlowlorisConnection proves the REST server hangs up on
// a request whose headers never arrive.
//
// Fail-on-pristine: pre-fix the http.Server had no ReadHeaderTimeout (nor any
// other deadline), so the connection and its goroutine were held indefinitely.
func TestF162RestServerClosesSlowlorisConnection(t *testing.T) {
	_, addr := startTestRestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// A request whose header section is never terminated.
	if _, err := conn.Write([]byte("GET " + ApiGetBlockHeight +
		" HTTP/1.1\r\nHost: localhost\r\n")); err != nil {
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
