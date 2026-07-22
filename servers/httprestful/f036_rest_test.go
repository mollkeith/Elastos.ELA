// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// F-036: the REST service enforced none of the JSON-RPC auth (user/pass +
// WhiteIPList live only in servers/httpjsonrpc), and exposed GET /api/v1/restart.
// Because common/log's Fatal does NOT exit, every failure path in Start() fell
// through to Serve(nil) and panicked -- and on the restart path that panic runs in
// a bare goroutine outside net/http's per-connection recover, so it killed the
// whole daemon (2 concurrent unauthenticated GETs were enough).
package httprestful

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
)

// the package logger is nil in a bare test binary; Start() logs on its error paths.
func init() { log.NewDefault(t_logPath, 0, 0, 0) }

const t_logPath = "/tmp/f036-test-logs"

// TestF036RestartRouteNotExposed proves the unauthenticated remote restart
// primitive is gone. Fail-on-pristine: the route is present pre-fix.
func TestF036RestartRouteNotExposed(t *testing.T) {
	rt := InitRestServer().(*restServer)
	for path := range rt.getMap {
		if strings.Contains(strings.ToLower(path), "restart") {
			t.Fatalf("unauthenticated restart route still exposed (GET): %s", path)
		}
	}
	for path := range rt.postMap {
		if strings.Contains(strings.ToLower(path), "restart") {
			t.Fatalf("unauthenticated restart route still exposed (POST): %s", path)
		}
	}
}

// TestF036StartReturnsOnBindFailure proves Start() no longer hands a nil listener
// to Serve. Fail-on-pristine: pre-fix this panics (nil pointer dereference in
// net/http.(*Server).Serve).
func TestF036StartReturnsOnBindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	orig := config.Parameters
	defer func() { config.Parameters = orig }()
	config.Parameters = &config.Configuration{HttpRestPort: port}

	rt := InitRestServer().(*restServer)
	done := make(chan interface{}, 1)
	go func() {
		defer func() { done <- recover() }()
		rt.Start()
	}()

	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("Start panicked on bind failure (would kill the daemon): %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return on bind failure")
	}
	if rt.listener != nil {
		t.Fatal("listener must be nil after a failed bind")
	}
}
