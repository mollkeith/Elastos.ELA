// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-23 — the optional profiler bound ALL interfaces and SILENTLY IGNORED the
// configured ProfileHost.
//
// FAIL-ON-PRISTINE, against the PRODUCTION call path (utils.StartPProf, which is
// what main.go:101-103 launches — not a helper written for the test):
//
//	pristine: listenAddr := net.JoinHostPort("", port)   -> 0.0.0.0:port
//	          viewer.WithLinkAddr(host)                  -> host only decorates links
//	fixed   : listenAddr := ProfileListenAddr(port, host) -> host:port, loopback default
//
// TestFV23StartPProfBindsLoopbackOnlyByDefault dials the box's own non-loopback
// address. On pristine that dial SUCCEEDS (the socket is on every interface) and the
// test fails; with the fix it is refused. That is a property of the listening socket,
// not of any string this test computed.
package utils

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// freePort reserves and immediately releases a port so StartPProf can take it.
func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint32(port)
}

// nonLoopbackIPv4 returns a routable IPv4 address of this host, or "" when the box
// has none (in which case the off-box exposure leg cannot be observed here).
func nonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil && v4.IsGlobalUnicast() {
			return v4.String()
		}
	}
	return ""
}

// dialable reports whether a TCP connection to host:port completes.
func dialable(host string, port uint32) bool {
	c, err := net.DialTimeout("tcp",
		net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// waitDialable polls until host:port accepts, or the deadline passes.
func waitDialable(host string, port uint32, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if dialable(host, port) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestFV23ProfileListenAddrDefaultsToLoopback pins the resolver contract that the
// production StartPProf now hands to viewer.WithAddr.
func TestFV23ProfileListenAddrDefaultsToLoopback(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		{"unset host defaults to loopback", "", "127.0.0.1:9999"},
		{"whitespace-only host defaults to loopback", "   ", "127.0.0.1:9999"},
		{"configured host is honoured", "10.1.2.3", "10.1.2.3:9999"},
		{"explicit all-interfaces stays explicit", "0.0.0.0", "0.0.0.0:9999"},
		{"ipv6 host is bracketed", "::1", "[::1]:9999"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ProfileListenAddr(9999, c.host); got != c.want {
				t.Fatalf("FV-23: ProfileListenAddr(9999, %q) = %q, want %q "+
					"(pristine ignored the host entirely and always produced \":9999\")",
					c.host, got, c.want)
			}
		})
	}
}

// TestFV23StartPProfBindsLoopbackOnlyByDefault is the behavioural fail-on-pristine
// leg: it starts the REAL production StartPProf with no ProfileHost configured — the
// mainnet default, since ProfilePort has no DefaultParams entry and ProfileHost is
// empty unless set — and proves the resulting socket is not reachable off-box.
func TestFV23StartPProfBindsLoopbackOnlyByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("binds a listening socket; skipped under -short")
	}
	port := freePort(t)

	// The production entry point, launched exactly as main.go launches it.
	go StartPProf(port, "")

	if !waitDialable(DefaultProfileHost, port, 10*time.Second) {
		t.Fatalf("FV-23: the profiler never came up on %s:%d", DefaultProfileHost, port)
	}

	external := nonLoopbackIPv4()
	if external == "" {
		t.Skip("no non-loopback IPv4 on this host: off-box exposure cannot be observed")
	}
	if dialable(external, port) {
		t.Fatalf("FV-23: the profiler accepted a connection on the non-loopback address "+
			"%s:%d. With no ProfileHost configured it must bind loopback only — the "+
			"unauthenticated net/http/pprof surface (/debug/pprof, /cmdline, /profile, "+
			"/trace) is otherwise reachable from the whole network.", external, port)
	}
}
