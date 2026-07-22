// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package httpnodeinfo

import (
	"net/http"
	"net/http/httptest"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux, exactly as
	// the real binary does transitively (utils StartPProf -> statsview -> net/http/pprof).
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF036InfoMuxIsolatesPprof proves the fix: the node-info port must NOT expose
// the pprof debug endpoints. The old StartServer served http.DefaultServeMux (nil
// handler), which the imported net/http/pprof init() has populated with
// /debug/pprof/*  -> /debug/pprof/cmdline leaks the process argv (incl. a possible
// --password). The new private mux serves only /info.
func TestF036InfoMuxIsolatesPprof(t *testing.T) {
	// The DefaultServeMux (what the pre-fix code served) DOES expose pprof -- this is
	// the leak the fix removes. Asserting it here documents/anchors the vulnerability.
	def := httptest.NewServer(http.DefaultServeMux)
	defer def.Close()
	r1, err := http.Get(def.URL + "/debug/pprof/cmdline")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, r1.StatusCode,
		"DefaultServeMux serves /debug/pprof/cmdline (the pre-fix leak the private mux avoids)")

	// The private info mux must NOT.
	priv := httptest.NewServer(newInfoMux())
	defer priv.Close()
	for _, path := range []string{"/debug/pprof/cmdline", "/debug/pprof/heap", "/debug/pprof/goroutine"} {
		r, err := http.Get(priv.URL + path)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode,
			"info port must NOT expose "+path)
	}
}
