// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

var errWriterFull = errors.New("writer refused the write")

// budgetWriter accepts budget bytes and fails every write after that.
type budgetWriter struct {
	budget int
	buf    bytes.Buffer
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if len(p) > w.budget {
		n, _ := w.buf.Write(p[:w.budget])
		w.budget = 0
		return n, errWriterFull
	}
	n, err := w.buf.Write(p)
	w.budget -= n
	return n, err
}

// TestF128HeaderSerializeReportsTrailingSentinelWriteError is the
// fail-on-pristine test for the write half of F-128. Header.Serialize used to
// call w.Write([]byte{1}) and discard both return values, so a writer that
// failed on the trailing sentinel produced a truncated header and Serialize
// still reported success.
func TestF128HeaderSerializeReportsTrailingSentinelWriteError(t *testing.T) {
	header := &Header{Version: 1, Timestamp: 2, Bits: 3, Nonce: 4, Height: 5}

	var full bytes.Buffer
	if err := header.Serialize(&full); err != nil {
		t.Fatalf("baseline serialize failed: %v", err)
	}
	total := full.Len()
	if total < 2 {
		t.Fatalf("unexpected serialized header length %d", total)
	}

	// Everything fits except the one-byte trailing sentinel.
	w := &budgetWriter{budget: total - 1}
	err := header.Serialize(w)
	if err == nil {
		t.Fatal("F-128: Serialize reported success while the trailing " +
			"sentinel byte was dropped, emitting a truncated header")
	}
	if !errors.Is(err, errWriterFull) {
		t.Fatalf("expected the writer error to propagate, got %v", err)
	}
	if w.buf.Len() != total-1 {
		t.Fatalf("expected %d bytes written, got %d", total-1, w.buf.Len())
	}
}

// TestF128HeaderSerializeRoundTripUnchanged pins that the write-side fix moved
// nothing on the happy path, and documents the read-side behaviour that is
// deliberately left alone: Header.Deserialize still tolerates a missing
// trailing sentinel, because requiring it would change what
// blockchain/txvalidator.go accepts and therefore needs a height gate.
func TestF128HeaderSerializeRoundTripUnchanged(t *testing.T) {
	header := &Header{Version: 7, Timestamp: 11, Bits: 13, Nonce: 17, Height: 19}

	var buf bytes.Buffer
	if err := header.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	encoded := buf.Bytes()

	var got Header
	if err := got.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if got.Height != header.Height || got.Nonce != header.Nonce {
		t.Fatal("round trip lost header fields")
	}

	// Documented, unchanged: the sentinel is still not required on read.
	var truncated Header
	if err := truncated.Deserialize(
		bytes.NewReader(encoded[:len(encoded)-1])); err != nil {
		t.Fatalf("read-side strictness must stay gated, but Deserialize "+
			"now rejects a header without the trailing sentinel: %v", err)
	}

	_ = io.EOF
}
