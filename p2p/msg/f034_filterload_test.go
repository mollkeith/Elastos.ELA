package msg

import (
	"bytes"
	"testing"
)

// TestF034EmptyFilterRejected proves the F-034 primary guard: a FilterLoad with an
// empty filter but a nonzero hash-func count is malformed (it would cause a
// modulo-by-zero panic on the bloom match path) and must be rejected on the wire.
//
// Fail-on-pristine: without the guard, Deserialize returns nil and the malformed
// filter is accepted, so the `err == nil` branch fires.
func TestF034EmptyFilterRejected(t *testing.T) {
	fl := &FilterLoad{Filter: []byte{}, HashFuncs: 1}

	var buf bytes.Buffer
	if err := fl.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	var got FilterLoad
	if err := got.Deserialize(&buf); err == nil {
		t.Fatal("expected Deserialize to reject empty filter with nonzero hash funcs")
	}
}

// TestF034EmptyFilterZeroHashFuncsAccepted guards the fix from over-rejecting:
// a legitimate side-chain SPV filter uses an empty filter with HashFuncs == 0 and
// must still round-trip.
func TestF034EmptyFilterZeroHashFuncsAccepted(t *testing.T) {
	fl := &FilterLoad{Filter: []byte{}, HashFuncs: 0}

	var buf bytes.Buffer
	if err := fl.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	var got FilterLoad
	if err := got.Deserialize(&buf); err != nil {
		t.Fatalf("empty filter with zero hash funcs must be accepted, got %v", err)
	}
}
