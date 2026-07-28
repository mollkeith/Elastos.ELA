package blockchain

import (
	"strings"
	"testing"

	program "github.com/elastos/Elastos.ELA/core/contract/program"
)

// TestF050SchnorrShortParameter proves the F-050 crash-harden: a Schnorr program
// whose Parameter is shorter than 64 bytes must be cleanly rejected instead of
// panicking at `copy(signature[:], program.Parameter[:64])`.
//
// Fail-on-pristine: with the length guard removed, checkSchnorrSignatures panics
// with "slice bounds out of range [:64]" on the 10-byte Parameter below.
func TestF050SchnorrShortParameter(t *testing.T) {
	// 35-byte Schnorr code: [OP_1, 0x21(=33), <33 pubkey bytes>].
	code := make([]byte, 35)
	code[0] = 0x51 // OP_1 / PUSH1
	code[1] = 0x21 // 33 = length of the following public key

	prog := program.Program{Code: code, Parameter: make([]byte, 10)}

	// Height 0 against a never-reached gate, so this asserts the short-Parameter
	// rejection is UNGATED. See checkSchnorrSignatures for why the short half
	// needs no gate: the base panicked on it, so no retained block carries one.
	ok, err := checkSchnorrSignatures(prog, [32]byte{}, 0, ^uint32(0))
	if ok {
		t.Fatal("expected checkSchnorrSignatures to fail on a short Parameter")
	}
	if err == nil || !strings.Contains(err.Error(), "invalid schnorr signature length") {
		t.Fatalf("expected 'invalid schnorr signature length', got %v", err)
	}
}
