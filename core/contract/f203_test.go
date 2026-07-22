// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package contract

import "testing"

// TestF203IsMultiSigNoOOB — F-203: IsMultiSig had only a `len(code) < 37` entry guard,
// but the parser's variable advances (m/n selectors + 34-byte pubkey stride) push the
// index to len(code), so the case sub-reads and the final CHECKMULTISIG read sliced OOB
// -> pre-auth remote panic (reachable via RunPrograms / ReturnDeposit before any signature
// check). Drives the REAL IsMultiSig with the pack's 37-byte crasher and truncation
// variants and asserts a clean `false` return (no panic). Pre-fix these panic with
// "index out of range".
func TestF203IsMultiSigNoOOB(t *testing.T) {
	// The pack's exact repro: [0x51][0x21][33 bytes][0x01][0x01] = 37 bytes. The parser
	// reaches i==37 at the final CHECKMULTISIG read.
	crasher := []byte{0x51, 0x21}
	crasher = append(crasher, make([]byte, 33)...)
	crasher = append(crasher, 0x01, 0x01)
	if len(crasher) != 37 {
		t.Fatalf("setup: want 37-byte crasher, got %d", len(crasher))
	}

	variants := [][]byte{
		crasher,
		// case-2 (2-byte) n-selector truncated at the end.
		append(append([]byte{0x51, 0x21}, make([]byte, 33)...), 0x02, 0x01),
		make([]byte, 37),  // all zeros
		make([]byte, 40),  // longer, pubkey-stride overrun
		make([]byte, 100), // many-pubkey overrun
	}
	for _, code := range variants {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("F-203: IsMultiSig panicked on %d-byte code (must return false): %v", len(code), r)
				}
			}()
			// A crafted/truncated code must be classified as NOT multisig, cleanly.
			if IsMultiSig(code) {
				t.Fatalf("F-203: %d-byte crafted code must not be a valid multisig", len(code))
			}
		}()
	}
}
