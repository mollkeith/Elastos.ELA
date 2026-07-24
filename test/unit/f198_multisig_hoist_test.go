// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package unit

import (
	"runtime"
	"testing"

	"github.com/elastos/Elastos.ELA/crypto"
)

// f198KeyPair returns a private key and the 34-byte public-key script entry that
// parsePublicKeys hands to VerifyMultisigSignatures (leading 0x21 length byte
// plus the 33-byte compressed point).
func f198KeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := pub.EncodePoint(true)
	if err != nil {
		t.Fatal(err)
	}
	script := make([]byte, 0, crypto.PublicKeyScriptLength-1)
	script = append(script, byte(len(encoded)))
	script = append(script, encoded...)
	return priv, script
}

// f198Sig wraps a raw 64-byte signature into the 65-byte signature-script form
// (leading 0x40 length byte) that VerifyMultisigSignatures parses.
func f198Sig(raw []byte) []byte {
	out := make([]byte, 0, crypto.SignatureScriptLength)
	out = append(out, byte(len(raw)))
	return append(out, raw...)
}

// TestF198_MultisigVerifyHoistsPerPairInvariants proves the per-(signature,key)
// work in VerifyMultisigSignatures no longer scales with n*s.
//
// The probe uses n public keys and n signatures that can never match (all-zero
// r||s, which ecdsa.Verify rejects immediately and almost allocation-free), so
// the inner loop runs the full n*n times in both trees.  The ONLY difference
// between trees is the hoisted work: the unpatched loop performs n*n P-256 point
// decompressions plus n*n SHA-256 passes over the unsigned transaction, the
// patched loop performs n decompressions and one SHA-256.
//
// FAIL-ON-PRISTINE: measured on this tree with go1.22.10, n=100 gives 422,502
// allocated objects unpatched and 33,944 patched (10,000 point decompressions
// versus 100; the ~30k floor is the n*n cheap ecdsa rejections, which are
// identical in both trees).  The budget below sits 4.4x above the patched
// figure and 2.8x below the unpatched one.
func TestF198_MultisigVerifyHoistsPerPairInvariants(t *testing.T) {
	const n = 100
	const m = 1
	const mallocBudget = 150000

	publicKeys := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		_, script := f198KeyPair(t)
		publicKeys = append(publicKeys, script)
	}

	// n signatures that match nothing, forcing the full n*n scan.
	signatures := make([]byte, 0, n*crypto.SignatureScriptLength)
	for i := 0; i < n; i++ {
		signatures = append(signatures, f198Sig(make([]byte, 64))...)
	}

	data := make([]byte, 64*1024) // stand-in for an unsigned transaction

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := crypto.VerifyMultisigSignatures(m, n, publicKeys, signatures, data)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatalf("precondition: probe signatures must not verify")
	}

	mallocs := after.Mallocs - before.Mallocs
	t.Logf("F-198 probe: n=%d signatures=%d mallocs=%d", n, n, mallocs)
	if mallocs > mallocBudget {
		t.Fatalf("F-198: VerifyMultisigSignatures allocated %d objects for a "+
			"%d-key / %d-signature program (budget %d) -- the public-key "+
			"decompression and the unsigned-transaction hash are still being "+
			"redone inside the n*s loop", mallocs, n, n, mallocBudget)
	}
}

// TestF198_ValidMultisigStillVerifies is the plain non-regression check.
func TestF198_ValidMultisigStillVerifies(t *testing.T) {
	const n = 3
	const m = 2

	data := []byte("unsigned transaction bytes")

	privs := make([][]byte, 0, n)
	publicKeys := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		priv, script := f198KeyPair(t)
		privs = append(privs, priv)
		publicKeys = append(publicKeys, script)
	}

	var signatures []byte
	for i := 0; i < m; i++ {
		raw, err := crypto.Sign(privs[i], data)
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, f198Sig(raw)...)
	}

	if err := crypto.VerifyMultisigSignatures(m, n, publicKeys, signatures,
		data); err != nil {
		t.Fatalf("F-198: a valid %d-of-%d multisig no longer verifies: %v", m, n, err)
	}
}

// TestF198_UndecodableKeyAfterMatchStaysAccepted is the acceptance-neutrality
// guard-rail, and the reason the public-key decode is memoised LAZILY instead of
// being lifted out of the loop wholesale.
//
// parsePublicKeys does not check that a key decodes, so a program can carry an
// undecodable key.  The existing loop breaks out of the key scan as soon as a
// signature matches an earlier key, so such a key is never reached and the
// program verifies.  Decoding every key up-front would flip this program from
// valid to invalid -- an acceptance change, which is out of scope for a
// post-restart hardening fix.  This test must pass on BOTH trees; if it ever
// fails, the hoist has become acceptance-changing and must be gated instead.
func TestF198_UndecodableKeyAfterMatchStaysAccepted(t *testing.T) {
	data := []byte("unsigned transaction bytes")

	priv, good := f198KeyPair(t)

	// A 34-byte entry whose 33-byte body is not a point on P-256.
	bad := make([]byte, crypto.PublicKeyScriptLength-1)
	bad[0] = 33
	bad[1] = 0x02
	for i := 2; i < len(bad); i++ {
		bad[i] = 0xFF
	}
	if _, err := crypto.DecodePoint(bad[1:]); err == nil {
		t.Skip("probe key unexpectedly decodes; cannot exercise the lazy path")
	}

	raw, err := crypto.Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	signatures := f198Sig(raw)

	// Good key first: the loop matches and breaks before ever touching the bad
	// key, so the program must still be accepted.
	if err := crypto.VerifyMultisigSignatures(1, 2, [][]byte{good, bad},
		signatures, data); err != nil {
		t.Fatalf("F-198: hoist changed an ACCEPTANCE decision -- a program that "+
			"never reaches its undecodable key is now rejected: %v", err)
	}

	// Bad key first: the loop reaches it before any match, so the program must
	// still be rejected, with the decode error.
	if err := crypto.VerifyMultisigSignatures(1, 2, [][]byte{bad, good},
		signatures, data); err == nil {
		t.Fatalf("F-198: a program whose first key is undecodable must still be " +
			"rejected")
	}
}
