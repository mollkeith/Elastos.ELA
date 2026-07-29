// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package crypto

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
)

// TestF190SchnorrNonceNotDerivedFromMathRandSeed is the fail-on-pristine test
// for F-190, the sibling of F-059 in the same weak-randomness root-cause class.
//
// Before the fix, the Schnorr signing nonce k0 was sha256(privateKey ||
// randomBytes(32)) where randomBytes came from the math/rand global source.
// The node and CLI binaries explicitly re-seed that global source from
// wall-clock time (p2p/server/server.go:1524, dpos/p2p/server.go:1058,
// cmd/ela-cli.go:49), so the nonce is a pure function of a guessable seed.
//
// The test models that directly: it re-seeds the global source to the same
// value before each of two signatures over *different* messages with the same
// key. On pristine code both signatures come out with the same R, which is
// textbook nonce reuse - the test then recovers the private key from the pair
// and fails. With the fix (crypto/rand) the two R values differ and it passes.
func TestF190SchnorrNonceNotDerivedFromMathRandSeed(t *testing.T) {
	const seedValue = int64(1721764800000000000)

	privateKey, ok := new(big.Int).SetString(
		"8e7b372c1ceea18883032d6cdbf67e7dee5e7507c30012af81cfb7e9b60c00cc", 16)
	if !ok {
		t.Fatal("could not decode the test private key")
	}

	var m1, m2 [32]byte
	copy(m1[:], []byte("F-190 nonce reuse message one   "))
	copy(m2[:], []byte("F-190 nonce reuse message two   "))
	if m1 == m2 {
		t.Fatal("the two test messages must differ")
	}

	rand.Seed(seedValue)
	sig1, err := AggregateSignatures([]*big.Int{privateKey}, m1)
	if err != nil {
		t.Fatalf("AggregateSignatures(m1): %v", err)
	}

	rand.Seed(seedValue)
	sig2, err := AggregateSignatures([]*big.Int{privateKey}, m2)
	if err != nil {
		t.Fatalf("AggregateSignatures(m2): %v", err)
	}

	if !bytes.Equal(sig1[:32], sig2[:32]) {
		// Distinct nonces under an identical math/rand seed: the signing
		// entropy no longer comes from the seeded generator.
		return
	}

	// Identical R over two different messages under the same key. Recover the
	// private key the way an observer of two on-chain signatures would:
	//   s1 - s2 = (e1 - e2) * d  (mod N)
	// getE appends to the rX slice it is handed, so hand it a fresh backing
	// array rather than a window onto the signature.
	rX := make([]byte, 32)
	copy(rX, sig1[:32])

	Px, Py := Curve.ScalarBaseMult(intToByte(privateKey))
	e1 := getE(Px, Py, rX, m1)
	e2 := getE(Px, Py, rX, m2)

	s1 := new(big.Int).SetBytes(sig1[32:])
	s2 := new(big.Int).SetBytes(sig2[32:])

	numerator := new(big.Int).Mod(new(big.Int).Sub(s1, s2), N)
	denominator := new(big.Int).Mod(new(big.Int).Sub(e1, e2), N)

	recoveredMatches := false
	if denominator.Sign() != 0 {
		if inverse := new(big.Int).ModInverse(denominator, N); inverse != nil {
			recovered := new(big.Int).Mod(new(big.Int).Mul(numerator, inverse), N)
			recoveredMatches = recovered.Cmp(privateKey) == 0
		}
	}

	t.Fatalf("F-190: the Schnorr signing nonce is a pure function of the "+
		"math/rand global seed - two signatures over different messages under "+
		"seed %d reused R=%x; private key recovered from that pair: %v",
		seedValue, rX, recoveredMatches)
}
