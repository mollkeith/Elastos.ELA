// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
)

// Same real ELA merged-mining proof as the malleation witness (chainID 6).
const (
	gateAuxPowHex  = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4b0313ee0904a880495b742f4254432e434f4d2ffabe6d6d9581ba0156314f1e92fd03430c6e4428a32bb3f1b9dc627102498e5cfbf26261020000004204cb9a010f32a00601000000000000ffffffff0200000000000000001976a914c0174e89bd93eacd1d5a1af4ba1802d412afc08688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90000000014acac4ee8fdd8ca7e0b587b35fce8c996c70aefdf24c333038bdba7af531266000000000001ccc205f0e1cb435f50cc2f63edd53186b414fcb22b719da8c59eab066cf30bdb0000000000000020d1061d1e456cae488c063838b64c4911ce256549afadfc6a4736643359141b01551e4d94f9e8b6b03eec92bb6de1e478a0e913e5f733f5884857a7c2b965f53ca880495bffff7f20a880495b"
	gateAuxHashHex = "7926398947f332fe534b15c628ff0cd9dc6f7d3ea59c74801dc758ac65428e64"
	gateChainID    = 6
)

func gateAuxPow(t *testing.T) auxpow.AuxPow {
	t.Helper()
	b, err := common.HexStringToBytes(gateAuxPowHex)
	if err != nil {
		t.Fatal(err)
	}
	var ap auxpow.AuxPow
	if err := ap.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return ap
}

// TestF041F090IsCanonicalCatchesWhatCheckMisses: AuxPow.Check accepts all three
// encodings, but IsCanonical accepts only the canonical one.
func TestF041F090IsCanonicalCatchesWhatCheckMisses(t *testing.T) {
	auxHash, err := common.Uint256FromHexString(gateAuxHashHex)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical.
	can := gateAuxPow(t)
	can.ParentHash = can.ParBlockHeader.Hash()
	can.ParMerkleIndex = 0
	if !can.Check(auxHash, gateChainID) {
		t.Fatal("canonical must pass Check")
	}
	if !can.IsCanonical() {
		t.Fatal("canonical AuxPow must be IsCanonical()")
	}

	// F-041 malleation: unvalidated ParentHash.
	m1 := gateAuxPow(t)
	m1.ParentHash = can.ParentHash
	m1.ParMerkleIndex = 0
	m1.ParentHash[0] ^= 0xff
	if !m1.Check(auxHash, gateChainID) {
		t.Fatal("F-041: malleated ParentHash must still pass Check")
	}
	if m1.IsCanonical() {
		t.Fatal("F-041: non-canonical ParentHash must be rejected by IsCanonical")
	}

	// F-090 malleation: high-bit ParMerkleIndex.
	m2 := gateAuxPow(t)
	m2.ParentHash = can.ParentHash
	m2.ParMerkleIndex = 0x40000000
	if !m2.Check(auxHash, gateChainID) {
		t.Fatal("F-090: high-bit ParMerkleIndex must still pass Check")
	}
	if m2.IsCanonical() {
		t.Fatal("F-090: non-zero ParMerkleIndex must be rejected by IsCanonical")
	}
}

// TestF041F090CanonicalGate exercises the exact decision CheckBlockSanity makes:
//
//	reject  <=>  auxPowMalleationActive(height) && !AuxPow.IsCanonical()
//
// It confirms the height gate: below StrictMoneyRangeHeight nothing is rejected
// (byte-identical replay of historical non-canonical encodings), and at/above it
// malleated encodings are rejected while canonical ones and non-malleated ones
// are accepted.
func TestF041F090CanonicalGate(t *testing.T) {
	const activation uint32 = 1000
	b := gateChain(t, activation)

	if b.auxPowMalleationActive(activation - 1) {
		t.Fatal("gate must be inactive below activation")
	}
	if !b.auxPowMalleationActive(activation) || !b.auxPowMalleationActive(activation+1) {
		t.Fatal("gate must be active at and above activation (>= semantics)")
	}

	can := gateAuxPow(t)
	can.ParentHash = can.ParBlockHeader.Hash()
	can.ParMerkleIndex = 0

	mal := gateAuxPow(t)
	mal.ParentHash = can.ParentHash
	mal.ParMerkleIndex = 0x40000000 // F-090 malleation

	reject := func(height uint32, ap *auxpow.AuxPow) bool {
		return b.auxPowMalleationActive(height) && !ap.IsCanonical()
	}

	// Below the gate: even a malleated encoding is accepted (replay parity).
	if reject(activation-1, &mal) {
		t.Fatal("below gate: malleated AuxPow must NOT be rejected (byte-identical replay)")
	}
	// At/above the gate: malleated rejected, canonical accepted.
	if !reject(activation, &mal) {
		t.Fatal("at gate: malleated AuxPow must be rejected")
	}
	if !reject(activation+1, &mal) {
		t.Fatal("above gate: malleated AuxPow must be rejected")
	}
	if reject(activation, &can) {
		t.Fatal("at gate: canonical AuxPow must be accepted (no false positive that would halt the chain)")
	}
	if reject(activation+1, &can) {
		t.Fatal("above gate: canonical AuxPow must be accepted")
	}
}
