// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/common"
)

// Real ELA merged-mining proof (chainID 6) lifted from auxpow_test.go. It is a
// valid AuxPow: ParMerkleIndex=0, ParCoinBaseMerkle empty, coinbase commits to
// auxHashHex1.
const (
	malAuxPowHex1 = "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4b0313ee0904a880495b742f4254432e434f4d2ffabe6d6d9581ba0156314f1e92fd03430c6e4428a32bb3f1b9dc627102498e5cfbf26261020000004204cb9a010f32a00601000000000000ffffffff0200000000000000001976a914c0174e89bd93eacd1d5a1af4ba1802d412afc08688ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90000000014acac4ee8fdd8ca7e0b587b35fce8c996c70aefdf24c333038bdba7af531266000000000001ccc205f0e1cb435f50cc2f63edd53186b414fcb22b719da8c59eab066cf30bdb0000000000000020d1061d1e456cae488c063838b64c4911ce256549afadfc6a4736643359141b01551e4d94f9e8b6b03eec92bb6de1e478a0e913e5f733f5884857a7c2b965f53ca880495bffff7f20a880495b"
	malAuxHashHex1 = "7926398947f332fe534b15c628ff0cd9dc6f7d3ea59c74801dc758ac65428e64"
	malAuxChainID  = 6
)

func mustAuxPow(t *testing.T) auxpow.AuxPow {
	t.Helper()
	b, err := common.HexStringToBytes(malAuxPowHex1)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	var ap auxpow.AuxPow
	if err := ap.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("aux deserialize: %v", err)
	}
	return ap
}

// TestF041F090MalleationDivergesConsensusSeed is the fail-on-pristine witness:
// it runs on the PRISTINE tree with only pre-existing symbols and PASSES,
// proving both malleations are real and live. Each malleation keeps
// AuxPow.Check() true (pristine accepts it) and leaves the block's consensus
// identity Header.Hash() (SerializeNoAux, excludes the AuxPow) BYTE-IDENTICAL,
// yet changes Header.HashWithAux() -- the exact 8 bytes
// dpos/state/arbitrators.go getRandomDposV2Producers reads as the DPoSV2
// committee RNG seed. Same block, two encodings, two committees, zero PoW cost.
func TestF041F090MalleationDivergesConsensusSeed(t *testing.T) {
	ap := mustAuxPow(t)
	// Canonical baseline: ParentHash names the parent block hash, coinbase index 0.
	ap.ParentHash = ap.ParBlockHeader.Hash()
	ap.ParMerkleIndex = 0

	auxHash, err := common.Uint256FromHexString(malAuxHashHex1)
	if err != nil {
		t.Fatal(err)
	}

	h := Header{
		Version:    0x20000000,
		Previous:   common.Uint256{0x11},
		MerkleRoot: common.Uint256{0x22},
		Timestamp:  1600000000,
		Bits:       0x1d00ffff,
		Nonce:      42,
		Height:     2260451,
		AuxPow:     ap,
	}

	if !h.AuxPow.Check(auxHash, malAuxChainID) {
		t.Fatal("canonical AuxPow must pass pristine Check")
	}
	baseID := h.Hash()          // consensus identity / PoW anchor / block-index key
	baseSeed := h.HashWithAux() // DPoSV2 committee RNG source

	seedTail := func(u common.Uint256) [8]byte {
		var x [8]byte
		copy(x[:], u[24:])
		return x
	}
	baseTail := seedTail(baseSeed)

	// --- F-041: ParentHash is unvalidated -> flip it freely. ---
	t.Run("F-041_ParentHash", func(t *testing.T) {
		m := h // copy
		mp := m.AuxPow.ParentHash
		mp[0] ^= 0xff // any other 32 bytes
		m.AuxPow.ParentHash = mp

		if !m.AuxPow.Check(auxHash, malAuxChainID) {
			t.Fatal("F-041: malleated ParentHash must STILL pass Check (proves it is unvalidated)")
		}
		if m.Hash() != baseID {
			t.Fatal("F-041: block identity Hash() must be unchanged (SerializeNoAux excludes AuxPow)")
		}
		if m.HashWithAux() == baseSeed {
			t.Fatal("F-041: HashWithAux() must diverge (the malleation is otherwise inert)")
		}
		if seedTail(m.HashWithAux()) == baseTail {
			t.Fatal("F-041: DPoSV2 seed bytes [24:32] must diverge -> committee split")
		}
	})

	// --- F-090: only the low len(ParCoinBaseMerkle) bits of ParMerkleIndex are
	// consumed; here that length is 0, so every non-negative index is accepted.
	// Set a high bit to malleate. ---
	t.Run("F-090_ParMerkleIndexHighBit", func(t *testing.T) {
		m := h // copy
		m.AuxPow.ParMerkleIndex = 0x40000000

		if !m.AuxPow.Check(auxHash, malAuxChainID) {
			t.Fatal("F-090: high-bit ParMerkleIndex must STILL pass Check (proves the bits are inert to validation)")
		}
		if m.Hash() != baseID {
			t.Fatal("F-090: block identity Hash() must be unchanged")
		}
		if m.HashWithAux() == baseSeed {
			t.Fatal("F-090: HashWithAux() must diverge")
		}
		if seedTail(m.HashWithAux()) == baseTail {
			t.Fatal("F-090: DPoSV2 seed bytes [24:32] must diverge -> committee split")
		}
	})
}
