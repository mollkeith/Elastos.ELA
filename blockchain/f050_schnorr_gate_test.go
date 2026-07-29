package blockchain

import (
	"math/big"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	program "github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/crypto"
)

// F-050 GATE SPLIT — the Schnorr Parameter length check must not flip a retained
// block's verdict.
//
// The released base c61c9e61 had NO length check in checkSchnorrSignatures. It
// went straight to copy(signature[:], program.Parameter[:64]), which means:
//
//	len(Parameter) >  64 -> ACCEPTED. The slice took the leading 64 bytes and
//	                        SchnorrVerify ran normally.
//	len(Parameter) == 64 -> normal path.
//	len(Parameter) <  64 -> PANIC. ReadVarBytes returns make([]byte, count) for
//	                        anything under 64 KiB, so cap == len and the reslice
//	                        is genuinely out of range.
//
// HEAD collapsed all three into a single ungated `!= 64` rejection. That turns
// the over-long case from accept into reject with no height gate, on a feature
// (single-key Schnorr) live on mainnet since NormalSchnorrStartHeight 1,405,000.
// Roughly 855,000 retained blocks sit in that window, so it is a Rule 1 defect.
//
// These tests pin the split:
//   - over-long is ACCEPTED below StrictMoneyRangeHeight and REJECTED at or above it
//   - short is REJECTED at every height, ungated
//
// FAIL-ON-PRISTINE: restore the single ungated `if len(program.Parameter) != 64`
// and TestF050SchnorrOverLongParameterGated/accepted_below_the_gate fails with
// "check schnorr signature failed: invalid schnorr signature length".
//
// WIRING: every case below drives the real RunPrograms entry point with a real
// height, not checkSchnorrSignatures directly, so the two threaded arguments are
// pinned too. Passing a constant 0 for blockHeight at the call sites (validation.go
// lines 49 and 70) makes the at-gate and above-gate rejections fail; passing 0 for
// strictMoneyHeight makes the below-gate acceptance fail.

// schnorrFixture builds a valid single-key Schnorr program: the redeem script, the
// matching program hash, the signed data, and a genuine 64-byte signature over it.
// Single-key is exactly the mainnet-live NormalSchnorrStartHeight case.
func schnorrFixture(t *testing.T) (data []byte, hash common.Uint168, code []byte, sig [64]byte) {
	t.Helper()

	priv, ok := new(big.Int).SetString(
		"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef", 16)
	if !ok {
		t.Fatal("could not parse the fixture private key")
	}

	px, py := crypto.Curve.ScalarBaseMult(priv.Bytes())
	var encoded [33]byte
	copy(encoded[:], crypto.Marshal(crypto.Curve, px, py))

	pub, err := crypto.DecodePoint(encoded[:])
	if err != nil {
		t.Fatalf("DecodePoint: %v", err)
	}

	c, err := contract.CreateSchnorrContract(pub)
	if err != nil {
		t.Fatalf("CreateSchnorrContract: %v", err)
	}

	data = []byte("F-050 schnorr parameter length gate fixture")
	sig, err = crypto.AggregateSignatures([]*big.Int{priv}, common.Sha256D(data))
	if err != nil {
		t.Fatalf("AggregateSignatures: %v", err)
	}

	return data, *c.ToProgramHash(), c.Code, sig
}

func runSchnorr(data []byte, hash common.Uint168, code, parameter []byte,
	blockHeight, strictMoneyHeight uint32) error {
	return RunPrograms(data, []common.Uint168{hash},
		[]*program.Program{{Code: code, Parameter: parameter}},
		blockHeight, strictMoneyHeight)
}

// TestF050SchnorrExact64Unchanged is the control. A well-formed 64-byte signature
// must verify identically on both sides of the gate, so any failure below is the
// length split and not a broken fixture.
func TestF050SchnorrExact64Unchanged(t *testing.T) {
	data, hash, code, sig := schnorrFixture(t)
	gate := config.MainNetStrictMoneyRangeHeight

	for _, h := range []uint32{
		config.MainNetNormalSchnorrStartHeight,
		config.MainNetForcedRollbackHeight,
		gate - 1,
		gate,
		gate + 1,
	} {
		if err := runSchnorr(data, hash, code, sig[:], h, gate); err != nil {
			t.Fatalf("a valid 64-byte signature must verify at height %d, got %v", h, err)
		}
	}
}

// TestF050SchnorrOverLongParameterGated is the Rule 1 proof. An over-long Parameter
// whose leading 64 bytes are a valid signature was a valid spend under the released
// base, so it must stay accepted on retained history and may only be rejected at or
// above StrictMoneyRangeHeight.
func TestF050SchnorrOverLongParameterGated(t *testing.T) {
	data, hash, code, sig := schnorrFixture(t)
	gate := config.MainNetStrictMoneyRangeHeight

	// 65 bytes: the real signature plus one trailing byte, the minimal over-long case.
	over := append(append([]byte{}, sig[:]...), 0xff)
	if len(over) != 65 {
		t.Fatalf("fixture error: want a 65-byte parameter, got %d", len(over))
	}

	t.Run("accepted below the gate", func(t *testing.T) {
		// Heights inside the real exposure window: Schnorr activation, the last
		// retained block, and the block immediately before the gate.
		for _, h := range []uint32{
			config.MainNetNormalSchnorrStartHeight,
			config.MainNetForcedRollbackHeight,
			gate - 1,
		} {
			if err := runSchnorr(data, hash, code, over, h, gate); err != nil {
				t.Fatalf("RETAINED-HISTORY FLIP at height %d: the released base "+
					"accepted a 65-byte Parameter by slicing the first 64 bytes, "+
					"this build rejected it: %v", h, err)
			}
		}
	})

	t.Run("rejected at and above the gate", func(t *testing.T) {
		for _, h := range []uint32{gate, gate + 1} {
			err := runSchnorr(data, hash, code, over, h, gate)
			if err == nil {
				t.Fatalf("expected a 65-byte Parameter to be rejected at height %d", h)
			}
			if !strings.Contains(err.Error(), "invalid schnorr signature length") {
				t.Fatalf("expected the length rejection at height %d, got %v", h, err)
			}
		}
	})

	t.Run("below the gate only the leading 64 bytes are authoritative", func(t *testing.T) {
		// Base semantics: the trailing bytes are ignored entirely, so a garbage
		// tail cannot make a good signature bad, and a good tail cannot rescue a
		// bad leading signature.
		bad := append(append([]byte{}, sig[:]...), 0x00)
		bad[0] ^= 0x01 // corrupt the leading signature, keep the length at 65
		if err := runSchnorr(data, hash, code, bad, gate-1, gate); err == nil {
			t.Fatal("a corrupted leading signature must still fail below the gate")
		}
	})
}

// TestF050SchnorrShortParameterUngated proves the other half stays ungated. The base
// PANICKED on a short Parameter, so it could never accept one and no retained block
// can carry one. Rejecting at every height is therefore verdict-preserving.
func TestF050SchnorrShortParameterUngated(t *testing.T) {
	data, hash, code, sig := schnorrFixture(t)
	gate := config.MainNetStrictMoneyRangeHeight

	// 63 bytes: the real signature with its last byte removed.
	short := append([]byte{}, sig[:63]...)
	if len(short) != 63 {
		t.Fatalf("fixture error: want a 63-byte parameter, got %d", len(short))
	}

	for _, h := range []uint32{
		0,
		config.MainNetNormalSchnorrStartHeight,
		config.MainNetForcedRollbackHeight,
		gate - 1,
		gate,
		gate + 1,
	} {
		err := runSchnorr(data, hash, code, short, h, gate)
		if err == nil {
			t.Fatalf("expected a 63-byte Parameter to be rejected at height %d", h)
		}
		if !strings.Contains(err.Error(), "invalid schnorr signature length") {
			t.Fatalf("expected the length rejection at height %d, got %v", h, err)
		}
	}
}

// TestF050SchnorrShortParameterCapEqualsLen underpins the ungated decision. The
// justification for rejecting len<64 without a gate is that the base panicked
// rather than accepted, and that only holds if Parameter[:64] is a true
// out-of-range slice. It is: Program.Deserialize sources Parameter from
// common.ReadVarBytes, which returns make([]byte, count) for anything under
// 64 KiB, so cap equals len and there is no spare capacity to reslice into.
func TestF050SchnorrShortParameterCapEqualsLen(t *testing.T) {
	var p program.Program
	if err := p.Deserialize(strings.NewReader(
		// varint length 0x3f (63), then 63 parameter bytes, then varint 0x02 and
		// a 2-byte code, which is all Deserialize needs to return cleanly.
		string(append(append([]byte{0x3f}, make([]byte, 63)...), 0x02, 0x51, 0x21)))); err != nil {
		t.Fatalf("Program.Deserialize: %v", err)
	}
	if len(p.Parameter) != 63 {
		t.Fatalf("want a 63-byte Parameter, got %d", len(p.Parameter))
	}
	if cap(p.Parameter) >= 64 {
		t.Fatalf("UNGATED DECISION INVALIDATED: a deserialized 63-byte Parameter has "+
			"cap %d, so the base's Parameter[:64] would have resliced into spare "+
			"capacity instead of panicking, and the short case could have been "+
			"ACCEPTED on retained history. Re-derive the gating for len<64.",
			cap(p.Parameter))
	}
}
