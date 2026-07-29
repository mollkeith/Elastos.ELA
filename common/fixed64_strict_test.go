// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package common

import (
	"math"
	"math/big"
	"math/rand"
	"testing"
)

// craftedOutput is one of the two outputs of the mainnet transaction in block
// 2260451 whose sum wraps signed 64-bit.
const craftedOutput Fixed64 = 9223322038057596306

// TestLegacyArithmeticStillWraps pins the pre-activation behaviour. Historical
// blocks were validated against these wrapped totals, so a node replaying the
// chain must continue to reproduce them. If this test ever fails, historical
// replay is broken and a fresh node can no longer sync past block 2260451.
func TestLegacyArithmeticStillWraps(t *testing.T) {
	// Accumulated through a variable so the wrap actually occurs; Go evaluates
	// constant expressions at arbitrary precision and would reject this at
	// compile time.
	var total Fixed64
	total += craftedOutput
	total += craftedOutput

	// 2*9223322038057596306 - 2^64 == -99997594359004
	const wrapped Fixed64 = -99997594359004
	if total != wrapped {
		t.Fatalf("legacy sum must wrap to %d, got %d", wrapped, total)
	}
}

// TestStrictArithmeticRejectsCraftedSum is the same input through the checked
// primitive, which must reject rather than wrap.
func TestStrictArithmeticRejectsCraftedSum(t *testing.T) {
	if _, err := AddFixed64(craftedOutput, craftedOutput); err == nil {
		t.Fatal("expected crafted output sum to be rejected")
	}
	if MoneyRange(craftedOutput) {
		t.Fatal("crafted output must be outside money range")
	}
}

// TestAddBoundary asserts the exact activation boundary: a sum landing on
// MaxInt64 succeeds, one sela more fails.
func TestAddBoundary(t *testing.T) {
	if got, err := AddFixed64(Fixed64(math.MaxInt64)-1, 1); err != nil ||
		got != Fixed64(math.MaxInt64) {
		t.Fatalf("sum to exactly MaxInt64 must succeed, got %d err %v", got, err)
	}
	if _, err := AddFixed64(Fixed64(math.MaxInt64), 1); err == nil {
		t.Fatal("MaxInt64+1 must be rejected")
	}
	if _, err := SubtractFixed64(Fixed64(math.MinInt64), 1); err == nil {
		t.Fatal("MinInt64-1 must be rejected")
	}
	if _, err := MultiplyFixed64(Fixed64(math.MinInt64), -1); err == nil {
		t.Fatal("MinInt64 * -1 must be rejected")
	}
}

// TestMoneyRange covers the aggregate bound.
func TestMoneyRange(t *testing.T) {
	for _, c := range []struct {
		v  Fixed64
		ok bool
	}{{0, true}, {1, true}, {MaxELAMoney, true}, {MaxELAMoney + 1, false},
		{-1, false}, {craftedOutput, false}} {
		if MoneyRange(c.v) != c.ok {
			t.Fatalf("MoneyRange(%d) = %v, want %v", c.v, !c.ok, c.ok)
		}
	}
}

// TestPrimitivesDifferentialAgainstBigInt fuzzes all three checked primitives
// against arbitrary-precision arithmetic: the checked result must equal the
// big.Int result exactly whenever it is representable, and must error whenever
// it is not.
func TestPrimitivesDifferentialAgainstBigInt(t *testing.T) {
	min, max := big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64)
	fits := func(z *big.Int) bool { return z.Cmp(min) >= 0 && z.Cmp(max) <= 0 }
	rng := rand.New(rand.NewSource(1))

	pick := func() Fixed64 {
		switch rng.Intn(4) {
		case 0:
			return Fixed64(math.MaxInt64 - rng.Int63n(4))
		case 1:
			return Fixed64(math.MinInt64 + rng.Int63n(4))
		case 2:
			return Fixed64(rng.Int63n(1000) - 500)
		default:
			return Fixed64(rng.Int63()) * Fixed64(1-2*rng.Intn(2))
		}
	}

	for i := 0; i < 200000; i++ {
		a, b := pick(), pick()
		x, y := big.NewInt(int64(a)), big.NewInt(int64(b))

		for _, op := range []struct {
			name string
			got  func() (Fixed64, error)
			want *big.Int
		}{
			{"add", func() (Fixed64, error) { return AddFixed64(a, b) }, new(big.Int).Add(x, y)},
			{"sub", func() (Fixed64, error) { return SubtractFixed64(a, b) }, new(big.Int).Sub(x, y)},
			{"mul", func() (Fixed64, error) { return MultiplyFixed64(a, b) }, new(big.Int).Mul(x, y)},
		} {
			got, err := op.got()
			if fits(op.want) {
				if err != nil {
					t.Fatalf("%s(%d,%d): unexpected error %v", op.name, a, b, err)
				}
				if int64(got) != op.want.Int64() {
					t.Fatalf("%s(%d,%d) = %d, want %s", op.name, a, b, got, op.want)
				}
			} else if err == nil {
				t.Fatalf("%s(%d,%d) = %d, want overflow error", op.name, a, b, got)
			}
		}
	}
}
