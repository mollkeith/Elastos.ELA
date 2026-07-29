// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT license.
//
// Battle-test suite for the Fixed64 checked-arithmetic foundation that the
// v0.9.9.7 money fix stands on. Each subtest is an independent green check.

package common

import (
	"math"
	"math/big"
	"testing"
)

const maxMoney = int64(MaxELAMoney) // 1e17 sela == 1e9 ELA

// ---- MoneyRange boundary lattice ----
func TestBattleMoneyRange(t *testing.T) {
	cases := []struct {
		name string
		v    int64
		want bool
	}{
		{"zero", 0, true},
		{"one", 1, true},
		{"max-minus-1", maxMoney - 1, true},
		{"exact-max", maxMoney, true},
		{"max-plus-1", maxMoney + 1, false},
		{"ten-x-max", maxMoney * 10, false},
		{"neg-one", -1, false},
		{"neg-max", -maxMoney, false},
		{"MaxInt64", math.MaxInt64, false},
		{"MinInt64", math.MinInt64, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MoneyRange(Fixed64(c.v)); got != c.want {
				t.Fatalf("MoneyRange(%d)=%v, want %v", c.v, got, c.want)
			}
		})
	}
}

// ---- AddFixed64: must error on positive AND negative wrap ----
func TestBattleAddFixed64(t *testing.T) {
	cases := []struct {
		name    string
		a, b    int64
		wantErr bool
		wantSum int64
	}{
		{"0+0", 0, 0, false, 0},
		{"1+1", 1, 1, false, 2},
		{"max+max-ok-int64", maxMoney, maxMoney, false, 2 * maxMoney}, // 2e17 < MaxInt64
		{"MaxInt64+1", math.MaxInt64, 1, true, 0},
		{"MaxInt64+0", math.MaxInt64, 0, false, math.MaxInt64},
		{"halfmax+halfmax", math.MaxInt64/2 + 1, math.MaxInt64/2 + 1, true, 0},
		{"MinInt64+-1", math.MinInt64, -1, true, 0},
		{"MaxInt64+-1", math.MaxInt64, -1, false, math.MaxInt64 - 1},
		{"neg+neg-ok", -5, -5, false, -10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sum, err := AddFixed64(Fixed64(c.a), Fixed64(c.b))
			if c.wantErr {
				if err == nil {
					t.Fatalf("AddFixed64(%d,%d) wanted overflow error, got %d", c.a, c.b, int64(sum))
				}
				// cross-check against big.Int: the true sum really is out of int64 range
				bg := new(big.Int).Add(big.NewInt(c.a), big.NewInt(c.b))
				if bg.IsInt64() {
					t.Fatalf("claimed overflow but big.Int sum %s fits int64", bg)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddFixed64(%d,%d) unexpected error %v", c.a, c.b, err)
			}
			if int64(sum) != c.wantSum {
				t.Fatalf("AddFixed64(%d,%d)=%d, want %d", c.a, c.b, int64(sum), c.wantSum)
			}
		})
	}
}

// ---- SubtractFixed64: must error on underflow both directions ----
func TestBattleSubtractFixed64(t *testing.T) {
	cases := []struct {
		name     string
		a, b     int64
		wantErr  bool
		wantDiff int64
	}{
		{"5-3", 5, 3, false, 2},
		{"3-5", 3, 5, false, -2},
		{"max-max", maxMoney, maxMoney, false, 0},
		{"MinInt64-1", math.MinInt64, 1, true, 0},
		{"MaxInt64--1", math.MaxInt64, -1, true, 0},
		{"0-MinInt64", 0, math.MinInt64, true, 0},
		{"0-0", 0, 0, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := SubtractFixed64(Fixed64(c.a), Fixed64(c.b))
			if c.wantErr {
				if err == nil {
					t.Fatalf("SubtractFixed64(%d,%d) wanted error, got %d", c.a, c.b, int64(d))
				}
				return
			}
			if err != nil {
				t.Fatalf("SubtractFixed64(%d,%d) unexpected error %v", c.a, c.b, err)
			}
			if int64(d) != c.wantDiff {
				t.Fatalf("SubtractFixed64(%d,%d)=%d, want %d", c.a, c.b, int64(d), c.wantDiff)
			}
		})
	}
}

// ---- MultiplyFixed64: must error on product overflow ----
func TestBattleMultiplyFixed64(t *testing.T) {
	cases := []struct {
		name    string
		a, b    int64
		wantErr bool
		wantP   int64
	}{
		{"0*big", 0, math.MaxInt64, false, 0},
		{"big*0", math.MaxInt64, 0, false, 0},
		{"2*3", 2, 3, false, 6},
		{"-2*-3", -2, -3, false, 6},
		{"MaxInt64*2", math.MaxInt64, 2, true, 0},
		{"MinInt64*-1", math.MinInt64, -1, true, 0},
		{"1e10*1e10", 10_000_000_000, 10_000_000_000, true, 0}, // 1e20 > MaxInt64
		{"max*2-int64ok", maxMoney, 2, false, 2 * maxMoney},     // 2e17 < MaxInt64
		{"MaxInt64*1", math.MaxInt64, 1, false, math.MaxInt64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := MultiplyFixed64(Fixed64(c.a), Fixed64(c.b))
			if c.wantErr {
				if err == nil {
					t.Fatalf("MultiplyFixed64(%d,%d) wanted overflow error, got %d", c.a, c.b, int64(p))
				}
				bg := new(big.Int).Mul(big.NewInt(c.a), big.NewInt(c.b))
				if bg.IsInt64() {
					t.Fatalf("claimed overflow but big.Int product %s fits int64", bg)
				}
				return
			}
			if err != nil {
				t.Fatalf("MultiplyFixed64(%d,%d) unexpected error %v", c.a, c.b, err)
			}
			if int64(p) != c.wantP {
				t.Fatalf("MultiplyFixed64(%d,%d)=%d, want %d", c.a, c.b, int64(p), c.wantP)
			}
		})
	}
}

// ---- differential fuzz: AddFixed64 must agree with big.Int on 20k pseudo-random pairs ----
func TestBattleAddFixed64DiffFuzz(t *testing.T) {
	// deterministic LCG so the run is reproducible (no time/rand seed).
	var st uint64 = 0x9E3779B97F4A7C15
	next := func() int64 {
		st = st*6364136223846793005 + 1442695040888963407
		return int64(st)
	}
	for i := 0; i < 20000; i++ {
		a, b := next(), next()
		sum, err := AddFixed64(Fixed64(a), Fixed64(b))
		bg := new(big.Int).Add(big.NewInt(a), big.NewInt(b))
		if bg.IsInt64() {
			if err != nil || int64(sum) != bg.Int64() {
				t.Fatalf("AddFixed64(%d,%d)=%d,err=%v but big.Int=%s", a, b, int64(sum), err, bg)
			}
		} else if err == nil {
			t.Fatalf("AddFixed64(%d,%d) did NOT error but true sum %s overflows int64", a, b, bg)
		}
	}
}
