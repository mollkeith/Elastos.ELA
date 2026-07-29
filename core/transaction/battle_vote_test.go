// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT license.
//
// Battle coverage for FIX-2: addVoteTotal, the height-gated checked vote-total
// accumulator that replaced the unchecked "totalVotes += cv.Votes" at three
// sites in voting.go. Locks BOTH properties:
//   (a) at/above StrictMoneyRangeHeight an overflowing/oversized total is REJECTED
//   (b) below the gate the legacy wrapping arithmetic is preserved BIT-IDENTICALLY
// (b) is the replay-safety property -- if it breaks, historical blocks stop validating.

package transaction

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

const (
	gateH   = uint32(2260451) // strict active at/above
	belowH  = gateH - 1
	aboveH  = gateH + 1
	maxMny  = int64(common.MaxELAMoney)
)

// ---- ABOVE the gate: rejection truth table ----
func TestBattleVoteStrictRejection(t *testing.T) {
	cases := []struct {
		name       string
		start      int64
		add        int64
		wantErr    bool
		wantResult int64
	}{
		{"zero-plus-zero", 0, 0, false, 0},
		{"small-sum", 1000, 2000, false, 3000},
		{"exact-max", 0, maxMny, false, maxMny},
		{"max-minus-1", 0, maxMny - 1, false, maxMny - 1},
		{"max-plus-1-rejected", 0, maxMny + 1, true, 0},
		{"two-max-rejected", maxMny, maxMny, true, 0},
		{"max-plus-tiny-rejected", maxMny, 1, true, 0},
		{"maxint64-rejected", 0, math.MaxInt64, true, 0},
		{"int64-wrap-rejected", math.MaxInt64, 1, true, 0},
		{"half-max-each-ok", maxMny / 2, maxMny / 2, false, maxMny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx := voteTotalTx(aboveH, gateH)
			got, err := tx.addVoteTotal(common.Fixed64(c.start), common.Fixed64(c.add))
			if c.wantErr {
				if err == nil {
					t.Fatalf("BREACH: addVoteTotal(%d,%d) accepted, got %d (want rejection)", c.start, c.add, int64(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("FALSE POSITIVE: addVoteTotal(%d,%d) rejected a legit total: %v", c.start, c.add, err)
			}
			if int64(got) != c.wantResult {
				t.Fatalf("addVoteTotal(%d,%d)=%d, want %d", c.start, c.add, int64(got), c.wantResult)
			}
		})
	}
}

// ---- BELOW the gate: legacy wrapping preserved bit-identically (replay-safety) ----
func TestBattleVoteLegacyPreserved(t *testing.T) {
	cases := []struct {
		name  string
		start int64
		add   int64
	}{
		{"normal", 1000, 2000},
		{"exact-max", 0, maxMny},
		{"over-max-still-accepted", maxMny, maxMny},
		{"maxint64-wraps-not-errors", math.MaxInt64, 1},
		{"huge-wrap", math.MaxInt64, math.MaxInt64},
		{"negative", -5, -5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx := voteTotalTx(belowH, gateH)
			got, err := tx.addVoteTotal(common.Fixed64(c.start), common.Fixed64(c.add))
			if err != nil {
				t.Fatalf("REPLAY BREAK: legacy path errored on (%d,%d): %v -- historical blocks would stop validating",
					c.start, c.add, err)
			}
			want := common.Fixed64(c.start) + common.Fixed64(c.add) // the original raw += semantics
			if got != want {
				t.Fatalf("REPLAY BREAK: legacy addVoteTotal(%d,%d)=%d, raw += gives %d (must be bit-identical)",
					c.start, c.add, int64(got), int64(want))
			}
		})
	}
}

// ---- the gate boundary itself ----
func TestBattleVoteGateBoundary(t *testing.T) {
	overflowing := func(h uint32) error {
		tx := voteTotalTx(h, gateH)
		_, err := tx.addVoteTotal(common.Fixed64(maxMny), common.Fixed64(maxMny))
		return err
	}
	cases := []struct {
		name      string
		height    uint32
		wantErr   bool
	}{
		{"far-below-gate", 1, false},
		{"one-below-gate", gateH - 1, false},
		{"exactly-at-gate", gateH, true},
		{"one-above-gate", gateH + 1, true},
		{"far-above-gate", gateH + 1_000_000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := overflowing(c.height)
			if c.wantErr && err == nil {
				t.Fatalf("height %d: expected strict rejection, got acceptance", c.height)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("height %d: expected legacy acceptance, got %v", c.height, err)
			}
		})
	}
}

// ---- accumulating many entries: rejection must happen, and before wrapping ----
func TestBattleVoteAccumulationSeries(t *testing.T) {
	series := []struct {
		name    string
		each    int64
		count   int
		wantErr bool
	}{
		{"2-x-max-rejects", maxMny, 2, true},
		{"93-x-max-rejects", maxMny, 93, true},
		{"1000-small-ok", maxMny / 2000, 1000, false},
		{"single-max-ok", maxMny, 1, false},
	}
	for _, s := range series {
		t.Run(s.name, func(t *testing.T) {
			tx := voteTotalTx(aboveH, gateH)
			var total common.Fixed64
			var err error
			for i := 0; i < s.count; i++ {
				total, err = tx.addVoteTotal(total, common.Fixed64(s.each))
				if err != nil {
					break
				}
				if int64(total) < 0 {
					t.Fatalf("BREACH: running total went NEGATIVE (%d) without an error at entry %d", int64(total), i)
				}
			}
			if s.wantErr && err == nil {
				t.Fatalf("BREACH: %d entries of %d accepted, final total %d", s.count, s.each, int64(total))
			}
			if !s.wantErr && err != nil {
				t.Fatalf("FALSE POSITIVE: %d entries of %d rejected: %v", s.count, s.each, err)
			}
		})
	}
}
