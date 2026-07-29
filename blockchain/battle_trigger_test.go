// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT license.
//
// Battle coverage for FIX-1: the forced-rollback trigger byte-order fix.
// As shipped, the config trigger was DISPLAY order but was parsed straight and
// compared against the block's INTERNAL hash -> armed=false -> the rollback
// silently never fired on mainnet. These tests lock in both directions:
//   (a) a display-order trigger MUST arm, and
//   (b) an internal-order trigger MUST NOT arm
// so a future "cleanup" that swaps the constant back cannot silently disarm
// chain recovery. They also prove a FALSE ARM is impossible (rewinding a
// healthy chain would be catastrophic).

package blockchain

import (
	"errors"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// the real mainnet incident values
const (
	mainnetTriggerDisplay  = "e1a11e04942a7513f0256dbf3605080490800fd845f8e261deffcec68c2ea9af"
	mainnetTriggerInternal = "afa92e8cc6ceffde61e2f845d80f809004080536bf6d25f013752a94041ea1e1"
)

// ---- arming truth table ----
func TestBattleTriggerArming(t *testing.T) {
	cases := []struct {
		name      string
		tipHeight int
		target    uint32
		trigger   string
		wantArmed bool
		wantErr   bool
	}{
		{"display-order-matches-arms", 20, 10, hashAt(11).ReversedString(), true, false},
		// the shipped bug: internal-order trigger must NOT arm
		{"internal-order-does-not-arm", 20, 10, hashAt(11).String(), false, false},
		{"wrong-block-does-not-arm", 20, 10, hashAt(99).ReversedString(), false, false},
		{"empty-trigger-no-arm-no-err", 20, 10, "", false, false},
		{"tip-equals-target-no-arm", 10, 10, hashAt(11).ReversedString(), false, false},
		{"tip-below-target-no-arm", 5, 10, hashAt(11).ReversedString(), false, false},
		{"tip-exactly-target-plus-1-arms", 11, 10, hashAt(11).ReversedString(), true, false},
		{"malformed-hex-errors", 20, 10, "not-a-hash", false, true},
		{"short-hex-errors", 20, 10, "dead", false, true},
		{"long-hex-errors", 20, 10, mainnetTriggerDisplay + "ff", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := armChain(t, c.tipHeight, c.target, c.trigger)
			armed, err := b.ForcedRollbackArmed()
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for trigger %q, got armed=%v", c.trigger, armed)
				}
				if armed {
					t.Fatalf("BREACH: armed=true on an errored trigger %q", c.trigger)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if armed != c.wantArmed {
				t.Fatalf("armed=%v, want %v (trigger=%q target=%d tip=%d)", armed, c.wantArmed, c.trigger, c.target, c.tipHeight)
			}
		})
	}
}

// ---- FALSE-ARM SAFETY: a chain that does not hold the trigger block must never arm ----
// A false arm would rewind a HEALTHY chain -- worse than not firing at all.
func TestBattleTriggerNeverFalseArms(t *testing.T) {
	// every block hash in this chain is hashAt(i); try triggers for blocks that
	// are NOT at target+1 and confirm none of them arm.
	for _, wrong := range []byte{0, 1, 5, 9, 10, 12, 13, 20, 99, 255} {
		t.Run("wrong-block-"+string(rune('a'+int(wrong%26))), func(t *testing.T) {
			b := armChain(t, 20, 10, hashAt(wrong).ReversedString())
			armed, err := b.ForcedRollbackArmed()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if armed && wrong != 11 {
				t.Fatalf("FALSE ARM: armed on block %d which is not target+1 (=11)", wrong)
			}
		})
	}
}

// ---- byte-order round-trip identities (the property the fix depends on) ----
func TestBattleTriggerByteOrderIdentities(t *testing.T) {
	t.Run("reversed-parse-of-display-equals-internal", func(t *testing.T) {
		h := hashAt(11)
		parsed, err := common.Uint256FromReversedHexString(h.ReversedString())
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if !parsed.IsEqual(*h) {
			t.Fatalf("round-trip broken: parsed=%s want=%s", parsed.String(), h.String())
		}
	})
	t.Run("straight-parse-of-display-does-NOT-equal-internal", func(t *testing.T) {
		h := hashAt(11)
		parsed, err := common.Uint256FromHexString(h.ReversedString())
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if parsed.IsEqual(*h) {
			t.Fatal("straight parse of a display-order string matched the internal hash -- " +
				"the byte-order bug would not be detectable")
		}
	})
	t.Run("mainnet-display-reverses-to-internal", func(t *testing.T) {
		parsed, err := common.Uint256FromReversedHexString(mainnetTriggerDisplay)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if parsed.String() != mainnetTriggerInternal {
			t.Fatalf("mainnet regression: reversed(%s)=%s, want %s",
				mainnetTriggerDisplay, parsed.String(), mainnetTriggerInternal)
		}
	})
	t.Run("mainnet-internal-reverses-back-to-display", func(t *testing.T) {
		h, err := common.Uint256FromHexString(mainnetTriggerInternal)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if h.ReversedString() != mainnetTriggerDisplay {
			t.Fatalf("mainnet regression: reversedString=%s, want %s", h.ReversedString(), mainnetTriggerDisplay)
		}
	})
}

// ---- DEPTH-GUARD (audit finding): a node whose tip is > the incremental-rewind
// window (maxHistoryCapacity=720) past the target must refuse with the sentinel
// error. ForcedRollbackArmed deliberately does NOT depth-check (the guard lives in
// ForceRollback), so it still arms.
//
// CORRECTION (B1). This comment used to claim the sentinel's purpose was to be
// "non-fatally detectable by main.go via errors.Is, so a late upgrader is not
// bricked into a permanent boot loop", and main.go did exactly that. That was wrong,
// and the rehearsal measured how wrong: 48/48 nodes declined here and then refused
// to start further down anyway (alive 0/48), and in the depth band where the
// restored checkpoint lands below the target they would instead have come up
// UN-ROLLED-BACK on the exploit chain. A node that cannot complete the rollback must
// not join the recovered network, so the sentinel is now FATAL at the boot path and
// carries the operator remedy in its text. The sentinel is still a sentinel because
// the remedy differs from every other rewind failure -- not because anyone is meant
// to swallow it. See test/unit/b1b5_rollback_outcome_test.go.
func TestBattleForcedRollbackDepthGuard(t *testing.T) {
	const target = uint32(10)
	trigger := hashAt(11).ReversedString()

	t.Run("armed-true-even-past-capacity", func(t *testing.T) {
		b := armChain(t, int(target)+1000, target, trigger)
		armed, err := b.ForcedRollbackArmed()
		if err != nil || !armed {
			t.Fatalf("expected armed=true past capacity (guard is in ForceRollback), got armed=%v err=%v", armed, err)
		}
	})
	t.Run("depth-at-capacity-720-refuses-with-sentinel", func(t *testing.T) {
		b := armChain(t, int(target)+720, target, trigger) // depth == 720
		e := b.ForceRollback(nil)
		if e == nil {
			t.Fatal("expected capacity refusal at depth 720")
		}
		if !errors.Is(e, ErrForcedRollbackExceedsCapacity) {
			t.Fatalf("depth 720 must return the non-fatal sentinel, got %v", e)
		}
	})
	t.Run("depth-over-capacity-refuses-with-sentinel", func(t *testing.T) {
		b := armChain(t, int(target)+5000, target, trigger)
		e := b.ForceRollback(nil)
		if !errors.Is(e, ErrForcedRollbackExceedsCapacity) {
			t.Fatalf("depth 5000 must return the non-fatal sentinel, got %v", e)
		}
	})
	t.Run("error-text-names-a-remedy-that-is-not-a-no-op", func(t *testing.T) {
		b := armChain(t, int(target)+800, target, trigger)
		e := b.ForceRollback(nil)
		if e == nil {
			t.Fatal("capacity error must name a remedy, got nil")
		}
		// FV-18: the remedy used to print the POSITIONAL form `ela-cli rollback <N>`,
		// which -- measured on this tree -- prints the subcommand help and exits 0
		// without touching the store, so a runbook step checking the exit status
		// recorded success for an operation that never happened.
		if !contains(e.Error(), "ela-cli rollback --height") {
			t.Fatalf("the remedy must print the --height FLAG form, got: %v", e)
		}
		if !contains(e.Error(), "refusing to start") {
			t.Fatalf("the capacity refusal must say the node will not start, got: %v", e)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
