// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-22 — the RevertToPOW(NoBlock) acceptance decision must be a pure function of the
// block's own ancestry.
//
// Two defects, one edit:
//
//	change 1 (UNGATED)  the "how long since the previous block" reference was
//	                    BlockChain.BestChain.Timestamp — the VALIDATING NODE'S CURRENT
//	                    TIP. For a block on a competing branch that is a timestamp from
//	                    an unrelated chain. It is now the block's own parent.
//	change 2 (gate 1)   F-057 additionally consulted the node's peer-adjusted WALL
//	                    CLOCK (MedianAdjustedTime). Two honest nodes with identical
//	                    chain state and different peer sets could disagree. Withdrawn.
//	change 3 (gate 1)   OPTION (b), the owner's decision: withdrawing change 2 re-opened
//	                    F-057, so at/above gate 1 the demanded gap is now
//	                    noBlockTime + MaxTimeOffsetSeconds — more than a producer can
//	                    forge by post-dating its own header. Deterministic and
//	                    ancestry-only; costs failsafe latency 2h -> 4h.
//
// These tests drive the PRODUCTION function that owns the call site,
// (*BlockChain).checkTxsContext — the same function CheckBlockContext calls on every
// connected block — with a REAL RevertToPOW transaction inside a real block. Nothing
// about the decision is re-implemented here; the only inputs varied are the parent
// timestamp, the block timestamp, the node's best tip and the node's clock floor.
//
// FAIL-ON-PRISTINE, all three halves:
//   - change 1: at pristine HEAD the verdict follows BestChain, so every case below
//     where parent and tip disagree comes out inverted.
//   - change 2: at pristine HEAD, at/above gate 1, a block whose timestamps sit in the
//     future is REJECTED however genuine the stall, because the node's clock has not
//     reached them — and the same inputs yield a DIFFERENT verdict once the clock floor
//     moves. Both assertions are made explicitly.
//   - change 3: revert the option-(b) hunk and TestFV22OptionBRejectsTheForgedStall
//     fails at/above gate 1 with the forged block ACCEPTED — which is F-057 live.
//     DELETE the production call site instead (the SpecialContextCheck call in
//     core/transaction/transactionchecker.go ContextCheck, or the
//     CheckTransactionContextWithPrev call in checkTxsContext) and it still fails,
//     because these tests enter through the block path, not through the check.
package blockchain

import (
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// fv22Store answers only what the RevertToPOW context path actually asks. Anything
// else panics rather than silently returning a zero value.
type fv22Store struct {
	IChainStore
}

func (fv22Store) IsTxHashDuplicate(common.Uint256) bool     { return false }
func (fv22Store) IsDoubleSpend(interfaces.Transaction) bool { return false }
func (fv22Store) GetTransaction(common.Uint256) (interfaces.Transaction, uint32, error) {
	return nil, 0, nil
}

func fv22Chain(t *testing.T) *BlockChain {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = wiringGate

	store := fv22Store{}
	prev := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: bip30Arbiters{}, Store: store}
	t.Cleanup(func() { DefaultLedger = prev })

	st := &state.State{StateKeyFrame: &state.StateKeyFrame{}}
	st.ConsensusAlgorithm = state.DPOS

	b := &BlockChain{
		chainParams: params,
		db:          store,
		state:       st,
		TimeSource:  NewMedianTime(),
	}
	b.UTXOCache = NewUTXOCache(store, params)
	return b
}

// fv22Block returns a block at `height` carrying the exactly-correct coinbase (so an
// ACCEPTED RevertToPOW yields a clean nil) plus a real RevertToPOW(NoBlock) tx.
func fv22Block(t *testing.T, b *BlockChain, height, blockTs uint32) *types.Block {
	t.Helper()
	blk := bip30Block(t, b, height, []byte{0x22, byte(height & 0xff)})
	blk.Header.Timestamp = blockTs
	blk.Transactions = append(blk.Transactions, functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		&payload.RevertToPOW{Type: payload.NoBlock, WorkingHeight: height},
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		nil,
	))
	return blk
}

// fv22Verdict runs the production block-path context check and reports accept/reject.
func fv22Verdict(t *testing.T, b *BlockChain, height, parentTs, blockTs, bestTs uint32) (bool, string) {
	t.Helper()
	bestHash := common.Uint256{0xAA}
	parentHash := common.Uint256{0xBB}
	b.BestChain = &BlockNode{Hash: &bestHash, Height: height - 1, Timestamp: bestTs}
	prevNode := &BlockNode{Hash: &parentHash, Height: height - 1, Timestamp: parentTs}

	err := b.checkTxsContext(fv22Block(t, b, height, blockTs), prevNode)
	if err == nil {
		return true, ""
	}
	return false, err.Error()
}

// fv22NoBlockTime is RevertToPOWNoBlockTimeV1 (2h) — the legacy threshold, in force at
// every height used here (all above ChangeViewV1Height) BELOW gate 1.
const fv22NoBlockTime = uint32(2 * 3600)

// fv22Threshold is the gap the production rule demands at `height`: the legacy
// noBlockTime below gate 1, and the option-(b) noBlockTime + MaxTimeOffsetSeconds at
// and above it. Written from the two source constants, not from a literal, so a change
// to either constant moves the tests with the production rule.
func fv22Threshold(height uint32) uint32 {
	if height >= wiringGate {
		return fv22NoBlockTime + uint32(MaxTimeOffsetSeconds)
	}
	return fv22NoBlockTime
}

// TestFV22NoBlockRevertBindsToTheBlocksOwnParent is the change-1 proof, run in BOTH
// directions so neither outcome can be produced by an accident of the fixture, and at
// heights BELOW as well as above gate 1 — change 1 is ungated.
//
// MUTATION PROOF: make CheckTransactionContextWithPrev ignore prevNode (or revert
// checkTxsContext to CheckTransactionContext) and both directions invert at every
// height.
func TestFV22NoBlockRevertBindsToTheBlocksOwnParent(t *testing.T) {
	b := fv22Chain(t)
	// Timestamps deliberately in the future: the verdict must not depend on the
	// validating node's clock (see the clock-independence test).
	base := uint32(time.Now().Unix()) + 3_000_000

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1, 3_000_000} {
		// Direction 1: the PARENT says a full no-block interval elapsed; the node's own
		// tip says none did. Binding to the parent must ACCEPT.
		ok, msg := fv22Verdict(t, b, h, base, base+fv22Threshold(h), base+fv22Threshold(h))
		if !ok {
			t.Fatalf("FV-22 UNWIRED at height %d: the no-block interval is measured "+
				"against the validating node's tip, not the block's own parent "+
				"(parent says the interval elapsed): %s", h, msg)
		}

		// Direction 2: the PARENT says almost no time elapsed; the node's own tip says a
		// full interval did. Binding to the parent must REJECT.
		ok, _ = fv22Verdict(t, b, h, base, base+100, base-fv22Threshold(h))
		if ok {
			t.Fatalf("FV-22 UNWIRED at height %d: a RevertToPOW with no genuine gap "+
				"against its OWN parent was accepted because the validating node's "+
				"unrelated tip happened to be old enough", h)
		}
	}
}

// TestFV22NoBlockRevertIsIndependentOfTheNodeClock is the change-2 proof.
//
// The same block, the same parent, evaluated under two very different node clock
// states, must produce the same verdict. MedianAdjustedTime is
// max(TimeSource.AdjustedTime(), MedianTimePast+1s), so moving MedianTimePast moves
// exactly the quantity F-057 fed into the decision.
//
// MUTATION PROOF: re-add
//
//	if height >= gate { if MedianAdjustedTime().Unix()-lastBlockTime < noBlockTime { reject } }
//
// and the two clock states disagree at/above gate 1, which is precisely the
// "two honest nodes, identical chain state, opposite verdicts" failure.
func TestFV22NoBlockRevertIsIndependentOfTheNodeClock(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000

	clockStates := []struct {
		name  string
		floor time.Time
	}{
		{"node clock far behind the block timestamps", time.Unix(1, 0)},
		{"node clock past the block timestamps",
			time.Unix(int64(base)+int64(fv22NoBlockTime)+int64(MaxTimeOffsetSeconds)+1, 0)},
		{"node clock at the parent", time.Unix(int64(base), 0)},
	}

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1, 3_000_000} {
		var first bool
		for i, cs := range clockStates {
			b.MedianTimePast = cs.floor
			ok, msg := fv22Verdict(t, b, h, base, base+fv22Threshold(h), base)
			if i == 0 {
				first = ok
				if !ok {
					t.Fatalf("height %d: a genuine >=noBlockTime gap against the block's "+
						"own parent must be ACCEPTED regardless of where the node's "+
						"clock is (%s): %s", h, cs.name, msg)
				}
				continue
			}
			if ok != first {
				t.Fatalf("CLOCK IN CONSENSUS at height %d: the same block and the same "+
					"parent produced verdict %v with the first clock state and %v with "+
					"%q — two honest nodes with identical chain state can disagree",
					h, first, ok, cs.name)
			}
		}
	}
	b.MedianTimePast = time.Time{}
}

// TestFV22OptionBGateOneDiscontinuityIsExactlyTheIntendedOne pins the ONE behavioural
// step option (b) introduces at gate 1 — no more and no less.
//
// Below the gate the legacy rule must be untouched (retained history replays
// byte-identically); at and above it the demanded gap is noBlockTime +
// MaxTimeOffsetSeconds. The band in between — a gap that clears noBlockTime but not
// noBlockTime+MaxTimeOffsetSeconds — is the forgeable band, and it is precisely where
// the two verdicts must differ. Everything outside that band must still agree, so a
// sloppier gate (e.g. one that also moved the rule for gaps that already cleared both
// thresholds) fails here.
func TestFV22OptionBGateOneDiscontinuityIsExactlyTheIntendedOne(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000
	optB := fv22NoBlockTime + uint32(MaxTimeOffsetSeconds)

	for _, c := range []struct {
		name          string
		gap           uint32
		wantBelow     bool
		wantAtOrAbove bool
	}{
		{"gap one second short of the legacy threshold", fv22NoBlockTime - 1, false, false},
		{"gap exactly at the legacy threshold", fv22NoBlockTime, true, false},
		{"gap inside the forgeable band", fv22NoBlockTime + uint32(MaxTimeOffsetSeconds)/2, true, false},
		{"gap one second short of the option-(b) threshold", optB - 1, true, false},
		{"gap exactly at the option-(b) threshold", optB, true, true},
		{"gap far beyond both thresholds", 10 * fv22NoBlockTime, true, true},
	} {
		below, belowMsg := fv22Verdict(t, b, wiringBelowGate, base, base+c.gap, base)
		at, atMsg := fv22Verdict(t, b, wiringGate, base, base+c.gap, base)
		above, _ := fv22Verdict(t, b, wiringGate+500_000, base, base+c.gap, base)

		if below != c.wantBelow {
			t.Fatalf("%s: BELOW gate 1 the legacy rule must be untouched — want accept=%v, "+
				"got accept=%v (%s). Retained history no longer replays byte-identically.",
				c.name, c.wantBelow, below, belowMsg)
		}
		if at != c.wantAtOrAbove {
			t.Fatalf("%s: AT gate 1 option (b) must demand noBlockTime+MaxTimeOffsetSeconds — "+
				"want accept=%v, got accept=%v (%s)", c.name, c.wantAtOrAbove, at, atMsg)
		}
		if above != at {
			t.Fatalf("%s: the rule must not move again above gate 1 (at=%v above=%v) — "+
				"a second activation height has appeared", c.name, at, above)
		}
	}
}

// TestFV22OptionBRejectsTheForgedStall is the F-057 fail-on-pristine proof, driven
// through the production block path.
//
// THE FORGERY. RevertToPOWNoBlockTimeV1 (7200s) EQUALS MaxTimeOffsetSeconds (7200s),
// and CheckBlockSanity only bounds a header at AdjustedTime+MaxTimeOffsetSeconds. So a
// producer can post-date its own header by exactly MaxTimeOffsetSeconds and claim a
// full stall with ZERO elapsed time since the parent. Below gate 1 that is upstream
// behaviour and must still be ACCEPTED (retained history). At and above gate 1 option
// (b) must REJECT it.
//
// MUTATION PROOF: revert the option-(b) hunk in
// core/transaction/reverttopowtransaction.go and the at/above-gate cases below are
// ACCEPTED — the assertion fails naming the exploit. DELETE the production call site
// instead — the `SpecialContextCheck()` call in
// core/transaction/transactionchecker.go ContextCheck, or the
// `CheckTransactionContextWithPrev(prevNode, ...)` call in checkTxsContext — and it
// STILL fails, because the forged block is submitted to the block path and every
// no-block condition disappears with the call site.
func TestFV22OptionBRejectsTheForgedStall(t *testing.T) {
	b := fv22Chain(t)
	// A healthy chain: the parent landed "just now", so ZERO real time has elapsed.
	parentTs := uint32(time.Now().Unix())
	// The most a producer can forge: the header is post-dated by the full sanity
	// allowance. It lands exactly on the legacy threshold with no genuine stall.
	forged := parentTs + uint32(MaxTimeOffsetSeconds)

	for _, h := range []uint32{wiringGate, wiringGate + 1, 3_000_000} {
		ok, _ := fv22Verdict(t, b, h, parentTs, forged, parentTs)
		if ok {
			t.Fatalf("F-057 LIVE at height %d: a RevertToPOW(NoBlock) block whose header is "+
				"post-dated by MaxTimeOffsetSeconds (%d) over a parent that landed with ZERO "+
				"elapsed time was ACCEPTED — a producer can force DPoS->POW at will",
				h, MaxTimeOffsetSeconds)
		}
	}

	// Below the gate the same forgery must still be accepted: that is what mainnet ran,
	// and changing it would break replay of the retained chain.
	for _, h := range []uint32{wiringBelowGate, wiringBelowGate - 100_000} {
		if ok, msg := fv22Verdict(t, b, h, parentTs, forged, parentTs); !ok {
			t.Fatalf("height %d is BELOW gate 1: the legacy comparison must be unchanged, "+
				"but the block was rejected (%s) — retained history would no longer replay",
				h, msg)
		}
	}
}

// TestFV22OptionBAcceptsAGenuineStall is the no-false-rejects control: option (b)
// raises the bar, it does not remove the failsafe. A stall that genuinely exceeds the
// new threshold must still be accepted at and above gate 1.
func TestFV22OptionBAcceptsAGenuineStall(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000
	optB := fv22NoBlockTime + uint32(MaxTimeOffsetSeconds)

	for _, h := range []uint32{wiringGate, wiringGate + 1, 3_000_000} {
		for _, gap := range []uint32{optB, optB + 1, optB + 3600, 10 * optB} {
			if ok, msg := fv22Verdict(t, b, h, base, base+gap, base); !ok {
				t.Fatalf("height %d: a genuine stall of %ds clears the option-(b) threshold "+
					"(%ds) and must be ACCEPTED — the emergency failsafe has been disabled, "+
					"not hardened: %s", h, gap, optB, msg)
			}
		}
	}
}

// TestFV22ThresholdStillBites is the positive control for the whole file: the
// deterministic condition must still reject a block that does not clear the no-block
// interval against its own parent, and accept one that does. Without this a fix that
// simply deleted the check would satisfy every test above.
func TestFV22ThresholdStillBites(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000

	for _, h := range []uint32{wiringBelowGate, wiringGate, 3_000_000} {
		want := fv22Threshold(h)
		if ok, msg := fv22Verdict(t, b, h, base, base+want, base); !ok {
			t.Fatalf("height %d: a gap of exactly the demanded threshold (%d) must be "+
				"accepted: %s", h, want, msg)
		}
		ok, msg := fv22Verdict(t, b, h, base, base+want-1, base)
		if ok {
			t.Fatalf("height %d: a gap one second short of the demanded threshold (%d) must "+
				"be REJECTED — the no-block condition has been removed, not made "+
				"deterministic", h, want)
		}
		if !strings.Contains(msg, "CheckTransactionContext failed when verify block") {
			t.Fatalf("height %d: rejected for the wrong reason: %s", h, msg)
		}
	}
}

// fv22CountingTimeSource wraps a real MedianTimeSource and counts every read of the
// node's clock. It is the instrument for the regression test below.
type fv22CountingTimeSource struct {
	MedianTimeSource
	reads int
}

func (c *fv22CountingTimeSource) AdjustedTime() time.Time {
	c.reads++
	return c.MedianTimeSource.AdjustedTime()
}

// TestFV22OptionBConsultsNoNodeLocalTimeSource is the regression guard that makes the
// F-057 mistake unreintroducible.
//
// The at/above-gate in-block decision must be a pure function of consensus data —
// the block's header timestamp and its parent's timestamp. If ANY node-local clock is
// consulted there, two honest nodes with identical chain state can disagree, which is
// exactly why change 2 was withdrawn. The assertion is behavioural, not textual: the
// node's own time source is replaced by a counting wrapper and the count must be zero
// across the whole production block path.
//
// The counter is positive-controlled against the mempool-admission leg
// (CheckTransactionContext with timeStamp == 0), which DELIBERATELY still uses local
// time — a relay decision, not a block-acceptance decision. That leg must show reads,
// which proves the instrument works and that a zero above is a real result rather than
// a wrapper that never got installed.
func TestFV22OptionBConsultsNoNodeLocalTimeSource(t *testing.T) {
	b := fv22Chain(t)
	counter := &fv22CountingTimeSource{MedianTimeSource: b.TimeSource}
	b.TimeSource = counter

	base := uint32(time.Now().Unix()) + 3_000_000
	optB := fv22NoBlockTime + uint32(MaxTimeOffsetSeconds)

	for _, h := range []uint32{wiringGate, wiringGate + 1, 3_000_000} {
		for _, gap := range []uint32{0, fv22NoBlockTime, optB - 1, optB, 10 * optB} {
			fv22Verdict(t, b, h, base, base+gap, base)
		}
	}
	if counter.reads != 0 {
		t.Fatalf("CLOCK IN CONSENSUS: the at/above-gate in-block RevertToPOW decision read "+
			"the node's own time source %d times. F-057's withdrawn leg (or an equivalent) "+
			"has been reintroduced: two honest nodes with identical chain state and "+
			"different peer sets can now reach opposite verdicts on the same block",
			counter.reads)
	}

	// Positive control: the mempool-admission leg (timeStamp == 0) is the production
	// call the tx pool makes, and it is meant to consult local time.
	b.BestChain = &BlockNode{Hash: &common.Uint256{0xAA}, Height: wiringGate - 1, Timestamp: base}
	poolTx := functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		&payload.RevertToPOW{Type: payload.NoBlock, WorkingHeight: wiringGate},
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		nil,
	)
	if _, err := b.CheckTransactionContext(wiringGate, poolTx, 0, 0); err == nil {
		t.Fatal("fixture: the mempool leg was expected to reject this transaction")
	}
	if counter.reads == 0 {
		t.Fatal("instrument broken: the counting time source recorded no reads even on the " +
			"mempool leg, which does use local time — the zero above proves nothing")
	}
}
