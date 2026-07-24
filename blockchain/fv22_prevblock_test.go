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
//
// These tests drive the PRODUCTION function that owns the call site,
// (*BlockChain).checkTxsContext — the same function CheckBlockContext calls on every
// connected block — with a REAL RevertToPOW transaction inside a real block. Nothing
// about the decision is re-implemented here; the only inputs varied are the parent
// timestamp, the block timestamp, the node's best tip and the node's clock floor.
//
// FAIL-ON-PRISTINE, both halves:
//   - change 1: at pristine HEAD the verdict follows BestChain, so every case below
//     where parent and tip disagree comes out inverted.
//   - change 2: at pristine HEAD, at/above gate 1, a block whose timestamps sit in the
//     future is REJECTED however genuine the stall, because the node's clock has not
//     reached them — and the same inputs yield a DIFFERENT verdict once the clock floor
//     moves. Both assertions are made explicitly.
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

// fv22NoBlockTime is RevertToPOWNoBlockTimeV1 (2h) — the threshold in force at every
// height used here (all above ChangeViewV1Height).
const fv22NoBlockTime = uint32(2 * 3600)

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
		ok, msg := fv22Verdict(t, b, h, base, base+fv22NoBlockTime, base+fv22NoBlockTime)
		if !ok {
			t.Fatalf("FV-22 UNWIRED at height %d: the no-block interval is measured "+
				"against the validating node's tip, not the block's own parent "+
				"(parent says the interval elapsed): %s", h, msg)
		}

		// Direction 2: the PARENT says almost no time elapsed; the node's own tip says a
		// full interval did. Binding to the parent must REJECT.
		ok, _ = fv22Verdict(t, b, h, base, base+100, base-fv22NoBlockTime)
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
		{"node clock past the block timestamps", time.Unix(int64(base)+int64(fv22NoBlockTime)+1, 0)},
		{"node clock at the parent", time.Unix(int64(base), 0)},
	}

	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1, 3_000_000} {
		var first bool
		for i, cs := range clockStates {
			b.MedianTimePast = cs.floor
			ok, msg := fv22Verdict(t, b, h, base, base+fv22NoBlockTime, base)
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

// TestFV22GateOneIsNoLongerADiscontinuity records the shipped contract: after the
// withdrawal the NoBlock rule is the SAME rule above and below gate 1, so no
// coordinated activation is needed for it and no third gate exists. A future change
// that re-introduces a gate-1-only leg makes this fail.
func TestFV22GateOneIsNoLongerADiscontinuity(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000

	for _, c := range []struct {
		name     string
		parentTs uint32
		blockTs  uint32
	}{
		{"gap exactly at the threshold", base, base + fv22NoBlockTime},
		{"gap one second short", base, base + fv22NoBlockTime - 1},
		{"gap far beyond the threshold", base, base + 10*fv22NoBlockTime},
	} {
		below, _ := fv22Verdict(t, b, wiringBelowGate, c.parentTs, c.blockTs, c.parentTs)
		at, _ := fv22Verdict(t, b, wiringGate, c.parentTs, c.blockTs, c.parentTs)
		above, _ := fv22Verdict(t, b, wiringGate+500_000, c.parentTs, c.blockTs, c.parentTs)
		if below != at || at != above {
			t.Fatalf("%s: the NoBlock rule is not gate-uniform (below=%v at=%v above=%v) — "+
				"an acceptance discontinuity has been re-introduced at gate 1",
				c.name, below, at, above)
		}
	}
}

// TestFV22ThresholdStillBites is the positive control for the whole file: the
// deterministic condition that remains must still reject a block that does not clear
// the no-block interval against its own parent, and accept one that does. Without this
// a fix that simply deleted the check would satisfy every test above.
func TestFV22ThresholdStillBites(t *testing.T) {
	b := fv22Chain(t)
	base := uint32(time.Now().Unix()) + 3_000_000

	for _, h := range []uint32{wiringBelowGate, wiringGate, 3_000_000} {
		if ok, msg := fv22Verdict(t, b, h, base, base+fv22NoBlockTime, base); !ok {
			t.Fatalf("height %d: a gap of exactly noBlockTime must be accepted: %s", h, msg)
		}
		ok, msg := fv22Verdict(t, b, h, base, base+fv22NoBlockTime-1, base)
		if ok {
			t.Fatalf("height %d: a gap one second short of noBlockTime must be REJECTED — "+
				"the no-block condition has been removed, not made deterministic", h)
		}
		if !strings.Contains(msg, "CheckTransactionContext failed when verify block") {
			t.Fatalf("height %d: rejected for the wrong reason: %s", h, msg)
		}
	}
}
