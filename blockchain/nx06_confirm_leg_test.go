// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-06 — peer-supplied block Confirm accepted and PERSISTED with no membership or
// quorum check on the acceptance legs that skip checkBlockWithConfirmation.
//
// These tests drive the PRODUCTION function that owns the decision,
// (*BlockChain).connectBlockBracketed — not a helper, not a copy of the predicate.
// Every assertion is a comparison between two outcomes of that one function:
//
//	NX-06 refusal ......... "carries a confirm on an acceptance leg"
//	sentinel (no refusal) . "connectBlock must be called with a block that extends
//	                         the main chain"
//
// The sentinel is reached only if execution flows PAST the refusal, so deleting the
// refusal from connectBlockBracketed turns every "must be refused" case into the
// sentinel and this file goes red. That is the fail-on-pristine property: at pristine
// HEAD (and under any mutation that removes the call site) the forged confirm is
// accepted here and then persisted by dbStoreBlock a few lines further down.
package blockchain

import (
	"strings"
	"testing"

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

const nx06Sentinel = "connectBlock must be called with a block that extends the main chain"
const nx06Refusal = "carries a confirm on an acceptance leg"

// nx06Chain builds the minimum connectBlockBracketed needs to reach the confirm
// decision and, when no refusal fires, to fall through to the sentinel.
//
// BestChain deliberately holds a hash that is NOT the block's Previous, so the
// extends-the-main-chain check downstream of the confirm decision produces a distinct,
// recognisable error. Nothing between the refusal and that check is stubbed out.
func nx06Chain(t *testing.T, algo state.ConsesusAlgorithm) *BlockChain {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = wiringGate

	prev := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: &state.ArbitratorsMock{}}
	t.Cleanup(func() { DefaultLedger = prev })

	st := &state.State{StateKeyFrame: &state.StateKeyFrame{}}
	st.ConsensusAlgorithm = algo

	otherHash := common.Uint256{0xAA}
	return &BlockChain{
		chainParams: params,
		state:       st,
		BestChain:   &BlockNode{Hash: &otherHash},
		TimeSource:  NewMedianTime(),
	}
}

// nx06RevertToPOWTx builds the real RevertToPOW transaction whose presence in a block
// flips the revertToPOW leg (LEG B).
func nx06RevertToPOWTx(height uint32) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		&payload.RevertToPOW{Type: payload.NoBlock, WorkingHeight: height},
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		nil,
	)
}

// nx06Block returns a block at `height`, optionally carrying a RevertToPOW tx, plus a
// block node for it whose Parent is nil (so CheckBlockContext returns immediately and
// the confirm decision is the only thing under test).
func nx06Block(height uint32, withRevertToPOW bool) (*types.Block, *BlockNode) {
	txs := []interfaces.Transaction{}
	if withRevertToPOW {
		txs = append(txs, nx06RevertToPOWTx(height))
	}
	blk := &types.Block{
		Header: common2.Header{
			Height:    height,
			Previous:  common.Uint256{0xBB},
			Timestamp: 1600000000,
		},
		Transactions: txs,
	}
	h := blk.Hash()
	return blk, &BlockNode{Hash: &h, Height: height, Parent: nil}
}

// nx06ForgedConfirm is what an attacker with NO keys, NO membership and NO hashpower
// can staple to an honest block: the Confirm is outside Block.Hash(), so it never
// disturbs the proof of work. Sponsor is arbitrary bytes and Votes is empty — exactly
// the shape ConfirmSanityCheck accepts and ConfirmContextCheck would reject.
func nx06ForgedConfirm(blockHash common.Uint256) *payload.Confirm {
	return &payload.Confirm{
		Proposal: payload.DPOSProposal{
			Sponsor:   []byte{0x03, 0xda, 0x06, 0x59, 0x3d, 0x98},
			BlockHash: blockHash,
			Sign:      []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}
}

func nx06Err(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestNX06ForgedConfirmRefusedOnUnvalidatedLegs is the fix proof.
//
// Both legs at/above gate 1 must be REFUSED:
//
//	LEG A  the node's dpos state is ConsensusAlgorithm == POW
//	LEG B  the block carries a RevertToPOW transaction
//
// MUTATION PROOF: delete the refusal block from connectBlockBracketed (or neuter its
// condition) and both subtests report the sentinel instead — i.e. the forged confirm
// flowed on towards dbStoreBlock/SaveBlock, which is the defect.
func TestNX06ForgedConfirmRefusedOnUnvalidatedLegs(t *testing.T) {
	cases := []struct {
		name     string
		algo     state.ConsesusAlgorithm
		revertTx bool
	}{
		{"LEG A — chain in POW consensus mode", state.POW, false},
		{"LEG B — block carries a RevertToPOW tx", state.DPOS, true},
		{"both legs together", state.POW, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			b := nx06Chain(t, c.algo)
			for _, h := range []uint32{wiringGate, wiringGate + 1, wiringGate + 500000} {
				blk, node := nx06Block(h, c.revertTx)
				err := b.connectBlockBracketed(node, blk, nx06ForgedConfirm(blk.Hash()))
				if !strings.Contains(nx06Err(err), nx06Refusal) {
					t.Fatalf("NX-06 UNARMED at height %d (%s): a peer-supplied confirm that "+
						"nothing membership- or quorum-checks was NOT refused; "+
						"connectBlockBracketed returned: %s", h, c.name, nx06Err(err))
				}
			}
		})
	}
}

// TestNX06RideOnGateOne pins the activation to the one existing coordinated gate.
// Below StrictMoneyRangeHeight the legs stay open (replay-safety for retained
// history); at and above it they are closed. A call site that used a literal 0 gate
// would break the replay of retained history and is caught by the first loop; one that
// used MaxUint32 is caught by the second.
func TestNX06RideOnGateOne(t *testing.T) {
	b := nx06Chain(t, state.POW)

	for _, h := range []uint32{wiringGate - 1, wiringGate - 100000, 1000000} {
		blk, node := nx06Block(h, false)
		err := b.connectBlockBracketed(node, blk, nx06ForgedConfirm(blk.Hash()))
		if !strings.Contains(nx06Err(err), nx06Sentinel) {
			t.Fatalf("REPLAY BREAK at height %d: below gate 1 the confirm legs must stay "+
				"exactly as they were; got: %s", h, nx06Err(err))
		}
	}

	// Move the chain's own gate and assert the boundary moves with it — proving the
	// call site reads b.chainParams.StrictMoneyRangeHeight and the BLOCK's own height,
	// not a constant and not the current tip.
	moved := uint32(1500000)
	b.chainParams.StrictMoneyRangeHeight = moved

	blkBelow, nodeBelow := nx06Block(moved-1, false)
	if err := b.connectBlockBracketed(nodeBelow, blkBelow,
		nx06ForgedConfirm(blkBelow.Hash())); !strings.Contains(nx06Err(err), nx06Sentinel) {
		t.Fatalf("below the moved gate the confirm must still be accepted; got: %s", nx06Err(err))
	}
	blkAt, nodeAt := nx06Block(moved, false)
	if err := b.connectBlockBracketed(nodeAt, blkAt,
		nx06ForgedConfirm(blkAt.Hash())); !strings.Contains(nx06Err(err), nx06Refusal) {
		t.Fatalf("at the moved gate the confirm must be refused: the call site does not "+
			"read b.chainParams.StrictMoneyRangeHeight; got: %s", nx06Err(err))
	}
}

// TestNX06LeavesTheConfirmlessRescueBlockAlone is the liveness control, and it is the
// assertion that makes the refusal safe to ship.
//
// POW-mode blocks and RevertToPOW rescue blocks legitimately carry NO confirm — that
// is the confirm-exempt design. The refusal must fire on a PRESENT confirm only. If it
// keyed on the leg alone it would reject every rescue block and the emergency failsafe
// would never be able to fire; that regression is caught here.
func TestNX06LeavesTheConfirmlessRescueBlockAlone(t *testing.T) {
	for _, c := range []struct {
		name     string
		algo     state.ConsesusAlgorithm
		revertTx bool
	}{
		{"POW-mode block with no confirm", state.POW, false},
		{"RevertToPOW rescue block with no confirm", state.DPOS, true},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			b := nx06Chain(t, c.algo)
			for _, h := range []uint32{wiringGate, wiringGate + 1, wiringGate + 500000} {
				blk, node := nx06Block(h, c.revertTx)
				err := b.connectBlockBracketed(node, blk, nil)
				if !strings.Contains(nx06Err(err), nx06Sentinel) {
					t.Fatalf("LIVENESS BREAK at height %d (%s): a legitimately confirm-less "+
						"block must pass the confirm decision untouched; got: %s",
						h, c.name, nx06Err(err))
				}
			}
		})
	}
}

// TestNX06HealthyDPoSLegStillRunsTheRealCheck proves the refusal did not swallow the
// normal path: in DPoS mode, with no RevertToPOW tx, a present confirm must still be
// handed to checkBlockWithConfirmation (which rejects this one because its
// Proposal.BlockHash does not match the block). Reaching the sentinel here would mean
// the real membership/quorum check had been bypassed; reaching the NX-06 refusal would
// mean the refusal is over-broad and would kill every confirmed block.
func TestNX06HealthyDPoSLegStillRunsTheRealCheck(t *testing.T) {
	b := nx06Chain(t, state.DPOS)
	blk, node := nx06Block(wiringGate+10, false)

	mismatched := nx06ForgedConfirm(common.Uint256{0xCC})
	err := b.connectBlockBracketed(node, blk, mismatched)
	if !strings.Contains(nx06Err(err), "block confirmation validate failed") {
		t.Fatalf("the healthy DPoS leg must still route the confirm through "+
			"checkBlockWithConfirmation; got: %s", nx06Err(err))
	}
}

// TestNX06ConfirmIsOutsideBlockHash records the property the whole finding rests on:
// stapling a confirm to a block does not change the block's hash, so an attacker needs
// no hashpower — he takes an honest freshly-mined block off the wire and re-announces
// it with a confirm of his choosing.
func TestNX06ConfirmIsOutsideBlockHash(t *testing.T) {
	blk, _ := nx06Block(wiringGate, false)
	before := blk.Hash()
	db := &types.DposBlock{Block: blk, HaveConfirm: true, Confirm: nx06ForgedConfirm(before)}
	if !db.Block.Hash().IsEqual(before) {
		t.Fatal("attaching a confirm changed the block hash — the finding's premise " +
			"no longer holds and this batch must be re-derived")
	}
}
