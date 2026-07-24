// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-19 — the F-031 coinbase LockTime pin had ZERO production enforcement.
//
// The pin was written into CoinBaseTransaction.SpecialContextCheck and the shipped test
// (core/transaction/f031_coinbase_test.go, now deleted) called that method DIRECTLY, so it
// was green against a guard nothing on the block-connect path ever reaches: the method's
// only caller is the coinbase's own ContextCheck, whose only non-test caller is
// BlockChain.CheckTransactionContext, and all four call sites of that function structurally
// exclude the coinbase (checkTxsContext and pow/service.go iterate from index 1; the mempool
// rejects a coinbase outright). That test would have passed on a tree where the pin did not
// exist at all — which is precisely the failure mode this file exists to make impossible.
//
// These tests drive the REAL (*BlockChain).checkTxsContext — the production function that
// owns the relocated call site, on the block-connect path — using the wiring_bip30_test.go
// harness. The baseline control proves the block is otherwise accepted, so the ONLY thing
// that can produce a rejection is the checkCoinbaseLockTimePin call site inside
// checkCoinbaseTransactionContext.
//
// MUTATION PROOF (run, recorded in the batch report): delete the checkCoinbaseLockTimePin
// call from checkCoinbaseTransactionContext -> the at/above-gate cases return nil -> these
// tests FAIL. Restoring the pin ONLY in the coinbase's SpecialContextCheck (i.e. reverting
// to the shipped F-031 shape) does NOT make them pass, which is the whole point.
//
// FV-22 REBASE NOTE (why these call sites pass nil). checkTxsContext now takes the block's
// own parent as a second argument, so the RevertToPOW no-block rule is evaluated against
// the block's ancestry instead of the validating node's tip. nil here is DELIBERATE, not
// convenience: fv19Block builds a block whose ONLY transaction is the coinbase, and
// prevNode is consumed exclusively inside the `for i := 1; i < len(block.Transactions)`
// loop in checkTxsContext, which therefore never executes for these blocks. Neither
// checkCoinbaseBIP30 nor checkCoinbaseLockTimePin -- the two guards every assertion below
// keys on -- takes a parent. So no FV-19 assertion can read prevNode and nil cannot
// silently weaken one; a synthetic parent would be unreachable dead weight.
package blockchain

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// fv19Block is bip30Block with the coinbase LockTime under test control. Everything else —
// the reward split checkCoinbaseTransactionContext validates — is exactly what production
// expects, so a clean block returns nil and LockTime is the only variable.
func fv19Block(t *testing.T, b *BlockChain, height, lockTime uint32) *types.Block {
	t.Helper()
	total, err := b.coinbaseTotalReward(height, 0)
	if err != nil {
		t.Fatalf("coinbaseTotalReward: %v", err)
	}
	expected := total - common.Fixed64(math.Ceil(float64(total)*0.35))

	cb := functions.CreateTransaction(
		common2.TxVersion09,
		common2.CoinBase,
		payload.CoinBaseVersion,
		&payload.CoinBase{Content: []byte{0x19, byte(height), byte(height >> 8), byte(lockTime)}},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 65535},
			Sequence: 4294967295,
		}},
		[]*common2.Output{
			{AssetID: core.ELAAssetID, Value: expected, ProgramHash: common.Uint168{},
				Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 0, ProgramHash: common.Uint168{},
				Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
		},
		lockTime,
		[]*program.Program{},
	)
	return &types.Block{
		Header:       common2.Header{Height: height, Timestamp: uint32(time.Now().Unix())},
		Transactions: []interfaces.Transaction{cb},
	}
}

// TestFV19BaselineHonestCoinbaseAccepted is the positive control. An honest coinbase sets
// LockTime = its own block height (pow/service.go does exactly this), and that block must
// be accepted at every height — otherwise every rejection below would be meaningless.
func TestFV19BaselineHonestCoinbaseAccepted(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)
	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		if err := b.checkTxsContext(fv19Block(t, b, h, h), nil); err != nil {
			t.Fatalf("baseline: an honest coinbase (LockTime == height) at %d must be "+
				"accepted, got: %v", h, err)
		}
	}
}

// TestFV19ImmatureCoinbaseRejectedOnTheConnectPath is the finding's proof.
//
// LockTime = 0 makes checkInvalidUTXO compute currentHeight-0 >= CoinbaseMaturity for every
// height, so the producer's own reward output (coinbase Outputs[1], paid to an address of
// its choosing) is spendable immediately instead of after 100 blocks. LockTime > height
// makes the same uint32 subtraction UNDERFLOW to ~4e9, with the same result. Both must be
// rejected at and above gate 1.
func TestFV19ImmatureCoinbaseRejectedOnTheConnectPath(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)

	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		for name, lock := range map[string]uint32{
			"LockTime=0 (mature immediately)":     0,
			"LockTime>height (uint32 underflow)":  h + 1000,
			"LockTime<height (stale, not pinned)": h - 1,
		} {
			err := b.checkTxsContext(fv19Block(t, b, h, lock), nil)
			if err == nil {
				t.Fatalf("FV-19 at height %d, %s: checkTxsContext ACCEPTED a coinbase whose "+
					"LockTime is not its block height — the pin is not enforced on the "+
					"block-connect path (coinbase maturity / reorg-safety window bypassed)",
					h, name)
			}
			if !strings.Contains(bip30Err(err), "coinbase locktime must equal block height") {
				t.Fatalf("at height %d, %s: rejected for the WRONG reason: %v", h, name, err)
			}
		}
	}
}

// TestFV19BelowGateStaysLegacy is the retained-history guarantee: below
// StrictMoneyRangeHeight the identical malformed coinbase must still be ACCEPTED, so replay
// of [0, 2260450] is byte-identical. A call site that passed a literal 0 gate would break
// replay and is caught here.
func TestFV19BelowGateStaysLegacy(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)
	for _, h := range []uint32{wiringBelowGate - 1_000_000, wiringBelowGate} {
		if err := b.checkTxsContext(fv19Block(t, b, h, 0), nil); err != nil {
			t.Fatalf("REPLAY BREAK at height %d: a LockTime=0 coinbase below the gate must be "+
				"accepted (legacy behaviour), got: %v", h, err)
		}
	}
}

// TestFV19GateArgumentIsTheCampaignGate moves the chain's own StrictMoneyRangeHeight and
// asserts the decision boundary moves with it — i.e. the call site passes
// b.chainParams.StrictMoneyRangeHeight and the block's OWN height, not a constant. This is
// also what pins the fix to gate 1 and proves no third gate was introduced.
func TestFV19GateArgumentIsTheCampaignGate(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)
	moved := uint32(900_000)
	b.chainParams.StrictMoneyRangeHeight = moved

	if err := b.checkTxsContext(fv19Block(t, b, moved-1, 0), nil); err != nil {
		t.Fatalf("below the moved gate a LockTime=0 coinbase must be accepted, got: %v", err)
	}
	if err := b.checkTxsContext(fv19Block(t, b, moved, 0), nil); err == nil {
		t.Fatal("at the moved gate a LockTime=0 coinbase must be rejected: the call site does " +
			"not pass b.chainParams.StrictMoneyRangeHeight")
	}
}
