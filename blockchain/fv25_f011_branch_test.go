// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-25 leg — the F-011 BRANCH SELECTION was uncovered.
//
// blockchain/f011_wiring_test.go constructs a bare &BlockChain{} and calls
// GetBlockDPOSReward, GetBlockDPOSRewardStrict and checkCoinbaseTransactionContext by
// hand. It genuinely drives the enforcement function and demonstrates accept-vs-reject
// on both bases -- but it never runs checkTxsContext, so the height fork that SELECTS
// between the two bases (blockvalidator.go, `if block.Height >=
// b.chainParams.RevisedDPoSRewardHeight`) is never executed and could be reverted with
// the test still green.
//
// This drives the real (*BlockChain).checkTxsContext and pins the selection itself.
//
// FAIL-ON-PRISTINE / MUTATION: replace the fork with either branch unconditionally and
// one of the two arms below fails. The coinbase is sized on the STRICT basis, so:
//
//	always-strict : the BELOW-gate arm wrongly ACCEPTS   -> test fails
//	always-legacy : the AT/ABOVE-gate arm wrongly REJECTS -> test fails
package blockchain

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// fv25Arbiters keeps checkCoinbaseTransactionContext on its DPoSV2 branch -- the only
// branch that reads the dposReward argument the height fork produces. (The
// non-DPoSV2 branch recomputes the arbiter leg locally and ignores the argument
// entirely, which is precisely why a test that does not pin this branch proves
// nothing about the fork.)
type fv25Arbiters struct{ state.Arbitrators }

func (fv25Arbiters) GetDPoSV2ActiveHeight() uint32       { return 1_413_578 }
func (fv25Arbiters) GetFinalRoundChange() common.Fixed64 { return 0 }
func (fv25Arbiters) GetArbitersRoundReward() map[common.Uint168]common.Fixed64 {
	return nil
}

const (
	fv25Revised  = uint32(2_265_000) // RevisedDPoSRewardHeight
	fv25CoinFee  = common.Fixed64(1_000_000)
	fv25MoneyGte = uint32(2_260_451) // StrictMoneyRangeHeight
)

// fv25Chain wires a BlockChain onto the recording store with the DPoSV2 arbiters mock.
func fv25Chain(t *testing.T) *BlockChain {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = fv25MoneyGte
	params.RevisedDPoSRewardHeight = fv25Revised

	prev := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: fv25Arbiters{}}
	t.Cleanup(func() { DefaultLedger = prev })

	return &BlockChain{
		chainParams: params,
		db:          &bip30Store{dup: map[common.Uint256]bool{}},
		state:       &state.State{StateKeyFrame: &state.StateKeyFrame{}},
		TimeSource:  NewMedianTime(),
	}
}

// fv25Block builds a single-coinbase block whose three DPoSV2 reward legs are sized on
// the STRICT (ELA-filtered) basis, and whose coinbase reports a non-zero Fee().
//
// The coinbase fee is the one input that separates the two bases without a second
// transaction: GetBlockDPOSReward sums tx.Fee() over ALL block transactions INCLUDING
// index 0, while checkTxsContext's own totalTxFee sums from i = 1. So the legacy basis
// sees fee+subsidy and the strict basis sees subsidy alone, and the arbiter leg differs
// by exactly ceil(0.35 x fee) -- the same shape as the real defect, where a NON-ELA fee
// inflates the leg above its ELA backing.
func fv25Block(t *testing.T, b *BlockChain, height uint32) *types.Block {
	t.Helper()
	total, err := b.coinbaseTotalReward(height, 0)
	if err != nil {
		t.Fatalf("coinbaseTotalReward: %v", err)
	}
	cr := common.Fixed64(math.Ceil(float64(total) * 0.3))
	arbStrict := common.Fixed64(math.Ceil(float64(total) * 0.35))
	miner := total - cr - arbStrict

	out := func(v common.Fixed64, ph common.Uint168) *common2.Output {
		return &common2.Output{AssetID: core.ELAAssetID, Value: v, ProgramHash: ph,
			Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}}
	}
	cb := functions.CreateTransaction(
		common2.TxVersion09, common2.CoinBase, payload.CoinBaseVersion,
		&payload.CoinBase{Content: []byte{byte(height), byte(height >> 8)}},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 65535},
			Sequence: 4294967295,
		}},
		[]*common2.Output{
			out(cr, *b.chainParams.CRConfiguration.CRAssetsProgramHash),
			out(miner, common.Uint168{}),
			out(arbStrict, *b.chainParams.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash),
		},
		height,
		[]*program.Program{},
	)
	cb.SetFee(fv25CoinFee)

	return &types.Block{
		Header:       common2.Header{Height: height, Timestamp: uint32(time.Now().Unix())},
		Transactions: []interfaces.Transaction{cb},
	}
}

// prevNode is nil throughout: checkTxsContext only dereferences it inside the
// `for i := 1` non-coinbase loop (FV-22 context binding), and every block built here
// carries the coinbase ALONE, so the loop body never runs. Same convention as the
// sibling blockchain suites (wiring_bip30_test.go, fv19_coinbase_locktime_test.go).
//
// TestFV25F011BranchSelectionIsExecuted pins the height fork itself.
func TestFV25F011BranchSelectionIsExecuted(t *testing.T) {
	b := fv25Chain(t)

	t.Run("at and above RevisedDPoSRewardHeight the STRICT basis is used", func(t *testing.T) {
		for _, h := range []uint32{fv25Revised, fv25Revised + 1} {
			if err := b.checkTxsContext(fv25Block(t, b, h), nil); err != nil {
				t.Fatalf("FV-25/F-011 at height %d: a coinbase sized on the ELA-filtered "+
					"basis must be ACCEPTED at and above RevisedDPoSRewardHeight; the "+
					"branch selection is not reaching GetBlockDPOSRewardStrict: %v", h, err)
			}
		}
	})

	t.Run("below RevisedDPoSRewardHeight the LEGACY basis is used", func(t *testing.T) {
		for _, h := range []uint32{fv25Revised - 1, fv25Revised - 100_000} {
			err := b.checkTxsContext(fv25Block(t, b, h), nil)
			if err == nil {
				t.Fatalf("FV-25/F-011 at height %d: below RevisedDPoSRewardHeight the "+
					"all-asset basis (GetBlockDPOSReward, which sums tx.Fee() over every "+
					"block transaction) must still be used, so a strict-basis coinbase is "+
					"REJECTED. Accepting it means the branch selection was removed and "+
					"the reward rule activated early -- a fleet split at the restart.", h)
			}
			if !strings.Contains(err.Error(), "last DPoS reward value not correct") {
				t.Fatalf("FV-25/F-011 at height %d: rejected for the wrong reason: %v", h, err)
			}
		}
	})

	t.Run("the boundary follows chainParams, not a constant", func(t *testing.T) {
		moved := uint32(1_900_000)
		orig := b.chainParams.RevisedDPoSRewardHeight
		b.chainParams.RevisedDPoSRewardHeight = moved
		defer func() { b.chainParams.RevisedDPoSRewardHeight = orig }()

		if err := b.checkTxsContext(fv25Block(t, b, moved), nil); err != nil {
			t.Fatalf("FV-25/F-011: the decision boundary must move with "+
				"chainParams.RevisedDPoSRewardHeight; at the moved gate the strict "+
				"coinbase was rejected: %v", err)
		}
		if err := b.checkTxsContext(fv25Block(t, b, moved-1), nil); err == nil {
			t.Fatal("FV-25/F-011: below the MOVED gate the legacy basis must still apply; " +
				"the call site is not reading chainParams.RevisedDPoSRewardHeight")
		}
	})
}
