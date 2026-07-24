// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TESTS — the F-093 / F-094 / F-106 special-tx bracket.
//
// The blocker: no-op'ing ALL SIX CommitPendingSpecialTx / UndoPendingSpecialTx call
// sites at HEAD left the entire suite green. The existing F-093 tests exercise the
// Arbiters METHODS (savepoint/commit/undo semantics) and their concurrency, never the
// production call sites that must invoke them.
//
// These tests install a RECORDING Arbitrators into DefaultLedger and drive the four
// production entry points that own the six sites, asserting the exact bracket sequence:
//
//	site 1  replayCheckpointBlock  — UndoPendingSpecialTx on PreProcessSpecialTx failure
//	site 2  replayCheckpointBlock  — CommitPendingSpecialTx on success
//	site 3  ProcessIllegalBlock    — CommitPendingSpecialTx (gossip path)
//	site 4  ProcessInactiveArbiter — CommitPendingSpecialTx (gossip path)
//	site 5  connectBlock           — UndoPendingSpecialTx on every failure exit
//	site 6  connectBlock           — CommitPendingSpecialTx on success
//
// Delete or no-op any one of them and the corresponding sequence assertion fails.
package blockchain

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// -----------------------------------------------------------------------------
// Recording Arbitrators. Only the bracket methods (plus the two lookups
// CheckInactiveArbitrators needs) are implemented; anything else panics, so a silent
// behaviour change on this path cannot pass unnoticed.
// -----------------------------------------------------------------------------

type recArbiters struct {
	state.Arbitrators
	mu    sync.Mutex
	calls []string

	// F-032 capture (see wiring_recordsponsor_test.go).

	// Set to stop CheckBlockContext immediately AFTER the F-032 call site, so the
	// argument assertions do not depend on the rest of block-context validation.
	illegalTxErr error
}

func (a *recArbiters) record(s string) {
	a.mu.Lock()
	a.calls = append(a.calls, s)
	a.mu.Unlock()
}

func (a *recArbiters) seq() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.calls))
	copy(out, a.calls)
	return out
}

func (a *recArbiters) LockSpecialTx()              { a.record("lock") }
func (a *recArbiters) UnlockSpecialTx()            { a.record("unlock") }
func (a *recArbiters) CommitPendingSpecialTx()     { a.record("commit") }
func (a *recArbiters) UndoPendingSpecialTx()       { a.record("undo") }
func (a *recArbiters) IsCRCArbitrator([]byte) bool { return false }
func (a *recArbiters) ProcessSpecialTxPayload(p interfaces.Payload, height uint32) error {
	a.record("process")
	return nil
}

// NX-01: the CheckRecordSponsorBinding hook is gone with the guard it recorded. The
// remaining CheckBlockContext hooks accept, so nothing but the sentinel below can reject.
func (a *recArbiters) CheckDPOSIllegalTx(block *types.Block) error      { return a.illegalTxErr }
func (a *recArbiters) CheckCRCAppropriationTx(block *types.Block) error { return nil }
func (a *recArbiters) CheckNextTurnDPOSInfoTx(block *types.Block) error { return nil }
func (a *recArbiters) CheckCustomIDResultsTx(block *types.Block) error  { return nil }

// -----------------------------------------------------------------------------
// Minimal store: connectBlock's persistence steps succeed without touching disk, so
// the ONLY observable is the bracket sequence.
// -----------------------------------------------------------------------------

type recFFLDB struct {
	IFFLDBChainStore
}

func (recFFLDB) Update(fn func(database.Tx) error) error { return nil }

// GetBlock reports "not stored", which is what makes CheckBlockContext take its
// documented block/confirm-cache fallback for the previous block.
func (recFFLDB) GetBlock(common.Uint256) (*types.DposBlock, error) {
	return nil, errors.New("not in store")
}

type recStore struct {
	IChainStore
	ffldb recFFLDB
}

func (s *recStore) GetFFLDB() IFFLDBChainStore { return s.ffldb }
func (s *recStore) SaveBlock(*types.Block, *BlockNode, *payload.Confirm, time.Time) error {
	return nil
}

// -----------------------------------------------------------------------------

func specialTxChain(t *testing.T) (*BlockChain, *recArbiters) {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()
	store := &recStore{}
	b := &BlockChain{
		chainParams: params,
		db:          store,
		index:       newBlockIndex(store, params),
		CkpManager:  checkpoint.NewManager(params),
		state: state.NewState(params, nil, nil, nil,
			func() bool { return false }, nil, nil, nil, nil, nil, nil, nil),
		TimeSource: NewMedianTime(),
		DepNodes:   make(map[common.Uint256][]*BlockNode),
		blockCache: make(map[common.Uint256]*types.Block),
	}

	arb := &recArbiters{}
	prevLedger := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: arb, Blockchain: b, Store: store}
	t.Cleanup(func() { DefaultLedger = prevLedger })
	return b, arb
}

// specialTxBlock is a plain block with no special transactions: PreProcessSpecialTx
// accepts it, so the bracket outcome is decided purely by the code path under test.
func specialTxBlock(height uint32, prev common.Uint256) *types.Block {
	cb := functions.CreateTransaction(
		common2.TxVersion09, common2.CoinBase, payload.CoinBaseVersion,
		&payload.CoinBase{Content: []byte{byte(height)}},
		[]*common2.Attribute{},
		[]*common2.Input{{Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 65535},
			Sequence: 4294967295}},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: 1, ProgramHash: common.Uint168{},
			Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}}},
		uint32(height), []*program.Program{})
	return &types.Block{
		Header:       common2.Header{Height: height, Previous: prev, Timestamp: 1},
		Transactions: []interfaces.Transaction{cb},
	}
}

// specialTxRejectedBlock carries an InactiveArbitrators tx whose sponsor is not a CRC
// arbiter, so PreProcessSpecialTx REJECTS it — the exact failure the undo site exists for.
func specialTxRejectedBlock(height uint32) *types.Block {
	blk := specialTxBlock(height, common.EmptyHash)
	ia := functions.CreateTransaction(
		common2.TxVersion09, common2.InactiveArbitrators, 0,
		&payload.InactiveArbitrators{Sponsor: []byte{0x02, 0x01}},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
	blk.Transactions = append(blk.Transactions, ia)
	return blk
}

func assertSeq(t *testing.T, arb *recArbiters, want []string, what string) {
	t.Helper()
	got := arb.seq()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WIRING SEVERED (%s): special-tx bracket sequence is %v, want %v.\n"+
			"A missing commit/undo means an emergency ForceChange either survives a rejected "+
			"block or is lost on an accepted one.", what, got, want)
	}
	if !containsAny(got, "commit", "undo") {
		t.Fatalf("WIRING SEVERED (%s): neither CommitPendingSpecialTx nor UndoPendingSpecialTx "+
			"was called", what)
	}
}

func containsAny(hay []string, needles ...string) bool {
	for _, h := range hay {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// SITES 3 and 4 — the two DPoS-gossip entry points.
// -----------------------------------------------------------------------------

// TestWiringSpecialTxBracketProcessIllegalBlock drives the REAL
// (*BlockChain).ProcessIllegalBlock. MUTATION PROOF: no-op the
// CommitPendingSpecialTx call there -> sequence becomes [lock process unlock] -> FAIL.
func TestWiringSpecialTxBracketProcessIllegalBlock(t *testing.T) {
	b, arb := specialTxChain(t)
	b.BestChain = &BlockNode{Height: 3, Hash: &common.Uint256{}}

	b.ProcessIllegalBlock(&payload.DPOSIllegalBlocks{})

	assertSeq(t, arb, []string{"lock", "process", "commit", "unlock"}, "ProcessIllegalBlock")
}

// TestWiringSpecialTxBracketProcessInactiveArbiter drives the REAL
// (*BlockChain).ProcessInactiveArbiter. MUTATION PROOF: no-op its
// CommitPendingSpecialTx call -> FAIL.
func TestWiringSpecialTxBracketProcessInactiveArbiter(t *testing.T) {
	b, arb := specialTxChain(t)
	b.BestChain = &BlockNode{Height: 3, Hash: &common.Uint256{}}

	b.ProcessInactiveArbiter(&payload.InactiveArbitrators{})

	assertSeq(t, arb, []string{"lock", "process", "commit", "unlock"}, "ProcessInactiveArbiter")
}

// -----------------------------------------------------------------------------
// SITES 5 and 6 — connectBlock's deferred commit/undo bracket.
// -----------------------------------------------------------------------------

// TestWiringSpecialTxBracketConnectBlockUndoesOnFailure drives the REAL
// (*BlockChain).connectBlock down a failure exit (the block does not extend the best
// chain) and asserts the deferred UNDO fires. This is the F-093 core property: a block
// that fails to connect must not leave the node rotated onto a rejected arbiter set.
//
// MUTATION PROOF: no-op UndoPendingSpecialTx in connectBlock's defer -> FAIL.
func TestWiringSpecialTxBracketConnectBlockUndoesOnFailure(t *testing.T) {
	b, arb := specialTxChain(t)
	tipHash := common.Uint256{0xAA}
	tip := &BlockNode{Height: 5, Hash: &tipHash}
	b.BestChain = tip

	// Previous != tip hash -> connectBlock returns the "extends the main chain" error.
	blk := specialTxBlock(6, common.Uint256{0xBB})
	node := &BlockNode{Height: 6, Hash: &common.Uint256{0xCC}, Parent: nil}

	if err := b.connectBlock(node, blk, nil); err == nil {
		t.Fatal("harness bug: connectBlock was expected to fail on this block")
	}
	assertSeq(t, arb, []string{"lock", "undo", "unlock"}, "connectBlock failure exit")
}

// TestWiringSpecialTxBracketConnectBlockCommitsOnSuccess drives the REAL
// (*BlockChain).connectBlock to a successful connect and asserts the deferred COMMIT
// fires. MUTATION PROOF: no-op CommitPendingSpecialTx in connectBlock's defer -> FAIL.
func TestWiringSpecialTxBracketConnectBlockCommitsOnSuccess(t *testing.T) {
	b, arb := specialTxChain(t)
	tipHash := common.Uint256{0xAA}
	tip := &BlockNode{Height: 5, Hash: &tipHash, Timestamp: 1}
	b.BestChain = tip
	b.SetTip(tip)

	blk := specialTxBlock(6, tipHash)
	nodeHash := blk.Hash()
	node := &BlockNode{Height: 6, Hash: &nodeHash, Parent: nil, Timestamp: 1}

	if err := b.connectBlock(node, blk, nil); err != nil {
		t.Fatalf("harness bug: connectBlock was expected to succeed, got: %v", err)
	}
	assertSeq(t, arb, []string{"lock", "commit", "unlock"}, "connectBlock success exit")
}

// -----------------------------------------------------------------------------
// SITES 1 and 2 — replayCheckpointBlock.
// -----------------------------------------------------------------------------

// TestWiringSpecialTxBracketReplayUndoesOnRejectedBlock drives the REAL
// (*BlockChain).replayCheckpointBlock with a block PreProcessSpecialTx rejects.
// MUTATION PROOF: no-op the UndoPendingSpecialTx call there -> FAIL.
func TestWiringSpecialTxBracketReplayUndoesOnRejectedBlock(t *testing.T) {
	b, arb := specialTxChain(t)

	err := b.replayCheckpointBlock(&types.DposBlock{Block: specialTxRejectedBlock(7)})
	if err == nil {
		t.Fatal("harness bug: PreProcessSpecialTx was expected to reject this block")
	}
	if !strings.Contains(err.Error(), "sponsor is not belong to arbitrators") {
		t.Fatalf("harness bug: rejected for an unexpected reason: %v", err)
	}
	assertSeq(t, arb, []string{"lock", "undo", "unlock"}, "replayCheckpointBlock rejected block")
}

// TestWiringSpecialTxBracketReplayCommitsOnAcceptedBlock drives the REAL
// (*BlockChain).replayCheckpointBlock to its success exit.
// MUTATION PROOF: no-op the CommitPendingSpecialTx call there -> FAIL.
func TestWiringSpecialTxBracketReplayCommitsOnAcceptedBlock(t *testing.T) {
	b, arb := specialTxChain(t)

	if err := b.replayCheckpointBlock(&types.DposBlock{
		Block: specialTxBlock(7, common.EmptyHash)}); err != nil {
		t.Fatalf("harness bug: replayCheckpointBlock was expected to succeed, got: %v", err)
	}
	assertSeq(t, arb, []string{"lock", "commit", "unlock"}, "replayCheckpointBlock accepted block")
}
