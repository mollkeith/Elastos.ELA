// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TEST — F-032 (RecordSponsor binding), tracked LIVE.
//
// The blocker: replacing the call site in CheckBlockContext with
//
//	_ = DefaultLedger.Arbitrators.CheckRecordSponsorBinding(...)
//
// (i.e. discarding the error) left the entire suite green at HEAD. The existing
// dpos/state/f032_test.go tests the METHOD; nothing proved CheckBlockContext both calls
// it AND returns its error, nor that it passes the right four arguments.
//
// This test drives the REAL (*BlockChain).CheckBlockContext with a recording Arbitrators
// and asserts (a) the error is propagated verbatim, and (b) each of the four arguments is
// the value the fix specifies: the RecordSponsor payload's Sponsor, the previous block's
// height, the previous block's CONFIRM PROPOSAL sponsor (the true sponsor), and the
// block's own height.
package blockchain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"
)

const (
	sponsorStart = uint32(100)
	sponsorBlock = uint32(200)
	prevHeight   = uint32(0) // prevNode.Height == 0 short-circuits the retarget maths
)

var (
	recordedSponsorKey  = []byte{0x03, 0xAA, 0xBB, 0xCC}
	trueSponsorKey      = []byte{0x03, 0xDD, 0xEE, 0xFF}
	errSponsorBinding   = errors.New("wiring sentinel: sponsor binding rejected")
	errStopAfterSponsor = errors.New("wiring sentinel: stop after the F-032 call site")
)

// sponsorChain builds a chain that can reach the F-032 call site inside CheckBlockContext.
func sponsorChain(t *testing.T) (*BlockChain, *recArbiters, *BlockNode, *types.Block) {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()
	params.DPoSConfiguration.RecordSponsorStartHeight = sponsorStart

	store := &recStore{}
	b := &BlockChain{
		chainParams:    params,
		db:             store,
		index:          newBlockIndex(store, params),
		CkpManager:     checkpoint.NewManager(params),
		state:          state.NewState(params, nil, nil, nil, func() bool { return false }, nil, nil, nil, nil, nil, nil, nil),
		TimeSource:     NewMedianTime(),
		DepNodes:       make(map[common.Uint256][]*BlockNode),
		orphans:        make(map[common.Uint256]*OrphanBlock),
		orphanConfirms: make(map[common.Uint256]*payload.Confirm),
		blockCache:     make(map[common.Uint256]*types.Block),
		confirmCache:   make(map[common.Uint256]*payload.Confirm),
	}

	arb := &recArbiters{}
	prevLedger := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: arb, Blockchain: b, Store: store}
	t.Cleanup(func() { DefaultLedger = prevLedger })

	// The previous block, reachable through the block/confirm caches (the fallback
	// CheckBlockContext takes when the store has no such block), carrying the TRUE
	// sponsor in its confirm proposal.
	prevHash := common.Uint256{0x11, 0x22}
	prevNode := &BlockNode{Height: prevHeight, Hash: &prevHash, Bits: params.PowConfiguration.PowLimitBits, Timestamp: 1}
	lastBlock := specialTxBlock(prevHeight, common.EmptyHash)
	b.blockCache[prevHash] = lastBlock
	b.confirmCache[prevHash] = &payload.Confirm{
		Proposal: payload.DPOSProposal{Sponsor: trueSponsorKey},
	}

	// The block under validation: one RecordSponsor tx naming recordedSponsorKey.
	blk := specialTxBlock(sponsorBlock, prevHash)
	blk.Header.Bits = params.PowConfiguration.PowLimitBits
	blk.Header.Timestamp = 1000
	rs := functions.CreateTransaction(
		common2.TxVersion09, common2.RecordSponsor, 0,
		&payload.RecordSponsor{Sponsor: recordedSponsorKey},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
	blk.Transactions = append(blk.Transactions, rs)

	return b, arb, prevNode, blk
}

// TestWiringRecordSponsorBindingErrorIsPropagated is the F-032 wiring proof.
//
// MUTATION PROOF: discard the error at the call site (`_ = DefaultLedger.Arbitrators.
// CheckRecordSponsorBinding(...)`) or delete the call -> CheckBlockContext no longer
// returns the sentinel -> this test FAILS.
func TestWiringRecordSponsorBindingErrorIsPropagated(t *testing.T) {
	b, arb, prevNode, blk := sponsorChain(t)
	arb.sponsorErr = errSponsorBinding

	err := b.CheckBlockContext(blk, prevNode)
	if err == nil {
		t.Fatal("WIRING SEVERED: CheckBlockContext accepted a block whose RecordSponsor binding " +
			"was rejected — the F-032 guard's error is discarded or the call is gone " +
			"(DPoS sponsor reward can be redirected to any arbiter)")
	}
	if !errors.Is(err, errSponsorBinding) {
		t.Fatalf("WIRING SEVERED: CheckBlockContext returned %v, not the binding error — the "+
			"F-032 result is not what rejects the block", err)
	}
	if arb.sponsorCalls != 1 {
		t.Fatalf("WIRING SEVERED: CheckRecordSponsorBinding was called %d times, want exactly 1",
			arb.sponsorCalls)
	}
}

// TestWiringRecordSponsorBindingReceivesTheRealArguments pins WHAT the call site passes.
// A call site that passed the recorded sponsor as BOTH arguments, or the current tip
// height instead of the previous block's, would be "wired" yet inert.
func TestWiringRecordSponsorBindingReceivesTheRealArguments(t *testing.T) {
	b, arb, prevNode, blk := sponsorChain(t)
	arb.sponsorErr = nil
	// Stop CheckBlockContext at the very next check so the argument assertions do not
	// depend on the rest of block-context validation; the capture has already happened.
	arb.illegalTxErr = errStopAfterSponsor

	if err := b.CheckBlockContext(blk, prevNode); !errors.Is(err, errStopAfterSponsor) {
		t.Fatalf("harness bug: expected the stop sentinel, got %v", err)
	}

	if arb.sponsorCalls != 1 {
		t.Fatalf("WIRING SEVERED: CheckRecordSponsorBinding was called %d times, want exactly 1",
			arb.sponsorCalls)
	}
	if !bytes.Equal(arb.sponsorRecorded, recordedSponsorKey) {
		t.Fatalf("arg 1 (recordedSponsor) = %x, want the RecordSponsor payload's Sponsor %x",
			arb.sponsorRecorded, recordedSponsorKey)
	}
	if arb.sponsorLastHeight != prevHeight {
		t.Fatalf("arg 2 (lastBlockHeight) = %d, want the previous block's height %d",
			arb.sponsorLastHeight, prevHeight)
	}
	if !bytes.Equal(arb.sponsorActual, trueSponsorKey) {
		t.Fatalf("arg 3 (actual sponsor) = %x, want the previous block's CONFIRM PROPOSAL "+
			"sponsor %x — passing anything else makes the binding vacuous",
			arb.sponsorActual, trueSponsorKey)
	}
	if arb.sponsorBlockHeight != sponsorBlock {
		t.Fatalf("arg 4 (blockHeight) = %d, want the validated block's own height %d — the "+
			"gate must key on the block, not the tip", arb.sponsorBlockHeight, sponsorBlock)
	}
}
