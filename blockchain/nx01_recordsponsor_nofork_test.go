// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-01 (Tier 0) — the ANTI-FORK test for the WITHDRAWN F-032 block-validity binding.
//
// F-032 as shipped rejected a block whose in-block RecordSponsor payload differed from the
// LOCALLY STORED lastBlock.Confirm.Proposal.Sponsor. That comparand is not a function of
// the chain: no block hash or signature commits to it (the Confirm rides alongside the
// block in types.DposBlock and is persisted per node by dbStoreBlock), the miner reads it
// RAW while the validator resolved it through the operator-local
// BlockConfirmProposalSponsors override, and two HONEST nodes legitimately hold different
// values for it after a DPoS view change — DPOSOnDutyHandler.ChangeView re-proposes the
// SAME block hash under a new sponsor and IllegalBehaviorMonitor.isProposalsIllegal
// refuses to slash that, so two valid confirms can exist and mempool.appendConfirm keeps
// whichever arrived last. Armed at RevisedDPoSRewardHeight, ~4,400 blocks past the restart
// tip, that was a permanent and unrecoverable consensus split.
//
// These tests drive the REAL (*BlockChain).CheckBlockContext — the production block
// validation path — with the RevisedDPoSRewardHeight gate ARMED (block height 200 >= gate
// 100), which is exactly the configuration in which the withdrawn binding would have
// rejected. They assert the property that must now hold forever: the IDENTITY of a
// node's stored confirm sponsor cannot decide whether a block is valid.
//
// FAIL-ON-PRISTINE — verified by mutation against BOTH reintroduction shapes:
//
//   - restore the deleted call site in CheckBlockContext
//     `if err := DefaultLedger.Arbitrators.CheckRecordSponsorBinding(recordedSponsor,
//     lastBlock.Height, lastBlock.Confirm.Proposal.Sponsor, block.Height); err != nil {
//     return err }`
//     -> recArbiters implements no such method and its embedded state.Arbitrators is nil,
//     so the production path faults -> both tests fail;
//
//   - reintroduce it INLINE, which is how a regression would most plausibly return
//     `if recordSponsorExist && !bytes.Equal(recordedSponsor,
//     lastBlock.Confirm.Proposal.Sponsor) { return errors.New("...") }`
//     -> CheckBlockContext returns that error instead of the harness sentinel -> both
//     tests fail, and TestNX01CompetingConfirmsCannotSplitTheChain reports the two nodes
//     reaching OPPOSITE verdicts on one block, which is the split itself.
//
// The tests deliberately assert ACCEPTANCE of a sponsor mismatch. That is the release-shape
// decision, not an oversight: the residual F-032 exposure (a producer naming a different
// current/last arbiter and redistributing a CONSERVED, non-inflationary sponsor reward) is
// accepted, and membership remains enforced by recordsponsortransaction.go
// SpecialContextCheck. No supply effect is claimed or implied.
package blockchain

import (
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
	sponsorStart = uint32(100) // RecordSponsorStartHeight for the harness
	sponsorGate  = uint32(100) // RevisedDPoSRewardHeight — ARMED for every test here
	sponsorBlock = uint32(200) // the block under validation, at/above the gate
	prevHeight   = uint32(0)   // prevNode.Height == 0 short-circuits the retarget maths
)

var (
	// The sponsor the BLOCK records — the value every node reads from the block itself.
	recordedSponsorKey = []byte{0x03, 0xAA, 0xBB, 0xCC}
	// Two different sponsors two honest nodes can legitimately have stored for the SAME
	// previous block after a view change. Neither equals recordedSponsorKey.
	storedSponsorA = []byte{0x03, 0xDD, 0xEE, 0xFF}
	storedSponsorB = []byte{0x02, 0x11, 0x22, 0x33}

	// Returned by the check immediately AFTER the record-sponsor region, so reaching it
	// proves the region did not reject.
	errStopAfterSponsor = errors.New("nx01 sentinel: validation passed the record-sponsor region")
)

// nx01Chain builds a chain whose stored previous block carries a confirm naming
// storedSponsor, with the RevisedDPoSRewardHeight gate armed. The returned cleanup
// restores DefaultLedger.
func nx01Chain(t *testing.T, storedSponsor []byte) (*BlockChain, *BlockNode, func()) {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()
	params.DPoSConfiguration.RecordSponsorStartHeight = sponsorStart
	// ARM the gate. Without this the withdrawn binding was a no-op at height 200 and the
	// mutation proof above would be vacuous.
	params.RevisedDPoSRewardHeight = sponsorGate

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

	// Every remaining CheckBlockContext hook accepts except CheckDPOSIllegalTx, which is
	// the first check AFTER the record-sponsor region.
	arb := &recArbiters{illegalTxErr: errStopAfterSponsor}
	prevLedger := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: arb, Blockchain: b, Store: store}

	prevHash := nx01PrevHash()
	prevNode := &BlockNode{Height: prevHeight, Hash: &prevHash,
		Bits: params.PowConfiguration.PowLimitBits, Timestamp: 1}
	b.blockCache[prevHash] = specialTxBlock(prevHeight, common.EmptyHash)
	b.confirmCache[prevHash] = &payload.Confirm{
		Proposal: payload.DPOSProposal{Sponsor: storedSponsor},
	}

	return b, prevNode, func() { DefaultLedger = prevLedger }
}

func nx01PrevHash() common.Uint256 { return common.Uint256{0x11, 0x22} }

// nx01Block is the block under validation: one RecordSponsor tx naming recordedSponsorKey.
// It is byte-identical whatever any node has stored, which is the whole point — every node
// must reach the same verdict on it.
func nx01Block(t *testing.T) *types.Block {
	t.Helper()
	prevHash := nx01PrevHash()
	blk := specialTxBlock(sponsorBlock, prevHash)
	blk.Header.Bits = config.GetDefaultParams().PowConfiguration.PowLimitBits
	blk.Header.Timestamp = 1000
	rs := functions.CreateTransaction(
		common2.TxVersion09, common2.RecordSponsor, 0,
		&payload.RecordSponsor{Sponsor: recordedSponsorKey},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{})
	blk.Transactions = append(blk.Transactions, rs)
	return blk
}

// TestNX01SponsorMismatchIsNotABlockValidityFailure drives the production
// CheckBlockContext with the gate armed and a RecordSponsor payload that disagrees with
// this node's stored confirm. Validation must pass THROUGH the record-sponsor region and
// stop at the next check, proving the region rejected nothing.
func TestNX01SponsorMismatchIsNotABlockValidityFailure(t *testing.T) {
	b, prevNode, restore := nx01Chain(t, storedSponsorA)
	defer restore()

	err := b.CheckBlockContext(nx01Block(t), prevNode)
	if !errors.Is(err, errStopAfterSponsor) {
		t.Fatalf("NX-01 REGRESSION: CheckBlockContext returned %v, want the sentinel that "+
			"proves the record-sponsor region was passed. A block whose RecordSponsor payload "+
			"disagrees with this node's STORED confirm sponsor must still be valid — the "+
			"stored confirm is node-local, no hash commits to it, and honest nodes hold "+
			"different values for it after a view change, so rejecting on it splits the chain "+
			"at RevisedDPoSRewardHeight.", err)
	}
}

// TestNX01CompetingConfirmsCannotSplitTheChain is the split scenario itself, expressed as
// a test. Node A and node B stored DIFFERENT confirms for the same previous block — the
// legitimate post-view-change state — and are handed the SAME successor block. They must
// reach the SAME verdict. Any rule that reads the stored confirm's sponsor makes these two
// verdicts differ, and neither node will ever accept the other's chain again.
func TestNX01CompetingConfirmsCannotSplitTheChain(t *testing.T) {
	blk := nx01Block(t)

	verdict := func(stored []byte) error {
		b, prevNode, restore := nx01Chain(t, stored)
		defer restore()
		return b.CheckBlockContext(blk, prevNode)
	}

	errA := verdict(storedSponsorA)
	errB := verdict(storedSponsorB)

	if !errors.Is(errA, errStopAfterSponsor) || !errors.Is(errB, errStopAfterSponsor) {
		t.Fatalf("NX-01 REGRESSION: node A verdict %v, node B verdict %v — want both to pass "+
			"the record-sponsor region. Two honest nodes that stored different confirms for "+
			"the same block are now deciding block validity differently: that is the "+
			"permanent chain split.", errA, errB)
	}
	if (errA == nil) != (errB == nil) {
		t.Fatalf("NX-01 CHAIN SPLIT: node A returned %v and node B returned %v for the SAME "+
			"block — the two nodes disagree on validity purely because they stored different "+
			"confirms for the previous block", errA, errB)
	}
}

// TestNX01ProducerAndValidatorAgreeOnTheRecordedSponsor pins the symmetry NX-05 broke.
// The producer (pow/service.go GenerateBlock) copies its OWN stored confirm sponsor into
// the RecordSponsor payload with no override applied. Validate the block that producer
// would emit against a node that stored a DIFFERENT confirm, and against one that stored
// the SAME confirm: both must accept. Before the withdrawal only the second did, so any
// operator sponsors-file entry at/above the gate — or any post-view-change disagreement —
// was a network-wide rejection of the block every miner produces.
func TestNX01ProducerAndValidatorAgreeOnTheRecordedSponsor(t *testing.T) {
	// The block a miner holding confirm A would emit: RecordSponsor == its own stored
	// sponsor, verbatim, exactly as pow.CreateRecordSponsorTx does.
	prevHash := nx01PrevHash()
	blk := specialTxBlock(sponsorBlock, prevHash)
	blk.Header.Bits = config.GetDefaultParams().PowConfiguration.PowLimitBits
	blk.Header.Timestamp = 1000
	blk.Transactions = append(blk.Transactions, functions.CreateTransaction(
		common2.TxVersion09, common2.RecordSponsor, 0,
		&payload.RecordSponsor{Sponsor: storedSponsorA},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{}))

	for _, tc := range []struct {
		name   string
		stored []byte
	}{
		{"validator stored the same confirm as the miner", storedSponsorA},
		{"validator stored a competing confirm", storedSponsorB},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			b, prevNode, restore := nx01Chain(t, tc.stored)
			defer restore()
			if err := b.CheckBlockContext(blk, prevNode); !errors.Is(err, errStopAfterSponsor) {
				t.Fatalf("NX-01/NX-05 REGRESSION: %s — CheckBlockContext returned %v. A miner "+
					"and a validator must never disagree about a block because of state that "+
					"lives outside it.", tc.name, err)
			}
		})
	}
}
