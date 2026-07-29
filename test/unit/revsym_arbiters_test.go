// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Reorg revert-symmetry harness, Arbiters/DPoS-state edition.
//
// It drives the REAL production entry points -- Arbiters.ProcessBlock (which calls
// State.ProcessBlock -> processTransactions -> History.Append/Commit) and
// Arbiters.RollbackTo (-> History.RollbackTo -> the revert closures) -- and then
// compares the COMPLETE derived state, field by field, including every unexported
// field of every Producer, every map value, the arbiter set, DutyIndex, the
// height-keyed Snapshots, the degradation state and the checkpoint the manager
// holds.
//
// WHY a new comparator: the shipped rollback suite compares abt.Snapshot()
// (*state.CheckPoint) with checkPointEqual/stateKeyFrameEqual/producerEqual, which
// compare a hand-picked subset of fields and compare several maps by len() alone.
// They are structurally blind to workedInRound, inactiveCountV2,
// DposV2EffectedProducers, DepositOutputs VALUES, UsedDposV2Votes,
// DPoSV2ActiveHeight and Snapshots -- i.e. to every field the Class-E
// revert-symmetry fixes touch. See TestRevsymShippedComparatorIsBlind.
package unit

import (
	"errors"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/test/revsym"
)

// revsymOptions returns the dump options used for every reorg case.
//
// The ONLY excluded value is utils.History.commits, a documented monotonic
// savepoint marker that RollbackTo deliberately does not decrement (see
// utils/history.go: "It is monotonic and is NOT disturbed by the capacity trim").
// Everything else -- including History.height, History.seekHeight, the retained
// change groups and their heights -- is compared.
func revsymOptions() revsym.Options {
	return revsym.NewOptions().SkipField(
		// Monotonic savepoint marker; RollbackTo deliberately does not decrement it
		// (utils/history.go: "It is monotonic and is NOT disturbed by the capacity trim").
		"utils.History.commits",
		// Per-block scratch: processTransactions unconditionally reassigns a fresh map
		// at its top (dpos/state/state.go:1576) before any read, it is not part of
		// StateKeyFrame and is never serialized into a checkpoint.
		"state.State.LastRenewalDPoSV2Votes",
		// (kept: the map is rebuilt per block, so post-rollback residue is unreachable)
	)
}

func dumpArbiters() string { return revsym.Dump(abt, revsymOptions()) }

// revsymStep is one block of the segment that gets applied and then undone.
type revsymStep struct {
	height uint32
	txs    []interfaces.Transaction
}

// runArbitersReorg applies the segment, undoes it with the production RollbackTo,
// and requires the complete derived state to be exactly what it was. It then
// re-applies the segment and requires the result to equal the first application,
// which catches a revert that "restores" by destroying information the forward
// path needs.
func runArbitersReorg(t *testing.T, name string, seg []revsymStep) {
	t.Helper()
	if len(seg) == 0 {
		t.Fatalf("%s: empty segment", name)
	}
	// A reorg forks at the PARENT of the first detached block, so the harness models
	// exactly that: the rollback target is seg[0].height-1 and a block must be
	// committed there. (The shipped rollback tests jump heights, which would leave
	// History.height below the target and make RollbackTo a partial no-op.)
	base := seg[0].height - 1
	if abt.History.Height() != base {
		abt.ProcessBlock(&types.Block{Header: common2.Header{Height: base}}, nil)
	}

	before := dumpArbiters()
	for _, s := range seg {
		abt.ProcessBlock(&types.Block{
			Header:       common2.Header{Height: s.height},
			Transactions: s.txs,
		}, nil)
	}
	applied := dumpArbiters()
	if revsym.Diff(before, applied, 1) == "" {
		t.Fatalf("%s: the segment changed NOTHING -- the case does not reach any "+
			"forward closure, so its rollback proves nothing", name)
	}

	if err := abt.RollbackTo(base); err != nil {
		t.Fatalf("%s: RollbackTo(%d): %v", name, base, err)
	}
	undone := dumpArbiters()
	if d := revsym.Diff(before, undone, 25); d != "" {
		t.Errorf("%s: REORG REVERT ASYMMETRY -- state after undo != state before the "+
			"segment (rollback target %d):\n%s", name, base, d)
	}

	for _, s := range seg {
		abt.ProcessBlock(&types.Block{
			Header:       common2.Header{Height: s.height},
			Transactions: s.txs,
		}, nil)
	}
	if d := revsym.Diff(applied, dumpArbiters(), 25); d != "" {
		t.Errorf("%s: RE-APPLY DIVERGENCE -- replaying the same segment after the undo "+
			"produced a different state:\n%s", name, d)
	}
}

// processFillers advances the chain by empty blocks.
func processFillers(from, count uint32) uint32 {
	h := from
	for i := uint32(0); i < count; i++ {
		h++
		abt.ProcessBlock(&types.Block{Header: common2.Header{Height: h}}, nil)
	}
	return h
}

func TestRevsym_Arbiters_RegisterProducer(t *testing.T) {
	initArbiters()
	h := abt.ChainParams.VoteStartHeight
	runArbitersReorg(t, "register-producer", []revsymStep{{h, []interfaces.Transaction{
		getRegisterProducerTx(abtList[0], abtList[0], "p1"),
		getRegisterProducerTx(abtList[1], abtList[1], "p2"),
		getRegisterProducerTx(abtList[2], abtList[2], "p3"),
		getRegisterProducerTx(abtList[3], abtList[3], "p4"),
	}}})
}

// registerFour registers four producers and returns the current height.
func registerFour() uint32 {
	h := abt.ChainParams.VoteStartHeight
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{
			getRegisterProducerTx(abtList[0], abtList[0], "p1"),
			getRegisterProducerTx(abtList[1], abtList[1], "p2"),
			getRegisterProducerTx(abtList[2], abtList[2], "p3"),
			getRegisterProducerTx(abtList[3], abtList[3], "p4"),
		},
	}, nil)
	return h
}

func TestRevsym_Arbiters_PendingToActive(t *testing.T) {
	initArbiters()
	h := registerFour()
	h = processFillers(h, 4)
	// The next block is the one that moves all four Pending -> Activity.
	runArbitersReorg(t, "pending-to-active", []revsymStep{{h + 1, nil}})
}

func TestRevsym_Arbiters_VoteProducer(t *testing.T) {
	initArbiters()
	h := registerFour()
	h = processFillers(h, 5)
	vote := getVoteProducerTx(10, []outputpayload.CandidateVotes{
		{Candidate: abtList[0], Votes: 5},
		{Candidate: abtList[1], Votes: 4},
		{Candidate: abtList[2], Votes: 3},
		{Candidate: abtList[3], Votes: 2},
	})
	runArbitersReorg(t, "vote-producer", []revsymStep{{h + 1, []interfaces.Transaction{vote}}})
}

func TestRevsym_Arbiters_UpdateProducer(t *testing.T) {
	initArbiters()
	h := registerFour()
	h = processFillers(h, 5)
	upd := getUpdateProducerTx(abtList[0], abtList[4], "p1-renamed")
	runArbitersReorg(t, "update-producer", []revsymStep{{h + 1, []interfaces.Transaction{upd}}})
}

func TestRevsym_Arbiters_CancelProducer(t *testing.T) {
	initArbiters()
	h := registerFour()
	h = processFillers(h, 5)
	runArbitersReorg(t, "cancel-producer", []revsymStep{
		{h + 1, []interfaces.Transaction{getCancelProducer(abtList[0])}}})
}

// TestRevsym_Arbiters_ReturnDeposit reaches State.returnDeposit -- the F-215
// returnAction whose revert used to hard-set producer.state = Canceled.
func TestRevsym_Arbiters_ReturnDeposit(t *testing.T) {
	initArbiters()
	register1 := getRegisterProducerTx(abtList[0], abtList[0], "p1")
	h := abt.ChainParams.VoteStartHeight
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{
			register1,
			getRegisterProducerTx(abtList[1], abtList[1], "p2"),
			getRegisterProducerTx(abtList[2], abtList[2], "p3"),
			getRegisterProducerTx(abtList[3], abtList[3], "p4"),
		},
	}, nil)
	h = processFillers(h, 5)

	h++
	abt.ProcessBlock(&types.Block{Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{getVoteProducerTx(10,
			[]outputpayload.CandidateVotes{{Candidate: abtList[0], Votes: 5}})}}, nil)

	cancel := getCancelProducer(abtList[0])
	h++
	abt.ProcessBlock(&types.Block{Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{cancel}}, nil)

	abt.GetProducerDepositAmount = func(programHash common.Uint168) (common.Fixed64, error) {
		for _, v := range abt.GetAllProducers() {
			hash, err := contract.PublicKeyToDepositProgramHash(v.Info().OwnerKey)
			if err == nil && hash.IsEqual(programHash) {
				return v.DepositAmount(), nil
			}
		}
		return common.Fixed64(0), errors.New("not found producer")
	}

	h += abt.ChainParams.CRConfiguration.DepositLockupBlocks
	abt.ProcessBlock(&types.Block{Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{cancel}}, nil)

	ret := getReturnProducerDeposit(abtList[0], 4999*1e8)
	ret.SetInputs([]*common2.Input{{
		Previous: common2.OutPoint{TxID: register1.Hash(), Index: 0},
	}})

	runArbitersReorg(t, "return-deposit", []revsymStep{
		{abt.ChainParams.CRConfiguration.CRVotingStartHeight, []interfaces.Transaction{ret}}})
}

// TestRevsym_Arbiters_RoundChange reaches the arbiter-set rotation:
// UpdateNextArbitrators (F-180's DPoSV2ActiveHeight closure lives here),
// SnapshotByHeight (F-109) and the DutyIndex advance.
func TestRevsym_Arbiters_RoundChange(t *testing.T) {
	initArbiters()
	savedCount := abt.ChainParams.DPoSConfiguration.NormalArbitratorsCount
	defer func() { abt.ChainParams.DPoSConfiguration.NormalArbitratorsCount = savedCount }()

	h := registerFour()
	h = processFillers(h, 5)
	h++
	abt.ProcessBlock(&types.Block{Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{getVoteProducerTx(10,
			[]outputpayload.CandidateVotes{
				{Candidate: abtList[0], Votes: 5},
				{Candidate: abtList[1], Votes: 4},
				{Candidate: abtList[2], Votes: 3},
				{Candidate: abtList[3], Votes: 2},
			})}}, nil)

	abt.ChainParams.DPoSConfiguration.NormalArbitratorsCount = 2

	// The block that computes the next arbiters.
	next := abt.ChainParams.PublicDPOSHeight -
		abt.ChainParams.DPoSConfiguration.PreConnectOffset - 1
	runArbitersReorg(t, "next-arbiters", []revsymStep{{next, nil}})

	// The block that installs them (round change + snapshot).
	runArbitersReorg(t, "round-change", []revsymStep{{abt.ChainParams.PublicDPOSHeight - 1, nil}})

	h = processFillers(abt.ChainParams.PublicDPOSHeight-1, 3)
	runArbitersReorg(t, "duty-advance", []revsymStep{{h + 1, nil}})
}

// TestRevsym_Arbiters_DeepReorg undoes a five-block segment in one RollbackTo,
// the shape of the mainnet 1,832,750 event (two chains sharing a parent).
func TestRevsym_Arbiters_DeepReorg(t *testing.T) {
	initArbiters()
	h := registerFour()
	h = processFillers(h, 5)

	seg := []revsymStep{
		{h + 1, []interfaces.Transaction{getVoteProducerTx(10,
			[]outputpayload.CandidateVotes{{Candidate: abtList[0], Votes: 5}})}},
		{h + 2, nil},
		{h + 3, []interfaces.Transaction{getUpdateProducerTx(abtList[1], abtList[1], "p2b")}},
		{h + 4, []interfaces.Transaction{getCancelProducer(abtList[2])}},
		{h + 5, nil},
	}
	runArbitersReorg(t, "deep-5-block-reorg", seg)
}
