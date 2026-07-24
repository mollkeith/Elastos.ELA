// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package unit

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

var (
	fvT3BestHeight uint32
	fvT3Keys       [][]byte
)

// fvT3Arbiters builds a PRIVATE Arbiters/State pair (other tests in this package
// mutate the shared config.DefaultParams). gate is the value given to
// StrictMoneyRangeHeight, i.e. gate 1.
func fvT3Arbiters(gate uint32) *state.Arbiters {
	fvT3Keys = make([][]byte, 0)
	for _, v := range []string{
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
		"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
		"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
		"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
	} {
		a, _ := common.HexStringToBytes(v)
		fvT3Keys = append(fvT3Keys, a)
	}
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = gate
	// The shipped mainnet default is 0 ("there will be no penalty in this version"),
	// which would make every penalty assertion below vacuously true. Configure a real
	// penalty so the fund-effect legs are actually exercised.
	params.DPoSConfiguration.EmergencyInactivePenalty = common.Fixed64(500)
	ckpManager := checkpoint.NewManager(params)
	params.DPoSConfiguration.CRCArbiters = []string{
		"03e435ccd6073813917c2d841a0815d21301ec3286bc1412bb5b099178c68a10b6",
		"038a1829b4b2bee784a99bebabbfecfec53f33dadeeeff21b460f8b4fc7c2ca771",
	}
	ar, _ := state.NewArbitrators(params, nil, nil,
		nil, nil, nil,
		nil, nil, nil, ckpManager)
	ar.RegisterFunction(func() uint32 { return fvT3BestHeight },
		func() *common.Uint256 { return &common.Uint256{} },
		func(h uint32) (*types.Block, error) {
			return &types.Block{Header: common2.Header{Height: h}}, nil
		}, nil)
	ar.State = state.NewState(params, nil, nil, nil,
		func() bool { return false },
		nil, nil, nil,
		nil, nil, nil, nil)
	return ar
}

// fvT3Chain registers and activates four producers through the real block path.
func fvT3Chain(t *testing.T, ar *state.Arbiters) uint32 {
	t.Helper()
	height := ar.ChainParams.VoteStartHeight
	fvT3BestHeight = height
	ar.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height},
		Transactions: []interfaces.Transaction{
			getRegisterProducerTx(fvT3Keys[0], fvT3Keys[0], "fv1"),
			getRegisterProducerTx(fvT3Keys[1], fvT3Keys[1], "fv2"),
			getRegisterProducerTx(fvT3Keys[2], fvT3Keys[2], "fv3"),
			getRegisterProducerTx(fvT3Keys[3], fvT3Keys[3], "fv4"),
		},
	}, nil)
	for i := 0; i < 6; i++ {
		height++
		fvT3BestHeight = height
		ar.ProcessBlock(&types.Block{Header: common2.Header{Height: height}}, nil)
	}
	assert.Equal(t, 4, len(ar.ActivityProducers), "harness: four producers must be active")
	return height
}

// fvT3Block connects one block carrying txs through Arbiters.ProcessBlock.
func fvT3Block(ar *state.Arbiters, height uint32, txs ...interfaces.Transaction) {
	fvT3BestHeight = height
	ar.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height}, Transactions: txs}, nil)
}

func fvT3InactiveTx(sponsor, inactive []byte, height uint32) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.InactiveArbitrators, 0,
		&payload.InactiveArbitrators{
			Sponsor:     sponsor,
			Arbitrators: [][]byte{inactive},
			BlockHeight: height,
		},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{},
		0, []*program.Program{},
	)
}

func fvT3ActivateTx(nodeKey []byte) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.ActivateProducer, 0,
		&payload.ActivateProducer{NodePublicKey: nodeKey},
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{},
		0, []*program.Program{},
	)
}

// TestFV11AlreadyInactiveRollbackDoesNotReactivate is the fail-on-pristine proof of
// FV-11's headline leg, driven end-to-end through the production block path
// (Arbiters.ProcessBlock -> State.ProcessBlock -> processTransactions ->
// processTransaction -> case InactiveArbitrators ->
// processEmergencyInactiveArbitrators) and the production reorg path
// (Arbiters.RollbackTo -> State.RollbackTo -> History.RollbackTo).
//
// CheckInactiveArbitrators admits a target that is merely IsDisabledProducer -- which
// includes a producer ALREADY in InactiveProducers -- and the shipped undo called
// revertSettingInactiveProducer unconditionally. Undoing that second marking
// therefore PROMOTED the producer to Active and re-inserted it into
// ActivityProducers, i.e. back into the arbiter-eligible set, while debiting a
// penalty it had never been credited.
//
// FAIL-ON-PRISTINE: after the rollback the producer is Active, is in
// ActivityProducers, its penalty is one EmergencyInactivePenalty short and its
// inactiveSince is 0.
func TestFV11AlreadyInactiveRollbackDoesNotReactivate(t *testing.T) {
	ar := fvT3Arbiters(math.MaxUint32) // below gate 1: the ROLLBACK half is ungated
	tip := fvT3Chain(t, ar)
	target := fvT3Keys[1]
	key := common.BytesToHexString(target)

	h1 := tip + 1
	fvT3Block(ar, h1, fvT3InactiveTx(fvT3Keys[0], target, h1))

	p := ar.GetProducer(target)
	if p == nil {
		t.Fatal("harness: producer not found")
	}
	assert.Equal(t, state.Inactive, p.State(), "sanity: H1 really made the producer inactive")
	penaltyAfterH1 := p.Penalty()
	inactiveSinceAfterH1 := p.InactiveSince()
	assert.True(t, penaltyAfterH1 > 0, "sanity: the emergency penalty was applied at H1")
	assert.Equal(t, h1, inactiveSinceAfterH1, "sanity: inactiveSince recorded H1")

	// A second, legal-but-sloppy payload names the SAME, already-inactive producer.
	h2 := h1 + 1
	fvT3Block(ar, h2, fvT3InactiveTx(fvT3Keys[2], target, h2))
	assert.Equal(t, state.Inactive, p.State(), "sanity: still inactive after H2")

	// Reorg across H2.
	assert.NoError(t, ar.RollbackTo(h1))

	assert.Equal(t, state.Inactive, p.State(),
		"FV-11: undoing a payload that named an ALREADY-INACTIVE producer must not "+
			"reactivate it (pristine promotes it back to Active)")
	if _, ok := ar.ActivityProducers[key]; ok {
		t.Fatal("FV-11: the producer must not be re-inserted into ActivityProducers by the undo")
	}
	if _, ok := ar.InactiveProducers[key]; !ok {
		t.Fatal("FV-11: the producer must remain in InactiveProducers")
	}
	assert.Equal(t, penaltyAfterH1, p.Penalty(),
		"FV-11: the undo must restore the captured penalty, not debit one the producer "+
			"was never credited (pristine lands one EmergencyInactivePenalty low)")
	assert.Equal(t, inactiveSinceAfterH1, p.InactiveSince(),
		"FV-11: inactiveSince must be restored to its captured original (pristine zeroes it)")
	if _, ok := ar.EmergencyInactiveArbiters[key]; !ok {
		t.Fatal("FV-11: the entry added by the FIRST payload must survive the undo of the second")
	}
}

// TestFV11RevertRestoresSelectedAndActivateRequest is FV-11's second leg, on the
// ORDINARY (legal) Active -> emergency-inactive -> revert path, so it holds even if
// no payload ever names an already-inactive producer.
//
// setInactiveProducer / revertSettingInactiveProducer were an inverse pair computed
// by hand rather than a capture/restore pair: `selected` was cleared by the forward
// and never restored, and `activateRequestHeight` was set to MaxUint32 by BOTH
// directions, so a pending ActivateProducer request was DESTROYED rather than
// restored.
//
// FAIL-ON-PRISTINE: Selected() returns false and ActivateRequestHeight() returns
// MaxUint32.
func TestFV11RevertRestoresSelectedAndActivateRequest(t *testing.T) {
	ar := fvT3Arbiters(math.MaxUint32)
	tip := fvT3Chain(t, ar)
	target := fvT3Keys[1]

	p := ar.GetProducer(target)
	if p == nil {
		t.Fatal("harness: producer not found")
	}

	// A real pending activation request, recorded through the production tx path.
	reqHeight := tip + 1
	fvT3Block(ar, reqHeight, fvT3ActivateTx(target))
	assert.Equal(t, reqHeight, p.ActivateRequestHeight(),
		"sanity: the ActivateProducer request was recorded")

	// A producer picked as a random candidate.
	p.SetSelected(true)

	h := reqHeight + 1
	fvT3Block(ar, h, fvT3InactiveTx(fvT3Keys[0], target, h))
	assert.Equal(t, state.Inactive, p.State(), "sanity: the producer really went inactive")
	assert.False(t, p.Selected(), "sanity: setInactiveProducer clears selected")
	assert.Equal(t, uint32(math.MaxUint32), p.ActivateRequestHeight(),
		"sanity: setInactiveProducer pins activateRequestHeight to MaxUint32")

	assert.NoError(t, ar.RollbackTo(h-1))

	assert.Equal(t, state.Active, p.State(),
		"the legitimate Active->Inactive path must still revert to Active")
	assert.True(t, p.Selected(),
		"FV-11: `selected` must be restored from the capture (pristine loses it on EVERY revert)")
	assert.Equal(t, reqHeight, p.ActivateRequestHeight(),
		"FV-11: a pending ActivateProducer request must be restored, not destroyed "+
			"(pristine leaves activateRequestHeight at MaxUint32)")
	assert.Equal(t, common.Fixed64(0), p.Penalty(), "the emergency penalty must be reverted")
}

// TestFV11ApplyIsIdempotentAtGate1 is the fail-on-pristine proof of FV-11's GATED
// half: re-marking an already-inactive producer added EmergencyInactivePenalty a
// SECOND time. The skip reuses GATE 1 (StrictMoneyRangeHeight) because it changes
// FORWARD derived state; no new height is introduced. A census of the block store
// found only 6 InactiveArbitrators transactions in all history (heights
// 408476..434811) and ZERO at or above gate 1, so retained history is unaffected --
// and the below-gate arm here pins that legacy behaviour in place.
func TestFV11ApplyIsIdempotentAtGate1(t *testing.T) {
	run := func(t *testing.T, gate uint32) common.Fixed64 {
		ar := fvT3Arbiters(gate)
		tip := fvT3Chain(t, ar)
		target := fvT3Keys[1]
		h1 := tip + 1
		fvT3Block(ar, h1, fvT3InactiveTx(fvT3Keys[0], target, h1))
		fvT3Block(ar, h1+1, fvT3InactiveTx(fvT3Keys[2], target, h1+1))
		p := ar.GetProducer(target)
		if p == nil {
			t.Fatal("harness: producer not found")
		}
		assert.Equal(t, state.Inactive, p.State())
		return p.Penalty()
	}

	// Gate far above the test heights -> legacy (non-idempotent) forward behaviour.
	below := run(t, math.MaxUint32)
	// Gate at 0 -> every test height is at/above gate 1.
	above := run(t, 0)

	assert.Equal(t, below/2, above,
		"FV-11 (gate 1): re-marking an ALREADY-INACTIVE producer must not add the "+
			"emergency penalty a second time at/above gate 1 (pristine doubles it at "+
			"every height)")
	assert.True(t, above > 0, "sanity: the first marking still applies the penalty")
}

// TestFV05RollbackSeekToUndoesEmergencyMarking is the fail-on-pristine proof of
// FV-05 on the production path: Arbiters.ProcessSpecialTxPayload leaves the
// emergency marking in History.tempChanges (a height-0 preview), and
// CkpManager.RestoreTo -> CheckPoint.OnRollbackSeekTo -> Arbiters.RollbackSeekTo ->
// State.RollbackSeekTo -> History.RollbackSeekTo discarded those closures instead of
// running them. The marking then became PERMANENT -- no later Append could reach it.
//
// FAIL-ON-PRISTINE: after RollbackSeekTo the producer is still Inactive, still
// carries the EmergencyInactivePenalty and still has an EmergencyInactiveArbiters
// entry.
func TestFV05RollbackSeekToUndoesEmergencyMarking(t *testing.T) {
	ar := fvT3Arbiters(math.MaxUint32)
	tip := fvT3Chain(t, ar)
	target := fvT3Keys[1]
	key := common.BytesToHexString(target)

	p := ar.GetProducer(target)
	if p == nil {
		t.Fatal("harness: producer not found")
	}
	assert.Equal(t, state.Active, p.State())

	// The gossip / pre-block emergency preview, exactly as PreProcessSpecialTx and the
	// four DPoS-gossip entry points issue it.
	assert.NoError(t, ar.ProcessSpecialTxPayload(
		&payload.InactiveArbitrators{
			Sponsor:     fvT3Keys[0],
			Arbitrators: [][]byte{target},
			BlockHeight: tip + 1,
		}, tip))

	assert.Equal(t, state.Inactive, p.State(), "sanity: the preview really marked it inactive")
	assert.True(t, p.Penalty() > 0, "sanity: the emergency penalty was applied")
	if _, ok := ar.EmergencyInactiveArbiters[key]; !ok {
		t.Fatal("sanity: the EmergencyInactiveArbiters entry was not added")
	}

	// The restore path: CkpManager.RestoreTo -> OnRollbackSeekTo.
	ar.RollbackSeekTo(tip - 1)

	assert.Equal(t, state.Active, p.State(),
		"FV-05: RollbackSeekTo must RUN the outstanding emergency preview's rollback "+
			"closure (pristine discards it and the marking becomes PERMANENT)")
	assert.Equal(t, common.Fixed64(0), p.Penalty(),
		"FV-05: the EmergencyInactivePenalty must be reversed with the marking")
	if _, ok := ar.EmergencyInactiveArbiters[key]; ok {
		t.Fatal("FV-05: the EmergencyInactiveArbiters entry must be removed with the marking")
	}
}

// TestFV12RecoverFromCheckPointsClearsSnapshotRing is the fail-on-pristine proof of
// FV-12, driven through the production ICheckPoint method the deep-reset path uses
// (Manager.OnReset -> dpos/state CheckPoint.OnReset -> Arbiters.RecoverFromCheckPoints).
//
// recoverFromCheckPoints replaces the whole derived state from a checkpoint but left
// a.Snapshots / a.SnapshotKeysDesc -- the height-keyed arbiter snapshot ring -- in
// place. After a deep reset the ring therefore still holds frames written on the
// ABANDONED branch, at exactly the heights the canonical replay will write again;
// SnapshotByHeight APPENDS to an existing key rather than replacing it and
// getSnapshot returns the whole slice, so the two arbiter universes get UNIONED for
// ProposalContextCheckByHeight / VoteContextCheckByHeight and for the
// illegal-proposal / illegal-vote transaction validators. F-082 makes that ring the
// AUTHORITATIVE voter universe at and above gate 1.
//
// FAIL-ON-PRISTINE: the abandoned-branch frames are still in the ring after the
// rebuild, and getSnapshot still answers for that height.
func TestFV12RecoverFromCheckPointsClearsSnapshotRing(t *testing.T) {
	ar := fvT3Arbiters(math.MaxUint32)
	tip := fvT3Chain(t, ar)

	// Populate the ring through the production path (ForceChange -> SnapshotByHeight).
	assert.NoError(t, ar.ProcessSpecialTxPayload(
		&payload.InactiveArbitrators{
			Sponsor:     fvT3Keys[0],
			Arbitrators: [][]byte{fvT3Keys[1]},
			BlockHeight: tip + 1,
		}, tip))

	if len(ar.Snapshots) == 0 || len(ar.SnapshotKeysDesc) == 0 {
		t.Fatal("harness: the snapshot ring was not populated; the test would be vacuous")
	}
	polluted := ar.SnapshotKeysDesc[0]
	fvT3BestHeight = polluted // so GetSnapshot takes the ring branch, not the tip shortcut
	assert.True(t, len(ar.GetSnapshot(polluted)) > 0, "sanity: the ring answers for that height")

	// The deep-reset rebuild.
	cp := state.NewCheckpoint(ar)
	assert.NoError(t, cp.OnReset())

	assert.Equal(t, 0, len(ar.Snapshots),
		"FV-12: a checkpoint rebuild must clear the height-keyed snapshot ring "+
			"(pristine keeps abandoned-branch frames)")
	assert.Equal(t, 0, len(ar.SnapshotKeysDesc),
		"FV-12: SnapshotKeysDesc must be cleared with Snapshots")
	assert.Equal(t, 0, len(ar.GetSnapshot(polluted)),
		"FV-12: no abandoned-branch arbiter universe may survive the rebuild")
}
