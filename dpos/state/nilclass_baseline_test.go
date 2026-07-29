// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// errNoBlock is returned by the harness getBlockByHeight so the REAL
// Arbiters.forceChange -- which ProcessSpecialTxPayload tail-calls -- returns an
// error instead of rotating an arbiter set the harness has no blocks for. It runs
// AFTER the nil-map write under test, so it neither masks nor shortcuts it.
var errNoBlock = fmt.Errorf("nilclass harness: no block")

// nilClassChain builds a REAL Arbiters over a REAL cr/state Committee and a REAL
// checkpoint.Manager -- NewArbitrators registers the dpos CheckPoint into that
// manager -- so the tests drive the exact production frames:
//
//	core/checkpoint.(*Manager).OnReset / OnRollbackTo
//	dpos/state.(*CheckPoint).OnReset  / OnRollbackTo
//	dpos/state.(*CheckPoint).initFromArbitrators
//	dpos/state.(*Arbiters).recoverFromCheckPoints
//	dpos/state.(*Arbiters).ProcessSpecialTxPayload
func nilClassChain(t *testing.T) (*Arbiters, *checkpoint.Manager, *config.Configuration) {
	t.Helper()
	// A PRIVATE parameter set: other tests in this package mutate the shared
	// config.DefaultParams, so isolate to stay test-order independent.
	params := config.GetDefaultParams()
	ckp := checkpoint.NewManager(params)
	// No checkpoint files: these tests only exercise the in-memory rebuild.
	ckp.SetNeedSave(false)

	abt, err := NewArbitrators(params, crstate.NewCommittee(params, ckp), nil,
		nil, nil, nil,
		nil, nil, nil, ckp)
	require.NoError(t, err)

	// The ledger wires these at startup; forceChange needs them non-nil.
	abt.RegisterFunction(
		func() uint32 { return 0 },
		func() *common.Uint256 { return &common.Uint256{} },
		func(uint32) (*types.Block, error) { return nil, errNoBlock },
		nil)

	return abt, ckp, params
}

// nilClassIllegalBlocks is a minimal, REAL DPOSIllegalBlocks payload. Its Hash() is
// the key ProcessSpecialTxPayload index-writes into illegalBlocksPayloadHashes; the
// evidence itself is deliberately empty so processIllegalEvidence finds no illegal
// producer and the test isolates the map write.
func nilClassIllegalBlocks(height uint32) *payload.DPOSIllegalBlocks {
	return &payload.DPOSIllegalBlocks{
		CoinType:    payload.ELACoin,
		BlockHeight: height,
	}
}

// runNoPanic runs fn and returns the recovered panic value, or nil.
func runNoPanic(fn func()) (recovered interface{}) {
	defer func() { recovered = recover() }()
	fn()
	return nil
}

// ---------------------------------------------------------------------------
// 1. FAIL-ON-PRISTINE: the nil-map write, driven through the real frames
// ---------------------------------------------------------------------------

// assertGossipAfterRebuildSurvives drives the REAL DPoS-gossip entry point
// (Arbiters.ProcessSpecialTxPayload, the body of BlockChain.ProcessIllegalBlock /
// ProcessInactiveArbiter) in the window between a checkpoint rebuild and the first
// ProcessBlock -- which is what re-makes illegalBlocksPayloadHashes.
//
// On a tree without the fix this PANICS -- deliberately uncaught, so the failure is
// the real production stack -- with
//
//	panic: assignment to entry in nil map
//
// at dpos/state/arbitrators.go, a.illegalBlocksPayloadHashes[obj.Hash()] = nil,
// because the rebuild plants a nil map on the LIVE Arbiters.
func assertGossipAfterRebuildSurvives(t *testing.T, abt *Arbiters, height uint32) {
	t.Helper()

	pld := nilClassIllegalBlocks(height)
	// REAL production frame, the one BlockChain.ProcessIllegalBlock calls.
	err := abt.ProcessSpecialTxPayload(pld, height)
	// forceChange bails out on the harness' block lookup, AFTER the map write.
	require.ErrorIs(t, err, errNoBlock)

	require.NotNil(t, abt.illegalBlocksPayloadHashes,
		"a rebuild must leave the LIVE Arbiters a usable illegalBlocksPayloadHashes map")
	_, ok := abt.illegalBlocksPayloadHashes[pld.Hash()]
	assert.True(t, ok, "the payload hash must actually be recorded as processed")
}

// TestNilClassOnResetThenIllegalBlockGossip drives Manager.OnReset ->
// CheckPoint.OnReset -> recoverFromCheckPoints -> ProcessSpecialTxPayload. OnReset is
// reached in production from blockchain.reorganizeChain's recoverFromDefault branch
// (detach length >= maxHistoryCapacity 720) via resetCheckpoints.
func TestNilClassOnResetThenIllegalBlockGossip(t *testing.T) {
	abt, ckp, _ := nilClassChain(t)

	// Dirty the live map first, so the assertion proves the rebuild REPLACED it with
	// a usable empty map rather than merely leaving a still-good one alone.
	abt.illegalBlocksPayloadHashes[common.Uint256{0xAA}] = nil

	require.NoError(t, ckp.OnReset())

	assert.Equal(t, 0, len(abt.illegalBlocksPayloadHashes),
		"a genesis-fresh rebuild starts with no processed illegal-block payloads")
	assertGossipAfterRebuildSurvives(t, abt, 0)
}

// TestNilClassDeepRollbackThenIllegalBlockGossip drives the sibling rebuild site:
// Manager.OnRollbackTo -> CheckPoint.OnRollbackTo deep branch (height < StartHeight),
// reached in production from blockchain/confirmvalidator.go checkBlockWithConfirmation.
func TestNilClassDeepRollbackThenIllegalBlockGossip(t *testing.T) {
	abt, ckp, _ := nilClassChain(t)

	const deepHeight = uint32(1)
	require.Greater(t, NewCheckpoint(abt).StartHeight(), deepHeight,
		"deepHeight must be below StartHeight or the deep rebuild branch is not taken")

	abt.illegalBlocksPayloadHashes[common.Uint256{0xBB}] = nil

	require.NoError(t, ckp.OnRollbackTo(deepHeight, false))

	assert.Equal(t, 0, len(abt.illegalBlocksPayloadHashes))
	assertGossipAfterRebuildSurvives(t, abt, 0)
}

// ---------------------------------------------------------------------------
// 2. THE INVARIANT: a rebuild equals a genesis-fresh NewArbitrators, field by field
// ---------------------------------------------------------------------------

// fieldPolicy says how a single Arbiters field must relate to the reference.
type fieldPolicy int

const (
	// baseline: must DeepEqual the same field on an independently constructed,
	// genesis-fresh NewArbitrators.
	baseline fieldPolicy = iota
	// carried: a genesis-time INPUT of NewArbitrators that is not a function of
	// chainParams, so the rebuild carries the live object's own instance across.
	// Must be the identical value the live Arbiters holds, and non-nil.
	carried
	// sameShape: an independently allocated instance whose identity legitimately
	// differs from the reference's; only nil-ness is asserted.
	sameShape
	// stateSpecial: *State, checked separately -- its StateKeyFrame must equal the
	// reference's, its closures deliberately must not exist (see below).
	stateSpecial
	// exempt: a lock. Nothing to assert.
	exempt
)

// nilClassArbitersPolicy is the COMPLETE audit table for every field of Arbiters.
// The test below fails if upstream adds, removes or renames a field, so the table
// cannot silently go stale -- that is what makes the completeness claim provable
// rather than asserted.
var nilClassArbitersPolicy = map[string]fieldPolicy{
	// --- embedded ---
	"State":       stateSpecial,
	"degradation": baseline, // F-096; fixed by a0152da, re-proved here

	// --- genesis-time inputs carried across from the live object ---
	"ChainParams":                  carried,
	"CRCommittee":                  carried,
	"CkpManager":                   carried,
	"BlockConfirmProposalSponsors": carried,

	// --- fresh instances: identity differs, nil-ness must not ---
	"History": sameShape,

	// --- the genesis baseline proper ---
	// Non-nil on a genesis-fresh Arbiters; every one of these was nil on a rebuild
	// before this commit except where noted.
	"illegalBlocksPayloadHashes": baseline, // WAS nil -> the live panic
	"LastDPoSRewards":            baseline, // WAS nil -> benign today
	"nextCandidates":             baseline, // WAS nil -> benign today
	"Snapshots":                  baseline, // WAS nil -> latent
	"SnapshotKeysDesc":           baseline, // WAS nil -> latent
	// Already correct before this commit; asserted so they cannot regress.
	"LastArbitrators":       baseline,
	"CurrentArbitrators":    baseline,
	"nextArbitrators":       baseline,
	"CurrentCRCArbitersMap": baseline,
	"nextCRCArbitersMap":    baseline,
	"CurrentReward":         baseline,
	"NextReward":            baseline,
	// Genuinely nil / zero on a genesis-fresh Arbiters too. Filling these would
	// DIVERGE from genesis-fresh, so DeepEqual against the reference is exactly the
	// right assertion: it pins them nil/zero in BOTH.
	"CurrentCandidates":   baseline,
	"nextCRCArbiters":     baseline,
	"arbitersRoundReward": baseline,
	"DutyIndex":           baseline,
	"crcChangedHeight":    baseline,
	"accumulativeReward":  baseline,
	"finalRoundChange":    baseline,
	"clearingHeight":      baseline,
	"forceChanged":        baseline,
	"started":             baseline,
	"pendingSpecialTx":    baseline,
	// Installed by RegisterFunction long after construction; nil on a genesis-fresh
	// Arbiters, so nil is the correct baseline. reflect.DeepEqual is false for two
	// non-nil funcs, so these are shape-checked.
	"bestHeight":       sameShape,
	"bestBlockHash":    sameShape,
	"getBlockByHeight": sameShape,

	// --- locks ---
	"mtx":          exempt,
	"specialTxMtx": exempt,
}

// readField reads a field, exported or not.
func readField(v reflect.Value, i int) interface{} {
	f := v.Field(i)
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface()
}

func isNilable(k reflect.Kind) bool {
	switch k {
	case reflect.Map, reflect.Slice, reflect.Ptr, reflect.Func, reflect.Interface, reflect.Chan:
		return true
	}
	return false
}

// TestNilClassRebuildEqualsGenesisFreshArbitrators is the invariant the previous
// commit CLAIMED and did not prove. It walks EVERY field of Arbiters -- with a
// policy table the test forces to stay exhaustive -- and compares the rebuild
// newBaselineArbiters() produces against an INDEPENDENTLY constructed, genesis-fresh
// NewArbitrators.
func TestNilClassRebuildEqualsGenesisFreshArbitrators(t *testing.T) {
	live, _, params := nilClassChain(t)

	// The reference: a second, independent, genesis-fresh production constructor.
	refCkp := checkpoint.NewManager(params)
	refCkp.SetNeedSave(false)
	ref, err := NewArbitrators(params, crstate.NewCommittee(params, refCkp), nil,
		nil, nil, nil,
		nil, nil, nil, refCkp)
	require.NoError(t, err)

	// Dirty the LIVE object everywhere the rebuild is supposed to reset it, so a
	// pass cannot come from the live object simply never having moved.
	live.DutyIndex = 7
	live.forceChanged = true
	live.crcChangedHeight = 11
	live.accumulativeReward = 13
	live.finalRoundChange = 17
	live.clearingHeight = 19
	live.started = true
	live.illegalBlocksPayloadHashes[common.Uint256{0x01}] = nil
	live.LastDPoSRewards["x"] = map[string]common.Fixed64{"y": 1}
	live.Snapshots[1] = nil
	live.SnapshotKeysDesc = append(live.SnapshotKeysDesc, 1)
	live.nextCandidates = append(live.nextCandidates, live.CurrentArbitrators...)
	live.arbitersRoundReward = map[common.Uint168]common.Fixed64{{0x02}: 3}
	live.degradation.state = DSInactive
	live.degradation.understaffedSince = 100
	live.degradation.inactivateHeight = 200
	live.degradation.inactiveTxs = map[common.Uint256]interface{}{{0x03}: nil}

	base, err := newBaselineArbiters(live)
	require.NoError(t, err)

	baseV := reflect.ValueOf(base).Elem()
	refV := reflect.ValueOf(ref).Elem()
	liveV := reflect.ValueOf(live).Elem()
	typ := baseV.Type()

	// Completeness: the policy table must name EXACTLY the fields Arbiters has.
	require.Equal(t, typ.NumField(), len(nilClassArbitersPolicy),
		"the Arbiters field-audit table is stale -- a field was added or removed")
	for i := 0; i < typ.NumField(); i++ {
		_, ok := nilClassArbitersPolicy[typ.Field(i).Name]
		require.True(t, ok, "Arbiters.%s is missing from the field-audit table",
			typ.Field(i).Name)
	}

	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		kind := typ.Field(i).Type.Kind()
		switch nilClassArbitersPolicy[name] {
		case baseline:
			assert.EqualValues(t, readField(refV, i), readField(baseV, i),
				"Arbiters.%s must equal a genesis-fresh NewArbitrators", name)
		case carried:
			assert.EqualValues(t, readField(liveV, i), readField(baseV, i),
				"Arbiters.%s is a genesis-time input; the rebuild must carry the live value", name)
			if isNilable(kind) {
				assert.False(t, baseV.Field(i).IsNil(),
					"Arbiters.%s must not be nil after a rebuild", name)
				assert.False(t, refV.Field(i).IsNil(),
					"Arbiters.%s is non-nil on a genesis-fresh Arbiters", name)
			}
		case sameShape:
			require.True(t, isNilable(kind))
			assert.Equal(t, refV.Field(i).IsNil(), baseV.Field(i).IsNil(),
				"Arbiters.%s nil-ness must match a genesis-fresh NewArbitrators", name)
		case stateSpecial, exempt:
			// handled below / nothing to assert
		}
	}

	// --- Arbiters.State: the one DOCUMENTED, JUSTIFIED divergence -------------
	//
	// The rebuild gives State only its StateKeyFrame, NOT the closures NewState
	// installs, because NewState calls events.Subscribe(state.handleEvents): building
	// one per reset would leak a subscription to a dead State on every deep reorg.
	// This is safe because initFromArbitrators reads exactly *ar.State.StateKeyFrame
	// off the rebuilt object and nothing else, and recoverFromCheckPoints re-points
	// the LIVE State's StateKeyFrame without replacing the live State itself.
	require.NotNil(t, base.State)
	require.NotNil(t, base.State.StateKeyFrame)
	assert.EqualValues(t, *ref.State.StateKeyFrame, *base.State.StateKeyFrame,
		"the rebuilt key frame must equal a genesis-fresh one, field for field")

	// Pin the divergence explicitly, so it is a decision on record and not a gap:
	// exactly these State fields are unset on the rebuild, and every one of them is
	// unreachable from it.
	unsetOnRebuild := map[string]bool{
		"ChainParams": true, "GetArbiters": true, "getCurrentCRMembers": true,
		"getNextCRMembers": true, "isInElectionPeriod": true, "History": true,
	}
	stV := reflect.ValueOf(base.State).Elem()
	refStV := reflect.ValueOf(ref.State).Elem()
	stT := stV.Type()
	for i := 0; i < stT.NumField(); i++ {
		name := stT.Field(i).Name
		if name == "StateKeyFrame" || !isNilable(stT.Field(i).Type.Kind()) {
			continue
		}
		if unsetOnRebuild[name] {
			assert.True(t, stV.Field(i).IsNil(),
				"State.%s is expected to be unset on a rebuild (documented divergence)", name)
			assert.False(t, refStV.Field(i).IsNil(),
				"State.%s is expected to be SET on a genesis-fresh NewArbitrators", name)
			continue
		}
		assert.Equal(t, refStV.Field(i).IsNil(), stV.Field(i).IsNil(),
			"State.%s must match a genesis-fresh NewArbitrators", name)
	}

	// --- and the LIVE object after the real rebuild path ---------------------
	// recoverFromCheckPoints plants a SUBSET of the baseline on the live Arbiters;
	// prove the planted subset is the genesis-fresh one too.
	live2, ckp2, _ := nilClassChain(t)
	live2.illegalBlocksPayloadHashes[common.Uint256{0x04}] = nil
	live2.degradation.state = DSInactive
	require.NoError(t, ckp2.OnReset())

	assert.NotNil(t, live2.illegalBlocksPayloadHashes)
	assert.Equal(t, 0, len(live2.illegalBlocksPayloadHashes))
	assert.NotNil(t, live2.LastDPoSRewards)
	assert.Equal(t, 0, len(live2.LastDPoSRewards))
	assert.NotNil(t, live2.nextCandidates)
	assert.Equal(t, 0, len(live2.nextCandidates))
	assert.Equal(t, DSNormal, live2.degradation.state)
	assert.NotNil(t, live2.degradation.inactiveTxs)
	assert.EqualValues(t, *ref.State.StateKeyFrame, *live2.State.StateKeyFrame)
	// The live State object itself is NOT replaced: its closures still work.
	assert.NotNil(t, live2.State.GetArbiters)
	assert.NotNil(t, live2.State.History)
}

// ---------------------------------------------------------------------------
// 3. BELT AND BRACES: initFromArbitrators tolerates a hand-built Arbiters
// ---------------------------------------------------------------------------

// TestNilClassInitFromArbitratorsIsNilTolerant pins the safety net: a FUTURE caller
// that hand-builds &Arbiters{} and skips newBaselineArbiters must get the documented
// legacy defaults instead of a nil deref or a nil map planted on the live object.
// The constructor guard is the fix; this only makes the class un-reopenable.
func TestNilClassInitFromArbitratorsIsNilTolerant(t *testing.T) {
	abt, _, _ := nilClassChain(t)
	c := NewCheckpoint(abt)

	bare := &Arbiters{} // no State, no degradation, no maps

	if rec := runNoPanic(func() { c.initFromArbitrators(bare) }); rec != nil {
		t.Fatalf("initFromArbitrators must tolerate a hand-built Arbiters, got panic: %v", rec)
	}

	// Documented legacy defaults.
	assert.EqualValues(t, *NewStateKeyFrame(), c.StateKeyFrame)
	assert.Equal(t, byte(DSNormal), c.DegradationState)
	assert.Equal(t, uint32(0), c.UnderstaffedSince)
	assert.Equal(t, uint32(0), c.InactivateHeight)
	assert.NotNil(t, c.InactiveTxs)
	assert.Equal(t, 0, len(c.InactiveTxs))
	// The two maps recoverFromCheckPoints would otherwise plant nil on the live
	// Arbiters, one of which ProcessSpecialTxPayload index-writes unguarded.
	assert.NotNil(t, c.IllegalBlocksPayloadHashes)
	assert.Equal(t, 0, len(c.IllegalBlocksPayloadHashes))
	assert.NotNil(t, c.LastDPoSRewards)
	assert.Equal(t, 0, len(c.LastDPoSRewards))
	// arbitersRoundReward is nil on a genesis-fresh Arbiters, so it stays nil.
	assert.Nil(t, c.ArbitersRoundReward)
}

// TestNilClassInitArbitratorsEstablishesFullBaseline pins the invariant at its
// source: initArbitrators over a bare &Arbiters{} must leave every field of the
// genesis baseline usable, and must not clobber anything already populated (the
// NewArbitrators ordering, where the composite literal runs first).
func TestNilClassInitArbitratorsEstablishesFullBaseline(t *testing.T) {
	params := config.GetDefaultParams()

	fresh := &Arbiters{}
	require.NoError(t, fresh.initArbitrators(params))
	assert.NotNil(t, fresh.degradation)
	assert.NotNil(t, fresh.illegalBlocksPayloadHashes)
	assert.NotNil(t, fresh.LastDPoSRewards)
	assert.NotNil(t, fresh.Snapshots)
	assert.NotNil(t, fresh.SnapshotKeysDesc)
	assert.NotNil(t, fresh.nextCandidates)
	assert.NotNil(t, fresh.History)
	assert.Same(t, params, fresh.ChainParams)

	// Nothing pre-populated is replaced -- this is what keeps NewArbitrators, whose
	// literal fills all of these BEFORE calling in, bit-for-bit unchanged.
	populated := &Arbiters{
		ChainParams:                config.GetDefaultParams(),
		degradation:                &degradation{state: DSInactive, understaffedSince: 7, inactivateHeight: 9},
		illegalBlocksPayloadHashes: map[common.Uint256]interface{}{{0x05}: nil},
		LastDPoSRewards:            map[string]map[string]common.Fixed64{"a": nil},
		Snapshots:                  map[uint32][]*CheckPoint{1: nil},
		SnapshotKeysDesc:           []uint32{1},
		nextCandidates:             make([]ArbiterMember, 3),
		History:                    nil,
	}
	keep := struct {
		params *config.Configuration
		degr   *degradation
	}{populated.ChainParams, populated.degradation}
	populated.History = nil
	require.NoError(t, populated.initArbitrators(params))
	assert.Same(t, keep.params, populated.ChainParams, "existing ChainParams kept")
	assert.Same(t, keep.degr, populated.degradation, "existing degradation kept")
	assert.Equal(t, DSInactive, populated.degradation.state)
	assert.Equal(t, 1, len(populated.illegalBlocksPayloadHashes))
	assert.Equal(t, 1, len(populated.LastDPoSRewards))
	assert.Equal(t, 1, len(populated.Snapshots))
	assert.Equal(t, []uint32{1}, populated.SnapshotKeysDesc)
	assert.Equal(t, 3, len(populated.nextCandidates))
}
