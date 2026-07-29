// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// f096NilFixChain builds a REAL Arbiters wired to a REAL checkpoint.Manager --
// NewArbitrators registers the dpos CheckPoint into that manager -- so the tests
// below drive the exact production frames of the captured crash:
//
//	core/checkpoint.(*Manager).OnReset      -> manager.go:215
//	dpos/state.(*CheckPoint).OnReset        -> checkpoint.go
//	dpos/state.(*CheckPoint).initFromArbitrators
//
// and the sibling Manager.OnRollbackTo -> CheckPoint.OnRollbackTo deep branch.
func f096NilFixChain(t *testing.T) (*Arbiters, *checkpoint.Manager, *config.Configuration) {
	// A PRIVATE parameter set: other tests in this package mutate the shared
	// config.DefaultParams, so isolate to keep the result test-order independent.
	params := config.GetDefaultParams()
	ckp := checkpoint.NewManager(params)
	// No checkpoint files: these tests only exercise the in-memory rebuild.
	ckp.SetNeedSave(false)

	abt, err := NewArbitrators(params, nil, nil,
		nil, nil, nil,
		nil, nil, nil, ckp)
	require.NoError(t, err)
	require.NotNil(t, abt.degradation,
		"NewArbitrators is the genesis-fresh reference: it always builds degradation")

	return abt, ckp, params
}

// f096Dirty drives the LIVE Arbiters into a non-baseline degradation state, so the
// assertions prove the rebuild RESETS to the genesis baseline instead of merely
// leaving an already-clean struct untouched.
func f096Dirty(a *Arbiters, h common.Uint256) {
	a.degradation.state = DSInactive
	a.degradation.understaffedSince = 100
	a.degradation.inactivateHeight = 200
	a.degradation.inactiveTxs = map[common.Uint256]interface{}{h: nil}
}

// f096AssertGenesisBaseline is the INVARIANT: after a reset / deep-rollback rebuild
// the live degradation state must be EXACTLY the baseline a genesis-fresh Arbiters
// has -- DSNormal, zero understaffedSince, zero inactivateHeight, empty (non-nil)
// processed-inactive-tx set. The reference is an independently constructed
// NewArbitrators, i.e. the production constructor, not a hand-rolled expectation.
func f096AssertGenesisBaseline(t *testing.T, a *Arbiters, params *config.Configuration) {
	reference, err := NewArbitrators(params, nil, nil,
		nil, nil, nil,
		nil, nil, nil, checkpoint.NewManager(params))
	require.NoError(t, err)

	require.NotNil(t, a.degradation, "rebuild must leave a usable degradation struct")
	assert.Equal(t, DSNormal, a.degradation.state,
		"a rebuilt-from-genesis node is in normal mode")
	assert.Equal(t, reference.degradation.state, a.degradation.state)
	assert.Equal(t, uint32(0), a.degradation.understaffedSince)
	assert.Equal(t, reference.degradation.understaffedSince, a.degradation.understaffedSince)
	assert.Equal(t, uint32(0), a.degradation.inactivateHeight)
	assert.Equal(t, reference.degradation.inactivateHeight, a.degradation.inactivateHeight)
	assert.NotNil(t, a.degradation.inactiveTxs,
		"non-nil so the next AddInactivePayload write does not panic")
	assert.Equal(t, 0, len(a.degradation.inactiveTxs))
	assert.Equal(t, len(reference.degradation.inactiveTxs), len(a.degradation.inactiveTxs))

	// The rebuild is a whole genesis baseline, not just a degradation reset.
	require.NotNil(t, a.State)
	require.NotNil(t, a.StateKeyFrame)
}

// TestF096NilFixOnResetRebuildsGenesisBaseline drives the REAL
// Manager.OnReset -> CheckPoint.OnReset path that blockchain.reorganizeChain takes
// through resetCheckpoints when a fork is at least maxHistoryCapacity (720) blocks
// deep. On the pristine tree this PANICS with a nil pointer dereference inside
// initFromArbitrators, because OnReset hands it a &Arbiters{} whose embedded
// *degradation was never built and F-096 reads ar.degradation.state.
func TestF096NilFixOnResetRebuildsGenesisBaseline(t *testing.T) {
	abt, ckp, params := f096NilFixChain(t)
	f096Dirty(abt, common.Uint256{0x01})

	// REAL production frames. Manager.OnReset only logs checkpoint errors, so the
	// pristine failure mode here is the panic, not a returned error.
	require.NoError(t, ckp.OnReset())

	f096AssertGenesisBaseline(t, abt, params)
}

// TestF096NilFixDeepRollbackRebuildsGenesisBaseline drives the REAL
// Manager.OnRollbackTo -> CheckPoint.OnRollbackTo deep branch (height <
// StartHeight), the sibling rebuild site. It is the harsher of the two: that
// branch never initialised ar.State either, so on the pristine tree it panics one
// dereference EARLIER than OnReset does.
func TestF096NilFixDeepRollbackRebuildsGenesisBaseline(t *testing.T) {
	abt, ckp, params := f096NilFixChain(t)

	// Pick a height that provably selects the deep rebuild branch. Read StartHeight
	// off a throwaway CheckPoint BEFORE dirtying, so nothing observes dirty state.
	const deepHeight = uint32(1)
	require.Greater(t, NewCheckpoint(abt).StartHeight(), deepHeight,
		"deepHeight must be below StartHeight or the deep rebuild branch is not taken")

	f096Dirty(abt, common.Uint256{0x02})

	// REAL production frames.
	require.NoError(t, ckp.OnRollbackTo(deepHeight, false))

	f096AssertGenesisBaseline(t, abt, params)
}

// TestF096NilFixInitArbitratorsEstablishesDegradation pins the invariant at its
// source: initArbitrators -- the only constructor the two rebuild sites run over a
// hand-built &Arbiters{} -- must leave a usable genesis-baseline degradation
// struct, and must NOT double-initialize or clobber one that already exists (the
// NewArbitrators order, where the literal fills degradation first).
func TestF096NilFixInitArbitratorsEstablishesDegradation(t *testing.T) {
	params := config.GetDefaultParams()

	fresh := &Arbiters{}
	require.NoError(t, fresh.initArbitrators(params))
	require.NotNil(t, fresh.degradation)
	assert.Equal(t, DSNormal, fresh.degradation.state)
	assert.Equal(t, uint32(0), fresh.degradation.understaffedSince)
	assert.Equal(t, uint32(0), fresh.degradation.inactivateHeight)
	assert.NotNil(t, fresh.degradation.inactiveTxs)
	assert.Equal(t, 0, len(fresh.degradation.inactiveTxs))

	// Pre-populated degradation survives untouched: this is what keeps the guard
	// from changing NewArbitrators, which fills degradation before calling in.
	populated := &Arbiters{degradation: &degradation{
		state:             DSInactive,
		understaffedSince: 7,
		inactivateHeight:  9,
		inactiveTxs:       map[common.Uint256]interface{}{{0x03}: nil},
	}}
	existing := populated.degradation
	require.NoError(t, populated.initArbitrators(params))
	assert.Same(t, existing, populated.degradation,
		"initArbitrators must not replace an existing degradation struct")
	assert.Equal(t, DSInactive, populated.degradation.state)
	assert.Equal(t, uint32(7), populated.degradation.understaffedSince)
	assert.Equal(t, uint32(9), populated.degradation.inactivateHeight)
	assert.Equal(t, 1, len(populated.degradation.inactiveTxs))
}
