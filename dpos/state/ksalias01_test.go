// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// KS-ALIAS-01 - stale alias entries in the StateKeyFrame producer ALIAS INDEXES
// (DposV2EffectedProducers and PendingCanceledProducers).
//
// At runtime both indexes hold the SAME *Producer pointer that one of the five
// owning state maps holds.  Serialize/Deserialize (restore) and copyProducerMap
// (snapshot) each allocate a fresh object per map, so after either the index
// entry stops tracking the producer and freezes.  Replay only ever mutates the
// producer through the owning state map, so the frozen duplicate then diverges
// - which is what makes the persisted dpos keyframe restore-baseline dependent.
//
// Tests 1-3 FAIL on the pristine tree and PASS with the fix.  Tests 4-5 are the
// consensus-inertness guards: they must pass on BOTH, because the fix is only
// safe as long as it moves no key and no len().
// ---------------------------------------------------------------------------

// ksAliasOwnerKey is the map key form used by every producer map in
// StateKeyFrame: hex(info.OwnerKey).
func ksAliasOwnerKey(p *Producer) string {
	return hex.EncodeToString(p.OwnerPublicKey())
}

// ksAliasNewProducer builds a DPoS-V2 producer carrying exactly one detailed
// vote entry, so that a whole StateKeyFrame containing it serializes to stable
// bytes (the serializers range over Go maps, so more than one entry per map
// would make the byte stream iteration-order dependent).
func ksAliasNewProducer() *Producer {
	p := &Producer{}
	p.SetInfo(payload.ProducerInfo{
		OwnerKey:      randomFakePK(),
		NodePublicKey: randomFakePK(),
		NickName:      "ks-alias-01",
		Url:           "https://example.invalid",
		Location:      1,
		NetAddress:    "127.0.0.1:20338",
		Signature:     []byte{0x01, 0x02},
		StakeUntil:    1000,
	})
	p.SetState(Active)
	p.identity = DPoSV2
	p.SetRegisterHeight(100)
	p.SetVotes(common.Fixed64(1))
	p.SetDposV2Votes(common.Fixed64(100000000))
	p.SetTotalAmount(common.Fixed64(200000000000))

	stake := *randomProgramHash()
	refer := *randomHash()
	p.detailedDPoSV2Votes =
		map[common.Uint168]map[common.Uint256]payload.DetailedVoteInfo{
			stake: {
				refer: payload.DetailedVoteInfo{
					StakeProgramHash: stake,
					TransactionHash:  refer,
					BlockHeight:      101,
					PayloadVersion:   0,
					VoteType:         outputpayload.DposV2,
					Info: []payload.VotesWithLockTime{
						{
							Candidate: p.info.OwnerKey,
							Votes:     common.Fixed64(100000000),
							LockTime:  2000,
						},
					},
				},
			},
		}
	p.expiredNFTVotes = make(map[common.Uint168]payload.DetailedVoteInfo)
	return p
}

// ksAliasNewKeyFrame wires one producer into ActivityProducers (the owning map)
// and into DposV2EffectedProducers, plus a second producer into
// CanceledProducers and PendingCanceledProducers - exactly the two overlapping
// index shapes the state machine creates at state.go:1677/2223 and
// state.go:1485/1991.
func ksAliasNewKeyFrame() (kf *StateKeyFrame, active, canceled *Producer) {
	kf = NewStateKeyFrame()

	active = ksAliasNewProducer()
	kf.ActivityProducers[ksAliasOwnerKey(active)] = active
	kf.DposV2EffectedProducers[ksAliasOwnerKey(active)] = active

	canceled = ksAliasNewProducer()
	canceled.SetState(Canceled)
	kf.CanceledProducers[ksAliasOwnerKey(canceled)] = canceled
	kf.PendingCanceledProducers[ksAliasOwnerKey(canceled)] = canceled

	return
}

// ksAliasMutate applies, through the OWNING state map only, the five field
// classes the three-baseline keystone comparison observed drifting
// (dposV2Votes, workedInRound, info.StakeUntil, info.Signature,
// detailedDPoSV2Votes).
func ksAliasMutate(kf *StateKeyFrame, activeKey, canceledKey string) {
	p := kf.ActivityProducers[activeKey]
	p.dposV2Votes = common.Fixed64(150000000)
	p.workedInRound = true
	info := p.info
	info.StakeUntil = 2000
	info.Signature = []byte{0xff, 0xfe, 0xfd}
	p.info = info
	for stake := range p.detailedDPoSV2Votes {
		for refer := range p.detailedDPoSV2Votes[stake] {
			delete(p.detailedDPoSV2Votes[stake], refer)
		}
	}

	c := kf.CanceledProducers[canceledKey]
	c.dposV2Votes = common.Fixed64(7)
	c.penalty = common.Fixed64(9)
}

func ksAliasSerialize(t *testing.T, kf *StateKeyFrame) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	assert.NoError(t, kf.Serialize(buf))
	return buf.Bytes()
}

func ksAliasRoundTrip(t *testing.T, kf *StateKeyFrame) *StateKeyFrame {
	t.Helper()
	out := NewStateKeyFrame()
	assert.NoError(t, out.Deserialize(bytes.NewReader(ksAliasSerialize(t, kf))))
	return out
}

func ksAliasKeySet(m map[string]*Producer) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// ---------------------------------------------------------------------------
//  1. FAIL-ON-PRISTINE: the restore path.  This is the keystone's three-baseline
//     comparison in miniature - baseline A never restores, baseline C restores
//     once - and it asserts the serialized keyframes stay byte-identical under an
//     identical mutation stream.
//
// ---------------------------------------------------------------------------
func TestKSAlias01_RestoreBaselineIndependence(t *testing.T) {
	kfA, active, canceled := ksAliasNewKeyFrame()
	activeKey, canceledKey := ksAliasOwnerKey(active), ksAliasOwnerKey(canceled)

	// Baseline C restores once, before any mutation, so both baselines start
	// from identical bytes.
	pre := ksAliasSerialize(t, kfA)
	kfC := ksAliasRoundTrip(t, kfA)
	assert.Equal(t, pre, ksAliasSerialize(t, kfC),
		"restore must be byte-faithful before any mutation")

	// Identical mutation stream, applied through the owning state map only.
	ksAliasMutate(kfA, activeKey, canceledKey)
	ksAliasMutate(kfC, activeKey, canceledKey)

	assert.Equal(t, ksAliasSerialize(t, kfA), ksAliasSerialize(t, kfC),
		"KS-ALIAS-01: a restored keyframe must serialize identically to a "+
			"never-restored one after the same mutations; a difference means "+
			"the alias index froze at its restore value")

	// The specific divergence the keystone observed, field by field.
	live := kfC.ActivityProducers[activeKey]
	eff := kfC.DposV2EffectedProducers[activeKey]
	assert.Same(t, live, eff,
		"DposV2EffectedProducers must alias the live producer after restore")
	assert.Equal(t, live.dposV2Votes, eff.dposV2Votes)
	assert.Equal(t, live.workedInRound, eff.workedInRound)
	assert.Equal(t, live.info.StakeUntil, eff.info.StakeUntil)
	assert.Equal(t, live.info.Signature, eff.info.Signature)
	assert.Equal(t, len(live.detailedDPoSV2Votes[firstStakeKey(live)]),
		len(eff.detailedDPoSV2Votes[firstStakeKey(eff)]))

	liveC := kfC.CanceledProducers[canceledKey]
	pend := kfC.PendingCanceledProducers[canceledKey]
	assert.Same(t, liveC, pend,
		"PendingCanceledProducers must alias the live producer after restore")
	assert.Equal(t, liveC.dposV2Votes, pend.dposV2Votes)
	assert.Equal(t, liveC.penalty, pend.penalty)
}

// firstStakeKey returns the single stake key of the fixture producer.
func firstStakeKey(p *Producer) common.Uint168 {
	for k := range p.detailedDPoSV2Votes {
		return k
	}
	return common.Uint168{}
}

// ---------------------------------------------------------------------------
//  2. FAIL-ON-PRISTINE: the snapshot path (StateKeyFrame.snapshot ->
//     copyProducerMap).  Snapshots are NOT exempt from the aliasing break.
//
// ---------------------------------------------------------------------------
func TestKSAlias01_SnapshotAliasPreserved(t *testing.T) {
	kf, active, canceled := ksAliasNewKeyFrame()
	activeKey, canceledKey := ksAliasOwnerKey(active), ksAliasOwnerKey(canceled)

	snap := kf.snapshot()

	assert.Same(t, snap.ActivityProducers[activeKey],
		snap.DposV2EffectedProducers[activeKey],
		"KS-ALIAS-01: snapshot() must not detach DposV2EffectedProducers")
	assert.Same(t, snap.CanceledProducers[canceledKey],
		snap.PendingCanceledProducers[canceledKey],
		"KS-ALIAS-01: snapshot() must not detach PendingCanceledProducers")

	// The snapshot must be internally consistent: a mutation applied through
	// the owning map has to be visible through the index.
	ksAliasMutate(snap, activeKey, canceledKey)
	assert.Equal(t, common.Fixed64(150000000),
		snap.DposV2EffectedProducers[activeKey].dposV2Votes)
	assert.Equal(t, common.Fixed64(7),
		snap.PendingCanceledProducers[canceledKey].dposV2Votes)

	// ...while still being an independent copy of the source keyframe.
	assert.NotSame(t, kf.ActivityProducers[activeKey],
		snap.ActivityProducers[activeKey],
		"snapshot must remain a copy, not an alias of the source")
	assert.Equal(t, common.Fixed64(100000000),
		kf.ActivityProducers[activeKey].dposV2Votes,
		"mutating the snapshot must not reach the source keyframe")
}

// ---------------------------------------------------------------------------
//  3. FAIL-ON-PRISTINE: three baselines - never restored, restored once,
//     restored twice - must all serialize identically after the same mutation
//     stream (baselines A/C/D of the keystone comparison).
//
// ---------------------------------------------------------------------------
func TestKSAlias01_ThreeBaselinesConverge(t *testing.T) {
	kfA, active, canceled := ksAliasNewKeyFrame()
	activeKey, canceledKey := ksAliasOwnerKey(active), ksAliasOwnerKey(canceled)

	kfC := ksAliasRoundTrip(t, kfA)
	kfD := ksAliasRoundTrip(t, ksAliasRoundTrip(t, kfA))

	for _, kf := range []*StateKeyFrame{kfA, kfC, kfD} {
		ksAliasMutate(kf, activeKey, canceledKey)
	}

	a := ksAliasSerialize(t, kfA)
	c := ksAliasSerialize(t, kfC)
	d := ksAliasSerialize(t, kfD)

	assert.Equal(t, a, c, "KS-ALIAS-01: baseline A vs C must be byte-identical")
	assert.Equal(t, a, d, "KS-ALIAS-01: baseline A vs D must be byte-identical")
	assert.Equal(t, c, d, "KS-ALIAS-01: baseline C vs D must be byte-identical")
}

// ---------------------------------------------------------------------------
//  4. CONSENSUS-INERTNESS GUARD (passes on pristine AND on the fix): the fix
//     must not add or remove a single key, because len(DposV2EffectedProducers)
//     feeds isDposV2Active() (state.go:626, arbitrators.go:2342) and is the one
//     consensus-visible property of these maps.
//
// ---------------------------------------------------------------------------
func TestKSAlias01_KeySetAndLenUnchanged(t *testing.T) {
	kf, _, _ := ksAliasNewKeyFrame()

	// More entries, so len() is not trivially 1.
	for i := 0; i < 5; i++ {
		p := ksAliasNewProducer()
		kf.ActivityProducers[ksAliasOwnerKey(p)] = p
		kf.DposV2EffectedProducers[ksAliasOwnerKey(p)] = p
	}

	wantEffected := ksAliasKeySet(kf.DposV2EffectedProducers)
	wantPending := ksAliasKeySet(kf.PendingCanceledProducers)
	wantLenEffected := len(kf.DposV2EffectedProducers)
	wantLenPending := len(kf.PendingCanceledProducers)

	restored := ksAliasRoundTrip(t, kf)
	cases := map[string]*StateKeyFrame{
		"restored":            restored,
		"snapshot":            kf.snapshot(),
		"snapshot-of-restore": restored.snapshot(),
	}

	for name, got := range cases {
		assert.Equal(t, wantLenEffected, len(got.DposV2EffectedProducers),
			"%s: len(DposV2EffectedProducers) must be unchanged", name)
		assert.Equal(t, wantLenPending, len(got.PendingCanceledProducers),
			"%s: len(PendingCanceledProducers) must be unchanged", name)
		assert.Equal(t, wantEffected, ksAliasKeySet(got.DposV2EffectedProducers),
			"%s: DposV2EffectedProducers key set must be unchanged", name)
		assert.Equal(t, wantPending, ksAliasKeySet(got.PendingCanceledProducers),
			"%s: PendingCanceledProducers key set must be unchanged", name)
	}
}

// ---------------------------------------------------------------------------
//  5. ORPHAN EDGE CASE (passes on pristine AND on the fix): an index key with no
//     producer in any of the five owning maps, and an index key that resolves to
//     a DIFFERENT producer identity, must both be KEPT verbatim.  Dropping the
//     first would change len(); re-pointing the second would swap a producer.
//
// ---------------------------------------------------------------------------
func TestKSAlias01_OrphanEntriesRetained(t *testing.T) {
	kf, _, _ := ksAliasNewKeyFrame()

	orphan := ksAliasNewProducer()
	orphanKey := ksAliasOwnerKey(orphan)
	kf.DposV2EffectedProducers[orphanKey] = orphan // no owning-map entry

	impostor := ksAliasNewProducer()
	mismatchKey := ksAliasOwnerKey(impostor)
	kf.ActivityProducers[mismatchKey] = impostor
	stranger := ksAliasNewProducer()
	kf.PendingCanceledProducers[mismatchKey] = stranger

	wantEffLen := len(kf.DposV2EffectedProducers)
	wantPendLen := len(kf.PendingCanceledProducers)

	for name, got := range map[string]*StateKeyFrame{
		"restored": ksAliasRoundTrip(t, kf),
		"snapshot": kf.snapshot(),
	} {
		assert.Equal(t, wantEffLen, len(got.DposV2EffectedProducers), name)
		assert.Equal(t, wantPendLen, len(got.PendingCanceledProducers), name)
		assert.Contains(t, got.DposV2EffectedProducers, orphanKey,
			"%s: orphan entry must never be dropped - that changes len()", name)
		assert.Contains(t, got.PendingCanceledProducers, mismatchKey, name)
		assert.Equal(t, stranger.info.OwnerKey,
			got.PendingCanceledProducers[mismatchKey].info.OwnerKey,
			"%s: a key collision must not re-point at a different producer", name)
	}
}

// ---------------------------------------------------------------------------
//  6. FAIL-ON-PRISTINE: the REAL persisted-checkpoint path.  CheckPoint.Serialize
//     / CheckPoint.Deserialize is what writes and reads the .dcp file, and
//     CheckPoint.Deserialize is the only thing that ever installs a StateKeyFrame
//     into a running node (Arbiters.RecoverFromCheckPoints, arbitrators.go:199).
//     This is the exact mechanism behind the observed restore-baseline dependence
//     of the dpos checkpoint blob.
//
// ---------------------------------------------------------------------------
func TestKSAlias01_CheckPointRestorePreservesAlias(t *testing.T) {
	kf, active, canceled := ksAliasNewKeyFrame()
	activeKey, canceledKey := ksAliasOwnerKey(active), ksAliasOwnerKey(canceled)

	c := &CheckPoint{
		StateKeyFrame: *kf,
		Height:        2260450,
		InactiveTxs:   make(map[common.Uint256]interface{}),
	}
	var buf bytes.Buffer
	assert.NoError(t, c.Serialize(&buf))

	restored := &CheckPoint{}
	assert.NoError(t, restored.Deserialize(bytes.NewReader(buf.Bytes())))

	assert.Same(t, restored.ActivityProducers[activeKey],
		restored.DposV2EffectedProducers[activeKey],
		"KS-ALIAS-01: a .dcp restore must not detach DposV2EffectedProducers")
	assert.Same(t, restored.CanceledProducers[canceledKey],
		restored.PendingCanceledProducers[canceledKey],
		"KS-ALIAS-01: a .dcp restore must not detach PendingCanceledProducers")

	// len() - the only consensus-visible property - must be untouched.
	assert.Equal(t, len(kf.DposV2EffectedProducers),
		len(restored.DposV2EffectedProducers))
	assert.Equal(t, len(kf.PendingCanceledProducers),
		len(restored.PendingCanceledProducers))

	// Replay the same mutation stream on both and compare the next keyframe a
	// node would write: they must be byte-identical.
	ksAliasMutate(&restored.StateKeyFrame, activeKey, canceledKey)
	ksAliasMutate(kf, activeKey, canceledKey)
	assert.Equal(t, ksAliasSerialize(t, kf),
		ksAliasSerialize(t, &restored.StateKeyFrame),
		"KS-ALIAS-01: the keyframe written after a .dcp restore must match the "+
			"keyframe written by a node that never restored")
}
