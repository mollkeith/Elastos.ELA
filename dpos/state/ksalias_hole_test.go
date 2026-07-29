// REFUTATION SCRATCH TEST - not part of the canonical tree.
// Demonstrates coverage holes in dpos/state/ksalias01_test.go by killing
// broken-fix mutants B7, B8 and B9 that the committed suite passes.

package state

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/stretchr/testify/assert"
)

// HOLE-1 (kills B8): the committed fixture only ever puts a producer in
// ActivityProducers or CanceledProducers, so a canonicalProducer() that forgot
// to probe PendingProducers / InactiveProducers / IllegalProducers is invisible
// to it.  Those three maps are reachable: DposV2EffectedProducers is populated
// at state.go:2223 from getDPoSV2Producer -> getProducerByOwnerPublicKey, which
// resolves across all five maps.
func TestKSAliasHOLE_AllFiveOwningMaps(t *testing.T) {
	type owning struct {
		put func(kf *StateKeyFrame, k string, p *Producer)
		get func(kf *StateKeyFrame, k string) *Producer
		st  ProducerState
	}
	maps := map[string]owning{
		"Pending": {
			func(kf *StateKeyFrame, k string, p *Producer) { kf.PendingProducers[k] = p },
			func(kf *StateKeyFrame, k string) *Producer { return kf.PendingProducers[k] },
			Pending,
		},
		"Inactive": {
			func(kf *StateKeyFrame, k string, p *Producer) { kf.InactiveProducers[k] = p },
			func(kf *StateKeyFrame, k string) *Producer { return kf.InactiveProducers[k] },
			Inactive,
		},
		"Illegal": {
			func(kf *StateKeyFrame, k string, p *Producer) { kf.IllegalProducers[k] = p },
			func(kf *StateKeyFrame, k string) *Producer { return kf.IllegalProducers[k] },
			Illegal,
		},
		"Activity": {
			func(kf *StateKeyFrame, k string, p *Producer) { kf.ActivityProducers[k] = p },
			func(kf *StateKeyFrame, k string) *Producer { return kf.ActivityProducers[k] },
			Active,
		},
		"Canceled": {
			func(kf *StateKeyFrame, k string, p *Producer) { kf.CanceledProducers[k] = p },
			func(kf *StateKeyFrame, k string) *Producer { return kf.CanceledProducers[k] },
			Canceled,
		},
	}

	for name, om := range maps {
		kf := NewStateKeyFrame()
		p := ksAliasNewProducer()
		p.SetState(om.st)
		k := ksAliasOwnerKey(p)
		om.put(kf, k, p)
		kf.DposV2EffectedProducers[k] = p

		r := ksAliasRoundTrip(t, kf)
		assert.Same(t, om.get(r, k), r.DposV2EffectedProducers[k],
			"%s: restore must re-point DposV2EffectedProducers at the producer "+
				"owned by %sProducers", name, name)

		s := kf.snapshot()
		assert.Same(t, om.get(s, k), s.DposV2EffectedProducers[k],
			"%s: snapshot must re-point DposV2EffectedProducers", name)
	}
}

// HOLE-2 (kills B7): every committed fixture starts ALIASED, so the index copy
// and the owning copy always carry identical bytes and the DIRECTION of the
// re-point is unobservable.  A real .dcp written by a node that restored on
// pristine code is already DRIFTED: the two copies differ.  The owning map's
// producer must win; adopting the stale index copy into the owning map would
// push stale values into ActivityProducers, which consensus dereferences
// everywhere.
func TestKSAliasHOLE_AlreadyDriftedCheckpoint(t *testing.T) {
	kf := NewStateKeyFrame()

	live := ksAliasNewProducer()
	k := ksAliasOwnerKey(live)
	live.dposV2Votes = common.Fixed64(999)
	kf.ActivityProducers[k] = live

	// Same producer identity, frozen at an older value - exactly what a
	// pristine-code restore leaves behind in the alias index.
	stale := ksAliasNewProducer()
	stale.SetInfo(live.info)
	stale.SetState(Active)
	stale.dposV2Votes = common.Fixed64(1)
	kf.DposV2EffectedProducers[k] = stale

	r := ksAliasRoundTrip(t, kf)

	assert.Same(t, r.ActivityProducers[k], r.DposV2EffectedProducers[k],
		"drifted .dcp: the two must be re-aliased")
	assert.Equal(t, common.Fixed64(999), r.ActivityProducers[k].dposV2Votes,
		"the OWNING producer must win; adopting the stale index copy into "+
			"ActivityProducers would corrupt consensus-visible state")
	assert.Equal(t, common.Fixed64(999), r.DposV2EffectedProducers[k].dposV2Votes,
		"the index must take the canonical value, not keep its frozen one")

	s := kf.snapshot()
	assert.Same(t, s.ActivityProducers[k], s.DposV2EffectedProducers[k])
	assert.Equal(t, common.Fixed64(999), s.ActivityProducers[k].dposV2Votes,
		"snapshot: the OWNING producer must win")
}

// HOLE-3 (kills B9): canonicalProducer's probe order is documented as mirroring
// getProducerByOwnerPublicKey, but nothing tests it, because no fixture puts one
// key in two owning maps.  Map disjointness is only INFERRED in the commit
// message, so the order is load-bearing until that is proven.
func TestKSAliasHOLE_ProbeOrderMirrorsResolver(t *testing.T) {
	kf := NewStateKeyFrame()

	active := ksAliasNewProducer()
	k := ksAliasOwnerKey(active)
	active.dposV2Votes = common.Fixed64(111)
	kf.ActivityProducers[k] = active

	inactive := ksAliasNewProducer()
	inactive.SetInfo(active.info)
	inactive.SetState(Inactive)
	inactive.dposV2Votes = common.Fixed64(222)
	kf.InactiveProducers[k] = inactive

	kf.DposV2EffectedProducers[k] = active

	s := kf.snapshot()
	assert.Same(t, s.ActivityProducers[k], s.DposV2EffectedProducers[k],
		"the alias index must resolve the way getProducerByOwnerPublicKey does "+
			"(ActivityProducers first), not some other map")
	assert.Equal(t, common.Fixed64(111), s.DposV2EffectedProducers[k].dposV2Votes)
}
