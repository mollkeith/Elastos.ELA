// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/stretchr/testify/assert"
)

// f202Arbiters builds the smallest Arbiters that getCandidateIndexAtRandom
// needs: a ChainParams with the DPoS counts and a block source.
func f202Arbiters(blk *types.Block) *Arbiters {
	a := &Arbiters{ChainParams: &config.Configuration{}}
	a.ChainParams.DPoSConfiguration.NormalArbitratorsCount = 24
	a.ChainParams.DPoSConfiguration.CandidatesCount = 72
	a.getBlockByHeight = func(uint32) (*types.Block, error) { return blk, nil }
	return a
}

// TestF202DrawDoesNotDisturbGlobalRand proves the real half of F-202.
//
// getCandidateIndexAtRandom used to call rand.Seed(seed) + rand.Intn() on the
// PROCESS-GLOBAL math/rand generator, which every other global-rand consumer in
// the binary (p2p, elanet) draws from concurrently. Two consequences:
//
//	(1) an interleaved global draw between the Seed and the Intn shifts the
//	    selected candidate, i.e. the "deterministic" arbiter selection is not
//	    deterministic; and
//	(2) the call re-seeds and advances the global stream as a side effect,
//	    perturbing every other consumer.
//
// (2) is the deterministically observable half, so that is what this test
// asserts: calling the function must leave the global stream exactly where it
// was. Pre-fix the global generator is re-seeded from the block hash and one
// value consumed, so the next global draw differs. Post-fix the function owns a
// private Source and the global stream is untouched.
func TestF202DrawDoesNotDisturbGlobalRand(t *testing.T) {
	blk := &types.Block{Header: common2.Header{Height: 100, Nonce: 0x5eed}}
	a := f202Arbiters(blk)

	// Baseline: what the global stream yields after a known seed.
	rand.Seed(20260724)
	want := rand.Int63()

	// Same known seed, but with the candidate draw in between.
	rand.Seed(20260724)
	idx, err := a.getCandidateIndexAtRandom(101, 0, 200)
	assert.NoError(t, err)
	assert.True(t, idx >= 0)
	got := rand.Int63()

	assert.Equal(t, want, got,
		"F-202: getCandidateIndexAtRandom must not touch the process-global "+
			"math/rand stream (pre-fix it re-seeded it from the block hash)")
}

// TestF202DrawIsStableAcrossGlobalRandTraffic asserts the selection itself is
// independent of what the rest of the process does to the global generator.
func TestF202DrawIsStableAcrossGlobalRandTraffic(t *testing.T) {
	blk := &types.Block{Header: common2.Header{Height: 100, Nonce: 0x5eed}}
	a := f202Arbiters(blk)

	first, err := a.getCandidateIndexAtRandom(101, 0, 200)
	assert.NoError(t, err)

	for i := 0; i < 64; i++ {
		// Simulate unrelated global-rand traffic from elsewhere in the binary.
		rand.Int63()
		again, err := a.getCandidateIndexAtRandom(101, 0, 200)
		assert.NoError(t, err)
		assert.Equal(t, first, again,
			"F-202: the block-seeded candidate index must not depend on the "+
				"global math/rand stream position")
	}
}

// TestF202SeededDrawEquivalence is the NO-ACCEPTANCE-CHANGE proof for the
// F-202 fix: for an undisturbed generator, rand.Seed(s)+rand.Intn(n) and
// rand.New(rand.NewSource(s)).Intn(n) return the identical value, so swapping
// the global generator for a private Source cannot change which candidate a
// historical block selects.
func TestF202SeededDrawEquivalence(t *testing.T) {
	seeds := []int64{
		0, 1, -1, 42, -42, 1 << 31, -(1 << 31), 1<<62 - 1, -(1<<62 - 1),
		20260724, -20260724, 0x0123456789abcdef, -0x0123456789abcdef,
	}
	counts := []int{1, 2, 3, 7, 24, 71, 72, 73, 200, 1000}

	for _, seed := range seeds {
		for _, n := range counts {
			rand.Seed(seed)
			want := rand.Intn(n)
			got := rand.New(rand.NewSource(seed)).Intn(n)
			assert.Equal(t, want, got,
				"seed=%d n=%d: private Source must reproduce the global "+
					"generator's value exactly", seed, n)
		}
	}
}
