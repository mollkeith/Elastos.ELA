// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Fail-on-pristine tests for F-163: DiscreteMining is reachable over JSON-RPC
// at the default service level, took an unchecked count, and held pow.started
// forever whenever block generation kept failing.
package pow

import (
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
)

// the package logger is nil in a bare test binary and the retry path logs on
// every attempt; level 5 is LevelOff, which keeps the pre-fix spin quiet.
func init() { log.NewDefault(t_f163LogPath, 5, 16, 64) }

const t_f163LogPath = "/tmp/f163-pow-test-logs"

// f163Budget is how long a DiscreteMining call is allowed to take before the
// test calls it hung. Every path under test either fails immediately or retries
// a bounded number of times, all of which fail immediately too.
const f163Budget = 5 * time.Second

// runDiscreteMining runs one DiscreteMining call under a deadline, reporting a
// panic or a hang rather than taking the test binary down with it.
func runDiscreteMining(t *testing.T, svc *Service, n uint32) error {
	t.Helper()
	type result struct {
		err      error
		panicked interface{}
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() {
			r.panicked = recover()
			done <- r
		}()
		_, r.err = svc.DiscreteMining(n)
	}()

	select {
	case r := <-done:
		if r.panicked != nil {
			t.Fatalf("DiscreteMining(%d) panicked: %v", n, r.panicked)
		}
		return r.err
	case <-time.After(f163Budget):
		t.Fatalf("DiscreteMining(%d) did not return within %v: the retry loop "+
			"is unbounded and pow.started is held for the life of the process",
			n, f163Budget)
		return nil
	}
}

// assertMiningReleased checks the call did not walk off holding the mining flags.
func assertMiningReleased(t *testing.T, svc *Service) {
	t.Helper()
	svc.mutex.Lock()
	defer svc.mutex.Unlock()
	if svc.started || svc.discreteMining {
		t.Fatal("DiscreteMining returned still holding the mining flags: " +
			"mining is wedged for the life of the process")
	}
}

// TestF163DiscreteMiningRejectsZeroCount proves a zero count is refused before
// anything is touched.
//
// Fail-on-pristine: pre-fix zero was accepted, the flags were taken and the
// generation loop ran - which mines a block for a caller who asked for none,
// and here dereferences the nil chain of this bare Service.
func TestF163DiscreteMiningRejectsZeroCount(t *testing.T) {
	svc := &Service{}

	err := runDiscreteMining(t, svc, 0)
	if err == nil {
		t.Fatal("DiscreteMining(0) must be rejected")
	}
	assertMiningReleased(t, svc)
}

// TestF163DiscreteMiningReleasesOnRepeatedFailure proves a persistent block
// generation failure terminates and gives the mining flags back.
//
// Fail-on-pristine: pre-fix the GenerateBlock error path was a bare `continue`
// in a `for {}` loop, so this call never returned - it span at full tilt
// holding pow.started, which wedges mining for the life of the process.
func TestF163DiscreteMiningReleasesOnRepeatedFailure(t *testing.T) {
	svc := &Service{
		// an address that cannot be decoded, so CreateCoinbaseTx - and with it
		// GenerateBlock - fails on every single attempt.
		PayToAddr: "this is not an address",
		chain: &blockchain.BlockChain{
			BestChain: &blockchain.BlockNode{Height: 0, Hash: &common.Uint256{}},
		},
		chainParams: config.GetDefaultParams(),
	}

	err := runDiscreteMining(t, svc, 1)
	if err == nil {
		t.Fatal("DiscreteMining must report a failure when no block can be generated")
	}
	assertMiningReleased(t, svc)
}
