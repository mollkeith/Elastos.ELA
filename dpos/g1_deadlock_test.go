// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package dpos

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/manager"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/events"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// G1 -- fail-on-pristine for the specialTxMtx x events.mtx AB-BA deadlock.
//
// Two lock-acquisition orders existed on the same pair of mutexes:
//
//	Edge 1  specialTxMtx -> events.mtx
//	        blockchain.connectBlock held Arbiters.specialTxMtx across
//	        events.Notify(ETBlockConnected) -- on every connected block -- and
//	        blockchain.saveBlockCheckpoints / replayCheckpointBlock still hold it
//	        across CkpManager.OnBlockSaved -> cr/state Checkpoint.OnBlockSaved ->
//	        Committee.ProcessBlock -> events.Notify(ETCRCChangeCommittee).
//
//	Edge 2  events.mtx -> specialTxMtx
//	        events.Notify runs every callback while holding events.mtx, and the
//	        Arbitrator's subscriber ran its ETTransactionAccepted arm INLINE:
//	        OnInactiveArbitratorsTxReceived -> Arbiters.LockSpecialTx.
//
// The publisher of ETTransactionAccepted is a detached goroutine
// (mempool/txpool.go:65 "go events.Notify"), so the two orders run concurrently and
// close the cycle. These tests drive both orders against ONE real state.Arbiters,
// through the PRODUCTION subscriber (Arbitrator.handleEvent -- the exact function
// value NewArbitrator registers) and the PRODUCTION bus (events.Notify), with a
// handshake that makes the interleaving deterministic rather than lucky.
//
//	FAIL-ON-PRISTINE: with the ETTransactionAccepted arm restored to its inline
//	form, both goroutines wedge forever -- the Edge-1 goroutine blocked on
//	events.mtx, the Edge-2 goroutine blocked on specialTxMtx -- the watchdog fires
//	and the test FAILS with both stacks. events.mtx is then held for the remainder
//	of the process, so every later test that touches the bus hangs too: that is how
//	a seconds-long package run turns into a 600 s timeout. With the fix the
//	deterministic case completes in milliseconds.
//
// The Edge-1 site is spelled here as LockSpecialTx -> events.Notify ->
// UnlockSpecialTx rather than by calling blockchain.saveBlockCheckpoints, which is
// unexported and needs a full chain and DB; that sequence is exactly and only what
// saveBlockCheckpoints does around its notify, and both the lock and the bus used
// here are the production ones.
// ---------------------------------------------------------------------------

// g1Wrap is the n001ArbWrap shape plus a completion counter. The production
// handler reaches the Arbiters only through a.cfg.Arbitrators, so counting
// UnlockSpecialTx here counts exactly the handler brackets that have closed --
// which is how each test drains its own detached handler goroutines before it
// returns. The tests' own Edge-1 goroutines lock the real *state.Arbiters directly
// and are therefore not counted.
type g1Wrap struct {
	state.Arbitrators
	cands [][]byte
	done  chan struct{}
}

func (w *g1Wrap) GetCandidates() [][]byte { return w.cands }

func (w *g1Wrap) UnlockSpecialTx() {
	w.Arbitrators.UnlockSpecialTx()
	select {
	case w.done <- struct{}{}:
	default:
	}
}

// g1Harness is the currently-armed deterministic run. The events package has no
// Unsubscribe, so the probe stays registered for the life of the test binary; it is
// inert whenever no harness is armed, which keeps the tests independent and safe
// under -count=N.
type g1Harness struct {
	tx            interfaces.Transaction
	eventsMtxHeld chan struct{}
	once          sync.Once
}

var (
	g1Armed    atomic.Value // always holds a *g1Harness (possibly nil)
	g1Disarmed = (*g1Harness)(nil)
)

func g1Current() *g1Harness {
	h, _ := g1Armed.Load().(*g1Harness)
	return h
}

// g1Probe is registered BEFORE the production subscriber, so within a single
// events.Notify it runs first: when it fires, events.mtx is held and the production
// subscriber has not been reached yet.
func g1Probe(e *events.Event) {
	h := g1Current()
	if h == nil || e.Type != events.ETTransactionAccepted {
		return
	}
	tx, ok := e.Data.(interfaces.Transaction)
	if !ok || tx != h.tx {
		return
	}
	h.once.Do(func() { close(h.eventsMtxHeld) })
}

func g1InactiveArbitratorsTx(p *payload.InactiveArbitrators) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.InactiveArbitrators, 0, p,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{},
		0, []*program.Program{},
	)
}

// g1Fixture is built once per test binary: one real Arbiters, one production
// subscriber registration, and one blockchain.DefaultLedger that is installed and
// deliberately never restored.
//
// Never restoring it is load-bearing. The fixed handler dispatches on its own
// goroutine, so it can still be inside
// OnInactiveArbitratorsTxReceived -> blockchain.DefaultLedger.Blockchain.GetHeight()
// after the test that published the event has returned; restoring the previous
// (empty) ledger would hand that goroutine a nil chain. Production never swaps the
// ledger, so this is a harness concern only. Each test still drains its own handler
// goroutines before returning, so nothing is left running across tests.
type g1Fixture struct {
	abt  *state.Arbiters
	wrap *g1Wrap
	arb  *Arbitrator
	tx   interfaces.Transaction
}

var (
	g1Once sync.Once
	g1Fix  *g1Fixture
)

func g1Setup(t *testing.T) *g1Fixture {
	g1Once.Do(func() {
		abt, tip := n001BuildArbiters(t)
		n001SetLedger(tip, abt) // installed permanently, see above

		// The handler only reaches Arbiters.LockSpecialTx for a node that is NOT a
		// current arbiter but IS inside the first GetArbitersCount()/3 candidates.
		candKey := n001AbtList[4]
		require.False(t, abt.IsArbitrator(candKey),
			"sanity: the harness key must not be a current arbiter")
		require.GreaterOrEqual(t, abt.GetArbitersCount()/3, 1,
			"sanity: at least one emergency-candidate slot")

		wrap := &g1Wrap{
			Arbitrators: abt,
			cands:       [][]byte{candKey},
			done:        make(chan struct{}, 4096),
		}
		arb := &Arbitrator{
			cfg: Config{Arbitrators: wrap, Server: n001Server{}},
			dposManager: manager.NewManager(manager.DPOSManagerConfig{
				PublicKey:   candKey,
				Arbitrators: wrap,
				ChainParams: n001Params,
			}),
		}

		events.Subscribe(g1Probe)         // must be registered first
		events.Subscribe(arb.handleEvent) // the production subscriber

		g1Fix = &g1Fixture{
			abt:  abt,
			wrap: wrap,
			arb:  arb,
			tx:   g1InactiveArbitratorsTx(n001Payload(tip)),
		}
	})
	return g1Fix
}

// g1DrainStale discards completion tokens left over from an earlier -count
// iteration.
func g1DrainStale(f *g1Fixture) {
	for {
		select {
		case <-f.wrap.done:
		default:
			return
		}
	}
}

// g1WaitHandlers blocks until n detached handler brackets have closed.
func g1WaitHandlers(t *testing.T, f *g1Fixture, n int, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for i := 0; i < n; i++ {
		select {
		case <-f.wrap.done:
		case <-deadline:
			t.Fatalf("G1: only %d/%d detached handler brackets closed in %s",
				i, n, within)
		}
	}
}

func g1Fail(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	args = append(args, buf[:n])
	t.Fatalf(format+"\n\n%s", args...)
}

func TestG1SpecialTxMtxEventsMtxNoInversion(t *testing.T) {
	f := g1Setup(t)
	g1DrainStale(f)

	h := &g1Harness{tx: f.tx, eventsMtxHeld: make(chan struct{})}
	g1Armed.Store(h)
	defer g1Armed.Store(g1Disarmed)

	specialTxHeld := make(chan struct{})
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Edge 1: hold specialTxMtx, then publish synchronously.
	go func() {
		defer wg.Done()
		f.abt.LockSpecialTx()
		close(specialTxHeld)
		<-h.eventsMtxHeld // the other goroutine is now inside events.Notify
		events.Notify(events.ETCRCChangeCommittee, &types.Block{})
		f.abt.UnlockSpecialTx()
	}()

	// Edge 2: publish from a different goroutine, as mempool/txpool.go:65 does.
	go func() {
		defer wg.Done()
		<-specialTxHeld
		events.Notify(events.ETTransactionAccepted, h.tx)
	}()

	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		g1Fail(t, "G1: specialTxMtx x events.mtx AB-BA deadlock -- neither the "+
			"specialTxMtx holder nor the events.mtx holder made progress in 30s.")
	}

	// Exactly one ETTransactionAccepted was published, so exactly one detached
	// handler bracket must open and close. Draining it also proves the emergency
	// bracket still runs -- the fix moved it off the bus, it did not skip it.
	g1WaitHandlers(t, f, 1, 30*time.Second)
}

// TestG1EventBusStaysLiveUnderSpecialTxStorm is the non-deterministic companion: it
// hammers both orders with no handshake at all, so a future change that
// reintroduces ANY blocking specialTxMtx acquisition on the bus goroutine is likely
// to wedge here even when it does not match the handshake above.
func TestG1EventBusStaysLiveUnderSpecialTxStorm(t *testing.T) {
	f := g1Setup(t)
	g1DrainStale(f)

	const goroutines = 4
	const iterations = 25

	var wg sync.WaitGroup
	wg.Add(2 * goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				f.abt.LockSpecialTx()
				events.Notify(events.ETCRCChangeCommittee, &types.Block{})
				f.abt.UnlockSpecialTx()
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				events.Notify(events.ETTransactionAccepted, f.tx)
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		g1Fail(t, "G1: event bus wedged under a specialTxMtx storm")
	}

	g1WaitHandlers(t, f, goroutines*iterations, 60*time.Second)
}
