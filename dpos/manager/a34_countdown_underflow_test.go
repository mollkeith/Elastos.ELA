// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// The view-change countdown underflow (rescue-path defect 3, A3.4).
//
// startViewOffset is legitimately seeded one above the current view offset:
// ResetByCurrentView calls Reset(GetViewOffset()+1) so the countdown starts
// counting at the NEXT view change. Both operands of the elapsed comparison
// are uint32, so until the view advances the subtraction wraps to about 4.29
// billion, which exceeds every threshold and reports a timeout that never
// elapsed. That path runs exactly after a recovery, where a spurious timeout
// does the most damage.
//
// The first test fails with the wrap guard removed. The second pins the
// countdown still firing once the view genuinely advances past the threshold,
// so the guard cannot be "fixed" by silencing the countdown entirely.
package manager

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/require"
)

// a34Arbiters is a 12-CRC / 36-total arbiter set in normal mode, the mainnet
// shape, so IsTimeOut reaches the elapsed comparison instead of an early gate.
type a34Arbiters struct {
	state.Arbitrators
}

func (a *a34Arbiters) GetCRCArbitersCount() int { return 12 }
func (a *a34Arbiters) GetArbitersCount() int    { return 36 }
func (a *a34Arbiters) IsInactiveMode() bool     { return false }

func a34Countdown(t *testing.T, viewOffset uint32) (*ViewChangesCountDown, *Consensus) {
	t.Helper()
	n002Setup(t) // installs a ledger whose tip is above PublicDPOSHeight
	cons := &Consensus{viewOffset: viewOffset}
	p := &ProposalDispatcher{cfg: ProposalDispatcherConfig{
		ChainParams: config.GetDefaultParams(),
	}}
	cd := &ViewChangesCountDown{
		dispatcher:  p,
		consensus:   cons,
		arbitrators: &a34Arbiters{},
	}
	return cd, cons
}

// TestA34ArmedCountdownDoesNotWrap seeds the countdown the way
// ResetByCurrentView does, one above the current offset. It must stay quiet
// until the view actually advances.
func TestA34ArmedCountdownDoesNotWrap(t *testing.T) {
	cd, cons := a34Countdown(t, 5)
	cd.Reset(cons.GetViewOffset() + 1)

	require.False(t, cd.IsTimeOut(),
		"a countdown armed for the next view change must not fire before it")
}

// TestA34ElapsedCountdownStillFires is the control: once the view offset has
// genuinely advanced past startViewOffset by the full threshold, the countdown
// must report the timeout.
func TestA34ElapsedCountdownStillFires(t *testing.T) {
	cd, cons := a34Countdown(t, 0)
	cd.Reset(1)
	// threshold is GetArbitersCount()*firstTimeoutFactor = 36 view changes
	cons.viewOffset = 1 + 36

	require.True(t, cd.IsTimeOut(),
		"the countdown must still fire once the view advances past the threshold")
}
