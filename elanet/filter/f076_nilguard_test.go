package filter

import (
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/core/types/interfaces"
)

// stubTxFilter is a no-op TxFilter used to exercise the wrapper's locking/nil
// handling without a real bloom implementation.
type stubTxFilter struct{}

func (stubTxFilter) Load(_ []byte) error                             { return nil }
func (stubTxFilter) Add(_ []byte) error                              { return nil }
func (stubTxFilter) MatchConfirmed(_ interfaces.Transaction) bool    { return false }
func (stubTxFilter) MatchUnconfirmed(_ interfaces.Transaction) bool  { return false }

// TestF076MatchOnNilFilter proves the F-076 nil-guard deterministically: calling
// Match{Confirmed,Unconfirmed} on a Filter whose underlying filter is nil (never
// loaded, or cleared) must return false, not dereference a nil interface.
//
// Fail-on-pristine: without the guard, `f.filter.MatchUnconfirmed(tx)` panics with
// "invalid memory address or nil pointer dereference".
func TestF076MatchOnNilFilter(t *testing.T) {
	f := New(func(uint8) TxFilter { return stubTxFilter{} })
	// f.filter is nil (New leaves it unset).
	if f.MatchUnconfirmed(nil) {
		t.Fatal("MatchUnconfirmed on nil filter must return false")
	}
	if f.MatchConfirmed(nil) {
		t.Fatal("MatchConfirmed on nil filter must return false")
	}
}

// TestF076LoadClearRace exercises the actual TOCTOU: one goroutine churns
// Load/Clear while another runs the server.go relay pattern
// (IsLoaded() then MatchUnconfirmed()). Pre-fix this nil-panics under load.
func TestF076LoadClearRace(t *testing.T) {
	f := New(func(uint8) TxFilter { return stubTxFilter{} })
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			f.mtx.Lock()
			f.filter = stubTxFilter{}
			f.mtx.Unlock()
			f.Clear()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500000; i++ {
			if f.IsLoaded() {
				f.MatchUnconfirmed(nil)
				f.MatchConfirmed(nil)
			}
		}
		close(stop)
	}()

	wg.Wait()
}
