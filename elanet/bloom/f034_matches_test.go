package bloom

import (
	"testing"

	"github.com/elastos/Elastos.ELA/p2p/msg"
)

// TestF034EmptyFilterNoPanic proves the F-034 defense-in-depth guard in matches():
// even if an empty filter (HashFuncs > 0) reaches the bloom layer, Matches must
// return false rather than panic on `mm % (len(Filter)<<3)` == `mm % 0`.
//
// Fail-on-pristine: without the len(bf.msg.Filter)==0 guard, Matches panics with
// "integer divide by zero" at hash().
func TestF034EmptyFilterNoPanic(t *testing.T) {
	f := LoadFilter(&msg.FilterLoad{Filter: []byte{}, HashFuncs: 1})
	if f.Matches([]byte{1, 2, 3}) {
		t.Fatal("expected no match on an empty filter")
	}
}
