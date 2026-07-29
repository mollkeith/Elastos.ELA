package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// F-098: RevertToPOW SpecialContextCheck's switch had no default -> an unknown Type
// (>=3) fell through to accept, forcing DPoS->POW with none of the stall/flag checks.
func f098Tx(height uint32, ptype byte) *RevertToPOWTransaction {
	p := &payload.RevertToPOW{Type: payload.RevertType(ptype), WorkingHeight: height}
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.RevertToPOW, 0, p,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0, []*program.Program{})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: height,
		Config: &config.Configuration{StrictMoneyRangeHeight: 2260451}})
	return txn.(*RevertToPOWTransaction)
}

// EXPLOIT-PROOF (run -count=5): below the gate (= pre-fix / legacy), an unknown
// RevertToPOW Type is ACCEPTED (no error) -> the forced DPoS->POW was genuinely reachable.
func TestF098ExploitIsReal(t *testing.T) {
	err, _ := f098Tx(2260450, 3).SpecialContextCheck() // unknown Type=3, below gate
	if err != nil {
		t.Fatalf("EXPLOIT NOT REAL: unknown RevertToPOW Type rejected below gate: %v", err)
	}
	t.Log("EXPLOIT CONFIRMED: unknown RevertToPOW Type accepted -> forced DPoS->POW with no preconditions")
}

// FIX-PROOF (run -count=20): unknown types rejected at/above the gate, accepted below (legacy).
func TestF098FixRevertToPOWType(t *testing.T) {
	const gate = uint32(2260451)
	for _, ptype := range []byte{3, 4, 10, 255} {
		name := "type-" + string(rune('a'+int(ptype%26)))
		t.Run(name, func(t *testing.T) {
			if err, _ := f098Tx(gate, ptype).SpecialContextCheck(); err == nil {
				t.Fatalf("BREACH: unknown Type %d accepted at gate -> DPoS->POW", ptype)
			}
			if err, _ := f098Tx(gate+1_000_000, ptype).SpecialContextCheck(); err == nil {
				t.Fatalf("BREACH: unknown Type %d accepted above gate", ptype)
			}
			if err, _ := f098Tx(gate-1, ptype).SpecialContextCheck(); err != nil {
				t.Fatalf("REPLAY BREAK: unknown Type %d rejected below gate (legacy): %v", ptype, err)
			}
		})
	}
}
