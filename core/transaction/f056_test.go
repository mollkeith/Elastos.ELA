package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
)

// F-056: RegisterAsset must be refused at/above StrictMoneyRangeHeight and
// preserved below it (replay-safety). Table-driven; run with -count=20.
func TestF056RegisterAssetHeightGate(t *testing.T) {
	const gate = uint32(2260451)
	mk := func(h uint32) *RegisterAssetTransaction {
		tx := &RegisterAssetTransaction{}
		tx.SetParameters(&TransactionParameters{
			Transaction: tx,
			BlockHeight: h,
			Config:      &config.Configuration{StrictMoneyRangeHeight: gate},
		})
		return tx
	}
	cases := []struct {
		name    string
		height  uint32
		wantErr bool
	}{
		{"genesis-era-allowed", 1, false},
		{"far-below-gate-allowed", 1_405_000, false},
		{"one-below-gate-allowed", gate - 1, false},
		{"exactly-at-gate-refused", gate, true},
		{"one-above-gate-refused", gate + 1, true},
		{"far-above-gate-refused", gate + 5_000_000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := mk(c.height).HeightVersionCheck()
			if c.wantErr && err == nil {
				t.Fatalf("BREACH: RegisterAsset allowed at height %d (>= gate %d)", c.height, gate)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("REPLAY BREAK: RegisterAsset refused at height %d (< gate) -> %v", c.height, err)
			}
		})
	}
}
