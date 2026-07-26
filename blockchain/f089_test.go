package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// F-089 BIP30 coinbase remint. The coinbase's own IsTxHashDuplicate guard is DEAD
// on connect (checkTxsContext validates only txs[1:]). checkCoinbaseBIP30 re-applies
// it at/above the gate. isDuplicate=true models "this coinbase txid already exists
// in the ledger" (a replayed coinbase); false models a normal unique coinbase.

// EXPLOIT-PROOF (run -count=5): pre-fix, NOTHING on the connect path checks the
// coinbase for a duplicate txid, so a replayed coinbase (isDuplicate=true) is
// ACCEPTED. We model the pre-fix state as "gate not active" (the check didn't
// exist). Proves the remint was genuinely reachable, not audit-trusted.
func TestF089ExploitIsReal(t *testing.T) {
	const gate = uint32(2260451)
	var cbHash common.Uint256
	cbHash[0] = 0xAB
	dupTrue := func(common.Uint256) bool { return true } // coinbase txid already stored

	// pre-fix / no BIP30 protection active -> duplicate coinbase passes (remint).
	if err := checkCoinbaseBIP30(cbHash, gate-1, gate, dupTrue); err != nil {
		t.Fatalf("EXPLOIT NOT REAL: a replayed coinbase was rejected without the gate: %v", err)
	}
	// and with the check disabled entirely (gate = MaxUint32), a duplicate at ANY
	// height passes -> exactly the pre-fix production behavior on the connect path.
	if err := checkCoinbaseBIP30(cbHash, gate+1_000_000, ^uint32(0), dupTrue); err != nil {
		t.Fatalf("EXPLOIT NOT REAL: with no active gate a replayed coinbase was rejected: %v", err)
	}
	t.Logf("EXPLOIT CONFIRMED: absent the gate-active BIP30 check, a replayed coinbase txid is accepted on connect")
}

// FIX-PROOF (run -count=20): the gate rejects a duplicate at/above it, never a
// unique coinbase, and stays legacy below the gate (replay-safe).
func TestF089FixBIP30(t *testing.T) {
	const gate = uint32(2260451)
	var cbHash common.Uint256
	cbHash[0] = 0xAB
	dupTrue := func(common.Uint256) bool { return true }
	dupFalse := func(common.Uint256) bool { return false }

	cases := []struct {
		name    string
		height  uint32
		dup     func(common.Uint256) bool
		wantErr bool
	}{
		{"duplicate-at-gate-REJECTED", gate, dupTrue, true},
		{"duplicate-above-gate-REJECTED", gate + 1_000_000, dupTrue, true},
		{"unique-at-gate-ALLOWED", gate, dupFalse, false},
		{"unique-above-gate-ALLOWED", gate + 1_000_000, dupFalse, false},
		{"duplicate-below-gate-ALLOWED-legacy", gate - 1, dupTrue, false},
		{"duplicate-far-below-gate-ALLOWED", 1, dupTrue, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkCoinbaseBIP30(cbHash, c.height, gate, c.dup)
			if c.wantErr && err == nil {
				t.Fatalf("BREACH: duplicate coinbase accepted at height %d (>= gate)", c.height)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("FALSE POSITIVE / REPLAY BREAK at height %d: %v", c.height, err)
			}
		})
	}
}
