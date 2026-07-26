package blockchain_test

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestExploit_EmitHex serializes the exact exploit transaction to wire hex so it
// can be submitted to a live regnet node via sendrawtransaction. Programs are
// empty: the money-range check runs in SanityCheck, BEFORE signature/reference
// checks, so an unsigned body is enough to demonstrate which check fires.
func TestExploit_EmitHex(t *testing.T) {
	tx := exploitTx(t)
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}
	t.Logf("EXPLOIT_TX_HEX=%s", hex.EncodeToString(buf.Bytes()))
}
