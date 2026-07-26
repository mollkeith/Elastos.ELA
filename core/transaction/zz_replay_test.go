package transaction

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"

	"github.com/stretchr/testify/assert"
)

// The REAL mainnet transaction from block 2,208,265 -- the one that declared
// 92,233,720,368.54765808 ELA against 1.9998 ELA locked, and which the RELEASED
// v0.9.9.6 accepted and DPoS-finalised. It is RETAINED history: height 2,208,265
// is 52,185 blocks BELOW the forced-rollback target 2,260,450, so every node must
// still validate it after the recovery.
const realTxHex = "0908010001c21c12b3c146962125ff61cb5d119c408c3df8cdc068d48f6f904fa15ea5283b0000ffffffff01b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a3e073eb0b00000000000000004bc816170711c86bd488ff04eae413777bf413f49903002a307842313741426664336535373934663263653062313863664444464135346233306336343866333933f0d8ffffffffff7f000000000001414072da9b708c3816cbaa62e7b0c07d8027bb1abc43c44370927a447953eb282e706d9886df7f7ed4a2e21c55feaa2f746f0d1a1ad5da6477b0e7cbd50dcb3a82f1232102d8c9ce0c7045387921072916ffe1960a8d4935e58a2e0ec35b5aaa3a1e07df20ac"

const realTxHeight = 2208265

func decodeRealTx(t *testing.T) interfaces.Transaction {
	raw, err := common.HexStringToBytes(realTxHex)
	assert.NoError(t, err)
	r := bytes.NewReader(raw)
	txn, err := functions.GetTransactionByBytes(r)
	assert.NoError(t, err)
	assert.NoError(t, txn.Deserialize(r))
	return txn
}

// TestRetainedHistoryStillValidates is the below-gate byte-identical invariant,
// applied to the one transaction in the chain that our new MoneyRange bound
// rejects. If this FAILS, a v1.0.0 node cannot replay the chain from genesis:
// it stops at height 2,208,265 on a block every existing node already accepted.
func TestRetainedHistoryStillValidates(t *testing.T) {
	txn := decodeRealTx(t)

	// sanity: we decoded the transaction we think we did
	assert.Equal(t, common2.TransferCrossChainAsset, txn.TxType())
	assert.Equal(t, byte(0x01), txn.PayloadVersion())
	assert.Equal(t, 1, len(txn.Outputs()))
	assert.Equal(t, common.Fixed64(199980000), txn.Outputs()[0].Value,
		"locked value should be 1.9998 ELA")

	// Drive the PRODUCTION output check at the transaction's REAL height.
	params := &TransactionParameters{
		Transaction: txn,
		BlockHeight: realTxHeight,
		Config:      config.GetDefaultParams(),
	}
	txn.SetParameters(params)

	err := txn.CheckTransactionOutput()
	if err != nil {
		t.Fatalf("REPLAY BREAKS: a v1.0.0 node REJECTS retained block %d.\n"+
			"  rejection: %v\n"+
			"  This transaction is on the canonical chain BELOW the rollback target\n"+
			"  2,260,450, so it must still validate. A node syncing from genesis\n"+
			"  will halt here.", realTxHeight, err)
	}
	t.Logf("retained transaction at height %d still validates", realTxHeight)
}

// TestOverMintRejectedAtAndAboveGate is the other half of the invariant: the same
// bytes that must be ACCEPTED as retained history must be REJECTED if anyone
// replays them after the recovery. Without this, gating the bound would simply
// reopen the hole.
func TestOverMintRejectedAtAndAboveGate(t *testing.T) {
	cfg := config.GetDefaultParams()
	gate := cfg.StrictMoneyRangeHeight

	for _, h := range []uint32{gate, gate + 1, gate + 100000} {
		txn := decodeRealTx(t)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: h, Config: cfg,
		})
		// SpecialContextCheck is the production dispatch that reaches the
		// height-gated bound; CheckTransactionOutput is sanity only.
		elaErr, _ := txn.SpecialContextCheck()
		assert.NotNil(t, elaErr, "over-mint MUST be rejected at height %d", h)
		if elaErr != nil {
			t.Logf("height %d -> rejected: %v", h, elaErr)
		}
	}
}

// TestGateBoundaryIsExact pins the boundary: the last height that accepts is
// gate-1, the first that rejects is gate. An off-by-one here either breaks
// replay or leaves the hole open for one block.
func TestGateBoundaryIsExact(t *testing.T) {
	cfg := config.GetDefaultParams()
	gate := cfg.StrictMoneyRangeHeight

	txn := decodeRealTx(t)
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: gate - 1, Config: cfg})
	e1, _ := txn.SpecialContextCheck()
	assert.Nil(t, e1, "gate-1 must still ACCEPT (retained history)")

	txn2 := decodeRealTx(t)
	txn2.SetParameters(&TransactionParameters{Transaction: txn2, BlockHeight: gate, Config: cfg})
	e2, _ := txn2.SpecialContextCheck()
	assert.NotNil(t, e2, "gate must REJECT")
	t.Logf("boundary exact: accept <= %d, reject >= %d", gate-1, gate)
}
