// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FV-19, second half — the uint32 underflow in the coinbase-maturity window.
//
// checkInvalidUTXO computes `currentHeight - referTxn.LockTime() < CoinbaseMaturity` on
// uint32. A coinbase whose LockTime is ABOVE the spending height makes that subtraction
// wrap to ~4e9, which is trivially >= 100, so the output reads as MATURE. That is the
// second of the two bypasses the LockTime pin exists to prevent (the first, LockTime = 0,
// needs no wrap: currentHeight-0 is >= 100 at every height past 100).
//
// SCOPE OF THIS TEST, STATED PLAINLY: it drives the real (*DefaultChecker).checkInvalidUTXO
// through the production TransactionParameters plumbing, a real blockchain.UTXOCache and a
// real CoinBaseTransaction, but it sits one level BELOW the production call site
// (DefaultChecker.ContextCheck, which reaches checkInvalidUTXO only after
// checkTransactionSignature, i.e. only for a fully signed transaction). That call site is
// asserted structurally instead, by the FV-19 row added to
// test/unit/wiring_callsites_test.go. This is the WEAKER of the two fail-on-pristine proofs
// in this batch and is labelled as such in the batch report; the LockTime pin itself is
// proven end to end on the real block-connect path in
// blockchain/fv19_coinbase_locktime_test.go.
//
// MUTATION PROOF (run, recorded in the batch report): delete the added
// `referTxn.LockTime() > currentHeight` guard -> this test FAILS (the future-dated coinbase
// is reported mature). Delete the checkInvalidUTXO call from ContextCheck -> the wiring row
// in test/unit FAILS.
package transaction

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// fv19Store is an IUTXOCacheStore that always returns the one referenced transaction.
type fv19Store struct{ tx interfaces.Transaction }

func (s *fv19Store) GetTransaction(common.Uint256) (interfaces.Transaction, uint32, error) {
	return s.tx, 0, nil
}

// fv19Spend is the spending transaction: one input referring to the coinbase above.
func fv19Spend() interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.TransferAsset,
		0,
		&payload.TransferAsset{},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.Uint256{0x19}, Index: 1},
			Sequence: math.MaxUint32,
		}},
		[]*common2.Output{{AssetID: core.ELAAssetID, Value: 1, Type: common2.OTNone,
			Payload: &outputpayload.DefaultOutput{}}},
		0,
		[]*program.Program{},
	)
}

// TestFV19CoinbaseMaturityUnderflow drives the production maturity decision with a
// referenced coinbase whose LockTime is ABOVE the spending height.
func TestFV19CoinbaseMaturityUnderflow(t *testing.T) {
	params := config.GetDefaultParams()
	gate := params.StrictMoneyRangeHeight
	assert.Equal(t, uint32(2260451), gate, "FV-19 rides gate 1; if this moves, re-derive")
	assert.Equal(t, uint32(100), params.PowConfiguration.CoinbaseMaturity)

	const currentHeight = uint32(2_300_000)

	// newChecker wires a real UTXOCache over a coinbase carrying refLockTime, points
	// DefaultLedger at a chain whose GetHeight() is currentHeight (len(Nodes)-1), and
	// returns a DefaultChecker holding the production parameter struct.
	newChecker := func(refLockTime, blockHeight uint32) (*DefaultChecker, interfaces.Transaction) {
		chain := &blockchain.BlockChain{}
		chain.Nodes = make([]*blockchain.BlockNode, currentHeight+1)
		chain.UTXOCache = blockchain.NewUTXOCache(
			&fv19Store{tx: newCoinBaseTransaction(new(payload.CoinBase), refLockTime)}, params)
		assert.Equal(t, currentHeight, chain.GetHeight())

		prev := blockchain.DefaultLedger
		blockchain.DefaultLedger = &blockchain.Ledger{Blockchain: chain}
		t.Cleanup(func() { blockchain.DefaultLedger = prev })

		spend := fv19Spend()
		c := &DefaultChecker{}
		c.parameters = &TransactionParameters{
			Transaction: spend,
			BlockHeight: blockHeight,
			Config:      params,
			BlockChain:  chain,
		}
		return c, spend
	}

	// CONTROL 1 — a genuinely mature coinbase must still be spendable. Without this the
	// test could be passing by rejecting everything.
	c, spend := newChecker(currentHeight-500, gate+1)
	assert.NoError(t, c.checkInvalidUTXO(spend),
		"a coinbase matured 500 blocks ago must remain spendable")

	// CONTROL 2 — the legacy immaturity rule is untouched: 50 < CoinbaseMaturity(100).
	c, spend = newChecker(currentHeight-50, gate+1)
	assert.Error(t, c.checkInvalidUTXO(spend),
		"a coinbase only 50 blocks old must still be locked (legacy rule unchanged)")

	// THE FINDING — LockTime above the spending height. currentHeight-LockTime underflows
	// to ~4e9 >= 100, so before the fix this reads as MATURE and the producer's own reward
	// is spendable with no maturity window at all.
	c, spend = newChecker(currentHeight+1000, gate+1)
	err := c.checkInvalidUTXO(spend)
	assert.Error(t, err,
		"FV-19: a coinbase whose LockTime is ABOVE the spending height must NOT be treated as "+
			"mature — the uint32 subtraction wraps to ~4e9 and bypasses CoinbaseMaturity entirely")
	if err != nil {
		assert.Contains(t, err.Error(), "the utxo of coinbase is locking")
	}

	// REPLAY — below gate 1 the legacy (wrapping) behaviour is preserved verbatim, so
	// retained history validates byte-identically. This is what makes the change gated
	// rather than an ungated acceptance change.
	c, spend = newChecker(currentHeight+1000, gate-1)
	assert.NoError(t, c.checkInvalidUTXO(spend),
		"below gate 1 the legacy wrapping behaviour must be preserved (byte-identical replay)")
}
