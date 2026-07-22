// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// F-089 (BIP30 coinbase remint) — the END-TO-END empirical proof the register
// (INFERRED-ITEMS.md A2) flagged as missing: two identical coinbases (same txid)
// actually resurrect a spent output through the REAL UnspentIndex.ConnectBlock.
// The upstream fix (checkCoinbaseBIP30 in blockchain.checkTxsContext, tested in
// blockchain/f089_test.go) rejects the duplicate-coinbase block before connect;
// this test proves what ConnectBlock does when that guard is absent.
package indexers_test

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

// f089Coinbase builds a coinbase tx with one output. Reusing the SAME returned
// object in two blocks models the BIP30 identical-coinbase (same-txid) scenario.
func f089Coinbase(content byte) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.CoinBase, payload.CoinBaseVersion,
		&payload.CoinBase{Content: []byte{content}},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: math.MaxUint16},
			Sequence: math.MaxUint32,
		}},
		[]*common2.Output{{
			AssetID:     core.ELAAssetID,
			Value:       common.Fixed64(500),
			ProgramHash: common.Uint168{},
			Type:        common2.OTNone,
			Payload:     &outputpayload.DefaultOutput{},
		}},
		0, []*program.Program{},
	)
}

// TestF089DuplicateCoinbaseResurrectsSpentOutput — end-to-end, >=5 scenarios.
// Connect coinbase C -> spend C:0 -> connect the SAME coinbase C again: the
// production UnspentIndex re-adds C:0, resurrecting the spent output (a remint /
// double-spend of the coinbase reward).
func TestF089DuplicateCoinbaseResurrectsSpentOutput(t *testing.T) {
	proven := 0
	for i := 0; i < 6; i++ {
		idx, db := f056NewIndex(t)

		cb := f089Coinbase(byte(i))
		cbHash := cb.Hash()

		// (1) Connect the coinbase — C:0 becomes unspent.
		f056Connect(t, idx, db, f056Block(100, cb))
		u1, _ := f056Unspent(t, db, cbHash)
		assert.Equal(t, []uint16{0}, u1, "coinbase output unspent after first connect")

		// (2) Spend C:0 with a normal tx — retired.
		ta := f056SpendTx(common2.TransferAsset, &payload.TransferAsset{}, cbHash, 0)
		f056Connect(t, idx, db, f056Block(101, ta))
		u2, _ := f056Unspent(t, db, cbHash)
		assert.Empty(t, u2, "coinbase output retired after being spent")

		// (3) Connect the SAME coinbase again (BIP30 duplicate) — RESURRECTS C:0.
		f056Connect(t, idx, db, f056Block(102, cb))
		u3, _ := f056Unspent(t, db, cbHash)
		assert.Equal(t, []uint16{0}, u3,
			"EXPLOIT[%d]: duplicate coinbase RESURRECTED the spent output (remint)", i)

		if len(u1) == 1 && len(u2) == 0 && len(u3) == 1 {
			proven++
		}
	}
	assert.GreaterOrEqual(t, proven, 5,
		"coinbase remint must be empirically reproduced >=5 times; got %d", proven)
}
