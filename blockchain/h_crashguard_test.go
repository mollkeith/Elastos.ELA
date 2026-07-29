// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	program "github.com/elastos/Elastos.ELA/core/contract/program"

	"github.com/stretchr/testify/assert"
)

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
}

// TestHRevertToDPOSSignatureCrashGuard — finding H (F-099 siblings in
// blockchain/txvalidator.go): CheckRevertToDPOSTransaction is called straight from the DPoS
// gossip handler with NO SanityCheck/CheckAttributeProgram, so an empty Programs() or a
// <2-byte code reaches checkArbitratorsSignatures and panics the receiving CRC arbiter on
// code[len-2]/code[0]. The guards convert the panic into a clean rejection (ungated
// crash-hardening; such a program never validly existed, so retained history is unchanged).
//
// Fail-on-pristine: without the guards these calls PANIC (index out of range); with them they
// return an error and never panic.
func TestHRevertToDPOSSignatureCrashGuard(t *testing.T) {
	mk := func(programs []*program.Program) interfaces.Transaction {
		return functions.CreateTransaction(
			common2.TxVersion09, common2.RevertToDPOS, 0, &payload.RevertToDPOS{},
			[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0, programs)
	}

	// (a) empty Programs -> pristine panics on Programs()[0].
	assert.NotPanics(t, func() {
		err := blockchain.CheckRevertToDPOSTransaction(mk([]*program.Program{}), 2260451)
		assert.Error(t, err, "empty-program RevertToDPOS must be rejected, not panic")
	})

	// (b) 1-byte code -> pristine panics on code[len(code)-2].
	assert.NotPanics(t, func() {
		err := blockchain.CheckRevertToDPOSTransaction(
			mk([]*program.Program{{Code: []byte{0x01}}}), 2260451)
		assert.Error(t, err, "short-code RevertToDPOS must be rejected, not panic")
	})
}
