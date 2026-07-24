// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Constructor-registry bootstrap for the G2 wiring tests.
//
// core/transaction imports blockchain, so the INTERNAL blockchain test package cannot
// import it. This external test package can, and its init runs in the same test binary
// before any test function — which is how the wiring tests in package blockchain get a
// populated functions.* registry.
package blockchain_test

import (
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types/functions"
)

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
}
