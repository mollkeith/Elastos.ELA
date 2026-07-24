// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package interfaces

type Parameters interface {
}

// PrevBlockAware is implemented by transaction check parameters that can be told
// which block is the PARENT of the block currently being validated.
//
// FV-22: transaction context checks that need "when was the previous block" must
// use the parent of the block under validation, not the validating node's current
// best tip. The two differ for every block that arrives on a competing branch, and
// core/transaction cannot reach a *blockchain.BlockNode through the shared
// functions.GetTransactionParameters hook, so blockchain sets it through this
// optional interface instead of widening that hook's signature.
type PrevBlockAware interface {
	SetPrevBlockTimestamp(timestamp uint32)
}
