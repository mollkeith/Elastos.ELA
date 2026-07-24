// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
)

type TransactionParameters struct {
	Transaction interfaces.Transaction

	BlockHeight         uint32
	TimeStamp           uint32
	Config              *config.Configuration
	BlockChain          *blockchain.BlockChain
	ProposalsUsedAmount common.Fixed64

	// FV-22: timestamp of the PARENT of the block under validation. Set through
	// interfaces.PrevBlockAware by blockchain.CheckTransactionContextWithPrev;
	// hasPrevBlockTimestamp distinguishes "parent says 0" from "nobody told us".
	prevBlockTimestamp    uint32
	hasPrevBlockTimestamp bool
}

// SetPrevBlockTimestamp implements interfaces.PrevBlockAware.
func (p *TransactionParameters) SetPrevBlockTimestamp(timestamp uint32) {
	p.prevBlockTimestamp = timestamp
	p.hasPrevBlockTimestamp = true
}

// PrevBlockTimestamp returns the timestamp of the parent of the block under
// validation, and whether it was supplied at all.
//
// FV-22: every production entry into transaction context checking supplies it --
// the block path from the real parent (blockvalidator.checkTxsContext), the mempool
// and mining paths from BestChain, which IS the parent of the block those
// transactions are destined for. The false case exists only for callers that build
// parameters directly.
func (p *TransactionParameters) PrevBlockTimestamp() (uint32, bool) {
	return p.prevBlockTimestamp, p.hasPrevBlockTimestamp
}
