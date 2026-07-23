// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package transaction

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestF104NFTDestroyDuplicateIDs — F-104: a NFTDestroyFromSideChain payload that repeats an
// NFT ID passes the (read-only) ExistNFTID/CanNFTDestroy checks and double-applies the
// destroy on ProcessBlock. The gated dedup rejects a repeated ID at/above StrictMoneyRangeHeight
// while leaving pre-gate history byte-identical.
//
// Fail-on-pristine: neutralize the dedup loop in nftdestroytransaction.go and the at/above-gate
// duplicate assertion loses the "duplicate NFT id" rejection.
func (s *txValidatorTestSuite) TestF104NFTDestroyDuplicateIDs() {
	const gate = uint32(2260451)
	mk := func(ids []common.Uint256, addrs []common.Uint168, h uint32) interfaces.Transaction {
		pl := &payload.NFTDestroyFromSideChain{IDs: ids, OwnerStakeAddresses: addrs}
		txn := functions.CreateTransaction(
			common2.TxVersion09, common2.NFTDestroyFromSideChain, 0, pl,
			[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{}, 0, []*program.Program{})
		txn = CreateTransactionByType(txn, s.Chain)
		txn.SetParameters(&TransactionParameters{
			Transaction: txn, BlockHeight: h,
			Config:     &config.Configuration{StrictMoneyRangeHeight: gate},
			BlockChain: s.Chain})
		return txn
	}
	id := common.Uint256{1}
	dupIDs := []common.Uint256{id, id}
	addrs := []common.Uint168{{1}, {2}} // equal length so the F-074 length check passes first

	// Above gate: the repeated ID is rejected by the F-104 dedup (before ExistNFTID).
	errAbove, _ := mk(dupIDs, addrs, gate).SpecialContextCheck()
	s.Require().Error(errAbove)
	s.Contains(errAbove.Error(), "duplicate NFT id",
		"F-104: a duplicate-ID NFTDestroy must be rejected at/above the gate")

	// Below gate: dedup inactive (replay-safe) -> it proceeds and fails later on ExistNFTID,
	// NOT on the duplicate check.
	errBelow, _ := mk(dupIDs, addrs, gate-1).SpecialContextCheck()
	s.Require().Error(errBelow)
	s.NotContains(errBelow.Error(), "duplicate NFT id",
		"below the gate the dedup is inactive (byte-identical replay)")

	// Distinct IDs above gate: no false-reject by the dedup.
	errDistinct, _ := mk([]common.Uint256{{1}, {2}}, addrs, gate).SpecialContextCheck()
	if errDistinct != nil {
		s.NotContains(errDistinct.Error(), "duplicate NFT id",
			"distinct IDs must not be rejected by the dedup")
	}
}
