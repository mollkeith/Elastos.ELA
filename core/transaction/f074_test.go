// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

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

// TestF074NFTDestroyLengthMismatch — F-074: a NFTDestroyFromSideChain payload whose IDs
// and OwnerStakeAddresses slices differ in length is accepted by the pre-fix
// SpecialContextCheck, then panics on ProcessBlock (the apply path indexes
// OwnerStakeAddresses[i] over the IDs loop) -> consensus halt. This drives the REAL
// SpecialContextCheck: above the gate the mismatch is rejected; below the gate the fix is
// inactive (replay-safe) and it proceeds past the length check; an equal-length payload is
// not falsely rejected by the length check.
func (s *txValidatorTestSuite) TestF074NFTDestroyLengthMismatch() {
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
	mismatchIDs := []common.Uint256{{1}, {2}}
	mismatchAddrs := []common.Uint168{{1}} // one short -> apply would index out of range

	// Above gate: rejected at the length check (before GetState).
	errAbove, _ := mk(mismatchIDs, mismatchAddrs, gate).SpecialContextCheck()
	s.Require().Error(errAbove)
	s.Contains(errAbove.Error(), "length mismatch",
		"F-074: mismatched NFTDestroy payload must be rejected at/above the gate")

	// Below gate: length check inactive (replay-safe) -> proceeds; fails later on
	// ExistNFTID ("the NFT is not exist"), NOT the length check.
	errBelow, _ := mk(mismatchIDs, mismatchAddrs, gate-1).SpecialContextCheck()
	s.Require().Error(errBelow)
	s.NotContains(errBelow.Error(), "length mismatch",
		"below the gate the length check is inactive (byte-identical replay)")

	// Equal-length above gate: no false-reject by the length check.
	errEq, _ := mk([]common.Uint256{{9}}, []common.Uint168{{9}}, gate).SpecialContextCheck()
	if errEq != nil {
		s.NotContains(errEq.Error(), "length mismatch",
			"an equal-length NFTDestroy must not be rejected by the length check")
	}
}
