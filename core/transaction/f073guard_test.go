// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package transaction

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestF073GuardRejectsCrossKeyAlias — finding I: the validation-layer guard rejects an
// NFTDestroy whose OwnerStakeAddresses alias one of its own NFTs' stake addresses (the
// cross-key vector empirically classified in dpos/state TestF073CrossKeyRewardMisallocation).
// Gated at StrictMoneyRangeHeight -> below-gate byte-identical.
//
// Fail-on-pristine: below the gate (or without the guard) the aliasing payload is NOT rejected
// for the aliasing reason (it proceeds to the ExistNFTID check).
func (s *txValidatorTestSuite) TestF073GuardRejectsCrossKeyAlias() {
	const gate = uint32(2260451)
	nftStake := func(id common.Uint256) common.Uint168 {
		ct, _ := contract.CreateStakeContractByCode(id.Bytes())
		return *ct.ToProgramHash()
	}
	mk := func(ids []common.Uint256, owners []common.Uint168, h uint32) interfaces.Transaction {
		pl := &payload.NFTDestroyFromSideChain{IDs: ids, OwnerStakeAddresses: owners}
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
	idA := common.Uint256{0xA1}
	idB := common.Uint256{0xB1}
	var normalOwner common.Uint168
	normalOwner[0] = 0x33
	// THE ATTACK: owner of A aliases B's NFT stake address (distinct ids -> F-104 passes).
	attack := []common.Uint168{nftStake(idB), normalOwner}
	ids := []common.Uint256{idA, idB}

	// Above gate: rejected by the aliasing guard.
	errAbove, _ := mk(ids, attack, gate).SpecialContextCheck()
	s.Require().Error(errAbove)
	s.Contains(errAbove.Error(), "aliases an NFT stake address",
		"F-073: an OwnerStakeAddress aliasing an in-tx NFT stake address must be rejected at/above the gate")

	// Below gate: guard inactive (replay-safe) -> proceeds; fails later on ExistNFTID, NOT the alias.
	errBelow, _ := mk(ids, attack, gate-1).SpecialContextCheck()
	s.Require().Error(errBelow)
	s.NotContains(errBelow.Error(), "aliases an NFT stake address",
		"below the gate the aliasing guard is inactive (byte-identical replay)")

	// Non-aliasing owners above gate: not rejected by the alias guard.
	errOk, _ := mk(ids, []common.Uint168{normalOwner, {0x44}}, gate).SpecialContextCheck()
	if errOk != nil {
		s.NotContains(errOk.Error(), "aliases an NFT stake address",
			"legitimate distinct owners must not trip the alias guard")
	}
}
