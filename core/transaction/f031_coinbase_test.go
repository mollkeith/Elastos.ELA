// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"github.com/elastos/Elastos.ELA/core"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestF031CoinbaseLockTimePin proves the coinbase-maturity bypass fix: at/above
// StrictMoneyRangeHeight a coinbase whose LockTime != block height is rejected, so
// checkInvalidUTXO's LockTime-derived 100-block maturity window cannot be bypassed
// (a malicious producer setting LockTime=0 to spend the reward immediately). Below
// the gate the legacy behavior is preserved (byte-identical replay).
//
// Fail-on-pristine: without the pin, the LockTime=0 coinbase with valid CRAssets
// outputs passes SpecialContextCheck (NoError) at/above the gate -> the test's
// EqualError assertion fails.
func (s *txValidatorTestSuite) TestF031CoinbaseLockTimePin() {
	gate := s.Chain.GetParams().StrictMoneyRangeHeight
	crAssets := s.Chain.GetParams().CRConfiguration.CRAssetsProgramHash
	s.Chain.GetState().ConsensusAlgorithm = 0x00 // BFT -> first output must be CR assets

	mkCoinbase := func(lockTime uint32) interfaces.Transaction {
		tx := newCoinBaseTransaction(new(payload.CoinBase), lockTime)
		tx.SetOutputs([]*common2.Output{
			{AssetID: core.ELAAssetID, ProgramHash: *crAssets},
			{AssetID: core.ELAAssetID, ProgramHash: s.foundationAddress},
		})
		return CreateTransactionByType(tx, s.Chain)
	}

	// At/above the gate, LockTime=0 (!= height) must be rejected by the pin.
	s.Chain.GetBestChain().Height = gate + 100
	err, _ := mkCoinbase(0).SpecialContextCheck()
	s.EqualError(err,
		"transaction validate error: output invalid:coinbase locktime must equal block height")

	// Below the gate, LockTime=0 is accepted (legacy, byte-identical).
	s.Chain.GetBestChain().Height = gate - 100
	errBelow, _ := mkCoinbase(0).SpecialContextCheck()
	s.NoError(errBelow)
}
