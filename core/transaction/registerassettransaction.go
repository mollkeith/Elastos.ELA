// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"errors"

	"github.com/elastos/Elastos.ELA/core/types/payload"
)

type RegisterAssetTransaction struct {
	BaseTransaction
}

func (t *RegisterAssetTransaction) IsAllowedInPOWConsensus() bool {
	return false
}

// HeightVersionCheck rejects RegisterAsset at/above the recovery gate (F-056).
// RegisterAsset spends real inputs but GetTxReference (chainstore.go:180) and the
// UnspentIndex skip it, so its inputs are never retired -> fee-mint / double-spend
// under DPoS. Custom assets are deprecated on the ELA mainchain (GetAssetByHash is
// hardcoded to ELA and marked for removal), so RegisterAsset has no legitimate
// post-genesis use. Height-gated: below the gate the legacy behavior is preserved
// verbatim for replay-safety; at/above it the type is refused.
func (t *RegisterAssetTransaction) HeightVersionCheck() error {
	if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
		return errors.New("RegisterAsset is not allowed at or above StrictMoneyRangeHeight")
	}
	return nil
}

func (t *RegisterAssetTransaction) CheckTransactionPayload() error {
	switch pld := t.Payload().(type) {
	case *payload.RegisterAsset:
		if pld.Asset.Precision < payload.MinPrecision || pld.Asset.Precision > payload.MaxPrecision {
			return errors.New("invalid asset precision")
		}
		if !checkAmountPrecise(pld.Amount, pld.Asset.Precision) {
			return errors.New("invalid asset value, out of precise")
		}
		return nil
	}

	return errors.New("invalid payload type")
}
