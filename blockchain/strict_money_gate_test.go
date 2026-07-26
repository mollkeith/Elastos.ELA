// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
)

// craftedFee is a fee large enough that adding block issuance to it would wrap
// signed 64-bit -- the shape the block 2260451 transaction produces.
const craftedFee = common.Fixed64(9223322038057596306)

func gateChain(t *testing.T, activation uint32) *BlockChain {
	t.Helper()
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = activation
	return &BlockChain{chainParams: params}
}

// TestCoinbaseTotalRewardBelowActivationPreservesWrapping pins the historical
// path: below activation the sum must wrap exactly as it always has, with no
// error, so blocks such as 2260451 continue to validate and a replaying node can
// cross them.
func TestCoinbaseTotalRewardBelowActivationPreservesWrapping(t *testing.T) {
	b := gateChain(t, 1000)

	got, err := b.coinbaseTotalReward(999, craftedFee)
	if err != nil {
		t.Fatalf("below activation must not error, got %v", err)
	}
	want := craftedFee + b.chainParams.GetBlockReward(999)
	if got != want {
		t.Fatalf("below activation must reproduce wrapping: got %d want %d", got, want)
	}
}

// TestCoinbaseTotalRewardAtActivationRejects asserts the boundary is inclusive:
// the activation height itself is already strict.
func TestCoinbaseTotalRewardAtActivationRejects(t *testing.T) {
	b := gateChain(t, 1000)

	if _, err := b.coinbaseTotalReward(1000, craftedFee); err == nil {
		t.Fatal("at activation height the crafted total must be rejected")
	}
	if _, err := b.coinbaseTotalReward(1001, craftedFee); err == nil {
		t.Fatal("above activation the crafted total must be rejected")
	}
}

// TestCoinbaseTotalRewardAcceptsNormalValues guards against a false positive
// that would halt the chain: ordinary fees must still pass once strict.
func TestCoinbaseTotalRewardAcceptsNormalValues(t *testing.T) {
	b := gateChain(t, 1000)

	for _, fee := range []common.Fixed64{0, 1, 100000000, 1000 * 100000000} {
		if _, err := b.coinbaseTotalReward(2000, fee); err != nil {
			t.Fatalf("ordinary fee %d must pass strict validation, got %v", fee, err)
		}
	}
}

// TestStrictMoneyActiveBoundary documents the comparison is >= not >.
func TestStrictMoneyActiveBoundary(t *testing.T) {
	b := gateChain(t, 1000)
	if b.StrictMoneyActive(999) {
		t.Fatal("must be inactive below activation")
	}
	if !b.StrictMoneyActive(1000) || !b.StrictMoneyActive(1001) {
		t.Fatal("must be active at and above activation")
	}
}
