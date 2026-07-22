// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package transaction

import (
	"errors"
	"testing"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/stretchr/testify/assert"
)

// TestF052NFTDestroyGenesisBinding proves F-052: NFTDestroyFromSideChain carried a
// GenesisBlockHash that SpecialContextCheck never validated against each NFT's recorded
// origin (NFTInfo.GenesisBlockHash), so an arbiter-signed destroy could name ANY sidechain
// genesis. The gated bind rejects a mismatch at/above StrictMoneyRangeHeight while leaving
// pre-gate history byte-identical.
//
// Fail-on-pristine: neutralize the `if !genesis.IsEqual(payloadGenesis)` guard in
// checkNFTDestroyGenesisBinding and the at/above-gate mismatch assertion flips to accepted.
func TestF052NFTDestroyGenesisBinding(t *testing.T) {
	const gate = uint32(2260451)

	realGenesis := common.Uint256{0xAA}
	wrongGenesis := common.Uint256{0xBB}
	id := common.Uint256{0x01}

	// lookup returns the NFT's true recorded origin sidechain genesis.
	genesisOf := func(common.Uint256) (common.Uint256, error) { return realGenesis, nil }
	missing := func(common.Uint256) (common.Uint256, error) {
		return common.Uint256{}, errors.New("nft is not exist")
	}
	ids := []common.Uint256{id}

	// BELOW the gate: mismatch accepted (retained-history behavior, byte-identical).
	assert.NoError(t, checkNFTDestroyGenesisBinding(ids, wrongGenesis, genesisOf, gate-1, gate),
		"below the gate the bind must be a no-op")

	// AT/ABOVE the gate, matching genesis -> accepted.
	assert.NoError(t, checkNFTDestroyGenesisBinding(ids, realGenesis, genesisOf, gate, gate),
		"a truthful NFTDestroy must pass at/above the gate")

	// AT/ABOVE the gate, WRONG genesis -> rejected.
	err := checkNFTDestroyGenesisBinding(ids, wrongGenesis, genesisOf, gate, gate)
	assert.Error(t, err, "a mismatched-genesis NFTDestroy must be rejected at/above the gate")
	if err != nil {
		assert.Contains(t, err.Error(), "does not match the NFT origin sidechain")
	}

	// AT/ABOVE the gate, a missing NFT surfaces the lookup error (defensive; the caller's
	// prior ExistNFTID loop already guards this in production).
	assert.Error(t, checkNFTDestroyGenesisBinding(ids, realGenesis, missing, gate, gate))
}
