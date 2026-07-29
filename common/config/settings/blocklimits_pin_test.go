// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package settings

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The three block-shape limits must be pinned on mainnet.
//
// WHY. MaxBlockSize, MaxTxPerBlock and MaxBlockHeaderSize are each settable from
// config.json and by CLI flag, and each is a consensus rule. A node that differs
// from the fleet on any of them accepts blocks the fleet rejects, or rejects blocks
// the fleet accepts, at EVERY height. There is no gate and no recovery: it is a
// permanent partition. Testnet legitimately runs a larger block, which is exactly
// how a copied testnet config partitions a mainnet node.
//
// THE ORDERING TRAP this test also guards. The pin cannot live in
// enforceCoordinatedMainnetParameters like the height pins do. That function runs
// AFTER the assignments that copy these values into the pact globals, so pinning
// the Configuration field there would be too late -- the consensus limit would
// already be set from the operator's value. This is why the block limits were
// missed when DPoSV2StartHeight and the Schnorr heights were pinned: those are read
// from Configuration at use time, these are not.
//
// FAIL-ON-PRISTINE: delete the pin block in SetupConfig (the `if !testNet &&
// isMainNetName(...)` stanza) and TestMainnetNameIsTreatedAsMainnet still passes,
// but the pin no longer runs -- so the guard that actually catches regression is
// TestUnrecognisedActiveNetCountsAsMainnet plus the settings_pin integration path.
// The isMainNetName contract below is the load-bearing half: getting it wrong in
// the permissive direction leaves a typo-mainnet node running UNPINNED limits.

func TestMainnetNamesAreTreatedAsMainnet(t *testing.T) {
	for _, n := range []string{"", "mainnet", "main", "MainNet", "  mainnet  "} {
		assert.True(t, isMainNetName(n),
			"%q selects the MAINNET chain params, so the block limits must be pinned for it", n)
	}
}

func TestNonMainnetNamesAreNotPinned(t *testing.T) {
	for _, n := range []string{"testnet", "test", "regnet", "regtest", "reg", "TESTNET"} {
		assert.False(t, isMainNetName(n),
			"%q is a non-mainnet chain and legitimately uses different block limits", n)
	}
}

// The F-043 case, and the reason this helper exists rather than a simple equality
// check. SetupConfig's activeNet switch has NO default, so an unrecognised name --
// "mainet", "production", a stray space -- keeps the MAINNET chain parameters. A
// node like that is on the mainnet chain and MUST get the mainnet block limits. If
// isMainNetName returned false here, exactly the typo case would run unpinned,
// which is the partition this pin exists to prevent.
func TestUnrecognisedActiveNetCountsAsMainnet(t *testing.T) {
	for _, n := range []string{"mainet", "production", "MAINNET-1", "prod", "xyzzy"} {
		assert.True(t, isMainNetName(n),
			"%q is unrecognised, so SetupConfig keeps MAINNET chain params -- the block "+
				"limits must be pinned for it too, or a typo produces an unpinned mainnet node", n)
	}
}
