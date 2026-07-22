// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/stretchr/testify/assert"
)

// Testnet parity: without ArmIncidentGates every incident gate is pinned to
// Disabled on a non-mainnet chain, so F-015 / F-212 / the same-block mirrors are
// INERT there and a green testnet proves nothing. These tests lock in the opt-in
// AND the safety invariant that it can never weaken mainnet.

const (
	tArmStrict  = uint32(500000)
	tArmFreeze  = uint32(400000)
	tArmRestrict = uint32(410000)
)

// TestArmIncidentGatesOffKeepsDisabled — default behaviour is unchanged.
func TestArmIncidentGatesOffKeepsDisabled(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "testnet"
	c.ArmIncidentGates = false
	c.StrictMoneyRangeHeight = tArmStrict
	c.CrossChainUTXOFreezeHeight = tArmFreeze
	c.CrossChainUTXORestrictionHeight = tArmRestrict

	enforceCrossChainUTXORestrictionHeights(c)
	enforceStrictMoneyAndRollbackHeights(c)

	assert.Equal(t, config.DisabledStrictMoneyRangeHeight, c.StrictMoneyRangeHeight)
	assert.Equal(t, config.DisabledCrossChainUTXORestrictionHeight, c.CrossChainUTXOFreezeHeight)
	assert.Equal(t, config.DisabledCrossChainUTXORestrictionHeight, c.CrossChainUTXORestrictionHeight)
}

// TestArmIncidentGatesOnHonoursConfig — the rehearsal opt-in actually arms them.
// Fail-on-pristine: pre-change these are forced to Disabled and the asserts fail.
func TestArmIncidentGatesOnHonoursConfig(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "testnet"
	c.ArmIncidentGates = true
	c.StrictMoneyRangeHeight = tArmStrict
	c.CrossChainUTXOFreezeHeight = tArmFreeze
	c.CrossChainUTXORestrictionHeight = tArmRestrict

	enforceCrossChainUTXORestrictionHeights(c)
	enforceStrictMoneyAndRollbackHeights(c)

	assert.Equal(t, tArmStrict, c.StrictMoneyRangeHeight,
		"armed rehearsal testnet must keep the configured StrictMoneyRangeHeight")
	assert.Equal(t, tArmFreeze, c.CrossChainUTXOFreezeHeight,
		"armed rehearsal testnet must keep the configured freeze height")
	assert.Equal(t, tArmRestrict, c.CrossChainUTXORestrictionHeight,
		"armed rehearsal testnet must keep the configured restriction height")
}

// TestArmIncidentGatesCannotWeakenMainnet — THE SAFETY INVARIANT. Even with the
// flag set and hostile overrides supplied, a mainnet-labelled config must still
// resolve to the coordinated mainnet values.
func TestArmIncidentGatesCannotWeakenMainnet(t *testing.T) {
	for _, label := range []string{"", "mainnet", "main", "MainNet "} {
		t.Run(label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label
			c.ArmIncidentGates = true // hostile: try to unpin mainnet
			c.StrictMoneyRangeHeight = 1
			c.CrossChainUTXOFreezeHeight = 1
			c.CrossChainUTXORestrictionHeight = 1
			c.ForcedRollbackHeight = 1
			c.ForcedRollbackTrigger = "deadbeef"

			enforceCrossChainUTXORestrictionHeights(c)
			enforceStrictMoneyAndRollbackHeights(c)

			assert.Equal(t, config.MainNetStrictMoneyRangeHeight, c.StrictMoneyRangeHeight,
				"ArmIncidentGates must NEVER unpin mainnet strict-money height")
			assert.Equal(t, config.MainNetCrossChainUTXOFreezeHeight, c.CrossChainUTXOFreezeHeight)
			assert.Equal(t, config.MainNetCrossChainUTXORestrictionHeight, c.CrossChainUTXORestrictionHeight)
			assert.Equal(t, config.MainNetForcedRollbackHeight, c.ForcedRollbackHeight)
			assert.Equal(t, config.MainNetForcedRollbackTrigger, c.ForcedRollbackTrigger)
		})
	}
}
