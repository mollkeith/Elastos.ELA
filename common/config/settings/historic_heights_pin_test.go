// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package settings

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"

	"github.com/stretchr/testify/assert"
)

// The historic mainnet activation heights must not be movable by config.json or
// a CLI flag.
//
// WHY. docs/config.json.md shipped "DPoSV2StartHeight": 2000000 while the
// compiled-in mainnet value is 1405000. An operator who copied the repository's
// own example config got a node that disagrees with the fleet about which
// transaction types are legal across a 595,000-block span. Every comparison
// against these heights is monotone, so the mistake is INERT for blocks above
// both values -- it does not fork an already-synced node at the 2,260,451
// restart -- but it forks any node that REPLAYS the span: a from-zero sync, or a
// restore from a snapshot below the wrong value.
//
// FAIL-ON-PRISTINE: delete the enforceMainnetHistoricActivationHeights call from
// enforceCoordinatedMainnetParameters and TestHistoricHeightsArePinnedOnMainnet
// fails on the first pin. Proven by removing the production call site.

func mainnetConfWith(mutate func(*config.Configuration)) *config.Configuration {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"
	mutate(c)
	return c
}

func TestHistoricHeightsArePinnedOnMainnet(t *testing.T) {
	def := config.GetDefaultParams()

	// the exact value the repository's own documentation told operators to use
	const docValue = uint32(2000000)
	assert.NotEqual(t, docValue, def.DPoSV2StartHeight,
		"precondition: the documented value must differ from the real one, "+
			"otherwise this test proves nothing")

	c := mainnetConfWith(func(c *config.Configuration) {
		c.DPoSV2StartHeight = docValue
		c.VoteStartHeight = 1
		c.CRCOnlyDPOSHeight = 2
		c.PublicDPOSHeight = 3
	})
	enforceCoordinatedMainnetParameters(c)

	assert.Equal(t, def.DPoSV2StartHeight, c.DPoSV2StartHeight,
		"DPoSV2StartHeight must be pinned to the mainnet value (%d), not the "+
			"documented %d", def.DPoSV2StartHeight, docValue)
	assert.Equal(t, def.VoteStartHeight, c.VoteStartHeight)
	assert.Equal(t, def.CRCOnlyDPOSHeight, c.CRCOnlyDPOSHeight)
	assert.Equal(t, def.PublicDPOSHeight, c.PublicDPOSHeight)
}

// A correctly configured mainnet node -- which is every node in the fleet, since
// these are the compiled-in defaults -- must see NO change of any kind.
func TestPinIsANoOpForACorrectMainnetNode(t *testing.T) {
	def := config.GetDefaultParams()
	c := mainnetConfWith(func(*config.Configuration) {})
	enforceCoordinatedMainnetParameters(c)

	assert.Equal(t, def.DPoSV2StartHeight, c.DPoSV2StartHeight)
	assert.Equal(t, def.VoteStartHeight, c.VoteStartHeight)
	assert.Equal(t, def.CRCOnlyDPOSHeight, c.CRCOnlyDPOSHeight)
	assert.Equal(t, def.PublicDPOSHeight, c.PublicDPOSHeight)
}

// Non-mainnet must be untouched: testnet and regnet carry their own real
// activation heights and a private/forked net may legitimately choose its own.
// Clobbering those would be a behaviour change on those nets.
func TestPinDoesNotTouchNonMainnet(t *testing.T) {
	for _, net := range []string{"testnet", "regnet"} {
		c := config.GetDefaultParams()
		c.ActiveNet = net
		c.DPoSV2StartHeight = 12345
		enforceMainnetHistoricActivationHeights(c)
		assert.Equal(t, uint32(12345), c.DPoSV2StartHeight,
			"%s must keep its own DPoSV2StartHeight", net)
	}
}

// Rule 1: the pin must not introduce a third coordinated mainnet gate. It reads
// the compiled-in defaults, so the only mainnet incident gates remain the two.
func TestPinIntroducesNoNewGate(t *testing.T) {
	assert.Equal(t, uint32(2260451), config.MainNetStrictMoneyRangeHeight)
	assert.Equal(t, uint32(2265000), config.MainNetRevisedDPoSRewardHeight)
	assert.Equal(t, uint32(1405000), config.GetDefaultParams().DPoSV2StartHeight,
		"DPoSV2StartHeight is a HISTORIC activation, not a new incident gate")
}
