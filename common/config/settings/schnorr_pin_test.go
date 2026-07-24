// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/stretchr/testify/assert"
)

// Real testnet / regnet Schnorr activation heights, restated here as literals so
// the anti-clobber tests below fail if TestNet()/RegNet() ever silently change.
const (
	testNetSchnorrStartHeight = uint32(965800 + 720*10) // 973000
	regNetSchnorrStartHeight  = uint32(875544 + 720*5)  // 879144
)

// schnorrOverride is the value a mis-configured or hostile operator supplies via
// --schnorrstartheight / config.json. 100 is below every reachable mainnet height,
// so on a pristine tree it both re-opens the F-185 aggregate-Schnorr withdraw path
// and makes SpecialContextCheck reject the V1 withdrawals the fleet accepts.
const schnorrOverride = uint32(100)

// applyMainnetPins is the PRODUCTION enforcement chain SetupConfig runs (same
// function, not a copy of its body), so these tests cannot drift from it.
func applyMainnetPins(c *config.Configuration) {
	enforceCoordinatedMainnetParameters(c)
}

// TestMainnetSchnorrStartHeightPinned is the core fail-on-pristine proof.
//
// Pristine: SchnorrStartHeight is exposed as the CLI flag --schnorrstartheight
// (common/config/config.go) and settable from config.json, and NOTHING in
// settings.go pins it -- unlike StrictMoneyRangeHeight, RevisedDPoSRewardHeight,
// the CrossChain-UTXO heights and the frozen-address list. So a mainnet node could
// be started with the aggregate-Schnorr withdraw feature ENABLED, which is exactly
// what the F-185 gate is there to prevent, and would additionally reject the V1
// withdrawals the rest of the fleet accepts (SpecialContextCheck rejects non-V2
// once BlockHeight > SchnorrStartHeight).
//
// Fail-on-pristine: drop enforceMainnetSchnorrActivationHeights from
// applyMainnetPins and this assertion sees 100 instead of math.MaxUint32.
func TestMainnetSchnorrStartHeightPinned(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"
	c.SchnorrStartHeight = schnorrOverride

	applyMainnetPins(c)

	assert.Equal(t, uint32(math.MaxUint32), c.SchnorrStartHeight,
		"a mainnet --schnorrstartheight override must be discarded: aggregate-Schnorr "+
			"withdraw is DISABLED on mainnet and the F-185 gate depends on that value")
	assert.Equal(t, config.MainNetSchnorrStartHeight, c.SchnorrStartHeight)
}

// TestMainnetSchnorrFamilyPinned covers the whole activation family. Every one of
// these is a CLI-overridable consensus activation height that a Schnorr rejection
// hangs off (F-026/F-046/F-175/F-185 plus CheckAttributeProgram), so an override
// on any of them diverges that node's acceptance decisions from the fleet.
func TestMainnetSchnorrFamilyPinned(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"
	c.SchnorrStartHeight = schnorrOverride
	c.NormalSchnorrStartHeight = schnorrOverride
	c.ProducerSchnorrStartHeight = schnorrOverride
	c.CRSchnorrStartHeight = schnorrOverride
	c.VotesSchnorrStartHeight = schnorrOverride

	applyMainnetPins(c)

	assert.Equal(t, config.MainNetSchnorrStartHeight, c.SchnorrStartHeight)
	assert.Equal(t, config.MainNetNormalSchnorrStartHeight, c.NormalSchnorrStartHeight)
	assert.Equal(t, config.MainNetProducerSchnorrStartHeight, c.ProducerSchnorrStartHeight)
	assert.Equal(t, config.MainNetCRSchnorrStartHeight, c.CRSchnorrStartHeight)
	assert.Equal(t, config.MainNetVotesSchnorrStartHeight, c.VotesSchnorrStartHeight)

	// The pinned values must be the compiled-in mainnet defaults, i.e. the pin can
	// never itself change an acceptance decision on a correctly configured node.
	assert.Equal(t, uint32(math.MaxUint32), c.SchnorrStartHeight)
	assert.Equal(t, uint32(1405000), c.NormalSchnorrStartHeight)
	assert.Equal(t, uint32(math.MaxUint32), c.ProducerSchnorrStartHeight)
	assert.Equal(t, uint32(math.MaxUint32), c.CRSchnorrStartHeight)
	assert.Equal(t, uint32(math.MaxUint32), c.VotesSchnorrStartHeight)
}

// TestMainnetSchnorrPinIsNoOpOnDefaults is the no-acceptance-change proof: a
// correctly configured mainnet node comes out of the enforcement chain
// byte-identical to the compiled-in defaults.
func TestMainnetSchnorrPinIsNoOpOnDefaults(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"
	before := struct{ s, n, p, cr, v uint32 }{
		c.SchnorrStartHeight, c.NormalSchnorrStartHeight,
		c.ProducerSchnorrStartHeight, c.CRSchnorrStartHeight,
		c.VotesSchnorrStartHeight,
	}

	applyMainnetPins(c)

	assert.Equal(t, before.s, c.SchnorrStartHeight)
	assert.Equal(t, before.n, c.NormalSchnorrStartHeight)
	assert.Equal(t, before.p, c.ProducerSchnorrStartHeight)
	assert.Equal(t, before.cr, c.CRSchnorrStartHeight)
	assert.Equal(t, before.v, c.VotesSchnorrStartHeight)
}

// TestMainnetSchnorrPinLabelNormalization mirrors the F-043 label handling: the
// mainnet arm is reached for the empty label and for whitespace/case variants, so
// a "MainNet " config.json cannot slip an override past the pin.
func TestMainnetSchnorrPinLabelNormalization(t *testing.T) {
	for _, label := range []string{"", "mainnet", "main", "MainNet ", " mainnet", "  MAINNET  ", "Main"} {
		t.Run("label="+label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label
			c.SchnorrStartHeight = schnorrOverride

			enforceMainnetSchnorrActivationHeights(c)

			assert.Equal(t, config.MainNetSchnorrStartHeight, c.SchnorrStartHeight,
				"mainnet label variant must still pin the Schnorr activation heights")
		})
	}
}

// TestTestNetSchnorrHeightsUntouched is the anti-clobber guard. Testnet and regnet
// carry REAL Schnorr activation heights (973000 / 879144) that the feature is
// genuinely live at; the pin must never reach them.
func TestTestNetSchnorrHeightsUntouched(t *testing.T) {
	c := config.GetDefaultParams()
	c.TestNet()
	c.ActiveNet = "testnet"

	enforceMainnetSchnorrActivationHeights(c)

	assert.Equal(t, testNetSchnorrStartHeight, c.SchnorrStartHeight,
		"testnet SchnorrStartHeight is a real activation height and must survive")
	assert.Equal(t, testNetSchnorrStartHeight, c.NormalSchnorrStartHeight)
}

func TestRegNetSchnorrHeightsUntouched(t *testing.T) {
	c := config.GetDefaultParams()
	c.RegNet()
	c.ActiveNet = "regnet"

	enforceMainnetSchnorrActivationHeights(c)

	assert.Equal(t, regNetSchnorrStartHeight, c.SchnorrStartHeight,
		"regnet SchnorrStartHeight is a real activation height and must survive")
	assert.Equal(t, regNetSchnorrStartHeight, c.NormalSchnorrStartHeight)
}

// TestPrivateNetSchnorrHeightsUntouched keeps the intentional private/forked-net
// contract: an unknown label may choose its own Schnorr activation heights. This is
// deliberately different from the incident gates, which are FORCED to Disabled on
// non-mainnet, because a private net enabling Schnorr affects only itself.
func TestPrivateNetSchnorrHeightsUntouched(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "private-net"
	c.SchnorrStartHeight = schnorrOverride
	c.ProducerSchnorrStartHeight = schnorrOverride

	enforceMainnetSchnorrActivationHeights(c)

	assert.Equal(t, schnorrOverride, c.SchnorrStartHeight)
	assert.Equal(t, schnorrOverride, c.ProducerSchnorrStartHeight)
}

// TestMainnetSchnorrPinSurvivesRehearsalArming proves the pin is not weakened by
// the rehearsal opt-in: ArmIncidentGates exists to ARM gates on a NON-mainnet
// chain, and must not become a way to enable aggregate-Schnorr withdraw on mainnet.
func TestMainnetSchnorrPinSurvivesRehearsalArming(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainnet"
	c.ArmIncidentGates = true
	c.SchnorrStartHeight = schnorrOverride

	applyMainnetPins(c)

	assert.Equal(t, config.MainNetSchnorrStartHeight, c.SchnorrStartHeight)
}

// TestMainNetSchnorrConstantsMatchDefaults locks the constants to the DefaultParams
// they were extracted from, so the pin can never drift away from the shipped
// mainnet posture.
func TestMainNetSchnorrConstantsMatchDefaults(t *testing.T) {
	d := config.GetDefaultParams()
	assert.Equal(t, d.SchnorrStartHeight, config.MainNetSchnorrStartHeight)
	assert.Equal(t, d.NormalSchnorrStartHeight, config.MainNetNormalSchnorrStartHeight)
	assert.Equal(t, d.ProducerSchnorrStartHeight, config.MainNetProducerSchnorrStartHeight)
	assert.Equal(t, d.CRSchnorrStartHeight, config.MainNetCRSchnorrStartHeight)
	assert.Equal(t, d.VotesSchnorrStartHeight, config.MainNetVotesSchnorrStartHeight)
}
