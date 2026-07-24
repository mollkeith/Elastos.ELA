// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types/functions"

	"github.com/stretchr/testify/assert"
)

// Testnet parity: without ArmIncidentGates every incident gate is pinned to
// Disabled on a non-mainnet chain, so F-015 / F-212 / the same-block mirrors are
// INERT there and a green testnet proves nothing. These tests lock in the opt-in
// AND the safety invariant that it can never weaken mainnet.

const (
	tArmStrict   = uint32(500000)
	tArmFreeze   = uint32(400000)
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
//
// NOTE: this loop only covers RECOGNIZED mainnet labels, i.e. exactly the cases the
// pins already handle. The label a real operator gets wrong is an UNRECOGNIZED one,
// which never reaches a mainnet arm at all; that case is covered by
// TestG3UnrecognizedLabelWithMainnetIdentityIsRefused below.
func TestArmIncidentGatesCannotWeakenMainnet(t *testing.T) {
	for _, label := range []string{"", "mainnet", "main", "MainNet "} {
		t.Run(label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label
			c.ArmIncidentGates = true // hostile: try to unpin mainnet
			c.StrictMoneyRangeHeight = 1
			c.RevisedDPoSRewardHeight = 1
			c.CrossChainUTXOFreezeHeight = 1
			c.CrossChainUTXORestrictionHeight = 1
			c.ForcedRollbackHeight = 1
			c.ForcedRollbackTrigger = "deadbeef"

			enforceCrossChainUTXORestrictionHeights(c)
			enforceStrictMoneyAndRollbackHeights(c)

			assert.Equal(t, config.MainNetStrictMoneyRangeHeight, c.StrictMoneyRangeHeight,
				"ArmIncidentGates must NEVER unpin mainnet strict-money height")
			assert.Equal(t, config.MainNetRevisedDPoSRewardHeight, c.RevisedDPoSRewardHeight,
				"ArmIncidentGates must NEVER unpin mainnet RevisedDPoSRewardHeight (reward gate)")
			assert.Equal(t, config.MainNetCrossChainUTXOFreezeHeight, c.CrossChainUTXOFreezeHeight)
			assert.Equal(t, config.MainNetCrossChainUTXORestrictionHeight, c.CrossChainUTXORestrictionHeight)
			assert.Equal(t, config.MainNetForcedRollbackHeight, c.ForcedRollbackHeight)
			assert.Equal(t, config.MainNetForcedRollbackTrigger, c.ForcedRollbackTrigger)
		})
	}
}

// ---------------------------------------------------------------------------
// G3 — ArmIncidentGates must not defeat the mainnet refuse-to-start guard.
// ---------------------------------------------------------------------------

// hostileHeights are the arbitrary operator-supplied values from the audit repro.
// None of them is a Disabled sentinel and the trigger is non-empty, which is why the
// pre-G3 three-field spot check waved them all through.
const (
	hostileStrict   = uint32(999999999)
	hostileRevised  = uint32(888888888)
	hostileRollback = uint32(777777777)
	hostileFreeze   = uint32(666666666)
	hostileSchnorr  = uint32(100)
	hostileTrigger  = "deadbeef"
)

// mislabelledMainnetConfig builds the G3 scenario: a config that keeps the REAL
// mainnet params and foundation identity because its ActiveNet label is unrecognized,
// carrying arbitrary gate heights that the rehearsal opt-in preserves.
func mislabelledMainnetConfig(label string, arm bool) *config.Configuration {
	c := config.GetDefaultParams()
	c.ActiveNet = label
	c.ArmIncidentGates = arm
	c.StrictMoneyRangeHeight = hostileStrict
	c.RevisedDPoSRewardHeight = hostileRevised
	c.ForcedRollbackHeight = hostileRollback
	c.ForcedRollbackTrigger = hostileTrigger
	c.CrossChainUTXOFreezeHeight = hostileFreeze
	c.SchnorrStartHeight = hostileSchnorr
	return c
}

// TestG3UnrecognizedLabelWithMainnetIdentityIsRefused is the fail-on-pristine proof
// for G3. Pristine: enforceMainnetIncidentGatesArmed only tested for the Disabled
// SENTINELS and an empty ForcedRollbackTrigger, and ArmIncidentGates makes the
// non-mainnet branches KEEP the operator's heights rather than disable them — so
// every assertion below saw ordinary numbers, nothing panicked, and a node with the
// real mainnet foundation identity started with gate 1 effectively off, the forced
// rollback disarmed, the CrossChain-UTXO freeze off and the F-185 aggregate-Schnorr
// withdraw path re-opened.
func TestG3UnrecognizedLabelWithMainnetIdentityIsRefused(t *testing.T) {
	for _, label := range []string{"mainet", "mainnnet", "production", "main-net", " Mainet "} {
		t.Run(label, func(t *testing.T) {
			c := mislabelledMainnetConfig(label, true)

			enforceCoordinatedMainnetParameters(c)

			assert.True(t, config.IsMainNetFoundationProgramHash(c.FoundationProgramHash),
				"precondition: an unrecognized label keeps the REAL mainnet foundation identity")
			assert.Equal(t, hostileStrict, c.StrictMoneyRangeHeight,
				"precondition: ArmIncidentGates keeps the operator's height, so no Disabled "+
					"sentinel is present for a spot check to catch")
			assert.Equal(t, hostileSchnorr, c.SchnorrStartHeight,
				"precondition: the Schnorr pin returns early for an unrecognized label")

			assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(c) },
				"a mainnet-identity node with off-fleet coordinated values must refuse to start")
		})
	}
}

// TestG3UnrecognizedLabelWithoutArmingStillRefused is the anti-regression control:
// the case the guard already caught before G3 must keep panicking.
func TestG3UnrecognizedLabelWithoutArmingStillRefused(t *testing.T) {
	c := config.GetDefaultParams()
	c.ActiveNet = "mainet"

	enforceCoordinatedMainnetParameters(c)

	assert.Equal(t, config.DisabledStrictMoneyRangeHeight, c.StrictMoneyRangeHeight,
		"precondition: without the opt-in the gates are disabled")
	assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(c) })
}

// TestG3MainnetIdentityRefusesArmIncidentGates covers the second arm of the fix: the
// flag is the NON-MAINNET rehearsal opt-in and must never appear on a node carrying
// the mainnet foundation identity, even when the label is spelled correctly and the
// pins have therefore already restored every coordinated value. That is the realistic
// path — a rehearsal config.json copied onto a mainnet box.
//
// Fail-on-pristine: pristine leaves every value at its pinned mainnet default here,
// so the old spot check found nothing and the node started.
func TestG3MainnetIdentityRefusesArmIncidentGates(t *testing.T) {
	for _, label := range []string{"", "mainnet", "main", "MainNet "} {
		t.Run(label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label
			c.ArmIncidentGates = true

			enforceCoordinatedMainnetParameters(c)

			assert.Equal(t, config.MainNetStrictMoneyRangeHeight, c.StrictMoneyRangeHeight,
				"precondition: the mainnet pins ran, so nothing looks wrong to a spot check")
			assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(c) },
				"a mainnet configuration carrying the rehearsal opt-in must refuse to start")
		})
	}
}

// TestG3EveryCoordinatedValueIsVerified walks the whole coordinated set one field at
// a time: start from a correct mainnet configuration, move exactly one value
// off-fleet, and require a refusal. Fail-on-pristine: the pre-G3 guard checked only
// StrictMoneyRangeHeight, CrossChainUTXOFreezeHeight and the trigger, and then only
// against sentinels — so every row here except the two sentinel rows started fine.
func TestG3EveryCoordinatedValueIsVerified(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*config.Configuration)
	}{
		{"ActiveNet", func(c *config.Configuration) { c.ActiveNet = "mainet" }},
		{"ArmIncidentGates", func(c *config.Configuration) { c.ArmIncidentGates = true }},
		{"StrictMoneyRangeHeight", func(c *config.Configuration) { c.StrictMoneyRangeHeight = hostileStrict }},
		{"RevisedDPoSRewardHeight", func(c *config.Configuration) { c.RevisedDPoSRewardHeight = hostileRevised }},
		{"CrossChainUTXOFreezeHeight", func(c *config.Configuration) { c.CrossChainUTXOFreezeHeight = hostileFreeze }},
		{"CrossChainUTXORestrictionHeight", func(c *config.Configuration) { c.CrossChainUTXORestrictionHeight = hostileFreeze }},
		{"ForcedRollbackHeight", func(c *config.Configuration) { c.ForcedRollbackHeight = hostileRollback }},
		{"ForcedRollbackTrigger", func(c *config.Configuration) { c.ForcedRollbackTrigger = hostileTrigger }},
		{"SchnorrStartHeight", func(c *config.Configuration) { c.SchnorrStartHeight = hostileSchnorr }},
		{"NormalSchnorrStartHeight", func(c *config.Configuration) { c.NormalSchnorrStartHeight = hostileSchnorr }},
		{"ProducerSchnorrStartHeight", func(c *config.Configuration) { c.ProducerSchnorrStartHeight = hostileSchnorr }},
		{"CRSchnorrStartHeight", func(c *config.Configuration) { c.CRSchnorrStartHeight = hostileSchnorr }},
		{"VotesSchnorrStartHeight", func(c *config.Configuration) { c.VotesSchnorrStartHeight = hostileSchnorr }},
		{"DPoSV2MinVotesLockTime", func(c *config.Configuration) {
			c.DPoSConfiguration.DPoSV2MinVotesLockTime = 1
		}},
		{"DPoSV2MaxVotesLockTime", func(c *config.Configuration) {
			c.DPoSConfiguration.DPoSV2MaxVotesLockTime = 1
		}},
		{"FrozenAddresses", func(c *config.Configuration) { c.FrozenAddresses = nil }},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = "mainnet"
			enforceCoordinatedMainnetParameters(c)
			assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(c) },
				"precondition: the un-corrupted mainnet configuration must start")

			testCase.corrupt(c)
			assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(c) },
				"an off-fleet %s must refuse to start", testCase.name)
		})
	}
}

// TestG3CorrectMainnetIsUnaffected is the no-behaviour-change proof: the real restart
// configuration — mainnet label, nothing overridden — passes the hardened guard, and
// every coordinated value is still the compiled-in constant afterwards.
func TestG3CorrectMainnetIsUnaffected(t *testing.T) {
	for _, label := range []string{"", "mainnet", "main", "MainNet ", "  MAINNET  "} {
		t.Run(label, func(t *testing.T) {
			c := config.GetDefaultParams()
			c.ActiveNet = label

			enforceCoordinatedMainnetParameters(c)
			assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(c) })

			assert.Equal(t, config.MainNetStrictMoneyRangeHeight, c.StrictMoneyRangeHeight)
			assert.Equal(t, config.MainNetRevisedDPoSRewardHeight, c.RevisedDPoSRewardHeight)
			assert.Equal(t, config.MainNetCrossChainUTXOFreezeHeight, c.CrossChainUTXOFreezeHeight)
			assert.Equal(t, config.MainNetCrossChainUTXORestrictionHeight, c.CrossChainUTXORestrictionHeight)
			assert.Equal(t, config.MainNetForcedRollbackHeight, c.ForcedRollbackHeight)
			assert.Equal(t, config.MainNetForcedRollbackTrigger, c.ForcedRollbackTrigger)
			assert.Equal(t, config.MainNetSchnorrStartHeight, c.SchnorrStartHeight)
			assert.Equal(t, config.MainNetNormalSchnorrStartHeight, c.NormalSchnorrStartHeight)
		})
	}
}

// TestG3RehearsalArmingUnaffected proves direction 2 of the fix: a genuine
// non-mainnet rehearsal chain still arms the incident gates and still starts. Both
// TestNet() and RegNet() install the testnet foundation identity, so the hardened
// guard returns early exactly as it must.
func TestG3RehearsalArmingUnaffected(t *testing.T) {
	for _, netCase := range []struct {
		label string
		apply func(*config.Configuration) *config.Configuration
	}{
		{"testnet", func(c *config.Configuration) *config.Configuration { return c.TestNet() }},
		{"regnet", func(c *config.Configuration) *config.Configuration { return c.RegNet() }},
	} {
		t.Run(netCase.label, func(t *testing.T) {
			c := netCase.apply(config.GetDefaultParams())
			c.ActiveNet = netCase.label
			c.ArmIncidentGates = true
			c.StrictMoneyRangeHeight = tArmStrict
			c.RevisedDPoSRewardHeight = tArmStrict
			c.CrossChainUTXOFreezeHeight = tArmFreeze
			c.CrossChainUTXORestrictionHeight = tArmRestrict
			c.ForcedRollbackHeight = tArmFreeze
			c.ForcedRollbackTrigger = hostileTrigger

			enforceCoordinatedMainnetParameters(c)

			assert.False(t, config.IsMainNetFoundationProgramHash(c.FoundationProgramHash),
				"a rehearsal net must not carry the mainnet foundation identity")
			assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(c) },
				"the rehearsal workflow must keep working: ArmIncidentGates exists for it")

			assert.Equal(t, tArmStrict, c.StrictMoneyRangeHeight, "gate must stay ARMED")
			assert.Equal(t, tArmStrict, c.RevisedDPoSRewardHeight, "gate must stay ARMED")
			assert.Equal(t, tArmFreeze, c.CrossChainUTXOFreezeHeight, "gate must stay ARMED")
			assert.Equal(t, tArmRestrict, c.CrossChainUTXORestrictionHeight, "gate must stay ARMED")
			assert.Equal(t, tArmFreeze, c.ForcedRollbackHeight, "rollback must stay ARMED")
			assert.Equal(t, hostileTrigger, c.ForcedRollbackTrigger, "rollback must stay ARMED")
		})
	}
}

// TestG3PrivateNetWithOwnFoundationUnaffected keeps the intentional private/forked-net
// contract: an unknown label with its own foundation is not mainnet and must start.
func TestG3PrivateNetWithOwnFoundationUnaffected(t *testing.T) {
	// Sterilize builds the genesis block through the functions.* tx hooks; initialize
	// them the way SetupConfig does so the real Sterilize path runs.
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters

	c := mislabelledMainnetConfig("private-net", true)
	c.FoundationAddress = "8ZNizBf4KhhPjeJRGpox6rPcHE5Np6tFx3"
	c = c.Sterilize()

	enforceCoordinatedMainnetParameters(c)

	assert.False(t, config.IsMainNetFoundationProgramHash(c.FoundationProgramHash))
	assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(c) },
		"a private/forked net with its own foundation must still start")
}

// ---------------------------------------------------------------------------
// G3 — end-to-end through the production entry point.
// ---------------------------------------------------------------------------

// setupConfigFromJSON runs the REAL SetupConfig against a temporary config.json, the
// same way a node starts. Wiring proof: these tests fail if the guard is ever dropped
// from SetupConfig, not just if its body is weakened.
func setupConfigFromJSON(t *testing.T, contents string) *config.Configuration {
	t.Helper()

	originalDefaultParams := config.DefaultParams
	originalParameters := config.Parameters
	t.Cleanup(func() {
		config.DefaultParams = originalDefaultParams
		config.Parameters = originalParameters
	})

	configPath := filepath.Join(t.TempDir(), "config.json")
	assert.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))

	config.DefaultParams = *config.GetDefaultParams()
	config.DefaultParams.Conf = configPath

	return NewSettings().SetupConfig(false, "", "")
}

// TestG3SetupConfigRefusesMislabelledMainnet is the production-path fail-on-pristine
// test: the exact file an operator would produce by typing "mainet" into a copied
// rehearsal config.json must not bring a node up.
func TestG3SetupConfigRefusesMislabelledMainnet(t *testing.T) {
	assert.Panics(t, func() {
		setupConfigFromJSON(t, `{
  "Configuration": {
    "ActiveNet": "mainet",
    "ArmIncidentGates": true,
    "StrictMoneyRangeHeight": 999999999,
    "RevisedDPoSRewardHeight": 888888888,
    "ForcedRollbackHeight": 777777777,
    "ForcedRollbackTrigger": "deadbeef",
    "CrossChainUTXOFreezeHeight": 666666666,
    "SchnorrStartHeight": 100
  }
}`)
	}, "SetupConfig must refuse a mislabelled mainnet config carrying off-fleet gate values")
}

// TestG3SetupConfigRefusesArmedMainnet — a rehearsal config.json copied onto a
// mainnet box with the label corrected is still a rehearsal config, and is refused.
func TestG3SetupConfigRefusesArmedMainnet(t *testing.T) {
	assert.Panics(t, func() {
		setupConfigFromJSON(t, `{
  "Configuration": {
    "ActiveNet": "mainnet",
    "ArmIncidentGates": true
  }
}`)
	}, "SetupConfig must refuse ArmIncidentGates on the mainnet identity")
}

// TestG3SetupConfigAcceptsMainnet — the real restart configuration still starts, with
// every coordinated value at its compiled-in constant.
func TestG3SetupConfigAcceptsMainnet(t *testing.T) {
	c := setupConfigFromJSON(t, `{
  "Configuration": {
    "ActiveNet": "mainnet"
  }
}`)

	assert.True(t, config.IsMainNetFoundationProgramHash(c.FoundationProgramHash))
	assert.Equal(t, config.MainNetStrictMoneyRangeHeight, c.StrictMoneyRangeHeight)
	assert.Equal(t, config.MainNetRevisedDPoSRewardHeight, c.RevisedDPoSRewardHeight)
	assert.Equal(t, config.MainNetForcedRollbackHeight, c.ForcedRollbackHeight)
	assert.Equal(t, config.MainNetForcedRollbackTrigger, c.ForcedRollbackTrigger)
	assert.Equal(t, config.MainNetCrossChainUTXOFreezeHeight, c.CrossChainUTXOFreezeHeight)
	assert.Equal(t, config.MainNetCrossChainUTXORestrictionHeight, c.CrossChainUTXORestrictionHeight)
}

// TestG3SetupConfigAcceptsArmedRehearsal — the rehearsal workflow end to end: the
// shape of the shipped rehearsal config.json still boots and still arms its gates.
func TestG3SetupConfigAcceptsArmedRehearsal(t *testing.T) {
	c := setupConfigFromJSON(t, `{
  "Configuration": {
    "ActiveNet": "regnet",
    "ArmIncidentGates": true,
    "StrictMoneyRangeHeight": 300,
    "RevisedDPoSRewardHeight": 300,
    "CrossChainUTXOFreezeHeight": 250,
    "CrossChainUTXORestrictionHeight": 260
  }
}`)

	assert.False(t, config.IsMainNetFoundationProgramHash(c.FoundationProgramHash))
	assert.Equal(t, uint32(300), c.StrictMoneyRangeHeight, "rehearsal gate must be ARMED")
	assert.Equal(t, uint32(300), c.RevisedDPoSRewardHeight, "rehearsal gate must be ARMED")
	assert.Equal(t, uint32(250), c.CrossChainUTXOFreezeHeight, "rehearsal gate must be ARMED")
	assert.Equal(t, uint32(260), c.CrossChainUTXORestrictionHeight, "rehearsal gate must be ARMED")
}
