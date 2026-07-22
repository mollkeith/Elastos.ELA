// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package settings

import (
	"fmt"
	"os"

	"github.com/RainFallsSilent/screw"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/spf13/viper"
	"path/filepath"
	"strings"
)

type Settings struct {
	viper  *viper.Viper
	params *config.Configuration
}

func (s *Settings) Viper() *viper.Viper {
	return s.viper
}

// ignore the error, for command line
func (s *Settings) loadConfigFile(files string, cfg *config.Config) {
	paths, fileName := filepath.Split(files)
	fileExt := filepath.Ext(files)
	s.viper.AddConfigPath(paths)
	s.viper.SetConfigName(strings.TrimSuffix(fileName, fileExt))
	s.viper.SetConfigType(strings.TrimPrefix(fileExt, "."))
	if err := s.viper.ReadInConfig(); err != nil {
		return
	}

	crcArbiters := s.viper.Get("configuration.dposconfiguration.crcarbiters")
	if crcArbiters != nil {
		cfg.DPoSConfiguration.CRCArbiters = []string{}
	}

	s.viper.Unmarshal(&cfg)
}

func (s *Settings) SetupConfig(withScrew bool, about string, version string) *config.Configuration {
	// Initialize functions
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters

	conf := &config.Config{
		Configuration: &config.DefaultParams,
	}
	if withScrew {
		screw.Bind(conf.Configuration, version, about)
	}
	if conf.Conf == "" {
		conf.Conf = config.ConfigFile
	}
	s.loadConfigFile(conf.Conf, conf)

	// switch activeNet params
	var testNet bool
	switch strings.ToLower(strings.TrimSpace(conf.ActiveNet)) {
	case "testnet", "test":
		testNet = true
		conf.TestNet()
		s.loadConfigFile(conf.Conf, conf)
	case "regnet", "regtest", "reg":
		conf.RegNet()
		s.loadConfigFile(conf.Conf, conf)
	}

	// F-043: an unrecognized ActiveNet keeps the MAINNET params (the switch above
	// has no default) while enforce*Heights() below treats it as non-mainnet and
	// DISABLES the CrossChain-UTXO freeze/restriction, strict-money-range and
	// forced-rollback controls. That combination (mainnet chain, incident gates
	// off) is what a typo such as "mainet"/"production" produces. Unknown labels
	// are still supported on purpose for private/forked nets, so warn loudly
	// rather than refuse to start.
	switch strings.ToLower(strings.TrimSpace(conf.ActiveNet)) {
	case "", "mainnet", "main", "testnet", "test", "regnet", "regtest", "reg":
	default:
		fmt.Fprintf(os.Stderr,
			"WARNING: unrecognized ActiveNet %q - keeping MAINNET chain params while "+
				"DISABLING the CrossChain-UTXO freeze/restriction, strict-money-range and "+
				"forced-rollback controls. Use one of: mainnet, testnet, regnet. If this is "+
				"an intentional private/forked net, ignore this warning.\n", conf.ActiveNet)
	}

	if conf.MaxBlockSize > 0 {
		pact.MaxBlockContextSize = conf.MaxBlockSize
	} else if !testNet {
		pact.MaxBlockContextSize = 2000000
	}

	if conf.MaxBlockHeaderSize > 0 {
		pact.MaxBlockHeaderSize = conf.MaxBlockHeaderSize
	}

	if conf.MaxTxPerBlock > 0 {
		pact.MaxTxPerBlock = conf.MaxTxPerBlock
	} else {
		pact.MaxTxPerBlock = 10000
	}

	instantBlock := conf.PowConfiguration.InstantBlock
	if instantBlock {
		conf.Configuration = conf.InstantBlock()
	}
	if withScrew {
		screw.Bind(conf.Configuration, version, about)
	}
	enforceCrossChainUTXORestrictionHeights(conf.Configuration)
	enforceStrictMoneyAndRollbackHeights(conf.Configuration)
	enforceFrozenAddresses(conf.Configuration)
	conf.Configuration = conf.Sterilize()
	// F-043 part 2: run AFTER Sterilize so FoundationProgramHash reflects any config.json
	// FoundationAddress (Sterilize recomputes it from a non-empty address). Running before
	// Sterilize would compare the INHERITED default hash, falsely refusing a private/forked
	// net that set a custom FoundationAddress with the incident gates off. Real mainnet has
	// an empty FoundationAddress, so Sterilize keeps the default identity and the
	// typo-mainnet-with-gates-off case is still caught.
	enforceMainnetIncidentGatesArmed(conf.Configuration)
	config.Parameters = conf.Configuration
	return conf.Configuration
}

// enforceCrossChainUTXORestrictionHeights prevents local configuration from
// changing the coordinated mainnet CrossChain UTXO consensus heights.
func enforceCrossChainUTXORestrictionHeights(configuration *config.Configuration) {
	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
		configuration.CrossChainUTXOFreezeHeight =
			config.MainNetCrossChainUTXOFreezeHeight
		configuration.CrossChainUTXORestrictionHeight =
			config.MainNetCrossChainUTXORestrictionHeight
	default:
		// Rehearsal opt-in: keep whatever the net defaults / config.json supplied so a
		// testnet can exercise the gated CrossChain-UTXO fixes. Mainnet never reaches
		// here (handled above), so this cannot weaken mainnet.
		if configuration.ArmIncidentGates {
			break
		}
		configuration.CrossChainUTXOFreezeHeight =
			config.DisabledCrossChainUTXORestrictionHeight
		configuration.CrossChainUTXORestrictionHeight =
			config.DisabledCrossChainUTXORestrictionHeight
	}
}

// enforceStrictMoneyAndRollbackHeights prevents local configuration from changing
// the coordinated mainnet strict-money activation, forced-rollback height and
// forced-rollback trigger. On a coordinated one-shot restart a single mismatched
// local value would fork that node, so these are pinned for mainnet exactly like
// the CrossChain heights.
func enforceStrictMoneyAndRollbackHeights(configuration *config.Configuration) {
	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
		configuration.StrictMoneyRangeHeight = config.MainNetStrictMoneyRangeHeight
		// Pin RevisedDPoSRewardHeight too: it is a --reviseddposrewardheight-overridable,
		// consensus-affecting coordinated height (F-212/F-032 reward gate). Leaving it
		// unpinned let a mainnet config.json/CLI override diverge reward math from the fleet
		// once the owner sets its activation value. No-op today (default MaxUint32/dormant).
		configuration.RevisedDPoSRewardHeight = config.MainNetRevisedDPoSRewardHeight
		configuration.ForcedRollbackHeight = config.MainNetForcedRollbackHeight
		configuration.ForcedRollbackTrigger = config.MainNetForcedRollbackTrigger
		// Pin the DPoS v2 vote lock-time bounds: payload.VoteRights clamps duration
		// to [DposV2MinVoteLockDuration, DposV2MaxVoteLockDuration] (7200/720000), so
		// an operator override of these validation params would let validation admit
		// a vote VoteRights then weights differently -- a consensus divergence.
		configuration.DPoSConfiguration.DPoSV2MinVotesLockTime = 7200
		configuration.DPoSConfiguration.DPoSV2MaxVotesLockTime = 720000
	default:
		// Rehearsal opt-in (see ArmIncidentGates): keep the supplied heights so the
		// strict-money / forced-rollback path can be exercised on a testnet. Mainnet
		// never reaches this branch, so mainnet cannot be weakened by the flag.
		if configuration.ArmIncidentGates {
			break
		}
		configuration.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
		configuration.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
		configuration.ForcedRollbackTrigger = ""
	}
}

// enforceMainnetIncidentGatesArmed (F-043 part 2) refuses to start the REAL mainnet
// chain with the incident controls disabled. The ActiveNet label switch that selects
// params has no default, so a typo (e.g. "mainet") keeps the mainnet foundation
// identity while enforce*Heights() above hit their default branch and DISABLE the
// CrossChain-UTXO freeze, strict-money-range and forced-rollback gates -- a mainnet
// node that would follow the corrupt chain. Discriminates by foundation IDENTITY, not
// the label (unknown labels are legitimately used for private/forked nets, which have a
// different foundation and are unaffected).
func enforceMainnetIncidentGatesArmed(configuration *config.Configuration) {
	if !config.IsMainNetFoundationProgramHash(configuration.FoundationProgramHash) {
		return
	}
	if configuration.StrictMoneyRangeHeight == config.DisabledStrictMoneyRangeHeight ||
		configuration.CrossChainUTXOFreezeHeight == config.DisabledCrossChainUTXORestrictionHeight ||
		configuration.ForcedRollbackTrigger == "" {
		panic(fmt.Sprintf(
			"config: ActiveNet %q resolves to the MAINNET chain (foundation identity) but the "+
				"incident controls are DISABLED (StrictMoneyRangeHeight=%d, "+
				"CrossChainUTXOFreezeHeight=%d, ForcedRollbackTrigger=%q). Refusing to start: a "+
				"mainnet node with the CrossChain-UTXO freeze / strict-money / forced-rollback "+
				"gates off would follow the corrupt chain. Set ActiveNet to \"mainnet\".",
			configuration.ActiveNet, configuration.StrictMoneyRangeHeight,
			configuration.CrossChainUTXOFreezeHeight, configuration.ForcedRollbackTrigger))
	}
}

// enforceFrozenAddresses prevents local configuration from changing the
// coordinated mainnet frozen-address list.
func enforceFrozenAddresses(configuration *config.Configuration) {
	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
		configuration.FrozenAddresses = config.MainNetFrozenAddresses()
	default:
		// Keep network-specific or empty lists for non-mainnet.
	}
}

func NewSettings() *Settings {
	settings := &Settings{
		viper: viper.New(),
	}
	return settings
}
