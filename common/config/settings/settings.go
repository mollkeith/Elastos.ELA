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
		configuration.ForcedRollbackHeight = config.MainNetForcedRollbackHeight
		configuration.ForcedRollbackTrigger = config.MainNetForcedRollbackTrigger
		// Pin the DPoS v2 vote lock-time bounds: payload.VoteRights clamps duration
		// to [DposV2MinVoteLockDuration, DposV2MaxVoteLockDuration] (7200/720000), so
		// an operator override of these validation params would let validation admit
		// a vote VoteRights then weights differently -- a consensus divergence.
		configuration.DPoSConfiguration.DPoSV2MinVotesLockTime = 7200
		configuration.DPoSConfiguration.DPoSV2MaxVotesLockTime = 720000
	default:
		configuration.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
		configuration.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
		configuration.ForcedRollbackTrigger = ""
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
