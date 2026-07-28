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

	// An unrecognized ActiveNet keeps the mainnet params (the switch above
	// has no default) while enforce*Heights() below treats it as non-mainnet and
	// disables the CrossChain-UTXO freeze/restriction, strict-money-range and
	// forced-rollback controls. That combination, mainnet chain with the incident
	// gates off, is what a typo such as "mainet"/"production" produces. Unknown
	// labels are still supported on purpose for private/forked nets, so warn loudly
	// rather than refuse to start.
	switch strings.ToLower(strings.TrimSpace(conf.ActiveNet)) {
	case "", "mainnet", "main", "testnet", "test", "regnet", "regtest", "reg":
	default:
		fmt.Fprintf(os.Stderr,
			"WARNING: unrecognized ActiveNet %q - keeping MAINNET chain params while "+
				"DISABLING the CrossChain-UTXO freeze/restriction, strict-money-range and "+
				"forced-rollback controls. Use one of: mainnet, testnet, regnet. If this is "+
				"an intentional private/forked net, ignore this warning; if this node is meant "+
				"to be MAINNET it will refuse to start (F-043 part 2 / G3).\n", conf.ActiveNet)
	}

	// Pin the three block-shape limits on MAINNET before they reach the pact
	// globals. Each is settable from config.json and by CLI flag, each is a
	// consensus rule, and a node that differs from the fleet on any of them
	// PERMANENTLY PARTITIONS: it accepts blocks the fleet rejects, or rejects
	// blocks the fleet accepts, at every height, with no gate and no recovery.
	//
	// This pin has to live HERE rather than in enforceCoordinatedMainnetParameters
	// (which runs later, at the enforceCoordinatedMainnetParameters call below):
	// by the time that function runs, the assignments beneath this comment have
	// already copied the operator's value into the pact globals, and pinning the
	// Configuration field afterwards would not undo it. That ordering is exactly
	// why this was missed when DPoSV2StartHeight and the Schnorr heights were
	// pinned -- those are read from Configuration at use time, these are not.
	//
	// Values are the compiled-in mainnet defaults, so a correctly configured
	// mainnet node sees NO change; only an override is discarded, loudly.
	// Non-mainnet is untouched: testnet legitimately runs a larger block.
	if !testNet && isMainNetName(conf.ActiveNet) {
		const (
			mainnetMaxBlockContextSize = 2000000
			mainnetMaxTxPerBlock       = 10000
		)
		if conf.MaxBlockSize != 0 && conf.MaxBlockSize != mainnetMaxBlockContextSize {
			fmt.Fprintf(os.Stderr,
				"WARNING: ignoring mainnet MaxBlockSize %d - pinned to the coordinated "+
					"mainnet value %d. A node using the supplied value would accept or "+
					"reject blocks the rest of the network does not, at every height, "+
					"and would be permanently partitioned.\n",
				conf.MaxBlockSize, mainnetMaxBlockContextSize)
		}
		conf.MaxBlockSize = mainnetMaxBlockContextSize
		if conf.MaxTxPerBlock != 0 && conf.MaxTxPerBlock != mainnetMaxTxPerBlock {
			fmt.Fprintf(os.Stderr,
				"WARNING: ignoring mainnet MaxTxPerBlock %d - pinned to the coordinated "+
					"mainnet value %d (same partition risk as MaxBlockSize).\n",
				conf.MaxTxPerBlock, mainnetMaxTxPerBlock)
		}
		conf.MaxTxPerBlock = mainnetMaxTxPerBlock
		if conf.MaxBlockHeaderSize != 0 {
			fmt.Fprintf(os.Stderr,
				"WARNING: ignoring mainnet MaxBlockHeaderSize %d - mainnet uses the "+
					"compiled-in default (same partition risk as MaxBlockSize).\n",
				conf.MaxBlockHeaderSize)
			conf.MaxBlockHeaderSize = 0
		}
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
	enforceCoordinatedMainnetParameters(conf.Configuration)
	conf.Configuration = conf.Sterilize()
	// Run AFTER Sterilize so FoundationProgramHash reflects any config.json
	// FoundationAddress (Sterilize recomputes it from a non-empty address). Running before
	// Sterilize would compare the inherited default hash, falsely refusing a private/forked
	// net that set a custom FoundationAddress with the incident gates off. Real mainnet has
	// an empty FoundationAddress, so Sterilize keeps the default identity and the
	// typo-mainnet-with-gates-off case is still caught.
	enforceMainnetIncidentGatesArmed(conf.Configuration)
	config.Parameters = conf.Configuration
	return conf.Configuration
}

// enforceCoordinatedMainnetParameters applies every pin that local configuration
// (config.json or a CLI flag) must not be able to move. Kept as a single function so
// the test suite exercises the exact production set and order rather than a copy of
// it: a pin added here is automatically covered.
//
// enforceMainnetIncidentGatesArmed is deliberately NOT part of this chain -- it must
// run AFTER Sterilize (see the comment at its call site in SetupConfig).
func enforceCoordinatedMainnetParameters(configuration *config.Configuration) {
	enforceCrossChainUTXORestrictionHeights(configuration)
	enforceStrictMoneyAndRollbackHeights(configuration)
	enforceFrozenAddresses(configuration)
	enforceMainnetSchnorrActivationHeights(configuration)
	enforceMainnetHistoricActivationHeights(configuration)
}

// enforceMainnetHistoricActivationHeights pins the HISTORIC consensus activation
// heights that are still settable from config.json or a CLI flag. Every one of
// them is long past on mainnet, so no correctly configured node can differ; but
// each is a fork if it does differ, and each is reachable by an operator typo.
//
// The concrete reason this exists: docs/config.json.md documented
// DPoSV2StartHeight as 2000000 while the compiled-in mainnet value is 1405000 --
// off by 595,000 blocks. An operator who copied the repository's OWN example
// config got a node that disagrees with the fleet about which transaction types
// are legal across that 595,000-block span, and nothing warned them. Since the
// only thing a mining pool can be asked to do is update the binary and start,
// any value they can get wrong by following our documentation has to be pinned
// in code rather than corrected in prose. (The doc is corrected too.)
//
// SCOPE, and why it is not the whole restart story: every one of these is
// compared against a block height, always monotonically, so for blocks ABOVE
// both the right and the wrong value the two agree and the mistake is inert. It
// therefore does NOT fork an already-synced node on restart day -- the restarted
// chain begins at 2,260,451, above all of them. It forks a node that REPLAYS the
// affected span: a from-zero sync, or a restore from a snapshot below the wrong
// value. That is exactly the core developer's validation item 3, and it is the
// path a new pool or exchange node takes.
//
// Values are read from the compiled-in mainnet defaults rather than restated, so
// this introduces NO new height literal (Rule 1) and cannot drift from
// GetDefaultParams(). NormalSchnorrStartHeight is already pinned at the same
// 1405000 by enforceMainnetSchnorrActivationHeights, so leaving DPoSV2StartHeight
// unpinned beside it was an inconsistency as much as a gap.
//
// Announced on os.Stderr for the same reason the rollback discard is: SetupConfig
// runs before setupLog, so the package logger is still nil here.
func enforceMainnetHistoricActivationHeights(configuration *config.Configuration) {
	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
	default:
		// Non-mainnet keeps whatever the net defaults or config.json supplied:
		// testnet and regnet carry their own real activation heights, and a
		// private/forked net may legitimately choose its own.
		return
	}

	def := config.GetDefaultParams()

	pins := []struct {
		flag    string
		field   *uint32
		mainnet uint32
	}{
		{"--dposv2startheight", &configuration.DPoSV2StartHeight,
			def.DPoSV2StartHeight},
		{"--votestartheight", &configuration.VoteStartHeight,
			def.VoteStartHeight},
		{"--crconlydposheight", &configuration.CRCOnlyDPOSHeight,
			def.CRCOnlyDPOSHeight},
		{"--publicdposheight", &configuration.PublicDPOSHeight,
			def.PublicDPOSHeight},
	}

	for _, p := range pins {
		if *p.field != p.mainnet {
			fmt.Fprintf(os.Stderr,
				"WARNING: ignoring mainnet %s %d - pinned to the coordinated "+
					"mainnet activation height %d. A node that used the supplied "+
					"value would disagree with the fleet about which transactions "+
					"are valid across that span and fork while syncing.\n",
				p.flag, *p.field, p.mainnet)
		}
		*p.field = p.mainnet
	}
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

// announceDiscardedRollbackOverride reports, on stderr, a --forcedrollbacktrigger or
// --forcedrollbackheight (equivalently a config.json ForcedRollbackTrigger /
// ForcedRollbackHeight) that the mainnet pin is about to throw away.
//
// Without it, an empty --forcedrollbacktrigger passed together with the disabled
// sentinel as --forcedrollbackheight still resolves to the coordinated mainnet
// target and leaves the node armed, saying nothing at all. The node's own
// capacity-refusal text in blockchain/forcedrollback.go tells the operator what
// unsetting the trigger does; this is the discard side of the same story.
//
// A correctly configured mainnet node, which is every node in the fleet since these
// are the compiled-in defaults, supplies neither value and prints nothing, so this
// cannot become boilerplate operators learn to skip.
//
// It writes to os.Stderr rather than through common/log because SetupConfig runs
// before setupLog: the package logger is still nil here and a log call would panic.
// enforceMainnetSchnorrActivationHeights announces its discards the same way.
func announceDiscardedRollbackOverride(configuration *config.Configuration) {
	if configuration.ForcedRollbackTrigger != config.MainNetForcedRollbackTrigger {
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring mainnet --forcedrollbacktrigger %q - pinned to the "+
				"coordinated mainnet trigger %s. There is NO way to disarm the forced "+
				"rollback on a mainnet node: it is a coordinated one-shot consensus "+
				"rewind, and a node that skipped it would rejoin on the chain the "+
				"recovery removes.\n",
			configuration.ForcedRollbackTrigger, config.MainNetForcedRollbackTrigger)
	}
	if configuration.ForcedRollbackHeight != config.MainNetForcedRollbackHeight {
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring mainnet --forcedrollbackheight %d - pinned to the "+
				"coordinated mainnet rollback target %d. This node WILL rewind to that "+
				"height if it holds the block above it.\n",
			configuration.ForcedRollbackHeight, config.MainNetForcedRollbackHeight)
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
		// Announce BEFORE the assignments below overwrite the evidence. A silently
		// discarded forced-rollback override is the one pin whose loss the operator
		// is guaranteed to notice only when it is too late (see the function's own
		// comment), so it is the one pin that must not be silent.
		announceDiscardedRollbackOverride(configuration)
		configuration.StrictMoneyRangeHeight = config.MainNetStrictMoneyRangeHeight
		// Pin RevisedDPoSRewardHeight too: it is a --reviseddposrewardheight-overridable,
		// consensus-affecting coordinated height (the revised DPoS reward gate). Unpinned, a
		// mainnet config.json or CLI override would diverge reward math from the fleet
		// once the owner sets its activation value. No-op today (default MaxUint32/dormant).
		configuration.RevisedDPoSRewardHeight = config.MainNetRevisedDPoSRewardHeight
		configuration.ForcedRollbackHeight = config.MainNetForcedRollbackHeight
		configuration.ForcedRollbackTrigger = config.MainNetForcedRollbackTrigger
		// Pin the DPoS v2 vote lock-time bounds: payload.VoteRights clamps duration
		// to [DposV2MinVoteLockDuration, DposV2MaxVoteLockDuration] (7200/720000), so
		// an operator override of these validation params would let validation admit
		// a vote VoteRights then weights differently -- a consensus divergence.
		configuration.DPoSConfiguration.DPoSV2MinVotesLockTime = mainnetDPoSV2MinVotesLockTime
		configuration.DPoSConfiguration.DPoSV2MaxVotesLockTime = mainnetDPoSV2MaxVotesLockTime
	default:
		// Rehearsal opt-in (see ArmIncidentGates): keep the supplied heights so the
		// strict-money / forced-rollback path can be exercised on a testnet. Mainnet
		// never reaches this branch, so mainnet cannot be weakened by the flag.
		if configuration.ArmIncidentGates {
			break
		}
		configuration.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
		// P4 symmetry: RevisedDPoSRewardHeight also disabled on non-mainnet (mainnet pins it;
		// ArmIncidentGates arms it above). Parallel to the other incident gates.
		configuration.RevisedDPoSRewardHeight = config.DisabledStrictMoneyRangeHeight
		configuration.ForcedRollbackHeight = config.DisabledForcedRollbackHeight
		configuration.ForcedRollbackTrigger = ""
	}
}

// enforceMainnetSchnorrActivationHeights prevents local configuration from changing
// the coordinated mainnet Schnorr activation heights. Every one of them is exposed as
// a CLI flag (--schnorrstartheight, --normalschnorrstartheight,
// --producerschnorrstartheight, --crschnorrstartheight, --votesschnorrstartheight) and
// is settable from config.json, and every one of them is a consensus activation height
// that the tree's Schnorr rejections hang off:
//
//   - SchnorrStartHeight gates the aggregate-Schnorr WithdrawFromSideChain payload.
//     Lowering it on mainnet does two consensus-relevant things at once: it re-opens
//     the plain-sum group-key path an arbiter with a rogue NodePublicKey can forge a
//     full-threshold withdraw through, and, because SpecialContextCheck rejects every
//     non-V2 withdraw once BlockHeight > SchnorrStartHeight, it makes the node reject
//     the V1 withdrawals the rest of the fleet accepts, forking it off.
//   - NormalSchnorrStartHeight (1405000, live on mainnet) gates Schnorr program codes
//     in CheckAttributeProgram.
//   - Producer/CR/VotesSchnorrStartHeight are the dormant gates the producer, CR and
//     vote Schnorr rejections hang off.
//
// Pinned for mainnet exactly like the CrossChain-UTXO, strict-money and
// RevisedDPoSReward heights above. The pinned values are the compiled-in mainnet
// defaults, so a correctly configured mainnet node sees no change of any kind and no
// acceptance decision moves; only an operator override is discarded (loudly).
//
// There is deliberately no non-mainnet branch, unlike the incident gates: testnet
// (973000) and regnet (879144) carry real Schnorr activation heights that
// TestNet()/RegNet() set, and a private/forked net may legitimately choose its own.
// Clobbering those would be a behaviour change on those nets, so they are untouched.
func enforceMainnetSchnorrActivationHeights(configuration *config.Configuration) {
	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
	default:
		return
	}

	pins := []struct {
		flag    string
		field   *uint32
		mainnet uint32
	}{
		{"--schnorrstartheight", &configuration.SchnorrStartHeight,
			config.MainNetSchnorrStartHeight},
		{"--normalschnorrstartheight", &configuration.NormalSchnorrStartHeight,
			config.MainNetNormalSchnorrStartHeight},
		{"--producerschnorrstartheight", &configuration.ProducerSchnorrStartHeight,
			config.MainNetProducerSchnorrStartHeight},
		{"--crschnorrstartheight", &configuration.CRSchnorrStartHeight,
			config.MainNetCRSchnorrStartHeight},
		{"--votesschnorrstartheight", &configuration.VotesSchnorrStartHeight,
			config.MainNetVotesSchnorrStartHeight},
	}

	for _, pin := range pins {
		if *pin.field == pin.mainnet {
			continue
		}
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring mainnet %s override %d - pinned to the coordinated "+
				"mainnet value %d. Schnorr activation heights are consensus heights; a "+
				"node that disagrees with the fleet about them forks off the chain.\n",
			pin.flag, *pin.field, pin.mainnet)
		*pin.field = pin.mainnet
	}
}

// mainnetDPoSV2MinVotesLockTime / mainnetDPoSV2MaxVotesLockTime are the coordinated
// mainnet DPoS v2 vote lock-time bounds. Named so the pin above and the verification
// below share one source of truth instead of repeating the literals.
const (
	mainnetDPoSV2MinVotesLockTime = uint32(7200)
	mainnetDPoSV2MaxVotesLockTime = uint32(720000)
)

// coordinatedMainnetValue pairs one coordinated mainnet consensus height with the
// compiled-in value every node in the fleet must agree on.
type coordinatedMainnetValue struct {
	name string
	got  uint32
	want uint32
}

// coordinatedMainnetValues is the COMPLETE set of heights the enforce* helpers above
// assign on their mainnet arm. enforceMainnetIncidentGatesArmed asserts equality
// against this set, which turns the guard into the post-condition of the whole pin
// chain rather than a three-field spot check: a configuration that never reached a
// mainnet arm is caught here even when the surviving values are ordinary numbers
// rather than the Disabled sentinels. A pin added above must be listed here.
func coordinatedMainnetValues(c *config.Configuration) []coordinatedMainnetValue {
	return []coordinatedMainnetValue{
		{"StrictMoneyRangeHeight", c.StrictMoneyRangeHeight,
			config.MainNetStrictMoneyRangeHeight},
		{"RevisedDPoSRewardHeight", c.RevisedDPoSRewardHeight,
			config.MainNetRevisedDPoSRewardHeight},
		{"CrossChainUTXOFreezeHeight", c.CrossChainUTXOFreezeHeight,
			config.MainNetCrossChainUTXOFreezeHeight},
		{"CrossChainUTXORestrictionHeight", c.CrossChainUTXORestrictionHeight,
			config.MainNetCrossChainUTXORestrictionHeight},
		{"ForcedRollbackHeight", c.ForcedRollbackHeight,
			config.MainNetForcedRollbackHeight},
		{"SchnorrStartHeight", c.SchnorrStartHeight,
			config.MainNetSchnorrStartHeight},
		{"NormalSchnorrStartHeight", c.NormalSchnorrStartHeight,
			config.MainNetNormalSchnorrStartHeight},
		{"ProducerSchnorrStartHeight", c.ProducerSchnorrStartHeight,
			config.MainNetProducerSchnorrStartHeight},
		{"CRSchnorrStartHeight", c.CRSchnorrStartHeight,
			config.MainNetCRSchnorrStartHeight},
		{"VotesSchnorrStartHeight", c.VotesSchnorrStartHeight,
			config.MainNetVotesSchnorrStartHeight},
		{"DPoSV2MinVotesLockTime", c.DPoSConfiguration.DPoSV2MinVotesLockTime,
			mainnetDPoSV2MinVotesLockTime},
		{"DPoSV2MaxVotesLockTime", c.DPoSConfiguration.DPoSV2MaxVotesLockTime,
			mainnetDPoSV2MaxVotesLockTime},
	}
}

// sameFrozenAddresses reports whether a frozen-address list carries exactly the
// coordinated mainnet entries, in order. ProgramHash is derived from Address by
// Sterilize and is deliberately not compared.
func sameFrozenAddresses(got, want []config.FrozenAddress) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i].Address != want[i].Address ||
			got[i].DisableStartHeight != want[i].DisableStartHeight {
			return false
		}
	}
	return true
}

// enforceMainnetIncidentGatesArmed refuses to start a node that carries the real
// mainnet foundation identity unless its coordinated consensus configuration is
// byte-for-byte the fleet's.
//
// The ActiveNet label switch that selects params has no default, so a typo (e.g.
// "mainet") keeps the mainnet params and this mainnet foundation identity while every
// enforce* helper above takes its non-mainnet branch. Discriminating by foundation
// identity rather than by label is what catches that; unknown labels remain
// legitimate for private/forked nets, which have a different foundation and return
// early here.
//
// Testing only for the disabled sentinels and an empty trigger is not enough: the
// rehearsal opt-in ArmIncidentGates, whose whole purpose is to make those default
// branches keep the operator's heights instead of disabling them, walks straight
// through such a test. A mislabelled node then starts believing it is mainnet, with
// gate 1 effectively off, the forced rollback disarmed, the CrossChain-UTXO freeze
// off and the aggregate-Schnorr withdraw path re-opened. Two rules close that:
//
//   - ArmIncidentGates is refused outright on the mainnet identity. It exists only to
//     arm a non-mainnet rehearsal chain; on mainnet the pins are unconditional, so the
//     flag can never be anything but a copied-in rehearsal config.
//   - every coordinated value must equal its compiled-in mainnet constant, so any
//     future pin that a mislabelled config bypasses is caught too.
//
// A correctly configured mainnet node reaches every mainnet arm above, so all of
// these hold by construction and nothing about its behaviour changes.
func enforceMainnetIncidentGatesArmed(configuration *config.Configuration) {
	if !config.IsMainNetFoundationProgramHash(configuration.FoundationProgramHash) {
		return
	}

	var problems []string

	switch strings.ToLower(strings.TrimSpace(configuration.ActiveNet)) {
	case "", "mainnet", "main":
	default:
		problems = append(problems, fmt.Sprintf(
			"ActiveNet=%q is not a recognized mainnet label, so the params switch kept "+
				"MAINNET params while every coordinated pin took its non-mainnet branch",
			configuration.ActiveNet))
	}

	if configuration.ArmIncidentGates {
		problems = append(problems,
			"ArmIncidentGates=true, which is the NON-MAINNET rehearsal opt-in and must never "+
				"appear in a mainnet configuration")
	}

	for _, value := range coordinatedMainnetValues(configuration) {
		if value.got != value.want {
			problems = append(problems, fmt.Sprintf("%s=%d, want the coordinated %d",
				value.name, value.got, value.want))
		}
	}

	if configuration.ForcedRollbackTrigger != config.MainNetForcedRollbackTrigger {
		problems = append(problems, fmt.Sprintf(
			"ForcedRollbackTrigger=%q, want the coordinated %q",
			configuration.ForcedRollbackTrigger, config.MainNetForcedRollbackTrigger))
	}

	if !sameFrozenAddresses(configuration.FrozenAddresses, config.MainNetFrozenAddresses()) {
		problems = append(problems, fmt.Sprintf(
			"FrozenAddresses (%d entries) are not the coordinated mainnet list (%d entries)",
			len(configuration.FrozenAddresses), len(config.MainNetFrozenAddresses())))
	}

	if len(problems) == 0 {
		return
	}

	panic(fmt.Sprintf(
		"config: this node carries the REAL MAINNET foundation identity but its coordinated "+
			"consensus configuration does not match the fleet. Refusing to start: a mainnet node "+
			"that disagrees about the CrossChain-UTXO freeze / strict-money-range / "+
			"forced-rollback / Schnorr activation values either follows the corrupt chain or "+
			"forks off the fleet. Problems: %s. Set ActiveNet to \"mainnet\", remove "+
			"ArmIncidentGates, and remove every local override of these values.",
		strings.Join(problems, "; ")))
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

// isMainNetName reports whether an ActiveNet string selects the MAINNET chain
// parameters. It mirrors the switch in SetupConfig exactly: an empty or
// unrecognised name keeps the mainnet params (the switch there has no default),
// so it must be treated as mainnet here too. Getting that wrong in the permissive
// direction would leave a typo-mainnet node running unpinned block limits, which
// is the partition this pin exists to prevent.
func isMainNetName(activeNet string) bool {
	switch strings.ToLower(strings.TrimSpace(activeNet)) {
	case "testnet", "test", "regnet", "regtest", "reg":
		return false
	default:
		return true
	}
}
