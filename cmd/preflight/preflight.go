// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package preflight

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastos/Elastos.ELA/blockchain"
	cmdcom "github.com/elastos/Elastos.ELA/cmd/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/utils/version"

	"github.com/urfave/cli"
)

var appSettings = settings.NewSettings()

// dataPath mirrors main.go: the chain data lives under <datadir>/data.
const dataPath = "data"

// Exit codes. They are the command's API: node.sh and the operator script both
// branch on them, so they are documented here and in the --help text, and
// TestPreflightExitCodesAreDistinct pins that no two mean the same thing.
const (
	// ExitReady -- the node will start. Either it will rewind, or there is
	// nothing to roll back. WARNINGS DO NOT CHANGE THIS: a store that may have
	// been restored from stale data still starts correctly, and claiming
	// otherwise would be claiming a signal the store does not carry.
	ExitReady = 0
	// ExitUsage -- bad flags, or a configuration this command cannot resolve.
	ExitUsage = 1
	// ExitStoreUnreadable -- there is no chain store at the path, or it cannot be
	// opened for reading. NOTHING was predicted.
	ExitStoreUnreadable = 2
	// ExitNodeRunning -- the store is locked by another process, so it cannot be
	// read consistently. Stop the node and run this again.
	ExitNodeRunning = 3
	// ExitWillRefuse -- the node will REFUSE to start. The reason is in the
	// BLOCKING section, verbatim as the node itself would print it.
	ExitWillRefuse = 4
	// ExitInternal -- the pre-flight itself failed. No prediction was made, and
	// nothing was written.
	ExitInternal = 5
)

// NewCommand builds the `ela-cli preflight` subcommand.
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "preflight",
		Usage: "Predict what this node will do on its next start (READ-ONLY)",
		Description: "Reads the node's own store and its RESOLVED configuration and " +
			"reports what will happen when the node is started: whether the forced " +
			"rollback will rewind, whether there is nothing to do, or whether the " +
			"node will refuse to start and why.\n\n" +
			"   It NEVER writes. The block store is opened through a read-only " +
			"driver that cannot start a writable transaction, cannot compact, and " +
			"does not perform the unclean-shutdown flat-file repair; the leveldb " +
			"'chain' store is not opened at all. Run it with the node STOPPED -- " +
			"if the node is running the store is locked and this command says so " +
			"and exits " + fmt.Sprint(ExitNodeRunning) + " rather than forcing anything.\n\n" +
			"   It also predicts the start-up check that refuses on a restored " +
			"checkpoint at or above the rollback target. That prediction reads the " +
			"height header of the default checkpoint snapshots WITHOUT loading them " +
			"and without running the node's checkpoint restore, so it is an upper " +
			"bound: a snapshot with an intact header and a corrupt body would fail " +
			"to load and the node's real restored height would be lower. The report " +
			"repeats this where it prints the number.\n\n" +
			"   EXIT CODES: " + fmt.Sprint(ExitReady) + " ready (will rewind, or " +
			"nothing to do); " + fmt.Sprint(ExitUsage) + " usage/configuration " +
			"error; " + fmt.Sprint(ExitStoreUnreadable) + " no readable chain " +
			"store; " + fmt.Sprint(ExitNodeRunning) + " the node is running " +
			"(store locked); " + fmt.Sprint(ExitWillRefuse) + " the node WILL " +
			"REFUSE to start; " + fmt.Sprint(ExitInternal) + " internal error. " +
			"Warnings never change the exit code -- consume the JSON 'warnings' " +
			"field for those.",
		ArgsUsage: "[args]",
		Flags: []cli.Flag{
			cmdcom.ConfigFileFlag,
			cmdcom.DataDirFlag,
			cmdcom.TestNetFlag,
			cmdcom.RegTestFlag,
			cmdcom.InstantBlockFlag,
			cli.BoolFlag{
				Name:  "json",
				Usage: "emit the report as JSON on stdout instead of text",
			},
		},
		Action: preflightAction,
	}
}

// resolveDataDir builds the chain-data path the same way main.go does, honouring
// --datadir. Copied in shape from cmd/rollback and cmd/purgeresidue, where the
// same flag was measured INERT (FV-18) before it was fixed.
func resolveDataDir(c *cli.Context, cfg *config.Configuration) string {
	return filepath.Join(resolveNodeDir(c, cfg), dataPath)
}

// resolveNodeDir returns the node's working directory (the parent of data/ and of
// logs/), honouring --datadir.
func resolveNodeDir(c *cli.Context, cfg *config.Configuration) string {
	flagDataDir := config.DataDir
	if cfg != nil && cfg.DataDir != "" {
		flagDataDir = cfg.DataDir
	}
	// c.IsSet, NOT c.String != "": cmdcom.DataDirFlag is declared with
	// Value: config.DataDir, so c.String("datadir") is NEVER empty and the flag
	// DEFAULT would silently shadow a configured DataDir.
	if c != nil && c.IsSet("datadir") {
		flagDataDir = c.String("datadir")
	}
	return flagDataDir
}

// preflightAction is the command body. It converts every failure -- including a
// panic out of the read-only store guard -- into a documented exit code.
func preflightAction(c *cli.Context) (err error) {
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintf(os.Stderr, "preflight: internal error: %v\n", p)
			err = cli.NewExitError("", ExitInternal)
		}
	}()

	// The production code this command calls logs. The package logger is nil
	// until something installs one, and log.Infof dereferences it -- but every
	// existing constructor opens a rotating FILE, and a read-only pre-flight must
	// not create a logs directory as a side effect of looking at a store.
	log.NewDiscardDefault(0)

	// Capture what the operator ASKED for before SetupConfig's mainnet pin
	// overwrites it, so the report can say what was discarded.
	supplied := readSuppliedRollbackOverride()

	cfg, cfgErr := setupConfigSafely()
	if cfgErr != nil {
		// MEASURED on this tree: settings.enforceMainnetIncidentGatesArmed
		// (F-043 part 2) does not RETURN on a mainnet-identity node whose
		// coordinated values have been tampered with -- it PANICS. That is the
		// node refusing to start, and it is a CONFIGURATION refusal, so it must
		// not be reported as an internal fault of this tool.
		fmt.Fprintf(os.Stderr, "preflight: THE NODE WILL REFUSE TO START -- it "+
			"rejects this configuration before it ever opens the store, so "+
			"nothing about the store was read:\n\n  %v\n", cfgErr)
		return cli.NewExitError("", ExitUsage)
	}
	if cfg == nil {
		return cli.NewExitError("preflight: could not resolve configuration",
			ExitUsage)
	}

	nodeDir := resolveNodeDir(c, cfg)
	dataDir := resolveDataDir(c, cfg)

	store, err := blockchain.NewReadOnlyChainStore(dataDir, cfg)
	if err != nil {
		return storeOpenExit(err, dataDir)
	}
	defer store.Close()

	chain, err := blockchain.LoadChainForPreflight(store, cfg)
	if err != nil {
		return storeOpenExit(err, dataDir)
	}

	report, err := blockchain.BuildPreflightReport(chain, blockchain.PreflightOptions{
		Version:         version.Version,
		DataDir:         dataDir,
		NodeDir:         nodeDir,
		SuppliedTrigger: supplied.trigger,
		SuppliedHeight:  supplied.height,
		TriggerSupplied: supplied.triggerSet,
		HeightSupplied:  supplied.heightSet,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "preflight: %v\n", err)
		return cli.NewExitError("", ExitInternal)
	}
	if c.Bool("json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return cli.NewExitError(fmt.Sprint("preflight: ", err), ExitInternal)
		}
	} else {
		fmt.Print(RenderText(report))
	}

	if report.Outcome == blockchain.PreflightWillRefuse {
		return cli.NewExitError("", ExitWillRefuse)
	}
	return nil
}

// setupConfigSafely resolves the node's configuration the way main.go does, and
// converts the coordinated-parameter guard's PANIC into an error.
func setupConfigSafely() (cfg *config.Configuration, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()
	return appSettings.SetupConfig(false, "", ""), nil
}

// storeOpenExit maps a store-open failure onto its documented exit code.
func storeOpenExit(err error, dataDir string) error {
	switch {
	case strings.Contains(err.Error(), blockchain.ErrChainStoreLocked.Error()):
		fmt.Fprintf(os.Stderr,
			"preflight: the chain store under %s is LOCKED by another process.\n"+
				"           That is what a RUNNING NODE looks like. Nothing was read "+
				"and nothing was predicted.\n"+
				"           Stop the node and run this again. This command will "+
				"never break or wait on that lock.\n", dataDir)
		return cli.NewExitError("", ExitNodeRunning)
	default:
		fmt.Fprintf(os.Stderr, "preflight: cannot read the chain store under %s: %v\n",
			dataDir, err)
		return cli.NewExitError("", ExitStoreUnreadable)
	}
}

// suppliedOverride is what the operator's own configuration asked for.
type suppliedOverride struct {
	trigger               string
	height                uint32
	triggerSet, heightSet bool
}

// readSuppliedRollbackOverride reads the operator's config.json BEFORE
// SetupConfig runs, because the mainnet pin overwrites both fields in place and
// there is afterwards no way to tell a discarded override from a correct one.
func readSuppliedRollbackOverride() suppliedOverride {
	var out suppliedOverride
	raw, err := os.ReadFile(config.ConfigFile)
	if err != nil {
		return out
	}
	var doc struct {
		Configuration struct {
			ForcedRollbackTrigger *string `json:"ForcedRollbackTrigger"`
			ForcedRollbackHeight  *uint32 `json:"ForcedRollbackHeight"`
		} `json:"Configuration"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out
	}
	if doc.Configuration.ForcedRollbackTrigger != nil {
		out.trigger = *doc.Configuration.ForcedRollbackTrigger
		out.triggerSet = true
	}
	if doc.Configuration.ForcedRollbackHeight != nil {
		out.height = *doc.Configuration.ForcedRollbackHeight
		out.heightSet = true
	}
	return out
}
