// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package rollback

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/elastos/Elastos.ELA/blockchain"
	cmdcom "github.com/elastos/Elastos.ELA/cmd/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"

	"github.com/urfave/cli"
)

var (
	appSettings = settings.NewSettings()
)

// ErrMissingHeight is returned when the required --height flag is absent.
//
// FV-18, MEASURED on this tree: `ela-cli rollback 2260450` -- the POSITIONAL form
// both forced-rollback remedy strings used to print -- hit the `NumFlags() == 0`
// branch, printed the subcommand help and returned nil, i.e. EXIT 0, having touched
// nothing. A restart-day runbook step that checks the exit status recorded SUCCESS
// for an operation that did not happen. Missing --height is now an error with a
// non-zero exit.
var ErrMissingHeight = errors.New("missing required flag --height <N>")

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "rollback",
		Usage: "Rollback blockchain data",
		Description: "With ela-cli rollback command, you could rollback blockchain data. " +
			"--height is REQUIRED; a bare positional height is not accepted.",
		ArgsUsage: "[args]",
		Flags: []cli.Flag{
			cli.IntFlag{
				Name:  "height",
				Usage: "the final height after rollback (REQUIRED)",
			},
			cmdcom.ConfigFileFlag,
			cmdcom.DataDirFlag,
			cmdcom.TestNetFlag,
			cmdcom.RegTestFlag,
			cmdcom.InstantBlockFlag,
		},
		Action: rollbackAction,
	}
}

// resolveDataDir builds the chain-data path the same way main.go does, honouring
// --datadir.
//
// FV-18, MEASURED on this tree: the package-level `dataDir = "elastos/data"` was
// passed straight to NewChainStore, so --datadir was INERT -- running
// `ela-cli rollback --height 0 --datadir /somewhere/else` from another directory
// created and operated on ./elastos/data under the CWD and left /somewhere/else
// untouched, then reported "Current height of blockchain is 0", which reads as a
// data problem rather than a flag problem. An operator remedy is only a remedy if
// the flags it is invoked with are honoured.
func resolveDataDir(c *cli.Context, cfg *config.Configuration) string {
	flagDataDir := config.DataDir
	if cfg != nil && cfg.DataDir != "" {
		flagDataDir = cfg.DataDir
	}
	// c.IsSet, NOT c.String != "": cmdcom.DataDirFlag is declared with
	// Value: config.DataDir, so c.String("datadir") is NEVER empty and the flag
	// DEFAULT would silently shadow a configured DataDir. IsSet is true only when
	// the operator actually named the flag.
	if c != nil && c.IsSet("datadir") {
		flagDataDir = c.String("datadir")
	}
	return filepath.Join(flagDataDir, dataPath)
}

// dataPath mirrors main.go: the chain data lives under <datadir>/data.
const dataPath = "data"

func rollbackAction(c *cli.Context) error {
	// NOTE: --conf is still inert here. This command does not run screw's flag
	// binding, and SetupConfig falls back to the config.ConfigFile CONSTANT
	// ("./config.json"), which cannot be assigned. The configuration therefore comes
	// from ./config.json relative to the CURRENT DIRECTORY, which is why the remedy
	// strings that name this command say to run it from the node's working
	// directory. Making --conf real needs a settings entry point that takes a path;
	// that belongs to the FV-18 tooling track, not to the rollback correctness fix.
	cfg := appSettings.SetupConfig(false, "", "")

	if !c.IsSet("height") {
		cli.ShowSubcommandHelp(c)
		return cli.NewExitError(fmt.Sprintf("%s -- usage: ela-cli rollback --height <N> "+
			"[--datadir <path>], run from the node's working directory", ErrMissingHeight), 1)
	}
	targetHeightStr := c.String("height")
	targetHeight, err := strconv.Atoi(targetHeightStr)
	if err != nil {
		fmt.Println("get height error:", err)
		return err
	}
	if targetHeight < 0 {
		return cli.NewExitError("get height error: height must be positive", 1)
	}

	log.NewDefault("logs/node", 0, 0, 0)
	dataDir := resolveDataDir(c, cfg)
	fmt.Println("rolling back the chain store at", dataDir, "to height", targetHeight)
	chainStore, err := blockchain.NewChainStore(dataDir, cfg)
	if err != nil {
		fmt.Println("create chain store failed, ", err)
		return err
	}
	defer chainStore.Close()
	ckpManager := checkpoint.NewManager(cfg)
	chain, err := blockchain.New(chainStore, cfg, nil, nil, ckpManager)
	if err != nil {
		fmt.Println("create blockchain failed, ", err)
		return err
	}
	nodes := chain.Nodes

	currentHeight := len(nodes) - 1
	if targetHeight >= currentHeight {
		// The data dir is named because an inert --datadir used to make a
		// wrong-directory invocation look exactly like this (FV-18).
		errorStr := fmt.Sprintf("Current height of blockchain is %d,"+
			" you can't do this, man. (chain store: %s)", currentHeight, dataDir)
		fmt.Println(errorStr)
		return cli.NewExitError(errorStr, 1)
	}

	for i := currentHeight; i > targetHeight; i-- {
		fmt.Println("current height is", i,
			"block hash before rollback:", nodes[i].Hash.String())

		// ONE implementation, driven from both places. This loop used to carry its
		// own copy of the three-transaction sequence. It had the header-row-last
		// ORDERING, so an interrupted run left the block in the index and therefore
		// re-visitable -- but it had no phase probe, so re-visiting it was the
		// problem: with the rollback transaction already committed and the raw entry
		// already purged, the re-run's GetBlock failed and the command could never
		// finish; with the rollback committed but the purge not yet done, the re-run
		// called RollbackBlock a SECOND time over the same block, re-applying
		// per-transaction rollback processors that are not idempotent. Neither
		// outcome is acceptable in the command that every forced-rollback refusal
		// message names as the operator remedy.
		//
		// blockchain.RollbackOneBlock is the automatic path's per-block rewind: it
		// probes the PERSISTED store first and skips exactly the steps that are
		// already durably committed, so a resumed run is exactly-once; it evicts the
		// RAM block cache after the raw purge; and it checks every error. It also
		// passes the block's own stored Confirm to RollbackBlock, where this loop
		// passed nil.
		if err := chain.RollbackOneBlock(nodes[i], nodes[i-1]); err != nil {
			fmt.Println("rollback block failed, ", i, err)
			return cli.NewExitError(err.Error(), 1)
		}

		fmt.Println("block hash after rollback:", nodes[i-1].Hash.String())
	}

	return nil
}
