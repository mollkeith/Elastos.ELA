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
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/database"

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
	if c != nil && c.String("datadir") != "" {
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
		fmt.Println("current height is", i)
		block, err := chainStore.GetFFLDB().GetBlock(*nodes[i].Hash)
		if err != nil {
			return err
		}
		fmt.Println("block hash before rollback:", block.Hash())
		// ORDERING: the rollback transaction FIRST, the block-header index row LAST.
		// removeBlockNode used to run first, and it deletes the row that b.Nodes is
		// rebuilt from at startup -- so an interruption or an error before
		// RollbackBlock committed left that block permanently un-rollbackable while
		// it stayed main-chain indexed and served by hash. Same defect, and same fix,
		// as blockchain.rollbackOneBlock: keeping the header row until every
		// destructive step is durably committed makes the rewind resumable, because
		// the block is still in nodes on the next run.
		err = chainStore.RollbackBlock(block.Block, nodes[i], nil, blockchain.CalcPastMedianTime(nodes[i-1]))
		if err != nil {
			fmt.Println("rollback block failed, ", block.Height, err)
			return err
		}

		// Residue #2 parity: RollbackBlock clears the height and tx indexes but NOT
		// the raw by-hash entry in ffldb-blockidx, so without this the manually
		// rolled-back node keeps serving the discarded blocks by hash (same defect the
		// forced-rollback path fixes). Purge the raw-store location entry too.
		if err = chainStore.GetFFLDB().DeleteBlockFromStore(*nodes[i].Hash); err != nil {
			fmt.Println("purge block store failed, ", block.Height, err)
			return err
		}

		if err = removeBlockNode(chainStore.GetFFLDB(), &block.Header); err != nil {
			return err
		}

		blockHashAfter := *nodes[i-1].Hash
		fmt.Println("block hash after rollback:", blockHashAfter)
	}

	return nil
}

func removeBlockNode(fflDB blockchain.IFFLDBChainStore, header *common.Header) error {
	return fflDB.Update(func(dbTx database.Tx) error {
		return blockchain.DBRemoveBlockNode(dbTx, header)
	})
}
