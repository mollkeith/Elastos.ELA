// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package purgeresidue

import (
	"fmt"
	"path/filepath"

	"github.com/elastos/Elastos.ELA/blockchain"
	cmdcom "github.com/elastos/Elastos.ELA/cmd/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"

	"github.com/urfave/cli"
)

var (
	appSettings = settings.NewSettings()
)

// dataPath mirrors main.go: the chain data lives under <datadir>/data.
const dataPath = "data"

// resolveDataDir builds the chain-data path the same way main.go does, honouring
// --datadir. The package-level "elastos/data" it replaces was passed straight to
// NewChainStore, so --datadir was advertised and INERT (FV-18, measured): the
// command silently created and cleaned a store under the CWD instead of the one the
// operator named.
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

// NewCommand builds the `ela-cli purgeresidue` subcommand: an offline cleaner that
// removes forced-rollback block-store residue (residue #2) left behind on an
// already-rolled-back node. It targets the configured ForcedRollbackHeight so it
// reuses the same source of truth as the automatic rollback, and refuses to run on
// networks where forced rollback is not configured.
func NewCommand() *cli.Command {
	return &cli.Command{
		Name:  "purgeresidue",
		Usage: "Purge forced-rollback block-store residue (residue #2)",
		Description: "Removes discarded blocks (strictly above the configured " +
			"forced-rollback height and no longer on the main chain) that a prior " +
			"forced or manual rollback left fetchable by hash in the raw ffldb block " +
			"store. Run with the node STOPPED.",
		ArgsUsage: "[args]",
		Flags: []cli.Flag{
			cmdcom.ConfigFileFlag,
			cmdcom.DataDirFlag,
			cmdcom.TestNetFlag,
			cmdcom.RegTestFlag,
			cmdcom.InstantBlockFlag,
		},
		Action: purgeResidueAction,
	}
}

func purgeResidueAction(c *cli.Context) error {
	// NOTE: --conf is still inert here -- SetupConfig falls back to the
	// config.ConfigFile CONSTANT, which cannot be assigned -- so the ActiveNet, and
	// with it the ForcedRollbackHeight this command purges above, comes from
	// ./config.json relative to the CURRENT DIRECTORY. Run it from the node's
	// working directory. See the note in cmd/rollback.
	cfg := appSettings.SetupConfig(false, "", "")

	target := cfg.ForcedRollbackHeight
	if target == 0 || target == config.DisabledForcedRollbackHeight {
		fmt.Println("forced rollback is not configured for this network; nothing to purge")
		return nil
	}

	log.NewDefault("logs/node", 0, 0, 0)
	dataDir := resolveDataDir(c, cfg)
	fmt.Println("purging residue above height", target, "in the chain store at", dataDir)
	chainStore, err := blockchain.NewChainStore(dataDir, cfg)
	if err != nil {
		fmt.Println("create chain store failed, ", err)
		return err
	}
	defer chainStore.Close()

	n, err := blockchain.PurgeForcedRollbackResidue(chainStore.GetFFLDB(), target)
	if err != nil {
		fmt.Println("purge residue failed, ", err)
		return cli.NewExitError(fmt.Sprint("purge residue failed: ", err), 1)
	}
	fmt.Printf("purged %d residual block(s) above forced-rollback height %d\n", n, target)
	return nil
}
