// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package purgeresidue

import (
	"fmt"

	"github.com/elastos/Elastos.ELA/blockchain"
	cmdcom "github.com/elastos/Elastos.ELA/cmd/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"

	"github.com/urfave/cli"
)

var (
	appSettings = settings.NewSettings()
	dataDir     = "elastos/data"
)

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
	cfg := appSettings.SetupConfig(false, "", "")

	target := cfg.ForcedRollbackHeight
	if target == 0 || target == config.DisabledForcedRollbackHeight {
		fmt.Println("forced rollback is not configured for this network; nothing to purge")
		return nil
	}

	log.NewDefault("logs/node", 0, 0, 0)
	chainStore, err := blockchain.NewChainStore(dataDir, cfg)
	if err != nil {
		fmt.Println("create chain store failed, ", err)
		return err
	}
	defer chainStore.Close()

	n, err := blockchain.PurgeForcedRollbackResidue(chainStore.GetFFLDB(), target)
	if err != nil {
		fmt.Println("purge residue failed, ", err)
		return err
	}
	fmt.Printf("purged %d residual block(s) above forced-rollback height %d\n", n, target)
	return nil
}
