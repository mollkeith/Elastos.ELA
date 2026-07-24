// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package rollback

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/elastos/Elastos.ELA/blockchain"
	cmdcom "github.com/elastos/Elastos.ELA/cmd/common"
	"github.com/elastos/Elastos.ELA/common/config/settings"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/database"

	"github.com/urfave/cli"
)

var (
	appSettings = settings.NewSettings()
	dataDir     = "elastos/data"
)

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:        "rollback",
		Usage:       "Rollback blockchain data",
		Description: "With ela-cli rollback command, you could rollback blockchain data.",
		ArgsUsage:   "[args]",
		Flags: []cli.Flag{
			cli.IntFlag{
				Name:  "height",
				Usage: "the final height after rollback",
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

func rollbackAction(c *cli.Context) error {
	config := appSettings.SetupConfig(false, "", "")

	if c.NumFlags() == 0 {
		cli.ShowSubcommandHelp(c)
		return nil
	}
	targetHeightStr := c.String("height")
	targetHeight, err := strconv.Atoi(targetHeightStr)
	if err != nil {
		fmt.Println("get height error:", err)
		return err
	}
	if targetHeight < 0 {
		fmt.Println("get height error: height must be positive")
		return nil
	}

	log.NewDefault("logs/node", 0, 0, 0)
	chainStore, err := blockchain.NewChainStore(dataDir, config)
	if err != nil {
		fmt.Println("create chain store failed, ", err)
		return err
	}
	defer chainStore.Close()
	ckpManager := checkpoint.NewManager(config)
	chain, err := blockchain.New(chainStore, config, nil, nil, ckpManager)
	if err != nil {
		fmt.Println("create blockchain failed, ", err)
		return err
	}
	nodes := chain.Nodes

	currentHeight := len(nodes) - 1
	if targetHeight >= currentHeight {
		errorStr := fmt.Sprintf("Current height of blockchain is %d,"+
			" you can't do this, man.", currentHeight)
		fmt.Println(errorStr)
		return errors.New(errorStr)
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
