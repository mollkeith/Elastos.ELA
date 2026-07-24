// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/utils/test"
	"github.com/stretchr/testify/require"
)

// f138Store is the minimum IChainStore initChainState needs to reach the
// missing-block-index branch: only GetFFLDB is ever called on it there.
type f138Store struct {
	IChainStore
	ffldb IFFLDBChainStore
}

func (s *f138Store) GetFFLDB() IFFLDBChainStore { return s.ffldb }

// TestF138_InitChainStateRefusesADatabaseWithoutABlockIndex.
//
// When the authoritative chainstate record is present but the v2 block-index
// bucket is not, initChainState returned nil: the node came up with an EMPTY block
// index, no tip and a nil BestChain, silently reporting success. The migration
// that used to close that gap sits commented out immediately above the branch, and
// its commented-out `return ... errors.New("initChainState failed")` shows failure
// was the intended outcome.
func TestF138_InitChainStateRefusesADatabaseWithoutABlockIndex(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()

	ffldb, err := NewChainStoreFFLDB(t.TempDir(), params)
	require.NoError(t, err)
	defer ffldb.Close()

	// A database that has been told where the best chain is, but has no v2 block
	// index to rebuild that chain from.
	require.NoError(t, ffldb.Update(func(dbTx database.Tx) error {
		if dbTx.Metadata().Bucket(blockIndexBucketName) != nil {
			if e := dbTx.Metadata().DeleteBucket(blockIndexBucketName); e != nil {
				return e
			}
		}
		return dbTx.Metadata().Put(chainStateKeyName, []byte{0x00})
	}))

	chain := &BlockChain{
		chainParams: params,
		db:          &f138Store{ffldb: ffldb},
		Nodes:       make([]*BlockNode, 0),
	}

	err = chain.initChainState()
	require.Error(t, err,
		"initChainState must not report success on a database it cannot load a tip from")
	require.Nil(t, chain.BestChain,
		"no tip may be published when the block index is missing")
}
