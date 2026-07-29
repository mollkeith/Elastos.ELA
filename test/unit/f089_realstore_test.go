// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package unit

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"

	"github.com/stretchr/testify/assert"
)

// TestF089RealStoreDuplicateCoinbase is the real-store integration test the safety
// re-verification asked for. The checkCoinbaseBIP30 unit test proves the GUARD
// LOGIC given an isDuplicate oracle; this test proves the ORACLE ITSELF — the exact
// b.db.IsTxHashDuplicate that checkCoinbaseBIP30 is wired to — actually detects a
// persisted coinbase txid against a REAL ffldb-backed ChainStore (not a mock), and
// does not false-positive on an unseen txid. Together they cover the fix end to end.
func TestF089RealStoreDuplicateCoinbase(t *testing.T) {
	// Build a real chain over a fresh ffldb store (functions are registered by the
	// package init() in txvalidator_test.go).
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()
	params.Sterilize()
	params.DPoSV2StartHeight = 0
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	blockchain.FoundationAddress = *params.FoundationProgramHash

	chainStore, err := blockchain.NewChainStore(
		filepath.Join(test.DataPath, "f089realstore"), params)
	assert.NoError(t, err)
	defer chainStore.Close()

	ckpManager := checkpoint.NewManager(params)
	chain, err := blockchain.New(chainStore, params,
		state.NewState(params, nil, nil, nil,
			func() bool { return false },
			nil, nil,
			nil, nil, nil, nil, nil),
		crstate.NewCommittee(params, ckpManager), ckpManager,
	)
	assert.NoError(t, err)
	// Init persists and indexes the genesis block (its tx index is caught up to
	// height 0), so its coinbase txid is stored exactly as on a live node.
	assert.NoError(t, chain.Init(nil))

	// The oracle wired into checkCoinbaseBIP30 detects the persisted coinbase txid.
	coinbaseHash := params.GenesisBlock.Transactions[0].Hash()
	assert.True(t, chain.GetDB().IsTxHashDuplicate(coinbaseHash),
		"real store flags the persisted genesis coinbase as a duplicate (BIP30 would reject a resurrection)")

	// An unseen txid is not a false duplicate.
	var fresh common.Uint256
	_, err = rand.Read(fresh[:])
	assert.NoError(t, err)
	assert.False(t, chain.GetDB().IsTxHashDuplicate(fresh),
		"real store does not false-positive on an unseen txid")
}
