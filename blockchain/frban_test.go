// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// FR-BAN — fail-on-pristine for the permanent refusal of the forced-rollback trigger block.
//
// THE HALT THIS PREVENTS. After the rewind an un-patched peer still holds the original
// block 2,260,451. Offering it to a rewound node does NOT simply get it rejected:
//
//	connectBestChain side-chain arm  -> caches it unvalidated, returns (false,false,nil)
//	mempool/blockpool.go             -> reads that as "not main, not orphan", calls
//	                                    CheckConfirmedBlockOnFork
//	mempool/blockevidence.go         -> builds DPOSIllegalBlocks from BOTH confirms
//	dpos/state/state.go              -> punishes the INTERSECTION of the two signer sets
//
// Two confirms of one height come from the same arbiter set, so the intersection is the
// ENTIRE active set. Below the 25-of-36 confirm threshold the chain stops. The machinery is
// working as designed; it simply cannot distinguish a planned rollback from mass
// equivocation. Pre-existing in v0.9.9.6.
//
// WHY A HASH BAN RATHER THAN A PEER ALLOWLIST. There is no allowlist to use.
// p2p/server/config.go declares Whitelists, assigns it nil in one place and never populates
// it; no config field maps to it. DisableListen is hardcoded false. The connection manager
// maintains 8 random outbound dials regardless of PermanentPeers. The only other control is
// a host firewall, which operators who can only update a binary and start a node cannot
// apply.
//
// FAIL-ON-PRISTINE: without the ban the block is parked as an orphan and processBlock
// returns (false, true, nil) — it is RETAINED, which is precisely the condition that feeds
// the evidence path. With the ban it is refused and never stored. The test asserts both the
// return and the absence from the orphan pool, so a fix that rejected the block but still
// cached it would still fail.
//
// UNGATED and needs no gate: it only ever REJECTS, it names a single hash ABOVE the
// 2,260,450 rollback target, and it introduces no new constant — the trigger is the already
// pinned ForcedRollbackTrigger.
package blockchain

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/require"
)

// frBanChain builds the same minimal BlockChain the orphan-pool tests use, so this drives
// the real processBlock rather than a reimplementation of it.
func frBanChain(t *testing.T) *BlockChain {
	t.Helper()
	log.NewDefault(t.TempDir(), 0, 0, 0)
	params := config.GetDefaultParams()

	ffldb, err := NewChainStoreFFLDB(t.TempDir(), params)
	require.NoError(t, err)
	t.Cleanup(func() { ffldb.Close() })

	store := &nx02Store{ffldb: ffldb}
	return &BlockChain{
		chainParams:    params,
		db:             store,
		index:          newBlockIndex(store, params),
		Nodes:          make([]*BlockNode, 0),
		DepNodes:       make(map[common.Uint256][]*BlockNode),
		orphans:        make(map[common.Uint256]*OrphanBlock),
		prevOrphans:    make(map[common.Uint256][]*OrphanBlock),
		orphanConfirms: make(map[common.Uint256]*payload.Confirm),
		TimeSource:     NewMedianTime(),
	}
}

// displayOrder renders a hash the way an operator reads it off a block explorer, which is
// the byte order the ForcedRollbackTrigger config value is written in.
func displayOrder(h common.Uint256) string {
	return common.BytesToHexString(common.BytesReverse(h[:]))
}

func TestFRBanTriggerBlockIsRefusedAndNotRetained(t *testing.T) {
	b := frBanChain(t)

	blk := nx02FreeOrphanBlock(t, b.chainParams, 1024)
	hash := blk.Hash()

	// Pin this block as the trigger, exactly as mainnet pins the real 2,260,451.
	b.chainParams.ForcedRollbackTrigger = displayOrder(hash)

	inMain, isOrphan, err := b.processBlock(blk, nil)

	require.Error(t, err,
		"FR-BAN: the forced-rollback trigger block must be REFUSED. Pristine parks it as "+
			"an orphan and returns nil, and retaining it is what feeds "+
			"CheckConfirmedBlockOnFork and slashes the whole arbiter set.")
	require.False(t, inMain, "a refused block must not be reported as connected")
	require.False(t, isOrphan,
		"FR-BAN: the trigger must not be reported as an orphan either; pristine returns "+
			"isOrphan=true, which is the retention this fix exists to prevent")

	_, retained := b.orphans[hash]
	require.False(t, retained,
		"FR-BAN: the trigger block must not be RETAINED anywhere. A fix that returned an "+
			"error but still cached the block would leave the evidence path reachable.")
}

// TestFRBanLeavesEveryOtherBlockAlone is the negative control. Without it, a change that
// refused ALL blocks would pass the test above while bricking the node.
func TestFRBanLeavesEveryOtherBlockAlone(t *testing.T) {
	b := frBanChain(t)

	banned := nx02FreeOrphanBlock(t, b.chainParams, 1024)
	b.chainParams.ForcedRollbackTrigger = displayOrder(banned.Hash())

	// A different block, at the same height, must still take the ordinary path.
	other := nx02FreeOrphanBlock(t, b.chainParams, 2048)
	require.NotEqual(t, banned.Hash(), other.Hash(), "harness: the two blocks must differ")

	_, isOrphan, err := b.processBlock(other, nil)
	require.NoError(t, err, "FR-BAN must not affect any block other than the trigger")
	require.True(t, isOrphan,
		"an unconnectable non-trigger block must still be parked as an orphan, i.e. the "+
			"ban is not a blanket refusal")
}

// TestFRBanIsInertWithNoTriggerConfigured pins the disarmed case: on a network with no
// forced rollback configured, the ban must do nothing at all.
func TestFRBanIsInertWithNoTriggerConfigured(t *testing.T) {
	b := frBanChain(t)
	b.chainParams.ForcedRollbackTrigger = ""

	blk := nx02FreeOrphanBlock(t, b.chainParams, 1536)
	_, isOrphan, err := b.processBlock(blk, nil)
	require.NoError(t, err, "with no trigger configured the ban must be inert")
	require.True(t, isOrphan, "the block must take the ordinary orphan path")
}
