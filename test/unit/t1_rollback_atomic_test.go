// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- TIER 1 fail-on-pristine proof for the forced-rollback atomicity
// cluster: ROLLBACK-ATOMICITY, PURGE-GUARD, RESUME-MARKER.
//
// Every test here drives the PRODUCTION call path -- (*BlockChain).ForceRollback,
// (*BlockChain).ForcedRollbackArmed, (*BlockChain).CheckForcedRollbackResidue and
// blockchain.PurgeForcedRollbackResidue -- against a real ffldb-backed store, and
// simulates a node RESTART the way main.go boots: close both stores, reopen them,
// and let blockchain.New rebuild b.Nodes from the persisted block-header index.
// That restart is what makes the defect visible at all, and it is why a harness
// that only calls ForceRollback once (as the shipped residue tests do) cannot see
// it by construction.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 2526a6b, this harness):
//
//	boot #0: in-RAM tip=6 armed=true   -> injected T2 error
//	boot #1: in-RAM tip=5 armed=true   -> injected T2 error
//	boot #2: in-RAM tip=4 armed=true   -> injected T2 error
//	boot #3: in-RAM tip=3 armed=true   -> injected T2 error
//	boot #4: in-RAM tip=2 armed=false  -> boots "recovered"
//	  discarded height 3: inStore=true mainChainIndexed=true(h=3) served=true
//	  discarded height 4: inStore=true mainChainIndexed=true(h=4) served=true
//	  discarded height 5: inStore=true mainChainIndexed=true(h=5) served=true
//	  discarded height 6: inStore=true mainChainIndexed=true(h=6) served=true
//	  PurgeForcedRollbackResidue purged=0 of 4
//
// With target=2 the block at target+1 is the analogue of mainnet 2,260,451.
package unit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"

	"github.com/stretchr/testify/assert"
)

// t1FailMode selects how the injected fault behaves.
type t1FailMode int

const (
	// t1FailNone passes every call through.
	t1FailNone t1FailMode = iota
	// t1FailBefore models an interruption BETWEEN the header-index removal and the
	// rollback transaction -- the exact window the finding names.
	t1FailBefore
	// t1FailAfter models a crash immediately AFTER the rollback transaction has
	// durably committed but before the later steps ran. It is what proves the
	// resume is exactly-once rather than merely re-runnable.
	t1FailAfter
)

// t1Store wraps a real IChainStore so the forced rollback's middle step can be made
// to fail, and records the heights RollbackBlock was actually invoked at (across
// every simulated restart) so double application is detectable.
type t1Store struct {
	blockchain.IChainStore
	mode  *t1FailMode
	calls *[]uint32
}

func (s *t1Store) RollbackBlock(b *types.Block, node *blockchain.BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	switch *s.mode {
	case t1FailBefore:
		return errors.New("injected: interrupted before the rollback transaction")
	case t1FailAfter:
		*s.calls = append(*s.calls, node.Height)
		if err := s.IChainStore.RollbackBlock(b, node, confirm, medianTimePast); err != nil {
			return err
		}
		return errors.New("injected: crashed after the rollback transaction committed")
	default:
		*s.calls = append(*s.calls, node.Height)
		return s.IChainStore.RollbackBlock(b, node, confirm, medianTimePast)
	}
}

// t1Close fully releases BOTH stores. ChainStore.Close() closes only the ffldb; the
// sibling leveldb keeps its file lock, so a restart simulation must also call
// CloseLeveldb or the reopen fails with "resource temporarily unavailable".
func t1Close(s blockchain.IChainStore) {
	s.Close()
	s.CloseLeveldb()
}

func t1Params(target uint32) *config.Configuration {
	params := config.GetDefaultParams()
	params.Sterilize()
	params.DPoSV2StartHeight = 0
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	params.ForcedRollbackHeight = target
	blockchain.FoundationAddress = *params.FoundationProgramHash
	return params
}

// t1Open boots a chain over dir exactly as main.go does: open the stores, then let
// blockchain.New rebuild the in-RAM index from the persisted block-header index --
// and STOP there.
//
// The stopping point is load-bearing, not convenience. main.go runs the forced
// rollback between blockchain.New and chain.Init (main.go: New at :168, rollback at
// :182-213, Init at :215), so the optional index manager has NOT been caught up when
// the rewind runs. A harness that called Init first would let the index manager
// re-connect a block whose rollback transaction had already committed in an earlier,
// interrupted run, and the resumed rewind would then fail an index-tip assertion
// that production never reaches. Callers that need the index manager (building the
// chain, or proving the node comes up afterwards) call chain.Init explicitly.
func t1Open(t *testing.T, dir string, params *config.Configuration,
	mode *t1FailMode, calls *[]uint32) (*blockchain.BlockChain, blockchain.IChainStore) {
	t.Helper()
	raw, err := blockchain.NewChainStore(dir, params)
	if err != nil {
		t.Fatalf("NewChainStore: %v", err)
	}
	var store blockchain.IChainStore = raw
	if mode != nil {
		store = &t1Store{IChainStore: raw, mode: mode, calls: calls}
	}
	ckpManager := checkpoint.NewManager(params)
	chain, err := blockchain.New(store, params,
		state.NewState(params, nil, nil, nil,
			func() bool { return false },
			nil, nil,
			nil, nil, nil, nil, nil),
		crstate.NewCommittee(params, ckpManager), ckpManager,
	)
	if err != nil {
		t1Close(store)
		t.Fatalf("blockchain.New: %v", err)
	}
	return chain, store
}

// t1BuildChain writes genesis+1..tip through the production store path and persists
// the block-header index rows the way block acceptance does (SaveBlock first, then
// the header-index flush). It returns the hashes and arms the trigger on params.
func t1BuildChain(t *testing.T, dir string, params *config.Configuration,
	tip uint32) map[uint32]common.Uint256 {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("clean data dir: %v", err)
	}
	chain, store := t1Open(t, dir, params, nil, nil)
	if err := chain.Init(nil); err != nil {
		t.Fatalf("chain.Init: %v", err)
	}

	hashByHeight := map[uint32]common.Uint256{0: params.GenesisBlock.Hash()}
	prevHash := hashByHeight[0]
	for h := uint32(1); h <= tip; h++ {
		blk := &types.Block{
			Header: common2.Header{
				Version: 0, Height: h, Previous: prevHash,
				Timestamp: 1600000000 + h, Bits: 0x1d03ffff,
			},
			Transactions: []interfaces.Transaction{residueCoinbase(h)},
		}
		hash := blk.Hash()
		node, lerr := chain.LoadBlockNode(&blk.Header, &hash)
		assert.NoError(t, lerr)
		buf := new(bytes.Buffer)
		assert.NoError(t, (&types.DposBlock{Block: blk}).Serialize(buf))
		assert.NoError(t, chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
			return dbTx.StoreBlock(hash, buf.Bytes())
		}))
		assert.NoError(t, chain.GetDB().SaveBlock(blk, node, nil,
			blockchain.CalcPastMedianTime(node)))
		chain.SetTip(node)
		chain.BestChain = node
		hashByHeight[h] = hash
		prevHash = hash
	}
	// Persist the block-header index rows (statusDataStored|statusValid == 3), which
	// is what initChainState rebuilds b.Nodes from on the next boot.
	assert.NoError(t, chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
		for h := uint32(1); h <= tip; h++ {
			hdr, herr := chain.GetDB().GetFFLDB().GetHeader(hashByHeight[h])
			if herr != nil {
				return herr
			}
			if serr := blockchain.DBStoreBlockNode(dbTx, hdr, 3); serr != nil {
				return serr
			}
		}
		return nil
	}))
	// The trigger is written in DISPLAY (explorer) byte order, as an operator would.
	params.ForcedRollbackTrigger = hashByHeight[params.ForcedRollbackHeight+1].ReversedString()
	t1Close(store)
	return hashByHeight
}

// t1EatHeaderRows reproduces the state the SHIPPED per-block ordering leaves after
// (tip-target) interrupted restarts: the block-header index rows above the target
// are gone, while the main-chain index, the raw block store and the best-chain
// state still describe the discarded chain.
func t1EatHeaderRows(t *testing.T, dir string, params *config.Configuration,
	hashByHeight map[uint32]common.Uint256, from, to uint32) {
	t.Helper()
	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()
	assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
		for h := from; h <= to; h++ {
			hdr, herr := fdb.GetHeader(hashByHeight[h])
			if herr != nil {
				return herr
			}
			if derr := blockchain.DBRemoveBlockNode(dbTx, hdr); derr != nil {
				return derr
			}
		}
		return nil
	}))
}

// TestT1RollbackAtomicityNoRestartRatchet is the primary ROLLBACK-ATOMICITY proof.
//
// It interrupts the rewind at the finding's exact window -- between the
// header-index removal and the rollback transaction -- and restarts the node
// repeatedly, which is the natural operator response because main.go exits on the
// error. The invariant asserted is that repeated interruption makes NO progress it
// has not durably earned: the loaded tip must not move, and the node must stay
// armed, so that a later clean run still has every discarded block to rewind.
//
// FAILS ON PRISTINE: the shipped ordering removes the header-index row FIRST, so
// each restart shrinks b.Nodes by one block without rolling it back; the tip
// assertion fails on the very first restart, and after four the node is no longer
// armed at all while blocks 3..6 remain main-chain indexed and served by hash.
func TestT1RollbackAtomicityNoRestartRatchet(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	dir := filepath.Join(test.DataPath, "t1atomic")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	mode := t1FailBefore
	var calls []uint32

	// Five interrupted boots -- one more than the (tip-target) it takes to ratchet
	// the shipped code all the way down to the target.
	for boot := 0; boot < 5; boot++ {
		chain, store := t1Open(t, dir, params, &mode, &calls)

		armed, aerr := chain.ForcedRollbackArmed()
		assert.NoError(t, aerr)
		assert.True(t, armed,
			"RATCHET [boot %d]: the node must STILL be armed after an interrupted "+
				"rewind. If it is not, the interrupted run destroyed the block-header "+
				"index rows the arming predicate reads, and the discarded blocks -- "+
				"including the target+1 block, mainnet 2,260,451 -- can never be "+
				"rolled back by this node again", boot)

		assert.Equal(t, tip, uint32(len(chain.Nodes)-1),
			"RATCHET [boot %d]: the loaded chain tip must not move when the rewind "+
				"was interrupted before any block's rollback transaction committed; "+
				"a moved tip means header rows were destroyed without the "+
				"corresponding rollback", boot)

		rerr := chain.ForceRollback(nil)
		assert.Error(t, rerr, "[boot %d] the injected failure must surface", boot)
		t1Close(store)
	}

	// The rewind must still be pending in full: nothing was rolled back.
	assert.Empty(t, calls,
		"no rollback transaction should have been attempted-and-committed while the "+
			"injected fault was active")

	// Now let it run cleanly. The whole rewind must still be available.
	mode = t1FailNone
	chain, store := t1Open(t, dir, params, &mode, &calls)
	armed, aerr := chain.ForcedRollbackArmed()
	assert.NoError(t, aerr)
	assert.True(t, armed, "the node must still be armed for the clean run")
	assert.NoError(t, chain.ForceRollback(nil), "the clean rewind must succeed")
	assert.Equal(t, target, uint32(len(chain.Nodes)-1))
	assert.Equal(t, []uint32{6, 5, 4, 3}, calls,
		"every discarded block must have been rolled back exactly once, tip-first")
	// main.go's next step: the node must actually come up on the rewound chain.
	assert.NoError(t, chain.Init(nil), "the node must initialise after the rewind")

	// The persisted store must agree -- this is the assertion main.go's
	// chain.GetHeight() check could not make.
	fdb := chain.GetDB().GetFFLDB()
	scan, serr := blockchain.ScanForcedRollbackStore(fdb, target)
	assert.NoError(t, serr)
	assert.True(t, scan.Clean(),
		"persisted store must hold nothing above the target after the rewind: %s",
		scan.Summary())
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		assert.False(t, fdb.IsBlockInStore(&hash),
			"discarded height %d must not be served by hash", h)
		exists, _, _ := fdb.BlockExists(&hash)
		assert.False(t, exists,
			"discarded height %d must not be main-chain indexed", h)
	}
	for h := uint32(0); h <= target; h++ {
		hash := hashByHeight[h]
		assert.True(t, fdb.IsBlockInStore(&hash),
			"OVER-DELETION: retained height %d must still be in the store", h)
	}
	// The in-progress marker must be gone once the store verified clean.
	marker, merr := chain.ReadForcedRollbackMarker()
	assert.NoError(t, merr)
	assert.Nil(t, marker, "the in-progress marker must be cleared after a clean rewind")
	t1Close(store)
}

// TestT1RollbackResumeIsExactlyOnce is the RESUME-MARKER proof.
//
// The fault here commits the rollback transaction and THEN fails, so the next boot
// finds a block that is half-done. A resume that merely re-ran every step would
// re-apply that block's per-transaction rollback processors, which are not
// idempotent. The phase probe reads the persisted main-chain index -- deleted in
// the SAME atomic transaction as those processors -- so it can tell.
//
// FAILS ON PRISTINE: the shipped code has no phase probe and no resume; the block
// whose rollback committed had its header row removed first, so it is not in
// b.Nodes on the next boot at all and the tip has ratcheted by one.
func TestT1RollbackResumeIsExactlyOnce(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(5)

	dir := filepath.Join(test.DataPath, "t1resume")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	mode := t1FailAfter
	var calls []uint32

	chain, store := t1Open(t, dir, params, &mode, &calls)
	assert.Error(t, chain.ForceRollback(nil), "the injected post-commit fault must surface")
	t1Close(store)
	assert.Equal(t, []uint32{5}, calls, "exactly the tip block's rollback committed")

	// The marker must record the interrupted rewind.
	mode = t1FailNone
	chain, store = t1Open(t, dir, params, &mode, &calls)
	marker, merr := chain.ReadForcedRollbackMarker()
	assert.NoError(t, merr)
	if assert.NotNil(t, marker, "an interrupted rewind must leave a durable marker") {
		assert.Equal(t, target, marker.Target)
		assert.Equal(t, tip, marker.Start)
	}
	assert.Equal(t, tip, uint32(len(chain.Nodes)-1),
		"the half-done block must still be in the loaded chain, so the rewind can "+
			"finish it")

	assert.NoError(t, chain.ForceRollback(nil), "the resumed rewind must succeed")
	assert.Equal(t, target, uint32(len(chain.Nodes)-1))

	// EXACTLY-ONCE: height 5 must not appear a second time.
	assert.Equal(t, []uint32{5, 4, 3}, calls,
		"DOUBLE APPLICATION: the resumed rewind must SKIP the block whose rollback "+
			"transaction already committed and must not re-run its rollback processors")
	assert.NoError(t, chain.Init(nil), "the node must initialise after the resume")

	scan, serr := blockchain.ScanForcedRollbackStore(chain.GetDB().GetFFLDB(), target)
	assert.NoError(t, serr)
	assert.True(t, scan.Clean(), "store must be clean after the resume: %s", scan.Summary())
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		assert.False(t, chain.GetDB().GetFFLDB().IsBlockInStore(&hash),
			"discarded height %d must not survive the resumed rewind", h)
	}
	t1Close(store)
}

// TestT1PurgeGuardRemovesInterruptedRollbackResidue is the PURGE-GUARD proof.
//
// The store is put in the exact shape an interrupted rollback leaves: the
// header-index rows above the target are gone, but the main-chain hash->height
// entries survived because RollbackBlock -- the thing that deletes them -- never
// ran. That is the residue the cleaner exists to remove.
//
// FAILS ON PRISTINE: guard (1) tested main-chain membership FIRST and kept every
// entry that resolved, so the sound height guard below it was never reached and
// the cleaner purged 0 of 4 (measured).
func TestT1PurgeGuardRemovesInterruptedRollbackResidue(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	dir := filepath.Join(test.DataPath, "t1purgeguard")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)
	t1EatHeaderRows(t, dir, params, hashByHeight, target+1, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()

	// Precondition: this is genuinely the interrupted-rollback shape -- still
	// main-chain indexed, still served by hash.
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		exists, hh, _ := fdb.BlockExists(&hash)
		assert.True(t, exists, "precondition: height %d still main-chain indexed", h)
		assert.Equal(t, h, hh)
		assert.True(t, fdb.IsBlockInStore(&hash),
			"precondition: height %d still served by hash", h)
	}

	purged, perr := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.NoError(t, perr)
	assert.Equal(t, int(tip-target), purged,
		"PURGE-GUARD: the cleaner must remove every above-target block left by an "+
			"interrupted rollback. Keeping them because their main-chain index entry "+
			"survived is exactly backwards: that entry survived BECAUSE the rollback "+
			"never ran")

	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		assert.False(t, fdb.IsBlockInStore(&hash),
			"height %d must not be served by hash after the purge", h)
		exists, _, _ := fdb.BlockExists(&hash)
		assert.False(t, exists,
			"height %d must not remain main-chain indexed after the purge", h)
	}
	// OVER-DELETION GUARD: retained history untouched.
	for h := uint32(0); h <= target; h++ {
		hash := hashByHeight[h]
		blk, gerr := fdb.GetBlock(hash)
		assert.NoError(t, gerr, "retained height %d must still be served", h)
		assert.NotNil(t, blk)
		exists, hh, _ := fdb.BlockExists(&hash)
		assert.True(t, exists, "retained height %d must stay main-chain indexed", h)
		assert.Equal(t, h, hh)
	}
	// Idempotent.
	purged2, perr2 := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.NoError(t, perr2)
	assert.Equal(t, 0, purged2, "a second purge must be a no-op")
}

// TestT1PurgeGuardRefusesLiveChain proves the reordering did not create an
// over-deletion hazard. The old guard (1) incidentally protected a node that had
// simply synced forward past the target (the offline `ela-cli purgeresidue` command
// takes its target from config, so an operator can run it on the wrong node). That
// protection is now explicit and stronger: it REPORTS the mistake instead of
// silently doing nothing.
func TestT1PurgeGuardRefusesLiveChain(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	dir := filepath.Join(test.DataPath, "t1purgelive")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()

	purged, perr := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.Error(t, perr,
		"the cleaner must REFUSE to run against a node whose retained chain extends "+
			"above the target; purging there would dismantle a live chain")
	assert.Equal(t, 0, purged)

	for h := uint32(0); h <= tip; h++ {
		hash := hashByHeight[h]
		assert.True(t, fdb.IsBlockInStore(&hash),
			"OVER-DELETION: height %d of a live chain must be untouched", h)
	}
}

// TestT1RatchetedStoreRefusesToBoot is the safety-net proof.
//
// It reproduces a store already ratcheted by the shipped binary and asserts the
// node refuses to start rather than coming up "recovered" on silently corrupt
// state. It also pins WHY neither shipped safety net could see it.
func TestT1RatchetedStoreRefusesToBoot(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	dir := filepath.Join(test.DataPath, "t1ratcheted")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)
	t1EatHeaderRows(t, dir, params, hashByHeight, target+1, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	// (i) The arming predicate is blind: the rows it reads were destroyed.
	armed, aerr := chain.ForcedRollbackArmed()
	assert.NoError(t, aerr)
	assert.False(t, armed,
		"precondition: a ratcheted node is no longer armed -- that is what makes it "+
			"boot silently")

	// (ii) main.go's shipped height assertion would have PASSED here: GetHeight() is
	// len(b.Nodes)-1, which the ratchet drove to exactly the target. It is also inside
	// `if forcedRollbackFired`, which is false on this boot -- so it never even ran.
	assert.Equal(t, target, chain.GetHeight(),
		"the shipped post-condition `chain.GetHeight() != target` is satisfied by a "+
			"fully ratcheted store, which is why it detected nothing")

	// (iii) The store, however, still describes the discarded chain.
	fdb := chain.GetDB().GetFFLDB()
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		exists, _, _ := fdb.BlockExists(&hash)
		assert.True(t, exists,
			"height %d is still main-chain indexed on the ratcheted store", h)
	}

	// (iv) The new safety net must refuse the boot.
	err := chain.CheckForcedRollbackResidue()
	assert.Error(t, err,
		"RATCHET SAFETY NET: a node whose database still records blocks above the "+
			"forced-rollback target as main chain, while its loaded tip is at the "+
			"target, must refuse to start -- the UTXO/derived-state rollback for those "+
			"blocks demonstrably never ran and no purge can repair it")
	assert.True(t, errors.Is(err, blockchain.ErrForcedRollbackStoreInconsistent),
		"the refusal must be the store-inconsistency class, got: %v", err)
}

// TestT1CheckForcedRollbackResidueAllowsHealthyNodes guards the safety net against
// false positives, which matter more than usual here: this runs on every node in a
// coordinated mainnet restart.
func TestT1CheckForcedRollbackResidueAllowsHealthyNodes(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	// (a) A node that rolled back correctly must boot.
	dirOK := filepath.Join(test.DataPath, "t1healthy")
	params := t1Params(target)
	t1BuildChain(t, dirOK, params, tip)
	{
		chain, store := t1Open(t, dirOK, params, nil, nil)
		assert.NoError(t, chain.ForceRollback(nil))
		assert.NoError(t, chain.CheckForcedRollbackResidue(),
			"a correctly rolled-back node must boot")
		t1Close(store)
	}
	{
		chain, store := t1Open(t, dirOK, params, nil, nil)
		assert.NoError(t, chain.CheckForcedRollbackResidue(),
			"and must keep booting on every later start")
		t1Close(store)
	}

	// (b) A node still syncing BELOW the target must boot untouched.
	dirLow := filepath.Join(test.DataPath, "t1lowtip")
	paramsLow := t1Params(target)
	hashesLow := t1BuildChain(t, dirLow, paramsLow, 1)
	// t1BuildChain arms the trigger from target+1, which does not exist here; point
	// it at a plausible hash so the configuration still looks armed.
	paramsLow.ForcedRollbackTrigger = hashesLow[1].ReversedString()
	{
		chain, store := t1Open(t, dirLow, paramsLow, nil, nil)
		assert.NoError(t, chain.CheckForcedRollbackResidue(),
			"a node syncing below the target must not be blocked")
		assert.True(t, chain.GetHeight() < target)
		t1Close(store)
	}

	// (c) A node holding a DIFFERENT chain above the target (never had the exploit
	// block, so never armed) must not be touched at all.
	dirFwd := filepath.Join(test.DataPath, "t1forward")
	paramsFwd := t1Params(target)
	hashesFwd := t1BuildChain(t, dirFwd, paramsFwd, tip)
	paramsFwd.ForcedRollbackTrigger = hashesFwd[0].ReversedString() // never matches
	{
		chain, store := t1Open(t, dirFwd, paramsFwd, nil, nil)
		armed, aerr := chain.ForcedRollbackArmed()
		assert.NoError(t, aerr)
		assert.False(t, armed)
		assert.NoError(t, chain.CheckForcedRollbackResidue(),
			"a node above the target on a chain the trigger does not match must boot")
		fdb := chain.GetDB().GetFFLDB()
		for h := uint32(0); h <= tip; h++ {
			hash := hashesFwd[h]
			assert.True(t, fdb.IsBlockInStore(&hash),
				"OVER-DELETION: height %d must be untouched", h)
		}
		t1Close(store)
	}
}

// TestT1ForcedRollbackInterruptStopsAtBlockBoundary proves the interrupt handling.
// The shipped rewind had none: it emitted about two progress lines for a 145-block
// rewind over a 25GB store and could not be stopped except by killing the process.
func TestT1ForcedRollbackInterruptStopsAtBlockBoundary(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)

	dir := filepath.Join(test.DataPath, "t1interrupt")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	interrupt := make(chan struct{})
	close(interrupt)

	chain, store := t1Open(t, dir, params, nil, nil)
	err := chain.ForceRollback(interrupt)
	assert.Error(t, err, "an interrupted rewind must report the interruption")
	assert.True(t, errors.Is(err, blockchain.ErrForcedRollbackInterrupted),
		"and must be distinguishable from corruption, got: %v", err)
	assert.Equal(t, tip, uint32(len(chain.Nodes)-1),
		"an interrupt before the first block must leave the chain untouched")
	t1Close(store)

	// Restart and finish: the interrupt must not have cost anything.
	chain, store = t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	armed, aerr := chain.ForcedRollbackArmed()
	assert.NoError(t, aerr)
	assert.True(t, armed, "the node must still be armed after an interrupt")
	assert.NoError(t, chain.ForceRollback(nil))
	assert.Equal(t, target, uint32(len(chain.Nodes)-1))
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		assert.False(t, chain.GetDB().GetFFLDB().IsBlockInStore(&hash),
			"discarded height %d must be gone after the resumed rewind", h)
	}
}

// TestT1SweepHandlesDetachedSideBlockResidue is a LIVENESS regression guard, not a
// defect proof.
//
// The purge refuses to run when the retained chain extends above the target, so
// that the offline `ela-cli purgeresidue` command cannot dismantle a node that
// simply synced forward. That refusal must NOT be triggered by a detached side
// block: the live reorg path (blockchain.go reorganizeChain at :1964 and :1989 ->
// disconnectBlock) calls RollbackBlock but never DBRemoveBlockNode, so a block that
// was connected and then reorganised away keeps BOTH its block-header-index row and
// its raw-store entry while losing its main-chain index entry. Above the rollback
// target that is residue and must be swept -- if it were misread as a live chain,
// ForceRollback's in-line sweep would fail and main.go would exit, bricking every
// node that had ever seen a reorg above the target.
func TestT1SweepHandlesDetachedSideBlockResidue(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(5)

	dir := filepath.Join(test.DataPath, "t1detached")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	// Detach height 5 exactly as disconnectBlock does -- the REAL production call,
	// RollbackBlock with no DBRemoveBlockNode after it -- so the main-chain index,
	// the best state and the optional indexes all move together and only the
	// header-index row and the stored body are left behind.
	{
		chain, store := t1Open(t, dir, params, nil, nil)
		assert.NoError(t, chain.Init(nil))
		fdb := chain.GetDB().GetFFLDB()
		blk, gerr := fdb.GetBlock(hashByHeight[tip])
		assert.NoError(t, gerr)
		node := chain.Nodes[tip]
		assert.NoError(t, chain.GetDB().RollbackBlock(blk.Block, node, blk.Confirm,
			blockchain.CalcPastMedianTime(chain.Nodes[tip-1])))
		t1Close(store)
	}

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()

	// Precondition: the detached block keeps its header row and its stored body.
	scan, serr := blockchain.ScanForcedRollbackStore(fdb, target)
	assert.NoError(t, serr)
	assert.Equal(t, 3, len(scan.HeaderRowsAbove), "heights 3,4,5 all have header rows")
	assert.Equal(t, 2, len(scan.LiveAbove),
		"only heights 3 and 4 are a LIVE chain above the target; the detached height "+
			"5 must not be counted, or the sweep would refuse and brick the node")

	// The rewind must still complete and sweep the detached block with everything else.
	assert.NoError(t, chain.ForceRollback(nil),
		"a detached side block above the target must not make the in-line sweep refuse")
	assert.Equal(t, target, uint32(len(chain.Nodes)-1))
	for h := target + 1; h <= tip; h++ {
		hash := hashByHeight[h]
		assert.False(t, fdb.IsBlockInStore(&hash),
			"height %d (including the detached one) must be swept", h)
	}
	after, aerr := blockchain.ScanForcedRollbackStore(fdb, target)
	assert.NoError(t, aerr)
	assert.True(t, after.Clean(), "store must be clean after the rewind: %s", after.Summary())
}
