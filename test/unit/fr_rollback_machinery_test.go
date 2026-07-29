// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package unit -- fail-on-pristine proofs for the four forced-rollback machinery
// defects found by verifying an external review against this tree.
//
// Every test drives a PRODUCTION entry point against a real ffldb-backed store and
// simulates restarts the way main.go boots (close both stores, reopen, let
// blockchain.New rebuild b.Nodes from the persisted block-header index). It reuses
// the harness in t1_rollback_atomic_test.go.
//
// MEASURED PRISTINE BEHAVIOUR (this tree at b3f79009, this harness):
//
//	FR-MARKER  ReadForcedRollbackMarker over a zero-length marker value:
//	           panic: runtime error: index out of range [0] with length 0
//	FR-02      resumed rewind, target=2, tip=3, crash after block 3's rollback
//	           transaction commits:
//	             chain.GetHeight()=2  ChainStore.GetHeight()=3
//	             SaveBlock(replacement block 3) -> "block height less than current
//	             block height"
//	FR-PURGE   PurgeForcedRollbackResidue at target=2 over an interrupted-rollback
//	           store (4 blocks main-chain indexed above the target):
//	             returns (4, nil); main-chain-above 4 -> 0
package unit

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"

	"github.com/stretchr/testify/assert"
)

// frMarkerCandidates renders the two possible on-disk encodings of the durable
// in-progress marker (version byte + target + start), so the test can LOCATE the
// production key by its value instead of hard-coding a key name that only the
// blockchain package knows. Nine bytes, one version byte, two uint32s -- whichever
// byte order the package uses, one of these two is what it wrote.
func frMarkerCandidates(target, start uint32) [][]byte {
	out := make([][]byte, 0, 2)
	for _, be := range []bool{false, true} {
		raw := make([]byte, 9)
		raw[0] = 1
		put := func(off int, v uint32) {
			if be {
				raw[off], raw[off+1] = byte(v>>24), byte(v>>16)
				raw[off+2], raw[off+3] = byte(v>>8), byte(v)
				return
			}
			raw[off], raw[off+1] = byte(v), byte(v>>8)
			raw[off+2], raw[off+3] = byte(v>>16), byte(v>>24)
		}
		put(1, target)
		put(5, start)
		out = append(out, raw)
	}
	return out
}

// TestFRMarkerUnreadableIsReportedNotPanicked is the fix for the one defect the
// review had already confirmed.
//
// ReadForcedRollbackMarker's guard short-circuits correctly, but the error it then
// FORMATS indexes raw[0] unconditionally. ffldb hands back a non-nil ZERO-LENGTH
// slice for a key stored with an empty value (measured here, both through the write
// cache and after a flush), so the marker read panics with index-out-of-range while
// producing its own diagnosis.
//
// That read runs from CheckAbandonedForcedRollback, which main.go calls BEFORE
// anything else on EVERY boot of EVERY node. So the failure mode is: a node whose
// marker is unreadable dies with a runtime panic instead of the refusal that would
// have told the operator what is wrong.
//
// FAILS ON PRISTINE: panic: runtime error: index out of range [0] with length 0.
func TestFRMarkerUnreadableIsReportedNotPanicked(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(4)
	dir := filepath.Join(test.DataPath, "frmarker")
	params := t1Params(target)
	t1BuildChain(t, dir, params, tip)

	// Let the PRODUCTION writer create the marker: ForceRollback writes and flushes
	// it before the first destructive step, and the injected fault stops it there.
	mode := t1FailBefore
	var calls []uint32
	chain, store := t1Open(t, dir, params, &mode, &calls)
	assert.Error(t, chain.ForceRollback(nil))
	marker, merr := chain.ReadForcedRollbackMarker()
	assert.NoError(t, merr)
	if !assert.NotNil(t, marker, "the production path must have written a marker") {
		t1Close(store)
		return
	}
	assert.Equal(t, target, marker.Target)
	assert.Equal(t, tip, marker.Start)

	// Find that key by its VALUE and empty it -- the shape a truncated write, a
	// hand-edited store or a future marker layout leaves behind.
	fdb := chain.GetDB().GetFFLDB()
	want := frMarkerCandidates(marker.Target, marker.Start)
	var found [][]byte
	assert.NoError(t, fdb.View(func(dbTx database.Tx) error {
		return dbTx.Metadata().ForEach(func(k, v []byte) error {
			for _, w := range want {
				if bytes.Equal(v, w) {
					found = append(found, append([]byte(nil), k...))
				}
			}
			return nil
		})
	}))
	if !assert.Len(t, found, 1, "expected exactly one metadata key holding the marker") {
		t1Close(store)
		return
	}
	assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Put(found[0], []byte{})
	}))
	assert.NoError(t, fdb.FlushCache())

	// The read must REPORT the unreadable marker. On pristine it panics here.
	var (
		got       *blockchain.ForcedRollbackMarker
		readErr   error
		panicked  interface{}
		readAgain = func() {
			defer func() { panicked = recover() }()
			got, readErr = chain.ReadForcedRollbackMarker()
		}
	)
	readAgain()
	assert.Nil(t, panicked,
		"MARKER-PANIC: reading a zero-length in-progress marker must not panic -- the "+
			"error message indexed raw[0] while reporting that the marker is "+
			"unreadable, so the node died formatting its own diagnosis on the one "+
			"boot where that diagnosis is what the operator needs: got panic %v", panicked)
	assert.Error(t, readErr,
		"an unreadable marker must be reported as an error, not silently accepted")
	assert.Nil(t, got, "no marker may be returned when the stored bytes are unreadable")
	if readErr != nil {
		assert.Contains(t, readErr.Error(), "0 bytes",
			"the diagnosis must name the length it actually found")
	}

	// And the boot-path check that reads it must refuse rather than crash.
	panicked = nil
	func() {
		defer func() { panicked = recover() }()
		readErr = chain.CheckAbandonedForcedRollback()
	}()
	assert.Nil(t, panicked, "CheckAbandonedForcedRollback must not panic on a bad marker")
	assert.Error(t, readErr, "an unreadable marker must stop the boot, loudly")

	// The VERSION byte must be checked too. A nine-byte marker whose first byte is
	// not this layout's version is another format's record sitting under this key,
	// and parsing its remaining eight bytes as target+start hands the boot path two
	// heights invented out of someone else's encoding.
	wrongVersion := append([]byte(nil), want[0]...)
	wrongVersion[0] = 0x7f
	assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Put(found[0], wrongVersion)
	}))
	assert.NoError(t, fdb.FlushCache())
	got, readErr = chain.ReadForcedRollbackMarker()
	assert.Error(t, readErr,
		"MARKER-VERSION: a marker of the right LENGTH but the wrong VERSION must be "+
			"reported as unreadable, not parsed as if it were this layout")
	assert.Nil(t, got, "no marker may be returned when the version byte is unknown")

	// The length test must be an EXACT-LENGTH test, not a lower bound. A marker
	// longer than the current layout is what a future (or foreign) version writes,
	// and parsing its first nine bytes as if they were this layout would hand the
	// boot path a target and a start height invented out of someone else's format.
	long := append(append([]byte(nil), want[0]...), 0xff, 0xff)
	assert.NoError(t, fdb.Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Put(found[0], long)
	}))
	assert.NoError(t, fdb.FlushCache())
	got, readErr = chain.ReadForcedRollbackMarker()
	assert.Error(t, readErr,
		"MARKER-LENGTH: an OVER-length marker must be reported as unreadable; "+
			"accepting it parses a foreign layout's bytes as this one's target and "+
			"start height")
	assert.Nil(t, got, "no marker may be returned when the stored bytes are unreadable")
	t1Close(store)
}

// TestFRResumedRewindLeavesStoreHeightAtTheRewoundTip is the FR-02 proof.
//
// ChainStore's height is lowered ONLY by the per-block rollback transaction
// (ChainStore.rollback: currentBlockHeight = b.Height-1). A RESUMED rewind skips
// that transaction for a block an earlier interrupted run already committed -- which
// is correct, it is what makes the rewind exactly-once -- so when the skipped block
// is the LAST one (target+1, mainnet 2,260,451) nothing lowers the height at all and
// it keeps the value initChainState derived from the surviving header row.
//
// The consequence is not cosmetic. ChainStore.handlePersistBlockTask rejects any
// block at or below currentBlockHeight, so the node refuses the RECOVERED chain's
// replacement block at target+1: it rolls back correctly, reports success, and can
// never accept the first block of the chain it was rolled back for.
//
// FAILS ON PRISTINE: store height 3 against a rewound tip of 2, and SaveBlock of the
// replacement block at height 3 returns "block height less than current block
// height".
func TestFRResumedRewindLeavesStoreHeightAtTheRewoundTip(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(3)
	dir := filepath.Join(test.DataPath, "frheight")
	params := t1Params(target)
	t1BuildChain(t, dir, params, tip)

	// boot #0 -- crash immediately AFTER block target+1's rollback transaction has
	// durably committed, before the raw purge and the header-row removal.
	mode := t1FailAfter
	var calls []uint32
	chain, store := t1Open(t, dir, params, &mode, &calls)
	assert.Error(t, chain.ForceRollback(nil))
	t1Close(store)

	// boot #1 -- resume cleanly. The rewind must finish AND leave a coherent store.
	mode = t1FailNone
	chain, store = t1Open(t, dir, params, &mode, &calls)
	defer t1Close(store)
	armed, aerr := chain.ForcedRollbackArmed()
	assert.NoError(t, aerr)
	assert.True(t, armed, "the interrupted rewind must still be armed on the next boot")
	assert.NoError(t, chain.ForceRollback(nil))

	assert.Equal(t, []uint32{target + 1}, calls,
		"exactly-once: the resumed run must not re-run the rollback transaction of a "+
			"block whose rollback already committed")
	assert.Equal(t, target, chain.GetHeight())
	assert.Equal(t, target, chain.GetDB().GetHeight(),
		"HEIGHT-DRIFT: after a RESUMED rewind the ChainStore height must describe the "+
			"rewound tip. It is lowered only by the per-block rollback transaction, "+
			"which the resume correctly skips for the block an earlier run already "+
			"committed -- so on pristine it stays at target+1 and the node then "+
			"rejects the recovered chain's own block at that height")

	// The load-bearing consequence: the replacement block at target+1 must be
	// acceptable. This is the first block of the recovered chain.
	prev := chain.Nodes[target]
	blk := &types.Block{
		Header: common2.Header{
			Version: 0, Height: target + 1, Previous: *prev.Hash,
			Timestamp: 1700000000, Bits: 0x1d03ffff,
		},
		Transactions: []interfaces.Transaction{residueCoinbase(target + 1)},
	}
	hash := blk.Hash()
	node, lerr := chain.LoadBlockNode(&blk.Header, &hash)
	assert.NoError(t, lerr)
	buf := new(bytes.Buffer)
	assert.NoError(t, (&types.DposBlock{Block: blk}).Serialize(buf))
	assert.NoError(t, chain.GetDB().GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbTx.StoreBlock(hash, buf.Bytes())
	}))
	assert.NoError(t,
		chain.GetDB().SaveBlock(blk, node, nil, blockchain.CalcPastMedianTime(node)),
		"STALLED NODE: a node that has just rolled back to %d must be able to accept "+
			"the recovered chain's replacement block at %d; on pristine the stale "+
			"ChainStore height rejects it as \"block height less than current block "+
			"height\" and the node sits at the target forever", target, target+1)
}

// TestFROfflinePurgeRefusesInterruptedRollbackEvidence is the proof for the offline
// cleaner claim.
//
// Main-chain index entries above the target are not residue: they are the signature
// of a rollback interrupted before its transaction committed, i.e. of blocks whose
// UTXO and derived-state processors were never reverted. The offline
// `ela-cli purgeresidue` command hands its store straight to
// PurgeForcedRollbackResidue with no diagnosis in between, and the shipped function
// DELETED those entries -- reporting a successful purge and leaving the operator
// with a store whose un-reverted state is exactly what remains.
//
// FAILS ON PRISTINE: the purge returns (4, nil) and main-chain-above goes 4 -> 0.
func TestFROfflinePurgeRefusesInterruptedRollbackEvidence(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(6)
	dir := filepath.Join(test.DataPath, "frpurge")
	params := t1Params(target)
	hashByHeight := t1BuildChain(t, dir, params, tip)

	// The store the SHIPPED per-block ordering leaves behind: header rows above the
	// target eaten, main-chain index and raw block store still describing the
	// discarded chain.
	t1EatHeaderRows(t, dir, params, hashByHeight, target+1, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)
	fdb := chain.GetDB().GetFFLDB()

	before, serr := blockchain.ScanForcedRollbackStore(fdb, target)
	assert.NoError(t, serr)
	assert.Len(t, before.MainChainAbove, int(tip-target),
		"harness precondition: the store must be in the interrupted-rollback shape")

	n, perr := blockchain.PurgeForcedRollbackResidue(fdb, target)
	assert.Equal(t, 0, n, "nothing may be purged from a store this function must refuse")
	assert.Error(t, perr,
		"PURGE-ERASES-EVIDENCE: the offline cleaner must REFUSE a store whose main "+
			"chain still runs above the rollback target. Those entries are the "+
			"diagnosis of an interrupted rollback, not residue, and deleting them "+
			"leaves the un-reverted UTXO/derived state in place behind a store that "+
			"now looks clean")
	assert.True(t, errors.Is(perr, blockchain.ErrForcedRollbackStoreInconsistent),
		"the refusal must carry the store-inconsistent sentinel so callers can "+
			"classify it, got: %v", perr)

	after, serr := blockchain.ScanForcedRollbackStore(fdb, target)
	assert.NoError(t, serr)
	assert.Equal(t, before.MainChainAbove, after.MainChainAbove,
		"EVIDENCE DESTROYED: every main-chain index entry above the target must "+
			"survive the refused purge -- it is what the next boot's refusal names")
	assert.Equal(t, before.StoredAbove, after.StoredAbove,
		"a refused purge must be a no-op on the raw block store too")
	assert.Equal(t, before.HeaderRowsAbove, after.HeaderRowsAbove,
		"a refused purge must be a no-op on the header index too")

	// And the boot path still diagnoses it, with the hashes intact.
	berr := chain.CheckForcedRollbackResidue()
	assert.Error(t, berr, "the node must still refuse to start on this store")
	assert.Contains(t, berr.Error(), hashByHeight[tip].String(),
		"the refusal must still be able to name the blocks involved")
	t1Close(store)

	// ONE stale entry is the whole defect. On mainnet the interrupted rewind that
	// matters is the one that stopped on the LAST block -- target+1, block
	// 2,260,451 -- so the refusal must be `> 0`, not "more than a handful".
	const soloTip = uint32(3)
	soloDir := filepath.Join(test.DataPath, "frpurgesolo")
	soloParams := t1Params(target)
	soloHashes := t1BuildChain(t, soloDir, soloParams, soloTip)
	t1EatHeaderRows(t, soloDir, soloParams, soloHashes, soloTip, soloTip)

	solo, soloStore := t1Open(t, soloDir, soloParams, nil, nil)
	defer t1Close(soloStore)
	soloScan, serr := blockchain.ScanForcedRollbackStore(solo.GetDB().GetFFLDB(), target)
	assert.NoError(t, serr)
	assert.Len(t, soloScan.MainChainAbove, 1,
		"harness precondition: exactly one stale main-chain entry above the target")
	n, perr = blockchain.PurgeForcedRollbackResidue(solo.GetDB().GetFFLDB(), target)
	assert.Equal(t, 0, n)
	assert.Error(t, perr,
		"SINGLE-ENTRY: one stale main-chain index entry above the target is already "+
			"an interrupted rollback -- and on mainnet it is the one that matters, the "+
			"rewind that stopped on block target+1 itself")
}

// TestFRManualRollbackIsExactlyOnceAcrossACrash is the proof for the manual
// `ela-cli rollback` command, the offline remedy every forced-rollback refusal
// message names.
//
// The command used to carry its own copy of the per-block rewind. It had picked up
// the header-row-last ORDERING, so an interrupted run left the block in the index
// and therefore re-visitable -- but it had no phase probe, and its body was
// unconditional:
//
//	block, _ := chainStore.GetFFLDB().GetBlock(*nodes[i].Hash)
//	chainStore.RollbackBlock(block.Block, nodes[i], nil, ...)
//
// On the store an interruption between the rollback transaction and the raw purge
// leaves behind -- rollback committed, body still fetchable, header row still there,
// which is exactly the store the block index reloads in full -- the re-run fetches
// the block and calls RollbackBlock a SECOND time over a rollback that has already
// committed, re-applying per-transaction rollback processors that are not
// idempotent.
//
// rollbackAction now delegates to blockchain.RollbackOneBlock, whose phase probe
// reads that state off the PERSISTED store and skips exactly the steps already
// committed.
//
// FAILS ON PRISTINE via the wiring inventory (rollbackAction must call
// RollbackOneBlock and must not call RollbackBlock/DeleteBlockFromStore/
// DBRemoveBlockNode itself); the assertions here prove the delegate is exactly-once
// when driven the way rollbackAction drives it -- from chain.Nodes, over a store
// reopened after the crash, without chain.Init.
func TestFRManualRollbackIsExactlyOnceAcrossACrash(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(4)
	dir := filepath.Join(test.DataPath, "frmanual")
	params := t1Params(target)
	t1BuildChain(t, dir, params, tip)

	// Crash immediately AFTER the top block's rollback transaction has durably
	// committed, before the raw purge and the header-row removal.
	mode := t1FailAfter
	var calls []uint32
	chain, store := t1Open(t, dir, params, &mode, &calls)
	assert.Error(t, chain.ForceRollback(nil))
	t1Close(store)
	assert.Equal(t, []uint32{tip}, calls, "harness precondition: one committed rollback")

	mode = t1FailNone
	chain, store = t1Open(t, dir, params, &mode, &calls)
	defer t1Close(store)

	nodes := chain.Nodes
	currentHeight := len(nodes) - 1
	assert.Equal(t, int(tip), currentHeight,
		"harness precondition: the header row survives the crash, so the manual "+
			"command still sees the block and will re-visit it")

	// The two facts that make the pristine loop's unconditional RollbackBlock a
	// RE-APPLICATION rather than a rollback.
	inStore := chain.GetDB().GetFFLDB().IsBlockInStore(nodes[tip].Hash)
	assert.True(t, inStore,
		"harness precondition: the body is still fetchable, so the pristine loop's "+
			"opening GetBlock succeeds and it proceeds to RollbackBlock")
	onMainChain, _, berr := chain.GetDB().GetFFLDB().BlockExists(nodes[tip].Hash)
	assert.NoError(t, berr)
	assert.False(t, onMainChain,
		"harness precondition: the rollback transaction -- which deletes the "+
			"main-chain index entry in the SAME atomic transaction as the "+
			"per-transaction rollback processors -- has already committed for this "+
			"block, so calling RollbackBlock again re-applies those processors")

	// The production manual loop, as rollbackAction now runs it.
	for i := currentHeight; i > int(target); i-- {
		assert.NoError(t, chain.RollbackOneBlock(nodes[i], nodes[i-1]),
			"MANUAL-RESUME: the manual rollback must finish a rewind its own "+
				"interrupted run started; height %d", i)
	}

	assert.Equal(t, []uint32{tip, tip - 1}, calls,
		"MANUAL-EXACTLY-ONCE: RollbackBlock must be invoked exactly once per height "+
			"across the crash and the resume. A second call at height %d means the "+
			"per-transaction rollback processors of an already-rolled-back block were "+
			"re-applied", tip)

	// The rewind is complete on disk: nothing above the target in any index.
	scan, serr := blockchain.ScanForcedRollbackStore(chain.GetDB().GetFFLDB(), target)
	assert.NoError(t, serr)
	assert.True(t, scan.Clean(),
		"after the manual rewind the persisted store must hold nothing above the "+
			"target: %s", scan.Summary())
}

// TestFRInitCheckpointInterruptIsNotSuccess is the FR-04 proof.
//
// initCheckpoint runs the checkpoint restore-and-replay on a goroutine and selects
// between its completion and the operator interrupt. On the interrupt branch it
// returned the SHARED error variable the goroutine is still writing -- nil, in
// practice -- so an interrupted initialisation was reported to main.go as a
// successful one, while the replay carried on rebuilding derived state behind it.
// main.go reads that nil as "derived state is rebuilt" and continues into the
// forced-rollback baseline assertion (which reads CkpManager.MaxHeight() while the
// goroutine is still mutating it), the P2P start and the DPoS mesh.
//
// FAILS ON PRISTINE: InitCheckpoint returns nil having replayed 0 of 9 blocks, and
// the goroutine then replays all 9.
func TestFRInitCheckpointInterruptIsNotSuccess(t *testing.T) {
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	const target = uint32(2)
	const tip = uint32(8)
	dir := filepath.Join(test.DataPath, "frinitckp")
	params := t1Params(target)
	// Pull the checkpoints' StartHeight down to genesis so the replay loop actually
	// runs over this short synthetic chain.
	params.VoteStartHeight = 0
	params.CRConfiguration.CRVotingStartHeight = 0
	t1BuildChain(t, dir, params, tip)

	chain, store := t1Open(t, dir, params, nil, nil)
	defer t1Close(store)

	arbiters, aerr := state.NewArbitrators(params, chain.GetCRCommittee(),
		nil, nil, nil, nil, nil, nil, nil, chain.CkpManager)
	assert.NoError(t, aerr)
	arbiters.RegisterFunction(chain.GetDB().GetHeight,
		func() *common.Uint256 { return &common.Uint256{} },
		func(height uint32) (*types.Block, error) { return nil, nil }, nil)
	origLedger := blockchain.DefaultLedger
	blockchain.DefaultLedger = &blockchain.Ledger{
		Blockchain: chain, Store: chain.GetDB(), Arbitrators: arbiters}
	defer func() { blockchain.DefaultLedger = origLedger }()

	// The interrupt is raised from INSIDE the replay, after its first block. That
	// also gives the test a happens-before edge with the replay goroutine
	// (firstBlock is unbuffered, so the send pairs with the receive below), which is
	// what lets the deferred DefaultLedger restore run without racing the
	// goroutine's own read of that global in restoreCheckpoints.
	interrupt := make(chan struct{})
	firstBlock := make(chan struct{})
	var replayCount int32
	var once sync.Once
	ierr := chain.InitCheckpoint(interrupt, nil, func() {
		if atomic.AddInt32(&replayCount, 1) == 1 {
			once.Do(func() { close(interrupt) })
			firstBlock <- struct{}{}
			return
		}
		time.Sleep(30 * time.Millisecond)
	})

	assert.Error(t, ierr,
		"INTERRUPT-REPORTED-SUCCESS: an interrupted checkpoint initialisation must "+
			"not be reported as a successful one. On pristine this returns nil, and "+
			"main.go then treats half-restored derived state as rebuilt")
	assert.True(t, errors.Is(ierr, blockchain.ErrCheckpointInitInterrupted),
		"the interrupt must carry its own sentinel, got: %v", ierr)

	// The replay must also STOP, rather than keep rebuilding derived state behind a
	// caller that has already been told the initialisation did not complete.
	<-firstBlock
	time.Sleep(500 * time.Millisecond)
	assert.EqualValues(t, 1, atomic.LoadInt32(&replayCount),
		"REPLAY-CONTINUES: the replay must stop at the first block boundary after "+
			"the interrupt; on pristine it replayed the whole chain after "+
			"InitCheckpoint had already returned")

	// ...and it must be able to EXIT. Its last statement is a send on the completion
	// channel, which nobody receives on this branch, so an unbuffered channel parks
	// it for the lifetime of the process, holding every lock and buffer it reached
	// through. Look for the goroutine ITSELF rather than counting goroutines: a
	// count is one unrelated background worker away from being wrong in either
	// direction.
	settled := false
	for i := 0; i < 60 && !settled; i++ {
		if !goroutineStackContains(replayGoroutineFrame) {
			settled = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.True(t, settled,
		"GOROUTINE-LEAK: the replay goroutine must be able to finish after an "+
			"interrupt; %s is still parked, which is what an unbuffered completion "+
			"channel with no receiver produces", replayGoroutineFrame)
}

// replayGoroutineFrame is the stack frame of initCheckpoint's replay goroutine.
const replayGoroutineFrame = "blockchain.(*BlockChain).initCheckpoint.func1"

// goroutineStackContains reports whether any live goroutine's stack names frame.
func goroutineStackContains(frame string) bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Contains(string(buf[:n]), frame)
		}
		buf = make([]byte, 2*len(buf))
	}
}
