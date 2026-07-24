// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package netsync

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	commonlog "github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elapeer "github.com/elastos/Elastos.ELA/elanet/peer"
	"github.com/elastos/Elastos.ELA/mempool"
	"github.com/elastos/Elastos.ELA/p2p/msg"
	p2ppeer "github.com/elastos/Elastos.ELA/p2p/peer"
)

// This file rebuilds the fail-on-pristine tests for F-035, F-054 and F-114 so
// that they DRIVE THE REAL PRODUCTION ENTRY POINTS (handleBlockMsg,
// handleInvMsg, haveInventory) instead of exercising the fix helpers in
// isolation. The earlier version asserted only on boundedSyncHeight /
// syncStalled / confirmInvNeedsStoreLookup, so reverting the production wiring
// while keeping those symbols left every test green -- proving nothing about
// whether the helpers are actually called. Each driving test below fails when
// its production hunk is reverted (a "symbol shim" that keeps the helper but
// drops the call is not enough to make it pass); the exact reverts and their
// output are recorded in the batch report.

func init() {
	// The chain store logs during construction, so the shared default logger
	// has to exist even when this test runs on its own.
	commonlog.NewDefault(filepath.Join(os.TempDir(), "ela-netsync-driving-test-logs"), 0, 0, 0)
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
	config.DefaultParams = *config.GetDefaultParams()
}

// newGenesisChain builds a real ffldb-backed chain holding only the genesis
// block, exactly as a freshly-started node would (the transaction functions are
// registered by init above). It is enough to exercise BlockExists,
// GetDposBlockByHash, GetHeight, LatestBlockLocator, GetOrphan* and the
// orphan-map fast path in processBlock.
func newGenesisChain(t *testing.T) (*blockchain.BlockChain, *config.Configuration) {
	t.Helper()

	params := config.GetDefaultParams()
	params.Sterilize()
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	blockchain.FoundationAddress = *params.FoundationProgramHash

	store, err := blockchain.NewChainStore(t.TempDir(), params)
	if err != nil {
		t.Fatalf("new chain store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ckp := checkpoint.NewManager(params)
	chain, err := blockchain.New(store, params,
		state.NewState(params, nil, nil, nil,
			func() bool { return false },
			nil, nil,
			nil, nil, nil, nil, nil),
		crstate.NewCommittee(params, ckp), ckp)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	if err := chain.Init(nil); err != nil {
		t.Fatalf("chain init: %v", err)
	}
	return chain, params
}

// fakeIPeer is a server.IPeer whose only job is to hand back a real,
// unconnected p2p peer so the elanet peer wrapper is usable: QueueMessage short
// circuits when the peer is not connected and Disconnect just closes the quit
// channel, so no network is involved.
type fakeIPeer struct{ base *p2ppeer.Peer }

func (f *fakeIPeer) ToPeer() *p2ppeer.Peer                              { return f.base }
func (f *fakeIPeer) AddBanScore(persistent, transient uint32, r string) {}
func (f *fakeIPeer) BanScore() uint32                                   { return 0 }

func newSyncTestPeer(height uint32) *elapeer.Peer {
	base := p2ppeer.NewInboundPeer(&p2ppeer.Config{})
	base.UpdateHeight(height)
	return elapeer.New(&fakeIPeer{base: base}, &elapeer.Listeners{})
}

func newPeerState(candidate bool, seed ...common.Uint256) *peerSyncState {
	st := &peerSyncState{
		syncCandidate:            candidate,
		requestedTxns:            make(map[common.Uint256]struct{}),
		requestedBlocks:          make(map[common.Uint256]struct{}),
		requestedConfirmedBlocks: make(map[common.Uint256]struct{}),
	}
	for _, h := range seed {
		st.requestedBlocks[h] = struct{}{}
	}
	return st
}

func newTestSyncManager(chain *blockchain.BlockChain, params *config.Configuration,
	pool *mempool.BlockPool) *SyncManager {
	return &SyncManager{
		chain:                    chain,
		chainParams:              params,
		blockMemPool:             pool,
		rejectedTxns:             make(map[common.Uint256]struct{}),
		requestedTxns:            make(map[common.Uint256]struct{}),
		requestedBlocks:          make(map[common.Uint256]struct{}),
		requestedConfirmedBlocks: make(map[common.Uint256]struct{}),
		peerStates:               make(map[*elapeer.Peer]*peerSyncState),
	}
}

func randHash(t *testing.T) common.Uint256 {
	t.Helper()
	var h common.Uint256
	if _, err := rand.Read(h[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return h
}

// orphanBlockAtHeight builds a block whose parent is unknown and pre-inserts it
// into the chain's orphan pool. processBlock returns isOrphan=true from the
// orphan-map check BEFORE CheckBlockSanity, so this reaches the real orphan
// branch of handleBlockMsg without a fully-valid block. The height stays below
// CRCOnlyDPOSHeight and RevertToPOWStartHeight so AddDposBlock routes to
// ProcessBlock.
func orphanBlockAtHeight(t *testing.T, chain *blockchain.BlockChain, height uint32) *types.DposBlock {
	t.Helper()
	prev := randHash(t)
	blk := &types.Block{Header: common2.Header{Height: height, Previous: prev, Nonce: height}}
	chain.AddOrphanBlock(blk)
	return &types.DposBlock{Block: blk, HaveConfirm: false}
}

// TestF114HandleBlockMsgClampsOrphanSyncHeight drives the REAL handleBlockMsg
// with an orphan block whose header claims a height far above our tip, and
// asserts the sync target is clamped. Pre-fix handleBlockMsg stored the raw
// attacker-supplied height (sm.syncHeight = bmsg.block.Block.Height); the sync
// slot is released only once the chain reaches syncHeight, so a huge claim
// pinned the slot to the sender for the life of the process and every other
// peer's inv was dropped.
//
// FAIL-ON-PRISTINE: revert the handleBlockMsg hunk to
//   sm.syncHeight = bmsg.block.Block.Height
// (keeping boundedSyncHeight defined) and syncHeight becomes the raw claim,
// which fails the "clamped below the claim" assertion.
func TestF114HandleBlockMsgClampsOrphanSyncHeight(t *testing.T) {
	chain, params := newGenesisChain(t)
	pool := mempool.NewBlockPool(params)
	pool.Chain = chain

	sm := newTestSyncManager(chain, params, pool)
	peer := newSyncTestPeer(0)

	// claimed is > maxSyncAhead and < CRCOnlyDPOSHeight/RevertToPOWStartHeight.
	const claimed = 300000
	dblk := orphanBlockAtHeight(t, chain, claimed)
	blockHash := dblk.Block.Hash()

	// Seed the request maps so the block counts as solicited (otherwise
	// handleBlockMsg disconnects the peer before doing anything).
	sm.peerStates[peer] = newPeerState(true, blockHash)
	sm.requestedBlocks[blockHash] = struct{}{}

	best := chain.BestChain.Height
	sm.handleBlockMsg(&blockMsg{block: dblk, peer: peer})

	if sm.syncPeer != peer {
		t.Fatalf("orphan branch not reached: syncPeer=%p want=%p", sm.syncPeer, peer)
	}
	if sm.syncHeight >= claimed {
		t.Fatalf("FAIL(F-114): handleBlockMsg stored the raw attacker claim as the "+
			"sync target: syncHeight=%d, claim=%d -- boundedSyncHeight is not wired in",
			sm.syncHeight, claimed)
	}
	if want := best + maxSyncAhead; sm.syncHeight != want {
		t.Fatalf("F-114: syncHeight=%d, want clamp best+maxSyncAhead=%d", sm.syncHeight, want)
	}
}

// TestF035SyncTimerNotResetByOrphan drives the REAL handleBlockMsg with a
// non-advancing (orphan) block delivered by the current sync peer, and asserts
// the stall timer is NOT reset. Pre-fix the timer was reset by ANY block the
// sync peer delivered (if peer == sm.syncPeer), so a peer that had taken the
// slot could hold it forever by dripping one unconnectable orphan just inside
// syncTimeout.
//
// FAIL-ON-PRISTINE: revert the handleBlockMsg hunk to
//   if peer == sm.syncPeer { sm.syncStartTime = time.Now() }
// and the timer is reset to now, which fails the "unchanged" assertion.
func TestF035SyncTimerNotResetByOrphan(t *testing.T) {
	chain, params := newGenesisChain(t)
	pool := mempool.NewBlockPool(params)
	pool.Chain = chain

	sm := newTestSyncManager(chain, params, pool)
	peer := newSyncTestPeer(300000)

	const claimed = 200000
	dblk := orphanBlockAtHeight(t, chain, claimed)
	blockHash := dblk.Block.Hash()

	t0 := time.Now().Add(-time.Hour)
	sm.syncPeer = peer
	// Keep syncHeight above the tip so the slot is not released and re-taken
	// (which would legitimately reset the timer); we are isolating the
	// "reset on any delivery" bug.
	sm.syncHeight = 5000
	sm.syncStartTime = t0
	sm.peerStates[peer] = newPeerState(true, blockHash)
	sm.requestedBlocks[blockHash] = struct{}{}

	sm.handleBlockMsg(&blockMsg{block: dblk, peer: peer})

	if sm.syncPeer != peer {
		t.Fatalf("precondition broken: sync slot changed, syncPeer=%p", sm.syncPeer)
	}
	if !sm.syncStartTime.Equal(t0) {
		t.Fatalf("FAIL(F-035): the stall timer was reset by a non-advancing orphan "+
			"delivered by the sync peer (before=%v after=%v) -- the tip-progress "+
			"guard is not wired in", t0, sm.syncStartTime)
	}
}

// TestF035StalledSyncPeerReselects drives the REAL handleInvMsg while the
// current sync peer is stalled, and asserts the slot is handed to another
// candidate. Pre-fix the inline stall check disconnected the stalled peer but
// did NOT re-run startSync (handleDonePeerMsg is the only caller, and it only
// fires on an actual disconnect notification), so the node simply stopped
// syncing after a stall.
//
// FAIL-ON-PRISTINE: revert the handleInvMsg hunk from
//   sm.dropStalledSyncPeer(time.Now())
// back to the inline "disconnect + syncPeer = nil" block (no startSync), and no
// new sync peer is selected, which fails the "reselected" assertion.
func TestF035StalledSyncPeerReselects(t *testing.T) {
	chain, params := newGenesisChain(t)
	pool := mempool.NewBlockPool(params)
	pool.Chain = chain

	sm := newTestSyncManager(chain, params, pool)

	stalled := newSyncTestPeer(100)
	candidate := newSyncTestPeer(100)
	reporter := newSyncTestPeer(100)

	sm.syncPeer = stalled
	sm.syncStartTime = time.Now().Add(-2 * syncTimeout) // stalled
	sm.peerStates[stalled] = newPeerState(false)        // no longer a candidate
	sm.peerStates[candidate] = newPeerState(true)
	sm.peerStates[reporter] = newPeerState(true)

	// An empty inv from a third peer: only the stall handling at the top of
	// handleInvMsg runs.
	sm.handleInvMsg(&invMsg{inv: &msg.Inv{}, peer: reporter})

	if sm.syncPeer == nil {
		t.Fatalf("FAIL(F-035): after the sync peer stalled, no replacement was " +
			"selected -- dropStalledSyncPeer does not re-run startSync")
	}
	if sm.syncPeer == stalled {
		t.Fatalf("FAIL(F-035): the stalled peer still holds the sync slot")
	}
}

// TestF054HaveInventoryConsultsBlockPool drives the REAL haveInventory for a
// confirmed-block announcement whose confirm we already hold in the block pool.
// Pre-fix haveInventory ignored the in-memory pool and answered from the chain
// only, so for a block we have without a stored confirm it returned false and
// the node then issued a getdata that loaded the FULL block off the flat-file
// store just to read one bool. The fix consults the pool first.
//
// The genesis block is used because BlockExists(genesisHash) is true on a fresh
// chain while its stored form carries no confirm, so the two trees diverge:
// fixed returns true (confirm found in pool), pristine returns false.
//
// FAIL-ON-PRISTINE: revert the haveInventory hunk (drop the
// blockMemPool.GetConfirm / buried-window short circuits) and haveInventory
// returns false for a confirm we demonstrably hold, failing the assertion.
func TestF054HaveInventoryConsultsBlockPool(t *testing.T) {
	chain, params := newGenesisChain(t)
	pool := mempool.NewBlockPool(params)
	pool.Chain = chain

	genesisHash := params.GenesisBlock.Hash()
	if !chain.BlockExists(&genesisHash) {
		t.Fatalf("precondition: fresh chain does not know its own genesis block")
	}

	// We hold the confirm in the pool but the chain's stored genesis has none.
	pool.AddToConfirmMap(&payload.Confirm{
		Proposal: payload.DPOSProposal{BlockHash: genesisHash},
	})

	sm := newTestSyncManager(chain, params, pool)

	have, err := sm.haveInventory(&msg.InvVect{
		Type: msg.InvTypeConfirmedBlock,
		Hash: genesisHash,
	})
	if err != nil {
		t.Fatalf("haveInventory error: %v", err)
	}
	if !have {
		t.Fatalf("FAIL(F-054): haveInventory did not consult the block pool for a " +
			"confirm we already hold -- it still falls through to the full-block " +
			"store read")
	}

	// Control: an unknown confirmed-block hash is still reported as not-have on
	// both trees (BlockExists is false, so no store read either way).
	unknown := randHash(t)
	if have, _ := sm.haveInventory(&msg.InvVect{
		Type: msg.InvTypeConfirmedBlock,
		Hash: unknown,
	}); have {
		t.Fatalf("haveInventory claimed an unknown confirmed block as known")
	}
}

// ---------------------------------------------------------------------------
// Supplementary pure-function checks. These are NOT the fail-on-pristine proof
// (they keep passing if the call sites are reverted while the helpers remain);
// the driving tests above are. They are retained because they cover the two
// arithmetic edges the driving tests cannot cheaply reach: the far-future clamp
// used at the second (handleInvMsg) F-114 site, and the F-054 buried-window
// branch, which would need a chain a thousand blocks deep to drive.
// ---------------------------------------------------------------------------

func TestBoundedSyncHeightTable(t *testing.T) {
	const best = 2260451
	cases := []struct {
		claimed, want uint32
	}{
		{^uint32(0), best + maxSyncAhead},
		{best + 10*maxSyncAhead, best + maxSyncAhead},
		{best + 10, best + 10},
		{best, best + 1},
		{best - 1000, best + 1},
		{0, best + 1},
	}
	for _, c := range cases {
		if got := boundedSyncHeight(c.claimed, best); got != c.want {
			t.Errorf("boundedSyncHeight(%d,%d)=%d want %d", c.claimed, best, got, c.want)
		}
		if boundedSyncHeight(c.claimed, best) <= best {
			t.Errorf("boundedSyncHeight(%d,%d) must exceed the tip %d", c.claimed, best, best)
		}
	}
}

func TestConfirmInvStoreLookupWindowTable(t *testing.T) {
	const best = 2260451
	cases := []struct {
		height uint32
		want   bool
	}{
		{best, true},
		{best - 1, true},
		{best - confirmInvLookupWindow, true},
		{best - confirmInvLookupWindow - 1, false},
		{1, false},
		{0, false},
		{best + 1, true},
	}
	for _, c := range cases {
		if got := confirmInvNeedsStoreLookup(c.height, best); got != c.want {
			t.Errorf("confirmInvNeedsStoreLookup(%d,%d)=%v want %v", c.height, best, got, c.want)
		}
	}
	// A fresh node (tip below the window) must never suppress a lookup.
	for h := uint32(0); h < 10; h++ {
		if !confirmInvNeedsStoreLookup(h, 5) {
			t.Errorf("confirmInvNeedsStoreLookup(%d,5)=false on a fresh chain", h)
		}
	}
	if stallCheckInterval >= syncTimeout {
		t.Fatalf("stallCheckInterval %v must be shorter than syncTimeout %v",
			stallCheckInterval, syncTimeout)
	}
}
