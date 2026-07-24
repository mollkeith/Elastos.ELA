// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"bytes"
	"errors"
	"sync"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/events"
)

const (
	cachedCount = 6

	// retainAheadCount bounds how far ABOVE the reference height a block may sit
	// in the pool and still be retained. F-092: appendBlock stores every block
	// that passes CheckBlockSanity -- whose only work gate is CheckProofOfWork
	// against PowLimit (2^255-1, i.e. free) -- at ANY height, and the retention
	// sweep only ever dropped entries BELOW the tip, so blocks minted at
	// arbitrary future heights were kept for the life of the process. Nothing
	// further above the tip than the pool's own retention window can be
	// confirmed from here anyway, and a genuinely connectable orphan is held by
	// the chain's orphan pool (AddOrphanBlock/ProcessOrphans), not by this map.
	retainAheadCount = cachedCount

	// maxOrphanConfirms bounds the number of confirms retained for blocks that
	// are not in the pool. F-117: appendConfirm stores the confirm before
	// confirmBlock runs, and the sweep only ever visited confirms keyed by
	// blocks that are in the pool -- so a confirm whose block never arrives was
	// retained for the life of the process.
	maxOrphanConfirms = 512

	// maxPooledBlocks and maxPooledBlockBytes bound bm.blocks by COUNT and by
	// BYTES.
	//
	// FV-15: F-092/F-117 bounded this pool by HEIGHT, but bm.blocks is keyed by
	// HASH, so nothing ever bounded how many DISTINCT blocks could sit at one
	// RETAINED height. Every one of them has a different hash, every one is
	// inside [floor, ceiling], and pruneLocked therefore retains all of them
	// until the tip moves past that height -- roughly three block intervals in
	// the steady state, and forever on a chain that has stopped connecting
	// blocks, because the sweep's only production driver is the block-connected
	// path (elanet/netsync/manager.go CleanFinalConfirmedBlock). Minting such a
	// block is free: appendBlock's only work gate is CheckBlockSanity, whose
	// CheckProofOfWork runs against PowLimit (2^255-1).
	//
	// The legitimate occupancy of the retention window is
	// cachedCount+retainAheadCount+1 = 13 heights, and the retained mainchain
	// has exactly ONE height in 2,260,596 that ever held two distinct blocks, so
	// 64 entries is roughly 5x the largest occupancy real history can justify.
	// The byte budget is the bound that actually matters -- a count cap alone
	// still concedes maxPooledBlocks x MaxBlockContextSize of RAM -- and it is
	// the one the F-092 comment was standing in for.
	maxPooledBlocks = 64

	// maxPooledBlockBytes is ~2.4x the theoretical maximum legitimate window
	// occupancy at the default 2 MB MaxBlockContextSize (13 x 2 MB = 26 MB), and
	// four orders of magnitude above real mainchain block sizes. When an
	// operator configures larger blocks this binds before maxPooledBlocks does,
	// which is the intended order: it is a hard RAM ceiling, and the entry
	// evicted first is always the one furthest from the tip.
	maxPooledBlockBytes = 64 * 1024 * 1024
)

type ConfirmInfo struct {
	Confirm *payload.Confirm
	Height  uint32
}

type BlockPool struct {
	Chain     *blockchain.BlockChain
	Store     blockchain.IChainStore
	IsCurrent func() bool

	sync.RWMutex
	blocks   map[common.Uint256]*types.Block
	confirms map[common.Uint256]*payload.Confirm
	// confirmAge counts how many retention sweeps a confirm whose block is not
	// in the pool has survived. Entries exist only for such orphan confirms, so
	// len(confirmAge) is also the orphan-confirm census used by
	// maxOrphanConfirms. (F-117)
	confirmAge map[common.Uint256]uint32
	// blockSizes and poolBytes are the byte accounting behind
	// maxPooledBlockBytes. blockSizes has exactly the same key set as blocks,
	// and poolBytes is the sum of its values; both are maintained only by
	// putBlockLocked and dropBlockLocked so they cannot drift. (FV-15)
	blockSizes map[common.Uint256]int
	poolBytes  int
	// shedding records whether the pool is currently at its bound, so the
	// operator gets one line when it starts shedding and one when it recovers
	// rather than one per evicted block. (FV-15)
	shedding    bool
	chainParams *config.Configuration
}

func (bm *BlockPool) AppendConfirm(confirm *payload.Confirm) (bool,
	bool, error) {
	bm.Lock()
	defer bm.Unlock()

	return bm.appendConfirm(confirm)
}

func (bm *BlockPool) AddDposBlock(dposBlock *types.DposBlock) (bool, bool, error) {
	if bm.Chain.GetState().ConsensusAlgorithm == state.POW {
		return bm.Chain.ProcessBlock(dposBlock.Block, dposBlock.Confirm)
	}

	if dposBlock.Block.Height > bm.chainParams.DPoSConfiguration.RevertToPOWStartHeight && !dposBlock.HaveConfirm {
		for _, tx := range dposBlock.Transactions {
			if tx.IsRevertToPOW() {
				return bm.Chain.ProcessBlock(dposBlock.Block, dposBlock.Confirm)
			}
		}
	}

	// main version >=H1
	if dposBlock.Block.Height >= bm.chainParams.CRCOnlyDPOSHeight {
		if dposBlock.Block.Height >= bm.chainParams.CRConfiguration.CRCommitteeStartHeight {
			if len(dposBlock.Block.Transactions) > 0 &&
				len(dposBlock.Block.Transactions[0].Outputs()) >= 1 &&
				dposBlock.Block.Transactions[0].Outputs()[0].ProgramHash.
					IsEqual(*bm.chainParams.DestroyELAProgramHash) {
				return bm.Chain.ProcessBlock(dposBlock.Block, dposBlock.Confirm)
			}
		}

		return bm.AppendDposBlock(dposBlock)
	}

	// old version [0, H1)
	return bm.Chain.ProcessBlock(dposBlock.Block, dposBlock.Confirm)
}

func (bm *BlockPool) AppendDposBlock(dposBlock *types.DposBlock) (bool, bool, error) {
	bm.Lock()
	defer bm.Unlock()
	if !dposBlock.HaveConfirm {
		return bm.appendBlock(dposBlock)
	}
	return bm.appendBlockAndConfirm(dposBlock)
}

func (bm *BlockPool) appendBlock(dposBlock *types.DposBlock) (bool, bool, error) {
	// add block
	block := dposBlock.Block
	hash := block.Hash()
	if _, ok := bm.blocks[hash]; ok {
		return false, false, errors.New("duplicate block in pool")
	}

	// FV-15: admission bound, and it must be checked BEFORE CheckBlockSanity so
	// an out-of-window block costs neither the serialization nor the merkle
	// work. This is the ONLY admission path that may refuse a block outright,
	// and it is safe to do so precisely here: a block with no confirm can never
	// reach Chain.ProcessBlock from this function (confirmBlock below fails on
	// the missing confirm), so no orphan is created and the netsync manager's
	// orphan recovery is not involved. The window is the same one pruneLocked
	// enforces on retention, so this rejects only blocks the very next sweep
	// would delete anyway -- and unlike the sweep, it holds while the chain is
	// stalled, which is when the sweep never runs.
	//
	// Debug, not Info: the netsync manager already logs every AddDposBlock
	// error at Warn, and an attacker sets the rate at which this fires.
	reference := bm.referenceHeightLocked(block.Height)
	if !retentionWindowContains(reference, block.Height) {
		log.Debugf("[AppendBlock] block %s at height %d is outside the pool "+
			"retention window around %d", hash, block.Height, reference)
		return false, false, errors.New(
			"block height outside the block pool retention window")
	}

	// verify block
	if err := bm.Chain.CheckBlockSanity(block); err != nil {
		log.Info("[AppendBlock] check block sanity failed, ", err)
		return false, false, err
	}
	if block.Height == bm.Chain.GetHeight()+1 {
		prevNode, exist := bm.Chain.LookupNodeInIndex(&block.Header.Previous)
		if !exist {
			log.Info("[AppendBlock] check block context failed, there is no previous block on the chain")
			return false, false, errors.New("there is no previous block on the chain")
		}
		if err := bm.Chain.CheckBlockContext(block, prevNode); err != nil {
			log.Info("[AppendBlock] check block context failed, ", err)
			return false, false, err
		}
	}

	bm.putBlockLocked(block, reference)

	// confirm block
	inMainChain, isOrphan, err := bm.confirmBlock(hash)
	if err != nil {
		log.Debug("[AppendDPOSBlock] ConfirmBlock failed, height", block.Height, "len(txs):",
			len(block.Transactions), "hash:", hash.String(), "err: ", err)

		// Notify the caller that the new block without confirm was accepted.
		// The caller would typically want to react by relaying the inventory
		// to other peers.
		events.Notify(events.ETBlockAccepted, block)
		if block.Height == blockchain.DefaultLedger.Blockchain.GetHeight()+1 {
			events.Notify(events.ETNewBlockReceived, dposBlock)
		}
		return inMainChain, isOrphan, nil
	}

	copyBlock := *dposBlock
	confirm := bm.confirms[hash]
	copyBlock.HaveConfirm = confirm != nil
	copyBlock.Confirm = confirm

	// notify new block received
	events.Notify(events.ETNewBlockReceived, &copyBlock)

	return inMainChain, isOrphan, nil
}

func (bm *BlockPool) appendBlockAndConfirm(dposBlock *types.DposBlock) (bool, bool, error) {
	block := dposBlock.Block
	hash := block.Hash()
	// verify block
	if err := bm.Chain.CheckBlockSanity(block); err != nil {
		return false, false, err
	}
	// add block
	//
	// FV-15: no height rejection here, by design. This path feeds
	// Chain.ProcessBlock, whose isOrphan result drives the netsync manager's
	// PushGetBlocksMsg ancestor recovery, so a node that is far behind must
	// still be able to hand a far-ahead block+confirm to the chain. The pool is
	// bounded by shedding instead, inside putBlockLocked.
	bm.putBlockLocked(block, bm.referenceHeightLocked(block.Height))
	// confirm block
	inMainChain, isOrphan, err := bm.appendConfirm(dposBlock.Confirm)
	if err != nil {
		log.Debug("[appendBlockAndConfirm] ConfirmBlock failed, hash:", hash.String(), "err: ", err)
		return inMainChain, isOrphan, nil
	}

	// notify new block received
	events.Notify(events.ETNewBlockReceived, dposBlock)

	return inMainChain, isOrphan, nil
}

func (bm *BlockPool) appendConfirm(confirm *payload.Confirm) (
	bool, bool, error) {

	// verify confirmation
	if err := blockchain.ConfirmSanityCheck(confirm); err != nil {
		return false, false, err
	}
	bm.confirms[confirm.Proposal.BlockHash] = confirm

	inMainChain, isOrphan, err := bm.confirmBlock(confirm.Proposal.BlockHash)
	if err != nil {
		// F-117: the confirm deliberately stays in bm.confirms so that a block
		// which arrives after its confirm can still be confirmed -- but from
		// here on it is tracked and bounded instead of being retained forever.
		bm.trackOrphanConfirmLocked(confirm.Proposal.BlockHash)
		return inMainChain, isOrphan, err
	}
	block := bm.blocks[confirm.Proposal.BlockHash]

	// notify new confirm accepted.
	events.Notify(events.ETConfirmAccepted, &ConfirmInfo{
		Confirm: confirm,
		Height:  block.Height,
	})

	return inMainChain, isOrphan, nil
}

func (bm *BlockPool) ConfirmBlock(hash common.Uint256) (bool, bool, error) {
	bm.Lock()
	inMainChain, isOrphan, err := bm.confirmBlock(hash)
	bm.Unlock()
	return inMainChain, isOrphan, err
}

func (bm *BlockPool) confirmBlock(hash common.Uint256) (bool, bool, error) {
	log.Info("[ConfirmBlock] block hash:", hash)

	block, ok := bm.blocks[hash]
	if !ok {
		return false, false, errors.New("there is no block in pool when confirming block")
	}
	log.Info("[ConfirmBlock] block height:", block.Height)

	confirm, ok := bm.confirms[hash]
	if !ok {
		return false, false, errors.New("there is no block confirmation in pool when confirming block")
	}

	if !bm.Chain.BlockExists(&hash) {
		inMainChain, isOrphan, err := bm.Chain.ProcessBlock(block, confirm)
		if err != nil {
			return inMainChain, isOrphan, errors.New("add block failed," + err.Error())
		}

		if !inMainChain && !isOrphan {
			if err := bm.CheckConfirmedBlockOnFork(bm.Chain.GetHeight(), block); err != nil {
				log.Error("[CheckConfirmedBlockOnFork] error:", err)
				return inMainChain, isOrphan, err
			}
		}

		if isOrphan && !inMainChain {
			bm.Chain.AddOrphanConfirm(confirm)
		}

		if isOrphan || !inMainChain {
			return inMainChain, isOrphan, errors.New("add orphan block")
		}
	} else {
		return false, false, errors.New("already processed block")
	}

	return true, false, nil
}

func (bm *BlockPool) AddToBlockMap(block *types.Block) {
	bm.Lock()
	defer bm.Unlock()

	// FV-15: this path performs no validation at all, so it is bounded by
	// shedding rather than by refusal.
	bm.putBlockLocked(block, bm.referenceHeightLocked(block.Height))
}

func (bm *BlockPool) GetBlock(hash common.Uint256) (*types.Block, bool) {
	bm.RLock()
	defer bm.RUnlock()

	block, ok := bm.blocks[hash]
	return block, ok
}

func (bm *BlockPool) GetDposBlockByHash(hash common.Uint256) (*types.DposBlock, error) {
	bm.RLock()
	defer bm.RUnlock()

	if block := bm.blocks[hash]; block != nil {
		confirm := bm.confirms[hash]
		return &types.DposBlock{
			Block:       block,
			HaveConfirm: confirm != nil,
			Confirm:     confirm,
		}, nil
	}
	return nil, errors.New("not found dpos block")
}

func (bm *BlockPool) AddToConfirmMap(confirm *payload.Confirm) {
	bm.Lock()
	defer bm.Unlock()

	bm.confirms[confirm.Proposal.BlockHash] = confirm
	// F-117: bound this entry too when its block is not in the pool.
	bm.trackOrphanConfirmLocked(confirm.Proposal.BlockHash)
}

func (bm *BlockPool) GetConfirm(hash common.Uint256) (
	*payload.Confirm, bool) {
	bm.Lock()
	defer bm.Unlock()

	confirm, ok := bm.confirms[hash]
	return confirm, ok
}

func (bm *BlockPool) CleanFinalConfirmedBlock(height uint32) {
	bm.Lock()
	defer bm.Unlock()

	bm.pruneLocked(height)
}

// pruneLocked evicts every pool entry that is outside the retention window
// around the given (just connected) reference height, and ages out confirms
// whose block is not in the pool. The caller must hold bm's write lock.
//
// F-092/F-117: this is retention only. It never rejects an incoming block or
// confirm, so it cannot change which blocks or transactions the node accepts:
// an evicted block that later becomes relevant is simply re-requested on the
// next announcement, and a connectable orphan lives in the chain's own orphan
// pool rather than here.
func (bm *BlockPool) pruneLocked(height uint32) {
	for hash, block := range bm.blocks {
		if !retentionWindowContains(height, block.Height) {
			bm.dropBlockLocked(hash)
		}
	}

	// FV-15: report recovery once, on the way back down.
	if bm.shedding && len(bm.blocks) < maxPooledBlocks/2 &&
		bm.poolBytes < maxPooledBlockBytes/2 {
		bm.shedding = false
		log.Infof("[BlockPool] pool is back under its bound (%d blocks / "+
			"%d bytes) around height %d", len(bm.blocks), bm.poolBytes, height)
	}

	// F-117: age out confirms with no block in the pool. Retaining them for a
	// while is deliberate -- a confirm may legitimately arrive before its block
	// -- but one whose block has not shown up within the pool's own retention
	// window is dead weight.
	for hash := range bm.confirms {
		if _, ok := bm.blocks[hash]; ok {
			delete(bm.confirmAge, hash)
			continue
		}
		age := bm.confirmAge[hash] + 1
		if age > cachedCount {
			delete(bm.confirms, hash)
			delete(bm.confirmAge, hash)
			continue
		}
		bm.confirmAge[hash] = age
	}
}

// retentionWindowContains reports whether a block at blockHeight is inside the
// pool's retention window around the reference height. pruneLocked and the
// FV-15 admission bound MUST agree on this window -- an admission rule stricter
// than retention would drop blocks the sweep would have kept, and one looser
// would admit blocks the sweep deletes at the next connect -- so both read it
// from here.
//
// F-092: reference-cachedCount underflowed for the first cachedCount heights
// and wrapped to ~2^32, which dropped the entire pool -- including the block
// being connected -- during genesis bootstrap.
func retentionWindowContains(reference, blockHeight uint32) bool {
	var floor uint32
	if reference > cachedCount {
		floor = reference - cachedCount
	}
	ceiling := ^uint32(0)
	if reference <= ceiling-retainAheadCount {
		ceiling = reference + retainAheadCount
	}
	return blockHeight >= floor && blockHeight <= ceiling
}

// referenceHeightLocked returns the height the retention window is centred on
// for an admission decision. The pool is wired to a chain in production; the
// fallback keeps the pool usable in isolation, where every height is trivially
// its own reference. The caller must hold bm's write lock.
func (bm *BlockPool) referenceHeightLocked(fallback uint32) uint32 {
	if bm.Chain == nil {
		return fallback
	}
	return bm.Chain.GetHeight()
}

// putBlockLocked inserts block into the pool and enforces the FV-15 count and
// byte caps. The caller must hold bm's write lock.
//
// It NEVER refuses the insert. Two of the three admission paths
// (appendBlockAndConfirm, AddToBlockMap) hand the block to
// Chain.ProcessBlock -- whose isOrphan result drives the netsync manager's
// PushGetBlocksMsg recovery -- so refusing there would convert a retention bug
// into a sync-liveness bug. Instead the pool sheds the entry FURTHEST from the
// reference height, which is exactly the entry pruneLocked would delete first
// and never the tip-adjacent block the node is actually trying to connect.
//
// It also makes the sweep self-driving: pruneLocked's only production caller is
// the block-connected path, so on a chain that has stopped connecting blocks it
// never runs at all. Running it here means an admission is itself enough to age
// the pool out.
func (bm *BlockPool) putBlockLocked(block *types.Block, reference uint32) {
	hash := block.Hash()
	if _, ok := bm.blocks[hash]; ok {
		// Already pooled: replace the value but keep the accounting, which is
		// already correct for this key.
		bm.blocks[hash] = block
		return
	}

	size := block.GetSize()
	if size < 0 {
		// Block.GetSize returns InvalidBlockSize (-1) when serialization fails.
		// Charge nothing rather than corrupting poolBytes; the count cap still
		// bounds such an entry.
		size = 0
	}

	if len(bm.blocks) >= maxPooledBlocks || bm.poolBytes+size > maxPooledBlockBytes {
		bm.pruneLocked(reference)
	}
	var evicted int
	for len(bm.blocks) > 0 &&
		(len(bm.blocks) >= maxPooledBlocks || bm.poolBytes+size > maxPooledBlockBytes) {
		if !bm.evictFurthestLocked(reference) {
			break
		}
		evicted++
	}
	// Log the TRANSITION into and out of shedding, never the individual
	// evictions: shedding only happens under a flood, so a per-eviction line
	// would itself be an amplifier.
	if evicted > 0 && !bm.shedding {
		bm.shedding = true
		log.Warnf("[BlockPool] pool is at its bound (%d blocks / %d bytes) "+
			"around height %d and is now shedding the entries furthest from "+
			"the tip", len(bm.blocks), bm.poolBytes, reference)
	}

	bm.blocks[hash] = block
	if bm.blockSizes == nil {
		bm.blockSizes = make(map[common.Uint256]int)
	}
	bm.blockSizes[hash] = size
	bm.poolBytes += size
}

// evictFurthestLocked drops the pooled block whose height is furthest from the
// reference height, breaking ties on the block hash so the choice is
// deterministic rather than dependent on Go map iteration order. It reports
// whether anything was evicted. The caller must hold bm's write lock. (FV-15)
func (bm *BlockPool) evictFurthestLocked(reference uint32) bool {
	var (
		victim   common.Uint256
		distance uint32
		found    bool
	)
	for hash, block := range bm.blocks {
		d := heightDistance(reference, block.Height)
		if !found || d > distance ||
			(d == distance && bytes.Compare(hash[:], victim[:]) > 0) {
			victim, distance, found = hash, d, true
		}
	}
	if !found {
		return false
	}
	bm.dropBlockLocked(victim)

	return true
}

// heightDistance returns |a-b| without overflowing uint32 subtraction.
func heightDistance(a, b uint32) uint32 {
	if a > b {
		return a - b
	}
	return b - a
}

// dropBlockLocked removes a pooled block together with its confirm, its orphan
// confirm age and its byte accounting. Every eviction goes through here so the
// byte accounting cannot drift from the map. The caller must hold bm's write
// lock. (FV-15)
func (bm *BlockPool) dropBlockLocked(hash common.Uint256) {
	if size, ok := bm.blockSizes[hash]; ok {
		bm.poolBytes -= size
		if bm.poolBytes < 0 {
			bm.poolBytes = 0
		}
		delete(bm.blockSizes, hash)
	}
	delete(bm.blocks, hash)
	delete(bm.confirms, hash)
	delete(bm.confirmAge, hash)
}

// PooledBlockStats reports the pool's current block count and retained bytes.
// It exists so the FV-15 bounds can be asserted from outside the package.
func (bm *BlockPool) PooledBlockStats() (int, int) {
	bm.RLock()
	defer bm.RUnlock()

	return len(bm.blocks), bm.poolBytes
}

// trackOrphanConfirmLocked registers a confirm whose block is not in the pool
// so the retention sweep can age it out, and enforces maxOrphanConfirms by
// dropping the stalest tracked entries first. The caller must hold bm's write
// lock. (F-117)
func (bm *BlockPool) trackOrphanConfirmLocked(hash common.Uint256) {
	if _, ok := bm.blocks[hash]; ok {
		return
	}
	if _, ok := bm.confirms[hash]; !ok {
		return
	}
	if bm.confirmAge == nil {
		bm.confirmAge = make(map[common.Uint256]uint32)
	}
	if _, ok := bm.confirmAge[hash]; !ok {
		bm.confirmAge[hash] = 0
	}

	for len(bm.confirmAge) > maxOrphanConfirms {
		var (
			victim    common.Uint256
			victimAge uint32
			found     bool
		)
		for h, age := range bm.confirmAge {
			if h == hash {
				continue
			}
			if !found || age > victimAge {
				victim, victimAge, found = h, age, true
			}
		}
		if !found {
			return
		}
		delete(bm.confirms, victim)
		delete(bm.confirmAge, victim)
	}
}

func NewBlockPool(params *config.Configuration) *BlockPool {
	return &BlockPool{
		blocks:      make(map[common.Uint256]*types.Block),
		confirms:    make(map[common.Uint256]*payload.Confirm),
		confirmAge:  make(map[common.Uint256]uint32),
		blockSizes:  make(map[common.Uint256]int),
		chainParams: params,
	}
}
