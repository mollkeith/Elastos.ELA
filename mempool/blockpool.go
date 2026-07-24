// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
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
	confirmAge  map[common.Uint256]uint32
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

	bm.blocks[block.Hash()] = block

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
	bm.blocks[block.Hash()] = block
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

	bm.blocks[block.Hash()] = block
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
	// F-092: height-cachedCount underflowed for the first cachedCount heights
	// and wrapped to ~2^32, which dropped the entire pool -- including the
	// block being connected -- during genesis bootstrap.
	var floor uint32
	if height > cachedCount {
		floor = height - cachedCount
	}
	ceiling := ^uint32(0)
	if height <= ceiling-retainAheadCount {
		ceiling = height + retainAheadCount
	}

	for hash, block := range bm.blocks {
		if block.Height < floor || block.Height > ceiling {
			delete(bm.blocks, hash)
			delete(bm.confirms, hash)
			delete(bm.confirmAge, hash)
		}
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
		chainParams: params,
	}
}
