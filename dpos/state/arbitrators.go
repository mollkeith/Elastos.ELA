// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/utils"
)

type ChangeType byte

const (
	// MajoritySignRatioNumerator defines the ratio numerator to achieve
	// majority signatures.
	MajoritySignRatioNumerator = float64(2)

	// MajoritySignRatioDenominator defines the ratio denominator to achieve
	// majority signatures.
	MajoritySignRatioDenominator = float64(3)

	// MaxNormalInactiveChangesCount defines the max count Arbiters can
	// change when more than 1/3 arbiters don't sign cause to confirm fail
	MaxNormalInactiveChangesCount = 3

	// MaxSnapshotLength defines the max length the SnapshotByHeight map should take
	MaxSnapshotLength = 20

	none         = ChangeType(0x00)
	updateNext   = ChangeType(0x01)
	normalChange = ChangeType(0x02)
)

var (
	ErrInsufficientProducer = errors.New("producers count less than min Arbiters count")
)

type ArbiterInfo struct {
	NodePublicKey   []byte
	IsNormal        bool
	IsCRMember      bool
	ClaimedDPOSNode bool
}

type Arbiters struct {
	*State
	*degradation
	ChainParams      *config.Configuration
	CRCommittee      *state.Committee
	bestHeight       func() uint32
	bestBlockHash    func() *common.Uint256
	getBlockByHeight func(uint32) (*types.Block, error)
	CkpManager       *checkpoint.Manager

	mtx sync.Mutex
	// #4: specialTxMtx serializes the whole emergency special-tx bracket
	// (markPendingSpecialTx -> mutate ForceChange -> Commit/UndoPendingSpecialTx)
	// against every OTHER such bracket, so the block-connect goroutine (under
	// blockchain b.mutex) and the DPoS-gossip goroutines (which take only a.mtx)
	// can never interleave a mark/commit/undo. It is acquired OUTSIDE a.mtx by the
	// bracket BOUNDARIES (connectBlock, the InitCheckpoint replay, the gossip
	// callers and the standalone reorg-detach rollback), NOT inside RollbackTo /
	// RollbackSeekTo -- connectBlock's confirm-failure path calls RollbackTo while
	// already holding specialTxMtx, so re-acquiring there would self-deadlock.
	// Lock order is [b.mutex ->] specialTxMtx -> a.mtx (a.mtx/b.IndexLock are the
	// only locks taken while holding it), so there is no inversion.
	specialTxMtx sync.Mutex
	started      bool
	DutyIndex    int

	CurrentReward RewardData
	NextReward    RewardData

	LastDPoSRewards map[string]map[string]common.Fixed64

	LastArbitrators    []ArbiterMember
	CurrentArbitrators []ArbiterMember
	CurrentCandidates  []ArbiterMember
	nextArbitrators    []ArbiterMember
	nextCandidates     []ArbiterMember

	// current cr arbiters map
	CurrentCRCArbitersMap map[common.Uint168]ArbiterMember
	// next cr arbiters map
	nextCRCArbitersMap map[common.Uint168]ArbiterMember
	// next cr arbiters
	nextCRCArbiters []ArbiterMember

	crcChangedHeight           uint32
	accumulativeReward         common.Fixed64
	finalRoundChange           common.Fixed64
	clearingHeight             uint32
	arbitersRoundReward        map[common.Uint168]common.Fixed64
	illegalBlocksPayloadHashes map[common.Uint256]interface{}

	Snapshots                    map[uint32][]*CheckPoint
	SnapshotKeysDesc             []uint32
	BlockConfirmProposalSponsors map[uint32][]byte

	forceChanged bool

	// pendingSpecialTx holds the state captured immediately before the emergency
	// ForceChange of a block's special transactions was applied. It is non-nil only
	// between PreProcessSpecialTx and the moment the carrying block is known to have
	// connected (CommitPendingSpecialTx) or to have failed (UndoPendingSpecialTx).
	pendingSpecialTx *specialTxSavepoint

	History *utils.History
}

// specialTxSavepoint captures every piece of Arbiters state that the emergency
// ForceChange driven by PreProcessSpecialTx mutates, so the whole effect can be
// reversed when the block that carried the special transaction never connects.
// The History part covers the arbiter rotation and the forceChanged flag; the rest
// covers the bookkeeping that lives OUTSIDE History and therefore survives every
// RollbackTo (F-094: degradation.inactiveTxs, illegalBlocksPayloadHashes; F-109
// class: the height-keyed snapshot ring appended by SnapshotByHeight).
type specialTxSavepoint struct {
	history        utils.Savepoint
	degradation    specialTxDegradationState
	illegalHashes  map[common.Uint256]interface{}
	snapshotKeys   []uint32
	snapshotFrames map[uint32]int
}

func (a *Arbiters) Start() {
	a.mtx.Lock()
	a.started = true
	a.mtx.Unlock()
}

func (a *Arbiters) SetNeedRevertToDPOSTX(need bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.NeedRevertToDPOSTX = need
}

func GetOwnerKeyStandardProgramHash(ownerKey []byte) (ownKeyProgramHash *common.Uint168, err error) {
	if len(ownerKey) == crypto.NegativeBigLength {
		ownKeyProgramHash, err = contract.PublicKeyToStandardProgramHash(ownerKey)
	} else {
		ownKeyProgramHash = common.ToProgramHash(byte(contract.PrefixStandard), ownerKey)
	}
	return ownKeyProgramHash, err
}

func (a *Arbiters) SetNeedNextTurnDPOSInfo(need bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.NeedNextTurnDPOSInfo = need
}

func (a *Arbiters) IsInPOWMode() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.isInPOWMode()
}

func (a *Arbiters) isInPOWMode() bool {
	return a.ConsensusAlgorithm == POW
}

func (a *Arbiters) GetRevertToPOWBlockHeight() uint32 {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.RevertToPOWBlockHeight
}

func (a *Arbiters) RegisterFunction(bestHeight func() uint32,
	bestBlockHash func() *common.Uint256,
	getBlockByHeight func(uint32) (*types.Block, error),
	getTxReference func(tx interfaces.Transaction) (
		map[*common2.Input]common2.Output, error)) {
	a.bestHeight = bestHeight
	a.bestBlockHash = bestBlockHash
	a.getBlockByHeight = getBlockByHeight
	a.GetTxReference = getTxReference
}

func (a *Arbiters) IsNeedNextTurnDPOSInfo() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.NeedNextTurnDPOSInfo
}

func (a *Arbiters) RecoverFromCheckPoints(point *CheckPoint) {
	a.mtx.Lock()
	a.recoverFromCheckPoints(point)
	a.mtx.Unlock()
}

func (a *Arbiters) recoverFromCheckPoints(point *CheckPoint) {
	// reset history
	a.History = utils.NewHistory(maxHistoryCapacity)
	a.State.History = utils.NewHistory(maxHistoryCapacity)

	// FV-12 (F-109 class, third site): reset the height-keyed arbiter snapshot ring
	// alongside History. recoverFromCheckPoints replaces the WHOLE derived state from
	// a checkpoint, but the live Arbiters keeps its own Snapshots/SnapshotKeysDesc --
	// so after a deep reset (reorganizeChain's forkCount >= 720 branch, or an
	// OnRollbackTo below StartHeight) the ring still carries frames written by the
	// ABANDONED branch, at exactly the heights the canonical replay will write again.
	// SnapshotByHeight APPENDS to an existing key rather than replacing it, and
	// GetSnapshot returns the whole frame slice, so the two arbiter universes are
	// UNIONED: ProposalContextCheckByHeight / VoteContextCheckByHeight
	// (blockchain/confirmvalidator.go) and the illegal-proposal / illegal-vote
	// transaction validators then accept a signer present in ANY frame at that height,
	// and can mix signers across frames within one confirm. F-082 makes GetSnapshot the
	// AUTHORITATIVE voter universe for illegal-confirm evidence at and above gate 1,
	// which increases -- not decreases -- reliance on this ring.
	//
	// Both fields are pure in-RAM caches: CheckPoint has no Snapshots field, so
	// initFromArbitrators can neither transfer nor clear them, and SnapshotByHeight
	// rebuilds them as the replay proceeds. Nothing is lost.
	//
	// GATE: none, same doctrine as the F-109 prune in RollbackTo -- the ring is only
	// ever polluted on the reorg / deep-reset path, and linear replay of retained
	// history never calls recoverFromCheckPoints with a populated ring (at startup the
	// map is empty, so the Restore -> OnInit path is a no-op here).
	a.Snapshots = make(map[uint32][]*CheckPoint)
	a.SnapshotKeysDesc = make([]uint32, 0)

	a.DutyIndex = point.DutyIndex
	a.LastArbitrators = point.LastArbitrators
	a.CurrentArbitrators = point.CurrentArbitrators
	a.CurrentCandidates = point.CurrentCandidates
	a.nextArbitrators = point.NextArbitrators
	a.nextCandidates = point.NextCandidates
	a.CurrentReward = point.CurrentReward
	a.NextReward = point.NextReward
	a.LastDPoSRewards = point.LastDPoSRewards
	a.StateKeyFrame = &point.StateKeyFrame
	a.accumulativeReward = point.AccumulativeReward
	a.finalRoundChange = point.FinalRoundChange
	a.clearingHeight = point.ClearingHeight
	a.arbitersRoundReward = point.ArbitersRoundReward
	a.illegalBlocksPayloadHashes = point.IllegalBlocksPayloadHashes

	a.crcChangedHeight = point.CRCChangedHeight
	a.CurrentCRCArbitersMap = point.CurrentCRCArbitersMap
	a.nextCRCArbitersMap = point.NextCRCArbitersMap
	a.nextCRCArbiters = point.NextCRCArbiters
	a.forceChanged = point.ForceChanged
	// F-096: restore degradation state so a cold restart does not re-run
	// PreProcessSpecialTx and re-trigger a spurious ForceChange.
	a.degradation.state = degradationState(point.DegradationState)
	a.degradation.understaffedSince = point.UnderstaffedSince
	a.degradation.inactivateHeight = point.InactivateHeight
	// F-096: copy (do not alias the transient CheckPoint map) for consistency with
	// the newCheckPoint/initFromArbitrators capture discipline; copyInactiveTxs
	// returns an empty map for a nil (legacy-checkpoint) source.
	a.degradation.inactiveTxs = copyInactiveTxs(point.InactiveTxs)
	// F-093: a restored checkpoint is a fresh, committed baseline; nothing is pending.
	a.pendingSpecialTx = nil
}

// CommitPendingSpecialTx makes the emergency ForceChange applied by
// ProcessSpecialTxPayload permanent. The block-connect boundary calls it once the
// block is stored, and the gossip entry points call it immediately (they are not
// tied to a block, so their effect is permanent exactly as it was before F-093).
func (a *Arbiters) CommitPendingSpecialTx() {
	a.mtx.Lock()
	a.pendingSpecialTx = nil
	a.mtx.Unlock()
}

// LockSpecialTx / UnlockSpecialTx (#4) are held by the bracket BOUNDARIES around
// the whole mark -> mutate -> commit/undo sequence so no two special-tx brackets
// (block-connect vs DPoS-gossip vs standalone reorg rollback) can interleave.
// They wrap the a.mtx-guarded savepoint methods, acquired outside a.mtx; they are
// deliberately NOT taken inside RollbackTo/RollbackSeekTo, whose undoPendingSpecialTx
// runs either under connectBlock's already-held specialTxMtx or under the reorg
// caller's, so re-acquiring would self-deadlock.
func (a *Arbiters) LockSpecialTx()   { a.specialTxMtx.Lock() }
func (a *Arbiters) UnlockSpecialTx() { a.specialTxMtx.Unlock() }

// UndoPendingSpecialTx reverses the emergency ForceChange applied by
// ProcessSpecialTxPayload for a block that failed to connect. It is a no-op for the
// overwhelming majority of blocks, which carry no special transaction at all, and a
// no-op for every block that connected (its effect was committed).
func (a *Arbiters) UndoPendingSpecialTx() {
	a.mtx.Lock()
	a.undoPendingSpecialTx()
	a.mtx.Unlock()
}

// markPendingSpecialTx captures the pre-special-tx state once per block. Multiple
// InactiveArbitrators payloads in the same block share one savepoint, so all of
// their ForceChanges are reversed together.
func (a *Arbiters) markPendingSpecialTx() {
	a.mtx.Lock()
	if a.pendingSpecialTx == nil {
		a.pendingSpecialTx = a.captureSpecialTxSavepoint()
	}
	a.mtx.Unlock()
}

// undoPendingSpecialTx restores the captured pre-special-tx state. Caller holds mtx.
func (a *Arbiters) undoPendingSpecialTx() {
	if a.pendingSpecialTx == nil {
		return
	}
	sp := a.pendingSpecialTx
	a.pendingSpecialTx = nil
	a.restoreSpecialTxSavepoint(sp)
}

// captureSpecialTxSavepoint snapshots the mutable state reachable from
// ProcessSpecialTxPayload. Caller holds mtx. Read-only: the accepted path is
// byte-identical to the pristine one.
func (a *Arbiters) captureSpecialTxSavepoint() *specialTxSavepoint {
	sp := &specialTxSavepoint{
		history:        a.History.Savepoint(),
		degradation:    a.degradation.captureForSpecialTx(),
		illegalHashes:  copyInactiveTxs(a.illegalBlocksPayloadHashes),
		snapshotKeys:   append([]uint32(nil), a.SnapshotKeysDesc...),
		snapshotFrames: make(map[uint32]int, len(a.Snapshots)),
	}
	for k, v := range a.Snapshots {
		sp.snapshotFrames[k] = len(v)
	}
	return sp
}

// restoreSpecialTxSavepoint puts back the state captured by
// captureSpecialTxSavepoint. Caller holds mtx.
func (a *Arbiters) restoreSpecialTxSavepoint(sp *specialTxSavepoint) {
	a.History.UndoTo(sp.history)
	a.degradation.restoreForSpecialTx(sp.degradation)
	a.illegalBlocksPayloadHashes = copyInactiveTxs(sp.illegalHashes)

	// SnapshotByHeight APPENDS a frame for the force-change height; drop the frames
	// and keys added after the savepoint. A key the ring evicted meanwhile cannot be
	// resurrected, so rebuild the key list from what the map still holds -- the
	// SnapshotKeysDesc/Snapshots invariant must not be broken by the undo.
	for k, frames := range a.Snapshots {
		n, ok := sp.snapshotFrames[k]
		if !ok {
			delete(a.Snapshots, k)
			continue
		}
		if len(frames) > n {
			a.Snapshots[k] = frames[:n]
		}
	}
	keys := make([]uint32, 0, len(sp.snapshotKeys))
	for _, k := range sp.snapshotKeys {
		if _, ok := a.Snapshots[k]; ok {
			keys = append(keys, k)
		}
	}
	a.SnapshotKeysDesc = keys
}

func (a *Arbiters) ProcessBlock(block *types.Block, confirm *payload.Confirm) {
	var sponsor []byte
	if confirm != nil {
		sponsor = confirm.Proposal.Sponsor
		if sp, ok := a.BlockConfirmProposalSponsors[block.Height]; ok {
			sponsor = sp
		}
	}

	a.State.ProcessBlock(block, sponsor, a.DutyIndex)
	a.IncreaseChainHeight(block, confirm)
}

func (a *Arbiters) CheckDPOSIllegalTx(block *types.Block) error {

	a.mtx.Lock()
	hashes := a.illegalBlocksPayloadHashes
	a.mtx.Unlock()

	if len(hashes) == 0 {
		return nil
	}

	foundMap := make(map[common.Uint256]bool)
	for k := range hashes {
		foundMap[k] = false
	}

	for _, tx := range block.Transactions {
		if tx.IsIllegalBlockTx() {
			foundMap[tx.Payload().(*payload.DPOSIllegalBlocks).Hash()] = true
		}
	}

	for _, found := range foundMap {
		if !found {
			return errors.New("expect an illegal blocks transaction in this block")
		}
	}
	return nil
}

func (a *Arbiters) CheckRevertToDPOSTX(block *types.Block) error {
	a.mtx.Lock()
	needRevertToDPOSTX := a.NeedRevertToDPOSTX
	a.mtx.Unlock()

	var revertToDPOSTxCount uint32
	for _, tx := range block.Transactions {
		if tx.IsRevertToDPOS() {
			revertToDPOSTxCount++
		}
	}

	var needRevertToDPOSTXCount uint32
	if needRevertToDPOSTX {
		needRevertToDPOSTXCount = 1
	}

	if revertToDPOSTxCount != needRevertToDPOSTXCount {
		return fmt.Errorf("current block height %d, RevertToDPOSTX "+
			"transaction count should be %d, current block contains %d",
			block.Height, needRevertToDPOSTXCount, revertToDPOSTxCount)
	}

	return nil
}

func (a *Arbiters) CheckNextTurnDPOSInfoTx(block *types.Block) error {
	a.mtx.Lock()
	needNextTurnDposInfo := a.NeedNextTurnDPOSInfo
	a.mtx.Unlock()

	var nextTurnDPOSInfoTxCount uint32
	for _, tx := range block.Transactions {
		if tx.IsNextTurnDPOSInfoTx() {
			nextTurnDPOSInfoTxCount++
		}
	}

	var needNextTurnDPOSInfoCount uint32
	if needNextTurnDposInfo {
		needNextTurnDPOSInfoCount = 1
	}
	if nextTurnDPOSInfoTxCount != needNextTurnDPOSInfoCount {
		return fmt.Errorf("current block height %d, NextTurnDPOSInfo "+
			"transaction count should be %d, current block contains %d",
			block.Height, needNextTurnDPOSInfoCount, nextTurnDPOSInfoTxCount)
	}

	return nil
}

func (a *Arbiters) CheckCRCAppropriationTx(block *types.Block) error {
	a.mtx.Lock()
	needAppropriation := a.CRCommittee.NeedAppropriation
	a.mtx.Unlock()

	var appropriationCount uint32
	for _, tx := range block.Transactions {
		if tx.IsCRCAppropriationTx() {
			appropriationCount++
		}
	}

	var needAppropriationCount uint32
	if needAppropriation {
		needAppropriationCount = 1
	}

	if appropriationCount != needAppropriationCount {
		return fmt.Errorf("current block height %d, appropriation "+
			"transaction count should be %d, current block contains %d",
			block.Height, needAppropriationCount, appropriationCount)
	}

	return nil
}

func (a *Arbiters) CheckCustomIDResultsTx(block *types.Block) error {
	a.mtx.Lock()
	needCustomProposalResult := a.CRCommittee.NeedRecordProposalResult
	a.mtx.Unlock()

	var cidProposalResultCount uint32
	for _, tx := range block.Transactions {
		if tx.IsCustomIDResultTx() {
			cidProposalResultCount++
		}
	}

	var needCIDProposalResultCount uint32
	if needCustomProposalResult {
		needCIDProposalResultCount = 1
	}

	if cidProposalResultCount != needCIDProposalResultCount {
		return fmt.Errorf("current block height %d, custom ID result "+
			"transaction count should be %d, current block contains %d",
			block.Height, needCIDProposalResultCount, cidProposalResultCount)
	}

	return nil
}

func (a *Arbiters) ProcessSpecialTxPayload(p interfaces.Payload,
	height uint32) error {
	// F-093/F-094: the emergency ForceChange below is applied by PreProcessSpecialTx
	// BEFORE block H is validated and stored, and it commits at height H-1 -- so a
	// later failure inside connectBlock leaves the node rotated onto an arbiter set
	// the network rejected, with the payload hash marked processed so the same tx can
	// never force-change again. Capture the pre-state; the block-connect boundary then
	// either commits it (block connected) or undoes it (block rejected).
	a.markPendingSpecialTx()
	switch obj := p.(type) {
	case *payload.DPOSIllegalBlocks:
		a.mtx.Lock()
		a.illegalBlocksPayloadHashes[obj.Hash()] = nil
		a.mtx.Unlock()
	case *payload.InactiveArbitrators:
		if !a.AddInactivePayload(obj) {
			log.Debug("[ProcessSpecialTxPayload] duplicated payload")
			return nil
		}
	default:
		return errors.New("[ProcessSpecialTxPayload] invalid payload type")
	}

	a.State.ProcessSpecialTxPayload(p, height)
	return a.ForceChange(height)
}

func (a *Arbiters) RollbackSeekTo(height uint32) {
	a.mtx.Lock()
	// #2 (F-093 residual): History.commits is incremented by Commit and decremented
	// ONLY by UndoTo; History.RollbackSeekTo pops change groups WITHOUT decrementing
	// commits. An outstanding special-tx savepoint (captured at commits=C) that
	// survived a seek would then let a later UndoTo's `h.commits > sp.commits` loop
	// over-pop groups that predate the savepoint, double-rolling-back committed state
	// below it. Reverse and clear any pending emergency change FIRST -- exactly as
	// RollbackTo:518 already does -- so no savepoint can outlive a seek. No-op on the
	// accepted path (pendingSpecialTx == nil). GATE: none (reorg/seek-only path;
	// mirrors the ungated undoPendingSpecialTx in RollbackTo).
	a.undoPendingSpecialTx()
	a.History.RollbackSeekTo(height)
	a.State.RollbackSeekTo(height)
	a.mtx.Unlock()
}

func (a *Arbiters) RollbackTo(height uint32) error {
	a.mtx.Lock()
	// F-093: a rollback must never leave behind a special-tx effect whose carrying
	// block has not connected. History.RollbackTo is strictly-greater-than, so the
	// ForceChange committed at block.Height-1 is invisible to it.
	a.undoPendingSpecialTx()
	a.History.RollbackTo(height)
	a.degradation.RollbackTo(height)
	err := a.State.RollbackTo(height)
	// F-109: prune height-keyed arbiter snapshots ABOVE the rollback target. SnapshotByHeight
	// APPENDS (not replaces) on an existing key, so a reorg that left stale snapshots >height
	// would corrupt later snapshot lookups. Reorg-only path (linear sync never calls
	// RollbackTo), so committed state replays byte-identically.
	newDesc := a.SnapshotKeysDesc[:0]
	for _, k := range a.SnapshotKeysDesc {
		if k > height {
			delete(a.Snapshots, k)
		} else {
			newDesc = append(newDesc, k)
		}
	}
	a.SnapshotKeysDesc = newDesc
	a.mtx.Unlock()

	return err
}

func (a *Arbiters) GetDutyIndexByHeight(height uint32) (index int) {
	a.mtx.Lock()
	if height >= a.ChainParams.DPoSConfiguration.DPOSNodeCrossChainHeight {
		if len(a.CurrentArbitrators) == 0 {
			index = 0
		} else {
			index = a.DutyIndex % len(a.CurrentArbitrators)
		}
	} else if height >= a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
		if len(a.CurrentCRCArbitersMap) == 0 {
			index = 0
		} else {
			index = a.DutyIndex % len(a.CurrentCRCArbitersMap)
		}
	} else if height >= a.ChainParams.CRCOnlyDPOSHeight-1 {
		if len(a.CurrentCRCArbitersMap) == 0 {
			index = 0
		} else {
			index = int(height-a.ChainParams.CRCOnlyDPOSHeight+1) % len(a.CurrentCRCArbitersMap)
		}
	} else {
		if len(a.CurrentArbitrators) == 0 {
			index = 0
		} else {
			index = int(height) % len(a.CurrentArbitrators)
		}
	}
	a.mtx.Unlock()
	return index
}

func (a *Arbiters) GetDutyIndex() int {
	a.mtx.Lock()
	index := a.DutyIndex
	a.mtx.Unlock()

	return index
}

func (a *Arbiters) GetArbitersRoundReward() map[common.Uint168]common.Fixed64 {
	a.mtx.Lock()
	result := a.arbitersRoundReward
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetFinalRoundChange() common.Fixed64 {
	a.mtx.Lock()
	result := a.finalRoundChange
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetLastBlockTimestamp() uint32 {
	a.mtx.Lock()
	result := a.LastBlockTimestamp
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) ForceChange(height uint32) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.forceChange(height)
}

func (a *Arbiters) forceChange(height uint32) error {
	block, err := a.getBlockByHeight(height)
	if err != nil {
		block, err = a.getBlockByHeight(a.bestHeight())
		if err != nil {
			return err
		}
	}
	a.SnapshotByHeight(height)

	if !a.isDPoSV2Run(block.Height) {
		if err := a.clearingDPOSReward(block, block.Height, false); err != nil {
			panic(fmt.Sprintf("normal change fail when clear DPOS reward: "+
				" transaction, height: %d, error: %s", block.Height, err))
		}
	}

	if err := a.UpdateNextArbitrators(height+1, height); err != nil {
		log.Info("force change failed at height:", height)
		return err
	}

	if err := a.ChangeCurrentArbitrators(height); err != nil {
		return err
	}

	if a.started {
		currentArbiters := a.getCurrentNeedConnectArbiters()
		nextArbiters := a.getNextNeedConnectArbiters()
		crArbiters := a.getNeedConnectCRArbiters()

		go events.Notify(events.ETDirectPeersChanged,
			&peer.PeersInfo{
				CurrentPeers: currentArbiters,
				NextPeers:    nextArbiters,
				CRPeers:      crArbiters})
	}
	oriForceChanged := a.forceChanged
	a.History.Append(height, func() {
		a.forceChanged = true
	}, func() {
		a.forceChanged = oriForceChanged
	})
	a.History.Commit(height)

	a.dumpInfo(height)
	return nil
}

func (a *Arbiters) tryHandleError(height uint32, err error) error {
	if err == ErrInsufficientProducer {
		log.Warn("found error: ", err, ", degrade to CRC only state")
		a.TrySetUnderstaffed(height)
		return nil
	} else {
		return err
	}
}

func (a *Arbiters) normalChange(height uint32) error {
	if err := a.ChangeCurrentArbitrators(height); err != nil {
		log.Warn("[NormalChange] change current arbiters error: ", err)
		return err
	}
	if err := a.UpdateNextArbitrators(height+1, height); err != nil {
		log.Warn("[NormalChange] update next arbiters error: ", err)
		return err
	}
	return nil
}

func (a *Arbiters) notifyNextTurnDPOSInfoTx(blockHeight, versionHeight uint32, forceChange bool) {
	if blockHeight > a.ChainParams.DPoSConfiguration.DexStartHeight {
		nextTurnDPOSInfoTx := a.createNextTurnDPOSInfoTransactionV2(blockHeight, forceChange)
		go events.Notify(events.ETAppendTxToTxPool, nextTurnDPOSInfoTx)

		return
	}

	if blockHeight+uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount+len(a.ChainParams.DPoSConfiguration.CRCArbiters)) >= a.DPoSV2ActiveHeight {
		nextTurnDPOSInfoTx := a.createNextTurnDPOSInfoTransactionV1(blockHeight, forceChange)
		go events.Notify(events.ETAppendTxToTxPool, nextTurnDPOSInfoTx)

		return
	}

	nextTurnDPOSInfoTx := a.createNextTurnDPOSInfoTransactionV0(blockHeight, forceChange)
	go events.Notify(events.ETAppendTxToTxPool, nextTurnDPOSInfoTx)

	return
}

func (a *Arbiters) IncreaseChainHeight(block *types.Block, confirm *payload.Confirm) {
	var notify = true
	var snapshotVotes = true
	a.mtx.Lock()
	var containsIllegalBlockEvidence bool
	for _, tx := range block.Transactions {
		if tx.IsIllegalBlockTx() {
			containsIllegalBlockEvidence = true
			break
		}
	}
	var forceChanged bool
	if containsIllegalBlockEvidence {
		if err := a.forceChange(block.Height); err != nil {
			log.Errorf("Found illegal blocks, ForceChange failed:%s", err)
			a.cleanArbitrators(block.Height)
			a.revertToPOWAtNextTurn(block.Height)
			log.Warn(fmt.Sprintf("force change fail at height: %d, error: %s",
				block.Height, err))
		}
		forceChanged = true
	} else {
		changeType, versionHeight := a.getChangeType(block.Height + 1)
		switch changeType {
		case updateNext:
			if err := a.UpdateNextArbitrators(versionHeight, block.Height); err != nil {
				a.revertToPOWAtNextTurn(block.Height)
				log.Warn(fmt.Sprintf("update next arbiters at height: %d, "+
					"error: %s, revert to POW mode", block.Height, err))
			}
		case normalChange:
			if a.isDPoSV2Run(block.Height) {
				if block.Height == a.DPoSV2ActiveHeight {
					if err := a.clearingDPOSReward(block, block.Height, true); err != nil {
						panic(fmt.Sprintf("normal change fail when clear DPOS reward: "+
							" transaction, height: %d, error: %s", block.Height, err))
					}
				} else {
					a.accumulateReward(block, confirm)
				}
			} else {
				if err := a.clearingDPOSReward(block, block.Height, true); err != nil {
					panic(fmt.Sprintf("normal change fail when clear DPOS reward: "+
						" transaction, height: %d, error: %s", block.Height, err))
				}
			}
			if err := a.normalChange(block.Height); err != nil {
				a.revertToPOWAtNextTurn(block.Height)
				log.Warn(fmt.Sprintf("normal change fail at height: %d, "+
					"error: %s， revert to POW mode", block.Height, err))
			}
		case none:
			a.accumulateReward(block, confirm)
			notify = false
			snapshotVotes = false
		}
	}

	oriIllegalBlocks := a.illegalBlocksPayloadHashes
	a.History.Append(block.Height, func() {
		a.illegalBlocksPayloadHashes = make(map[common.Uint256]interface{})
	}, func() {
		a.illegalBlocksPayloadHashes = oriIllegalBlocks
	})
	a.History.Commit(block.Height)
	bestHeight := a.bestHeight()
	if a.ConsensusAlgorithm != POW && block.Height >= bestHeight {
		if len(a.CurrentArbitrators) == 0 && (a.NoClaimDPOSNode || a.NoProducers) {
			a.createRevertToPOWTransaction(block.Height)
		}
	}
	if snapshotVotes {
		if err := a.snapshotVotesStates(block.Height); err != nil {
			panic(fmt.Sprintf("snap shot votes states error:%s", err))
		}
		a.History.Commit(block.Height)
	}
	if block.Height > bestHeight-MaxSnapshotLength {
		a.SnapshotByHeight(block.Height)
	}
	if block.Height >= bestHeight && (a.NeedNextTurnDPOSInfo || forceChanged) {
		a.notifyNextTurnDPOSInfoTx(block.Height, block.Height+1, forceChanged)
	}
	a.mtx.Unlock()
	if a.started && notify {
		currentArbiters := a.GetCurrentNeedConnectArbiters()
		nextArbiters := a.GetNextNeedConnectArbiters()
		crArbiters := a.GetNeedConnectCRArbiters()

		go events.Notify(events.ETDirectPeersChanged,
			&peer.PeersInfo{
				CurrentPeers: currentArbiters,
				NextPeers:    nextArbiters,
				CRPeers:      crArbiters})
	}
}

func (a *Arbiters) createRevertToPOWTransaction(blockHeight uint32) {

	var revertType payload.RevertType
	if a.NoProducers {
		revertType = payload.NoProducers
	} else {
		if blockHeight > a.DPoSV2ActiveHeight {
			log.Info("no need to create no claim DPoS node transaction")
			return
		}
		revertType = payload.NoClaimDPOSNode
	}
	revertToPOWPayload := payload.RevertToPOW{
		Type:          revertType,
		WorkingHeight: blockHeight + 1,
	}
	tx := functions.CreateTransaction(
		common2.TxVersion09,
		common2.RevertToPOW,
		payload.RevertToPOWVersion,
		&revertToPOWPayload,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
	go events.Notify(events.ETAppendTxToTxPoolWithoutRelay, tx)
}

func (a *Arbiters) revertToPOWAtNextTurn(height uint32) {
	oriNextArbitrators := a.nextArbitrators
	oriNextCandidates := a.nextCandidates
	oriNextCRCArbitersMap := a.nextCRCArbitersMap
	oriNextCRCArbiters := a.nextCRCArbiters
	oriNoProducers := a.NoProducers

	a.History.Append(height, func() {
		a.nextArbitrators = make([]ArbiterMember, 0)
		a.nextCandidates = make([]ArbiterMember, 0)
		a.nextCRCArbitersMap = make(map[common.Uint168]ArbiterMember)
		a.nextCRCArbiters = make([]ArbiterMember, 0)
		if a.ConsensusAlgorithm == DPOS {
			a.NoProducers = true
		}
	}, func() {
		a.nextArbitrators = oriNextArbitrators
		a.nextCandidates = oriNextCandidates
		a.nextCRCArbitersMap = oriNextCRCArbitersMap
		a.nextCRCArbiters = oriNextCRCArbiters
		a.NoProducers = oriNoProducers
	})
}
func (a *Arbiters) AccumulateReward(block *types.Block, confirm *payload.Confirm) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.accumulateReward(block, confirm)
}

// is already DPoS V2. when we are here we need new reward.
func (a *Arbiters) IsDPoSV2Run(blockHeight uint32) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.isDPoSV2Run(blockHeight)
}

func (a *Arbiters) GetDPoSV2ActiveHeight() uint32 {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.DPoSV2ActiveHeight
}

// is already DPoS V2. when we are here we need new reward.
func (a *Arbiters) isDPoSV2Run(blockHeight uint32) bool {
	return blockHeight >= a.DPoSV2ActiveHeight
}

func (a *Arbiters) getDPoSV2RewardsV2(dposReward common.Fixed64, sponsor []byte, height uint32) (rewards map[string]common.Fixed64) {
	log.Debugf("accumulateReward dposReward %v", dposReward)

	rewards = make(map[string]common.Fixed64)
	var isCR bool
	for _, cr := range a.CurrentCRCArbitersMap {
		if bytes.Equal(sponsor, cr.GetNodePublicKey()) {
			ownerProgramHash, _ := GetOwnerKeyStandardProgramHash(cr.GetOwnerPublicKey())
			stakeProgramHash := common.Uint168FromCodeHash(
				byte(contract.PrefixDPoSV2), ownerProgramHash.ToCodeHash())
			ownerAddr, _ := stakeProgramHash.ToAddress()
			rewards[ownerAddr] += dposReward
			isCR = true
			break
		}
	}

	if !isCR {
		// DPoS votes reward is: reward * 3 /4
		votesReward := dposReward * 3 / 4

		producer := a.getProducer(sponsor)
		if producer == nil {
			log.Error("v2 accumulateReward Sponsor not exist ", hex.EncodeToString(sponsor))
			return
		}
		ownerProgramHash, _ := GetOwnerKeyStandardProgramHash(producer.OwnerPublicKey())
		stakeProgramHash := common.Uint168FromCodeHash(
			byte(contract.PrefixDPoSV2), ownerProgramHash.ToCodeHash())
		ownerAddr, _ := stakeProgramHash.ToAddress()

		producersN := make(map[common.Uint168]float64)

		var totalNI float64
		for sVoteAddr, sVoteDetail := range producer.detailedDPoSV2Votes {
			if len(sVoteDetail) == 0 {
				continue
			}
			var totalN float64
			for _, votes := range sVoteDetail {
				totalN += float64(votes.VoteRights())
			}
			if totalN == 0 {
				continue
			}
			producersN[sVoteAddr] = totalN
			totalNI += totalN
		}

		for sVoteAddr, N := range producersN {
			addr, _ := sVoteAddr.ToAddress()
			p := N / totalNI * float64(votesReward)
			rewards[addr] += common.Fixed64(p)
			log.Debugf("getDPoSV2Rewards addr:%s, p:%s, reward:%s \n", addr, common.Fixed64(p), rewards[addr])
		}

		var totalUsedVotesReward common.Fixed64
		for _, v := range rewards {
			totalUsedVotesReward += v
		}

		// DPoS node reward is: reward - totalUsedVotesReward
		dposNodeReward := dposReward - totalUsedVotesReward
		rewards[ownerAddr] += dposNodeReward
		log.Debugf("getDPoSV2Rewards totalUsedVotesReward %s dposNodeReward %s,  \n", totalUsedVotesReward, dposNodeReward)
	}

	return rewards
}

// NX-01: CheckRecordSponsorBinding (F-032) is DELETED, not merely unwired. It made block
// validity a function of lastBlock.Confirm.Proposal.Sponsor -- a per-node stored value no
// block hash or signature commits to, which the miner reads raw while this function
// resolved it through BlockConfirmProposalSponsors, and which honest nodes legitimately
// disagree about after a DPoS view change. See blockchain/blockvalidator.go
// CheckBlockContext for the full rationale and for the diagnostic that replaced it.
// It is deleted rather than left in place because a guard with no production caller reads
// as armed while enforcing nothing; if a sponsor-binding rule is ever wanted again it must
// be derived from data the chain commits to, never from the stored confirm.

func (a *Arbiters) accumulateReward(block *types.Block, confirm *payload.Confirm) {
	if block.Height < a.ChainParams.PublicDPOSHeight {
		oriDutyIndex := a.DutyIndex
		a.History.Append(block.Height, func() {
			a.DutyIndex = oriDutyIndex + 1
		}, func() {
			a.DutyIndex = oriDutyIndex
		})
		return
	}

	var accumulative common.Fixed64
	accumulative = a.accumulativeReward
	var dposReward common.Fixed64
	if block.Height < a.ChainParams.CRConfiguration.CRVotingStartHeight || !a.forceChanged {
		dposReward = a.getBlockDPOSReward(block)
		accumulative += dposReward
	}

	if a.isDPoSV2Run(block.Height) {
		log.Debugf("accumulateReward dposReward %v", dposReward)
		oriDutyIndex := a.DutyIndex
		oriForceChanged := a.forceChanged

		var rewards map[string]common.Fixed64

		// need record rewards after RecordSponsorStartHeight, real reward at next block.
		if block.Height >= a.ChainParams.DPoSConfiguration.RecordSponsorStartHeight {
			possibleRewards := make(map[string]map[string]common.Fixed64)
			if confirm != nil {
				for _, arb := range a.CurrentArbitrators {
					arbNodePK := arb.GetNodePublicKey()
					rew := a.getDPoSV2RewardsV2(dposReward, arbNodePK, block.Height)
					possibleRewards[common.BytesToHexString(arbNodePK)] = rew
				}
			}
			var existSponsorTx bool
			var recordedSponsor string
			for _, tx := range block.Transactions {
				if tx.IsRecordSponorTx() {
					existSponsorTx = true
					pld := tx.Payload().(*payload.RecordSponsor)
					recordedSponsor = common.BytesToHexString(pld.Sponsor)
				}
			}
			if existSponsorTx {
				rewards = a.LastDPoSRewards[recordedSponsor]
			}

			originRewardsMap := copyDPoSRewardMap(a.LastDPoSRewards)
			a.History.Append(block.Height, func() {
				a.LastDPoSRewards = possibleRewards
			}, func() {
				a.LastDPoSRewards = originRewardsMap
			})

		} else {
			if confirm != nil {
				// get sponsor from cache first
				sponsor := confirm.Proposal.Sponsor
				if sp, ok := a.BlockConfirmProposalSponsors[block.Height]; ok {
					sponsor = sp
				}
				rewards = a.getDPoSV2RewardsV2(dposReward, sponsor, block.Height)
			}
		}

		a.History.Append(block.Height, func() {
			for k, v := range rewards {
				a.DPoSV2RewardInfo[k] += v
			}
			a.forceChanged = false
			a.DutyIndex = oriDutyIndex + 1
		}, func() {
			for k, v := range rewards {
				a.DPoSV2RewardInfo[k] -= v
			}
			a.forceChanged = oriForceChanged
			a.DutyIndex = oriDutyIndex
		})

	} else {
		oriAccumulativeReward := a.accumulativeReward
		oriArbitersRoundReward := a.arbitersRoundReward
		oriFinalRoundChange := a.finalRoundChange
		oriForceChanged := a.forceChanged
		oriDutyIndex := a.DutyIndex
		a.History.Append(block.Height, func() {
			a.accumulativeReward = accumulative
			a.arbitersRoundReward = nil
			a.finalRoundChange = 0
			a.forceChanged = false
			a.DutyIndex = oriDutyIndex + 1
		}, func() {
			a.accumulativeReward = oriAccumulativeReward
			a.arbitersRoundReward = oriArbitersRoundReward
			a.finalRoundChange = oriFinalRoundChange
			a.forceChanged = oriForceChanged
			a.DutyIndex = oriDutyIndex
		})
	}
}

func (a *Arbiters) clearingDPOSReward(block *types.Block, historyHeight uint32,
	smoothClearing bool) (err error) {
	if block.Height < a.ChainParams.PublicDPOSHeight ||
		block.Height == a.clearingHeight {
		return nil
	}

	dposReward := a.getBlockDPOSReward(block)
	accumulativeReward := a.accumulativeReward
	if smoothClearing {
		accumulativeReward += dposReward
		dposReward = 0
	}

	var change common.Fixed64
	var roundReward map[common.Uint168]common.Fixed64
	if roundReward, change, err = a.distributeDPOSReward(block.Height,
		accumulativeReward); err != nil {
		return
	}

	oriRoundReward := a.arbitersRoundReward
	oriAccumulativeReward := a.accumulativeReward
	oriClearingHeight := a.clearingHeight
	oriChange := a.finalRoundChange
	a.History.Append(historyHeight, func() {
		a.arbitersRoundReward = roundReward
		a.accumulativeReward = dposReward
		a.clearingHeight = block.Height
		a.finalRoundChange = change
	}, func() {
		a.arbitersRoundReward = oriRoundReward
		a.accumulativeReward = oriAccumulativeReward
		a.clearingHeight = oriClearingHeight
		a.finalRoundChange = oriChange
	})

	return nil
}

func (a *Arbiters) distributeDPOSReward(height uint32,
	reward common.Fixed64) (roundReward map[common.Uint168]common.Fixed64,
	change common.Fixed64, err error) {
	var realDPOSReward common.Fixed64
	if height >= a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight+2*uint32(len(a.CurrentArbitrators)) {
		roundReward, realDPOSReward, err = a.distributeWithNormalArbitratorsV3(height, reward)
	} else if height >= a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight+2*uint32(len(a.CurrentArbitrators)) {
		roundReward, realDPOSReward, err = a.distributeWithNormalArbitratorsV2(height, reward)
	} else if height >= a.ChainParams.CRConfiguration.CRCommitteeStartHeight+2*uint32(len(a.CurrentArbitrators)) {
		roundReward, realDPOSReward, err = a.distributeWithNormalArbitratorsV1(height, reward)
	} else {
		roundReward, realDPOSReward, err = a.distributeWithNormalArbitratorsV0(height, reward)
	}

	if err != nil {
		return nil, 0, err
	}

	change = reward - realDPOSReward
	if change < 0 {
		log.Error("reward:", reward, "realDPOSReward:", realDPOSReward, "height:", height,
			"b", a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight+2*uint32(len(a.CurrentArbitrators)),
			"c", a.ChainParams.CRConfiguration.CRCommitteeStartHeight+2*uint32(len(a.CurrentArbitrators)))
		return nil, 0, errors.New("real dpos reward more than reward limit")
	}

	return
}

func (a *Arbiters) distributeWithNormalArbitratorsV3(height uint32, reward common.Fixed64) (
	map[common.Uint168]common.Fixed64, common.Fixed64, error) {
	//if len(a.CurrentArbitrators) == 0 {
	//	return nil, 0, errors.New("not found arbiters when " +
	//		"distributeWithNormalArbitratorsV3")
	//}

	roundReward := map[common.Uint168]common.Fixed64{}
	totalBlockConfirmReward := float64(reward) * 0.25
	totalTopProducersReward := float64(reward) - totalBlockConfirmReward
	// Consider that there is no only CR consensus.
	arbitersCount := len(a.ChainParams.DPoSConfiguration.CRCArbiters) +
		a.ChainParams.DPoSConfiguration.NormalArbitratorsCount
	individualBlockConfirmReward := common.Fixed64(
		math.Floor(totalBlockConfirmReward / float64(arbitersCount)))
	totalVotesInRound := a.CurrentReward.TotalVotesInRound
	log.Debugf("distributeWithNormalArbitratorsV3 TotalVotesInRound %f", a.CurrentReward.TotalVotesInRound)
	if a.ConsensusAlgorithm == POW || len(a.CurrentArbitrators) == 0 ||
		len(a.ChainParams.DPoSConfiguration.CRCArbiters) == len(a.CurrentArbitrators) {
		// if no normal DPOS node, need to destroy reward.
		roundReward[*a.ChainParams.DestroyELAProgramHash] = reward
		return roundReward, reward, nil
	}
	log.Debugf("totalTopProducersReward totalTopProducersReward %f", totalTopProducersReward)
	rewardPerVote := totalTopProducersReward / float64(totalVotesInRound)
	realDPOSReward := common.Fixed64(0)
	for _, arbiter := range a.CurrentArbitrators {
		ownerHash := arbiter.GetOwnerProgramHash()
		rewardHash := ownerHash
		var r common.Fixed64
		if arbiter.GetType() == CRC {
			r = individualBlockConfirmReward
			log.Debugf("000 r =individualBlockConfirmReward %s", individualBlockConfirmReward.String())
			m, ok := arbiter.(*crcArbiter)
			if !ok || m.crMember.MemberState != state.MemberElected {
				rewardHash = *a.ChainParams.DestroyELAProgramHash
			} else if len(m.crMember.DPOSPublicKey) == 0 {
				nodePK := arbiter.GetNodePublicKey()
				ownerPK := a.getProducerKey(nodePK)
				opk, err := common.HexStringToBytes(ownerPK)
				if err != nil {
					panic("get owner public key err:" + err.Error())
				}
				programHash, err := GetOwnerKeyStandardProgramHash(opk)
				if err != nil {
					panic("public key to standard program hash err:" + err.Error())
				}
				votes := a.CurrentReward.OwnerVotesInRound[*programHash]
				individualCRCProducerReward := common.Fixed64(math.Floor(float64(
					votes) * rewardPerVote))
				r = individualBlockConfirmReward + individualCRCProducerReward
				rewardHash = *programHash
				log.Debugf("111 rewardHash%s  individualCRCProducerReward %s individualBlockConfirmReward %s votes %s", rewardHash.String(),
					individualCRCProducerReward.String(), individualBlockConfirmReward.String(), votes.String())
			} else {
				pk := arbiter.GetOwnerPublicKey()
				programHash, err := GetOwnerKeyStandardProgramHash(pk)
				if err != nil {
					rewardHash = *a.ChainParams.DestroyELAProgramHash
				} else {
					rewardHash = *programHash
				}
			}
		} else {
			votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
			individualProducerReward := common.Fixed64(math.Floor(float64(
				votes) * rewardPerVote))
			r = individualBlockConfirmReward + individualProducerReward
			log.Debugf("222 ownerHash%s  individualProducerReward %s individualBlockConfirmReward %s rewardPerVote %f", ownerHash.String(),
				individualProducerReward.String(), individualBlockConfirmReward.String(), rewardPerVote)
		}
		roundReward[rewardHash] += r
		realDPOSReward += r
		log.Debugf("333 distributeWithNormalArbitratorsV3 rewardHash%s  r %s realDPOSReward %s", rewardHash.String(),
			r.String(), realDPOSReward.String())
	}

	for _, candidate := range a.CurrentCandidates {
		ownerHash := candidate.GetOwnerProgramHash()
		votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
		individualProducerReward := common.Fixed64(math.Floor(float64(
			votes) * rewardPerVote))
		roundReward[ownerHash] = individualProducerReward
		log.Debugf("444 distributeWithNormalArbitratorsV3 ownerHash%s  individualProducerReward %s realDPOSReward %s",
			ownerHash.String(), individualProducerReward.String(), realDPOSReward.String())
		realDPOSReward += individualProducerReward
	}
	// Abnormal CR`s reward need to be destroyed.
	for i := len(a.CurrentArbitrators); i < arbitersCount; i++ {
		roundReward[*a.ChainParams.DestroyELAProgramHash] += individualBlockConfirmReward
		// F-212 (Q-B7): also account the destroyed empty-slot reward in realDPOSReward.
		// Otherwise the caller's `change = reward - realDPOSReward` over-states change by
		// the destroyed total and re-mints it to the CR+miner legs — the empty-slot reward
		// is emitted TWICE (once burned, once spendable). Gated at RevisedDPoSRewardHeight
		// (a fresh future height per the engineers, NOT the incident gate); below it the
		// legacy double-count is preserved byte-identically for replay. The empty-slot
		// reward is deterministic across nodes, so no split.
		if height >= a.ChainParams.RevisedDPoSRewardHeight {
			realDPOSReward += individualBlockConfirmReward
		}
	}
	return roundReward, realDPOSReward, nil
}

func (a *Arbiters) distributeWithNormalArbitratorsV2(height uint32, reward common.Fixed64) (
	map[common.Uint168]common.Fixed64, common.Fixed64, error) {
	//if len(a.CurrentArbitrators) == 0 {
	//	return nil, 0, errors.New("not found arbiters when " +
	//		"distributeWithNormalArbitratorsV2")
	//}
	roundReward := map[common.Uint168]common.Fixed64{}
	totalBlockConfirmReward := float64(reward) * 0.25
	totalTopProducersReward := float64(reward) - totalBlockConfirmReward
	// Consider that there is no only CR consensus.
	arbitersCount := len(a.ChainParams.DPoSConfiguration.CRCArbiters) + a.ChainParams.DPoSConfiguration.NormalArbitratorsCount
	individualBlockConfirmReward := common.Fixed64(
		math.Floor(totalBlockConfirmReward / float64(arbitersCount)))
	totalVotesInRound := a.CurrentReward.TotalVotesInRound
	if len(a.CurrentArbitrators) == 0 ||
		len(a.ChainParams.DPoSConfiguration.CRCArbiters) == len(a.CurrentArbitrators) {
		//if len(a.ChainParams.CRCArbiters) == len(a.CurrentArbitrators) {
		// if no normal DPOS node, need to destroy reward.
		roundReward[*a.ChainParams.DestroyELAProgramHash] = reward
		return roundReward, reward, nil
	}
	rewardPerVote := totalTopProducersReward / float64(totalVotesInRound)

	realDPOSReward := common.Fixed64(0)
	for _, arbiter := range a.CurrentArbitrators {
		ownerHash := arbiter.GetOwnerProgramHash()
		rewardHash := ownerHash
		var r common.Fixed64
		if _, ok := a.CurrentCRCArbitersMap[ownerHash]; ok {
			r = individualBlockConfirmReward
			m, ok := arbiter.(*crcArbiter)
			if !ok || m.crMember.MemberState != state.MemberElected || len(m.crMember.DPOSPublicKey) == 0 {
				rewardHash = *a.ChainParams.DestroyELAProgramHash
			} else {
				pk := arbiter.GetOwnerPublicKey()
				programHash, err := GetOwnerKeyStandardProgramHash(pk)
				if err != nil {
					rewardHash = *a.ChainParams.DestroyELAProgramHash
				} else {
					rewardHash = *programHash
				}
			}
		} else {
			votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
			individualProducerReward := common.Fixed64(math.Floor(float64(
				votes) * rewardPerVote))
			r = individualBlockConfirmReward + individualProducerReward
		}
		roundReward[rewardHash] += r
		realDPOSReward += r
	}
	for _, candidate := range a.CurrentCandidates {
		ownerHash := candidate.GetOwnerProgramHash()
		votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
		individualProducerReward := common.Fixed64(math.Floor(float64(
			votes) * rewardPerVote))
		roundReward[ownerHash] = individualProducerReward

		realDPOSReward += individualProducerReward
	}
	// Abnormal CR`s reward need to be destroyed.
	for i := len(a.CurrentArbitrators); i < arbitersCount; i++ {
		roundReward[*a.ChainParams.DestroyELAProgramHash] += individualBlockConfirmReward
		// F-212 (Q-B7): also account the destroyed empty-slot reward in realDPOSReward.
		// Otherwise the caller's `change = reward - realDPOSReward` over-states change by
		// the destroyed total and re-mints it to the CR+miner legs — the empty-slot reward
		// is emitted TWICE (once burned, once spendable). Gated at RevisedDPoSRewardHeight
		// (a fresh future height per the engineers, NOT the incident gate); below it the
		// legacy double-count is preserved byte-identically for replay. The empty-slot
		// reward is deterministic across nodes, so no split.
		if height >= a.ChainParams.RevisedDPoSRewardHeight {
			realDPOSReward += individualBlockConfirmReward
		}
	}
	return roundReward, realDPOSReward, nil
}

func (a *Arbiters) distributeWithNormalArbitratorsV1(height uint32, reward common.Fixed64) (
	map[common.Uint168]common.Fixed64, common.Fixed64, error) {
	if len(a.CurrentArbitrators) == 0 {
		return nil, 0, errors.New("not found arbiters when " +
			"distributeWithNormalArbitratorsV1")
	}
	roundReward := map[common.Uint168]common.Fixed64{}
	totalBlockConfirmReward := float64(reward) * 0.25
	totalTopProducersReward := float64(reward) - totalBlockConfirmReward
	individualBlockConfirmReward := common.Fixed64(
		math.Floor(totalBlockConfirmReward / float64(len(a.CurrentArbitrators))))
	totalVotesInRound := a.CurrentReward.TotalVotesInRound
	if len(a.ChainParams.DPoSConfiguration.CRCArbiters) == len(a.CurrentArbitrators) {
		roundReward[*a.ChainParams.CRConfiguration.CRCProgramHash] = reward
		return roundReward, reward, nil
	}
	rewardPerVote := totalTopProducersReward / float64(totalVotesInRound)
	realDPOSReward := common.Fixed64(0)
	for _, arbiter := range a.CurrentArbitrators {
		ownerHash := arbiter.GetOwnerProgramHash()
		rewardHash := ownerHash
		var r common.Fixed64
		if _, ok := a.CurrentCRCArbitersMap[ownerHash]; ok {
			r = individualBlockConfirmReward
			m, ok := arbiter.(*crcArbiter)
			if !ok || m.crMember.MemberState != state.MemberElected {
				rewardHash = *a.ChainParams.DestroyELAProgramHash
			} else {
				pk := arbiter.GetOwnerPublicKey()
				programHash, err := GetOwnerKeyStandardProgramHash(pk)
				if err != nil {
					rewardHash = *a.ChainParams.DestroyELAProgramHash
				} else {
					rewardHash = *programHash
				}
			}
		} else {
			votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
			individualProducerReward := common.Fixed64(math.Floor(float64(
				votes) * rewardPerVote))
			r = individualBlockConfirmReward + individualProducerReward
		}
		roundReward[rewardHash] += r
		realDPOSReward += r
	}
	for _, candidate := range a.CurrentCandidates {
		ownerHash := candidate.GetOwnerProgramHash()
		votes := a.CurrentReward.OwnerVotesInRound[ownerHash]
		individualProducerReward := common.Fixed64(math.Floor(float64(
			votes) * rewardPerVote))
		roundReward[ownerHash] = individualProducerReward

		realDPOSReward += individualProducerReward
	}
	return roundReward, realDPOSReward, nil
}

func (a *Arbiters) GetCurrentNeedConnectArbiters() []peer.PID {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.getCurrentNeedConnectArbiters()
}

func (a *Arbiters) getCurrentNeedConnectArbiters() []peer.PID {
	height := a.History.Height() + 1
	if height < a.ChainParams.CRCOnlyDPOSHeight-a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return nil
	}

	pids := make(map[string]peer.PID)
	for _, v := range a.CurrentArbitrators {
		key := common.BytesToHexString(v.GetNodePublicKey())
		var pid peer.PID
		copy(pid[:], v.GetNodePublicKey())
		pids[key] = pid
	}

	peers := make([]peer.PID, 0, len(pids))
	for _, pid := range pids {
		peers = append(peers, pid)
	}

	return peers
}

func (a *Arbiters) GetNextNeedConnectArbiters() []peer.PID {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.getNextNeedConnectArbiters()
}

func (a *Arbiters) getNextNeedConnectArbiters() []peer.PID {
	height := a.History.Height() + 1
	if height < a.ChainParams.CRCOnlyDPOSHeight-a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return nil
	}

	pids := make(map[string]peer.PID)
	for _, v := range a.nextArbitrators {
		key := common.BytesToHexString(v.GetNodePublicKey())
		var pid peer.PID
		copy(pid[:], v.GetNodePublicKey())
		pids[key] = pid
	}

	peers := make([]peer.PID, 0, len(pids))
	for _, pid := range pids {
		peers = append(peers, pid)
	}

	return peers
}

func (a *Arbiters) GetNeedConnectCRArbiters() []peer.PID {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.getNeedConnectCRArbiters()
}

func (a *Arbiters) getNeedConnectCRArbiters() []peer.PID {
	height := a.History.Height() + 1
	if height < a.ChainParams.CRCOnlyDPOSHeight-a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return nil
	}

	pids := make(map[string]peer.PID)
	for _, p := range a.CurrentCRCArbitersMap {
		abt, ok := p.(*crcArbiter)
		if !ok || abt.crMember.MemberState != state.MemberElected {
			continue
		}
		var pid peer.PID
		copy(pid[:], p.GetNodePublicKey())
		pids[common.BytesToHexString(p.GetNodePublicKey())] = pid
	}

	for _, p := range a.nextCRCArbitersMap {
		abt, ok := p.(*crcArbiter)
		if !ok || abt.crMember.MemberState != state.MemberElected {
			continue
		}
		var pid peer.PID
		copy(pid[:], p.GetNodePublicKey())
		pids[common.BytesToHexString(p.GetNodePublicKey())] = pid
	}

	peers := make([]peer.PID, 0, len(pids))
	for _, pid := range pids {
		peers = append(peers, pid)
	}

	return peers
}

func (a *Arbiters) GetNeedConnectArbiters() []peer.PID {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.getNeedConnectArbiters()
}

func (a *Arbiters) getNeedConnectArbiters() []peer.PID {
	height := a.History.Height() + 1
	if height < a.ChainParams.CRCOnlyDPOSHeight-
		a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return nil
	}

	pids := make(map[string]peer.PID)
	for _, p := range a.CurrentCRCArbitersMap {
		abt, ok := p.(*crcArbiter)
		if !ok || abt.crMember.MemberState != state.MemberElected {
			continue
		}
		var pid peer.PID
		copy(pid[:], p.GetNodePublicKey())
		pids[common.BytesToHexString(p.GetNodePublicKey())] = pid
	}

	for _, p := range a.nextCRCArbitersMap {
		abt, ok := p.(*crcArbiter)
		if !ok || abt.crMember.MemberState != state.MemberElected {
			continue
		}
		var pid peer.PID
		copy(pid[:], p.GetNodePublicKey())
		pids[common.BytesToHexString(p.GetNodePublicKey())] = pid
	}

	if height != a.ChainParams.CRCOnlyDPOSHeight-
		a.ChainParams.DPoSConfiguration.PreConnectOffset {
		for _, v := range a.CurrentArbitrators {
			key := common.BytesToHexString(v.GetNodePublicKey())
			var pid peer.PID
			copy(pid[:], v.GetNodePublicKey())
			pids[key] = pid
		}
	}

	for _, v := range a.nextArbitrators {
		key := common.BytesToHexString(v.GetNodePublicKey())
		var pid peer.PID
		copy(pid[:], v.GetNodePublicKey())
		pids[key] = pid
	}

	peers := make([]peer.PID, 0, len(pids))
	for _, pid := range pids {
		peers = append(peers, pid)
	}

	return peers
}

func (a *Arbiters) IsArbitrator(pk []byte) bool {
	arbitrators := a.GetArbitrators()

	for _, v := range arbitrators {
		if !v.IsNormal {
			continue
		}
		if bytes.Equal(pk, v.NodePublicKey) {
			return true
		}
	}
	return false
}

func (a *Arbiters) GetCurrentAndLastArbitrators() ([]*ArbiterInfo, []*ArbiterInfo) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.getCurrentAndLastArbitrators()
}

func (a *Arbiters) getCurrentAndLastArbitrators() ([]*ArbiterInfo, []*ArbiterInfo) {
	currentArbitrators := make([]*ArbiterInfo, 0, len(a.CurrentArbitrators))
	for _, v := range a.CurrentArbitrators {
		isNormal := true
		isCRMember := false
		claimedDPOSNode := false
		abt, ok := v.(*crcArbiter)
		if ok {
			isCRMember = true
			if !abt.isNormal {
				isNormal = false
			}
			if len(abt.crMember.DPOSPublicKey) != 0 {
				claimedDPOSNode = true
			}
		}
		currentArbitrators = append(currentArbitrators, &ArbiterInfo{
			NodePublicKey:   v.GetNodePublicKey(),
			IsNormal:        isNormal,
			IsCRMember:      isCRMember,
			ClaimedDPOSNode: claimedDPOSNode,
		})
	}

	lastArbitrators := make([]*ArbiterInfo, 0, len(a.LastArbitrators))
	for _, v := range a.LastArbitrators {
		isNormal := true
		isCRMember := false
		claimedDPOSNode := false
		abt, ok := v.(*crcArbiter)
		if ok {
			isCRMember = true
			if !abt.isNormal {
				isNormal = false
			}
			if len(abt.crMember.DPOSPublicKey) != 0 {
				claimedDPOSNode = true
			}
		}
		lastArbitrators = append(lastArbitrators, &ArbiterInfo{
			NodePublicKey:   v.GetNodePublicKey(),
			IsNormal:        isNormal,
			IsCRMember:      isCRMember,
			ClaimedDPOSNode: claimedDPOSNode,
		})
	}

	return currentArbitrators, lastArbitrators
}

func (a *Arbiters) GetArbitrators() []*ArbiterInfo {
	a.mtx.Lock()
	result := a.getArbitrators()
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetCurrentArbitratorKeys() [][]byte {
	var ret [][]byte
	for _, info := range a.getArbitrators() {
		ret = append(ret, info.NodePublicKey)
	}
	return ret
}

func (a *Arbiters) getArbitrators() []*ArbiterInfo {
	result := make([]*ArbiterInfo, 0, len(a.CurrentArbitrators))
	for _, v := range a.CurrentArbitrators {
		isNormal := true
		isCRMember := false
		claimedDPOSNode := false
		abt, ok := v.(*crcArbiter)
		if ok {
			isCRMember = true
			if !abt.isNormal {
				isNormal = false
			}
			if len(abt.crMember.DPOSPublicKey) != 0 {
				claimedDPOSNode = true
			}
		}
		result = append(result, &ArbiterInfo{
			NodePublicKey:   v.GetNodePublicKey(),
			IsNormal:        isNormal,
			IsCRMember:      isCRMember,
			ClaimedDPOSNode: claimedDPOSNode,
		})
	}
	return result
}

func (a *Arbiters) GetCandidates() [][]byte {
	a.mtx.Lock()
	result := make([][]byte, 0, len(a.CurrentCandidates))
	for _, v := range a.CurrentCandidates {
		result = append(result, v.GetNodePublicKey())
	}
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetNextArbitrators() []*ArbiterInfo {
	a.mtx.Lock()
	result := make([]*ArbiterInfo, 0, len(a.nextArbitrators))
	for _, v := range a.nextArbitrators {
		isNormal := true
		isCRMember := false
		claimedDPOSNode := false
		abt, ok := v.(*crcArbiter)
		if ok {
			isCRMember = true
			if !abt.isNormal {
				isNormal = false
			}
			if len(abt.crMember.DPOSPublicKey) != 0 {
				claimedDPOSNode = true
			}
		}
		result = append(result, &ArbiterInfo{
			NodePublicKey:   v.GetNodePublicKey(),
			IsNormal:        isNormal,
			IsCRMember:      isCRMember,
			ClaimedDPOSNode: claimedDPOSNode,
		})
	}
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetNextCandidates() [][]byte {
	a.mtx.Lock()
	result := make([][]byte, 0, len(a.nextCandidates))
	for _, v := range a.nextCandidates {
		result = append(result, v.GetNodePublicKey())
	}
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetCRCArbiters() []*ArbiterInfo {
	a.mtx.Lock()
	result := a.getCRCArbiters()
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) getCRCArbiters() []*ArbiterInfo {
	result := make([]*ArbiterInfo, 0, len(a.CurrentCRCArbitersMap))
	for _, v := range a.CurrentCRCArbitersMap {
		isNormal := true
		isCRMember := false
		claimedDPOSNode := false
		abt, ok := v.(*crcArbiter)
		if ok {
			isCRMember = true
			if !abt.isNormal {
				isNormal = false
			}
			if len(abt.crMember.DPOSPublicKey) != 0 {
				claimedDPOSNode = true
			}
		}
		result = append(result, &ArbiterInfo{
			NodePublicKey:   v.GetNodePublicKey(),
			IsNormal:        isNormal,
			IsCRMember:      isCRMember,
			ClaimedDPOSNode: claimedDPOSNode,
		})
	}

	return result
}

func (a *Arbiters) GetAllNextCRCArbiters() [][]byte {
	a.mtx.Lock()
	result := make([][]byte, 0, len(a.nextCRCArbiters))
	for _, v := range a.nextCRCArbiters {
		result = append(result, v.GetNodePublicKey())
	}
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetNextCRCArbiters() [][]byte {
	a.mtx.Lock()
	result := make([][]byte, 0, len(a.nextCRCArbiters))
	for _, v := range a.nextCRCArbiters {
		if !v.IsNormal() {
			continue
		}
		result = append(result, v.GetNodePublicKey())
	}
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetCurrentRewardData() RewardData {
	a.mtx.Lock()
	result := a.CurrentReward
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) GetNextRewardData() RewardData {
	a.mtx.Lock()
	result := a.NextReward
	a.mtx.Unlock()

	return result
}

func (a *Arbiters) IsCRCArbitrator(pk []byte) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, v := range a.CurrentCRCArbitersMap {
		if bytes.Equal(v.GetNodePublicKey(), pk) {
			return true
		}
	}
	return false
}

func (a *Arbiters) isNextCRCArbitrator(pk []byte) bool {
	for _, v := range a.nextCRCArbitersMap {
		if bytes.Equal(v.GetNodePublicKey(), pk) {
			return true
		}
	}
	return false
}

func (a *Arbiters) IsNextCRCArbitrator(pk []byte) bool {
	for _, v := range a.nextCRCArbiters {
		if bytes.Equal(v.GetNodePublicKey(), pk) {
			return true
		}
	}
	return false
}

func (a *Arbiters) IsMemberElectedNextCRCArbitrator(pk []byte) bool {
	for _, v := range a.nextCRCArbiters {
		if bytes.Equal(v.GetNodePublicKey(), pk) && v.(*crcArbiter).crMember.MemberState == state.MemberElected {
			return true
		}
	}
	return false
}

func (a *Arbiters) IsActiveProducer(pk []byte) bool {
	return a.State.IsActiveProducer(pk)
}

func (a *Arbiters) IsDisabledProducer(pk []byte) bool {
	return a.State.IsInactiveProducer(pk) || a.State.IsIllegalProducer(pk) || a.State.IsCanceledProducer(pk)
}

func (a *Arbiters) GetConnectedProducer(publicKey []byte) ArbiterMember {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, v := range a.CurrentCRCArbitersMap {
		if bytes.Equal(v.GetNodePublicKey(), publicKey) {
			return v
		}
	}

	for _, v := range a.nextCRCArbitersMap {
		if bytes.Equal(v.GetNodePublicKey(), publicKey) {
			return v
		}
	}

	findByPk := func(arbiters []ArbiterMember) ArbiterMember {
		for _, v := range arbiters {
			if bytes.Equal(v.GetNodePublicKey(), publicKey) {
				return v
			}
		}
		return nil
	}
	if ar := findByPk(a.CurrentArbitrators); ar != nil {
		return ar
	}
	if ar := findByPk(a.CurrentCandidates); ar != nil {
		return ar
	}
	if ar := findByPk(a.nextArbitrators); ar != nil {
		return ar
	}
	if ar := findByPk(a.nextCandidates); ar != nil {
		return ar
	}

	return nil
}

func (a *Arbiters) CRCProducerCount() int {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return len(a.CurrentCRCArbitersMap)
}

func (a *Arbiters) getOnDutyArbitrator() []byte {
	return a.getNextOnDutyArbitratorV(a.bestHeight()+1, 0).GetNodePublicKey()
}

func (a *Arbiters) GetOnDutyArbitrator() []byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	arbiter := a.getNextOnDutyArbitratorV(a.bestHeight()+1, 0)
	if arbiter != nil && arbiter.IsNormal() {
		return arbiter.GetNodePublicKey()
	}
	return []byte{}
}

func (a *Arbiters) GetNextOnDutyArbitrator(offset uint32) []byte {
	arbiter := a.getNextOnDutyArbitratorV(a.bestHeight()+1, offset)
	if arbiter == nil {
		return []byte{}
	}
	return arbiter.GetNodePublicKey()
}

func (a *Arbiters) GetOnDutyCrossChainArbitrator() []byte {
	var arbiter []byte
	height := a.bestHeight()
	if height < a.ChainParams.CRCOnlyDPOSHeight-1 {
		arbiter = a.GetOnDutyArbitrator()
	} else if height < a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
		a.mtx.Lock()
		crcArbiters := a.getCRCArbiters()
		sort.Slice(crcArbiters, func(i, j int) bool {
			return bytes.Compare(crcArbiters[i].NodePublicKey, crcArbiters[j].NodePublicKey) < 0
		})
		ondutyIndex := int(height-a.ChainParams.CRCOnlyDPOSHeight+1) % len(crcArbiters)
		arbiter = crcArbiters[ondutyIndex].NodePublicKey
		a.mtx.Unlock()
	} else if height < a.ChainParams.DPoSConfiguration.DPOSNodeCrossChainHeight {
		a.mtx.Lock()
		crcArbiters := a.getCRCArbiters()
		sort.Slice(crcArbiters, func(i, j int) bool {
			return bytes.Compare(crcArbiters[i].NodePublicKey,
				crcArbiters[j].NodePublicKey) < 0
		})
		index := a.DutyIndex % len(a.CurrentCRCArbitersMap)
		if crcArbiters[index].IsNormal {
			arbiter = crcArbiters[index].NodePublicKey
		} else {
			arbiter = nil
		}
		a.mtx.Unlock()
	} else {
		a.mtx.Lock()
		if len(a.CurrentArbitrators) != 0 && a.CurrentArbitrators[a.DutyIndex].IsNormal() {
			arbiter = a.CurrentArbitrators[a.DutyIndex].GetNodePublicKey()
		} else {
			arbiter = nil
		}
		a.mtx.Unlock()
	}

	return arbiter
}

func (a *Arbiters) GetCrossChainArbiters() []*ArbiterInfo {
	bestHeight := a.bestHeight()
	if bestHeight < a.ChainParams.CRCOnlyDPOSHeight-1 {
		return a.GetArbitrators()
	}
	if bestHeight < a.ChainParams.DPoSConfiguration.DPOSNodeCrossChainHeight {
		crcArbiters := a.GetCRCArbiters()
		sort.Slice(crcArbiters, func(i, j int) bool {
			return bytes.Compare(crcArbiters[i].NodePublicKey, crcArbiters[j].NodePublicKey) < 0
		})
		return crcArbiters
	}

	return a.GetArbitrators()
}

func (a *Arbiters) GetCrossChainArbitersCount() int {
	if a.bestHeight() < a.ChainParams.CRCOnlyDPOSHeight-1 {
		return len(a.ChainParams.DPoSConfiguration.OriginArbiters)
	}

	return len(a.ChainParams.DPoSConfiguration.CRCArbiters)
}

func (a *Arbiters) GetCrossChainArbitersMajorityCount() int {
	minSignCount := int(float64(a.GetCrossChainArbitersCount()) *
		MajoritySignRatioNumerator / MajoritySignRatioDenominator)
	return minSignCount
}

func (a *Arbiters) getNextOnDutyArbitratorV(height, offset uint32) ArbiterMember {
	// main version is >= H1
	if height >= a.ChainParams.CRCOnlyDPOSHeight {
		arbitrators := a.CurrentArbitrators
		if len(arbitrators) == 0 {
			return nil
		}
		index := (a.DutyIndex + int(offset)) % len(arbitrators)
		arbiter := arbitrators[index]

		return arbiter
	}

	// old version
	return a.getNextOnDutyArbitratorV0(height, offset)
}

func (a *Arbiters) GetArbitersCount() int {
	a.mtx.Lock()
	result := len(a.CurrentArbitrators)
	if result == 0 {
		result = a.ChainParams.DPoSConfiguration.NormalArbitratorsCount + len(a.ChainParams.DPoSConfiguration.CRCArbiters)
	}
	a.mtx.Unlock()
	return result
}

func (a *Arbiters) GetCRCArbitersCount() int {
	a.mtx.Lock()
	result := len(a.CurrentCRCArbitersMap)
	a.mtx.Unlock()
	return result
}

func (a *Arbiters) GetArbitersMajorityCount() int {
	a.mtx.Lock()
	var currentArbitratorsCount int
	if len(a.CurrentArbitrators) != 0 {
		currentArbitratorsCount = len(a.CurrentArbitrators)
	} else {
		currentArbitratorsCount = len(a.ChainParams.DPoSConfiguration.CRCArbiters) + a.ChainParams.DPoSConfiguration.NormalArbitratorsCount
	}
	minSignCount := int(float64(currentArbitratorsCount) *
		MajoritySignRatioNumerator / MajoritySignRatioDenominator)
	a.mtx.Unlock()
	return minSignCount
}

func (a *Arbiters) HasArbitersMajorityCount(num int) bool {
	return num > a.GetArbitersMajorityCount()
}

func (a *Arbiters) HasArbitersMinorityCount(num int) bool {
	a.mtx.Lock()
	count := len(a.CurrentArbitrators)
	a.mtx.Unlock()
	return num >= count-a.GetArbitersMajorityCount()
}

func (a *Arbiters) HasArbitersHalfMinorityCount(num int) bool {
	a.mtx.Lock()
	count := len(a.CurrentArbitrators)
	a.mtx.Unlock()
	return num >= (count-a.GetArbitersMajorityCount())/2
}

func (a *Arbiters) getChangeType(height uint32) (ChangeType, uint32) {

	// special change points:
	//		H1 - PreConnectOffset -> 	[updateNext, H1]: update next arbiters and let CRC arbiters prepare to connect
	//		H1 -> 						[normalChange, H1]: should change to new election (that only have CRC arbiters)
	//		H2 - PreConnectOffset -> 	[updateNext, H2]: update next arbiters and let normal arbiters prepare to connect
	//		H2 -> 						[normalChange, H2]: should change to new election (arbiters will have both CRC and normal arbiters)
	if height == a.ChainParams.CRCOnlyDPOSHeight-
		a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return updateNext, a.ChainParams.CRCOnlyDPOSHeight
	} else if height == a.ChainParams.CRCOnlyDPOSHeight {
		return normalChange, a.ChainParams.CRCOnlyDPOSHeight
	} else if height == a.ChainParams.PublicDPOSHeight-
		a.ChainParams.DPoSConfiguration.PreConnectOffset {
		return updateNext, a.ChainParams.PublicDPOSHeight
	} else if height == a.ChainParams.PublicDPOSHeight {
		return normalChange, a.ChainParams.PublicDPOSHeight
	}

	// main version >= H2
	if height > a.ChainParams.PublicDPOSHeight &&
		a.DutyIndex == len(a.CurrentArbitrators)-1 {
		return normalChange, height
	}

	if height > a.ChainParams.DPoSConfiguration.RevertToPOWStartHeight &&
		a.DutyIndex == len(a.ChainParams.DPoSConfiguration.CRCArbiters)+a.ChainParams.DPoSConfiguration.NormalArbitratorsCount-1 {
		return normalChange, height
	}

	return none, height
}

func (a *Arbiters) cleanArbitrators(height uint32) {
	oriCurrentCRCArbitersMap := copyCRCArbitersMap(a.CurrentCRCArbitersMap)
	oriCurrentArbitrators := a.CurrentArbitrators
	oriCurrentCandidates := a.CurrentCandidates
	oriNextCRCArbitersMap := copyCRCArbitersMap(a.nextCRCArbitersMap)
	oriNextArbitrators := a.nextArbitrators
	oriNextCandidates := a.nextCandidates
	oriDutyIndex := a.DutyIndex
	a.History.Append(height, func() {
		a.CurrentCRCArbitersMap = make(map[common.Uint168]ArbiterMember)
		a.CurrentArbitrators = make([]ArbiterMember, 0)
		a.CurrentCandidates = make([]ArbiterMember, 0)
		a.nextCRCArbitersMap = make(map[common.Uint168]ArbiterMember)
		a.nextArbitrators = make([]ArbiterMember, 0)
		a.nextCandidates = make([]ArbiterMember, 0)
		a.DutyIndex = 0
	}, func() {
		a.CurrentCRCArbitersMap = oriCurrentCRCArbitersMap
		a.CurrentArbitrators = oriCurrentArbitrators
		a.CurrentCandidates = oriCurrentCandidates
		a.nextCRCArbitersMap = oriNextCRCArbitersMap
		a.nextArbitrators = oriNextArbitrators
		a.nextCandidates = oriNextCandidates
		a.DutyIndex = oriDutyIndex
	})
}

func (a *Arbiters) ChangeCurrentArbitrators(height uint32) error {
	oriCurrentCRCArbitersMap := copyCRCArbitersMap(a.CurrentCRCArbitersMap)
	oriLastArbitrators := a.LastArbitrators
	oriCurrentArbitrators := a.CurrentArbitrators
	oriCurrentCandidates := a.CurrentCandidates
	oriCurrentReward := a.CurrentReward
	oriDutyIndex := a.DutyIndex
	a.History.Append(height, func() {
		sort.Slice(a.nextArbitrators, func(i, j int) bool {
			return bytes.Compare(a.nextArbitrators[i].GetNodePublicKey(),
				a.nextArbitrators[j].GetNodePublicKey()) < 0
		})
		a.CurrentCRCArbitersMap = copyCRCArbitersMap(a.nextCRCArbitersMap)
		a.LastArbitrators = a.CurrentArbitrators
		a.CurrentArbitrators = a.nextArbitrators
		a.CurrentCandidates = a.nextCandidates
		a.CurrentReward = a.NextReward
		a.DutyIndex = 0
	}, func() {
		a.CurrentCRCArbitersMap = oriCurrentCRCArbitersMap
		a.LastArbitrators = oriLastArbitrators
		a.CurrentArbitrators = oriCurrentArbitrators
		a.CurrentCandidates = oriCurrentCandidates
		a.CurrentReward = oriCurrentReward
		a.DutyIndex = oriDutyIndex
	})
	return nil
}

func (a *Arbiters) IsSameWithNextArbitrators() bool {

	if len(a.nextArbitrators) != len(a.CurrentArbitrators) {
		return false
	}
	for index, v := range a.CurrentArbitrators {
		// F-179: the comparison was inverted - it reported "not same" when the
		// keys WERE equal. A difference in any position means not the same set.
		if !bytes.Equal(v.GetNodePublicKey(), a.nextArbitrators[index].GetNodePublicKey()) {
			return false
		}
	}
	return true
}

func (a *Arbiters) ConvertToArbitersStr(arbiters [][]byte) []string {
	var arbitersStr []string
	for _, v := range arbiters {
		arbitersStr = append(arbitersStr, common.BytesToHexString(v))
	}
	return arbitersStr
}

func (a *Arbiters) createNextTurnDPOSInfoTransactionV0(blockHeight uint32, forceChange bool) interfaces.Transaction {

	var nextTurnDPOSInfo payload.NextTurnDPOSInfo
	nextTurnDPOSInfo.CRPublicKeys = make([][]byte, 0)
	nextTurnDPOSInfo.DPOSPublicKeys = make([][]byte, 0)
	var workingHeight uint32
	if forceChange {
		workingHeight = blockHeight
	} else {
		workingHeight = blockHeight + uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount+len(a.ChainParams.DPoSConfiguration.CRCArbiters))
	}
	nextTurnDPOSInfo.WorkingHeight = workingHeight
	for _, v := range a.nextArbitrators {
		if a.isNextCRCArbitrator(v.GetNodePublicKey()) {
			if abt, ok := v.(*crcArbiter); ok && abt.crMember.MemberState != state.MemberElected {
				nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, []byte{})
			} else {
				nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, v.GetNodePublicKey())
			}
		} else {
			nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, v.GetNodePublicKey())
		}
	}

	log.Debugf("[createNextTurnDPOSInfoTransaction] CRPublicKeys %v, DPOSPublicKeys%v\n",
		a.ConvertToArbitersStr(nextTurnDPOSInfo.CRPublicKeys), a.ConvertToArbitersStr(nextTurnDPOSInfo.DPOSPublicKeys))

	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.NextTurnDPOSInfo,
		0,
		&nextTurnDPOSInfo,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
}

func (a *Arbiters) createNextTurnDPOSInfoTransactionV2(blockHeight uint32, forceChange bool) interfaces.Transaction {

	var nextTurnDPOSInfo payload.NextTurnDPOSInfo
	nextTurnDPOSInfo.CRPublicKeys = make([][]byte, 0)
	nextTurnDPOSInfo.DPOSPublicKeys = make([][]byte, 0)
	var workingHeight uint32
	if forceChange {
		workingHeight = blockHeight
	} else {
		workingHeight = blockHeight + uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount+len(a.ChainParams.DPoSConfiguration.CRCArbiters))
	}
	nextTurnDPOSInfo.WorkingHeight = workingHeight
	for _, v := range a.nextCRCArbiters {
		nodePK := v.GetNodePublicKey()
		if v.IsNormal() {
			nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, nodePK)
		} else {
			nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, []byte{})
		}

		nextTurnDPOSInfo.CompleteCRPublicKeys = append(nextTurnDPOSInfo.CompleteCRPublicKeys, nodePK)
	}
	for _, v := range a.nextArbitrators {
		if a.isNextCRCArbitrator(v.GetNodePublicKey()) {
			if abt, ok := v.(*crcArbiter); ok && abt.crMember.MemberState != state.MemberElected {
				nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, []byte{})
			} else {
				nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, v.GetNodePublicKey())
			}
		} else {
			nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, v.GetNodePublicKey())
		}
	}

	log.Debugf("[createNextTurnDPOSInfoTransaction] CRPublicKeys %v, DPOSPublicKeys%v\n",
		a.ConvertToArbitersStr(nextTurnDPOSInfo.CRPublicKeys), a.ConvertToArbitersStr(nextTurnDPOSInfo.DPOSPublicKeys))

	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.NextTurnDPOSInfo,
		payload.NextTurnDPOSInfoVersion2,
		&nextTurnDPOSInfo,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
}

func (a *Arbiters) createNextTurnDPOSInfoTransactionV1(blockHeight uint32, forceChange bool) interfaces.Transaction {

	var nextTurnDPOSInfo payload.NextTurnDPOSInfo
	nextTurnDPOSInfo.CRPublicKeys = make([][]byte, 0)
	nextTurnDPOSInfo.DPOSPublicKeys = make([][]byte, 0)
	var workingHeight uint32
	if forceChange {
		workingHeight = blockHeight
	} else {
		workingHeight = blockHeight + uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount+len(a.ChainParams.DPoSConfiguration.CRCArbiters))
	}
	nextTurnDPOSInfo.WorkingHeight = workingHeight
	for _, v := range a.nextCRCArbiters {
		nodePK := v.GetNodePublicKey()
		if v.IsNormal() {
			nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, nodePK)
		} else {
			nextTurnDPOSInfo.CRPublicKeys = append(nextTurnDPOSInfo.CRPublicKeys, []byte{})
		}
	}
	for _, v := range a.nextArbitrators {
		if a.isNextCRCArbitrator(v.GetNodePublicKey()) {
			if abt, ok := v.(*crcArbiter); ok && abt.crMember.MemberState != state.MemberElected {
				nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, []byte{})
			} else {
				nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, v.GetNodePublicKey())
			}
		} else {
			nextTurnDPOSInfo.DPOSPublicKeys = append(nextTurnDPOSInfo.DPOSPublicKeys, v.GetNodePublicKey())
		}
	}

	log.Debugf("[createNextTurnDPOSInfoTransaction] CRPublicKeys %v, DPOSPublicKeys%v\n",
		a.ConvertToArbitersStr(nextTurnDPOSInfo.CRPublicKeys), a.ConvertToArbitersStr(nextTurnDPOSInfo.DPOSPublicKeys))

	return functions.CreateTransaction(
		common2.TxVersion09,
		common2.NextTurnDPOSInfo,
		0,
		&nextTurnDPOSInfo,
		[]*common2.Attribute{},
		[]*common2.Input{},
		[]*common2.Output{},
		0,
		[]*program.Program{},
	)
}

func (a *Arbiters) updateNextTurnInfo(height uint32, producers []ArbiterMember, unclaimed int) {
	nextCRCArbiters := a.nextArbitrators
	if !a.isDposV2Active() {
		a.nextArbitrators = append(a.nextArbitrators, producers...)
	} else {
		a.nextArbitrators = producers
	}
	sort.Slice(a.nextArbitrators, func(i, j int) bool {
		return bytes.Compare(a.nextArbitrators[i].GetNodePublicKey(), a.nextArbitrators[j].GetNodePublicKey()) < 0
	})
	if height >= a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
		//need sent a NextTurnDPOSInfo tx into mempool
		sort.Slice(nextCRCArbiters, func(i, j int) bool {
			return bytes.Compare(nextCRCArbiters[i].GetNodePublicKey(), nextCRCArbiters[j].GetNodePublicKey()) < 0
		})
		a.nextCRCArbiters = copyByteList(nextCRCArbiters)
	}
}

func (a *Arbiters) getProducers(count int, height uint32) ([]ArbiterMember, error) {
	if !a.isDPoSV2Run(height) {
		return a.GetNormalArbitratorsDesc(height, count,
			a.getSortedProducers(), 0)
	} else {
		return a.GetNormalArbitratorsDesc(height, count,
			a.getSortedProducersDposV2(), 0)
	}
}

func (a *Arbiters) getSortedProducers() []*Producer {
	votedProducers := a.State.GetVotedProducers()
	sort.Slice(votedProducers, func(i, j int) bool {
		if votedProducers[i].votes == votedProducers[j].votes {
			return bytes.Compare(votedProducers[i].info.NodePublicKey,
				votedProducers[j].NodePublicKey()) < 0
		}
		return votedProducers[i].Votes() > votedProducers[j].Votes()
	})

	return votedProducers
}

func (a *Arbiters) getSortedProducersDposV2() []*Producer {
	votedProducers := a.State.GetDposV2ActiveProducers()
	sort.Slice(votedProducers, func(i, j int) bool {
		if votedProducers[i].GetTotalDPoSV2VoteRights() == votedProducers[j].GetTotalDPoSV2VoteRights() {
			return bytes.Compare(votedProducers[i].info.NodePublicKey,
				votedProducers[j].NodePublicKey()) < 0
		}
		return votedProducers[i].GetTotalDPoSV2VoteRights() > votedProducers[j].GetTotalDPoSV2VoteRights()
	})

	return votedProducers
}

func (a *Arbiters) getSortedProducersWithRandom(height uint32, unclaimedCount int) ([]*Producer, error) {

	votedProducers := a.getSortedProducers()
	if height < a.ChainParams.DPoSConfiguration.NoCRCDPOSNodeHeight {
		return votedProducers, nil
	}

	// if the last random producer is not found or the poll ranked in the top
	// 23(may be 35) or the state is not active, need to get a candidate as
	// DPOS node at random.
	if a.LastRandomCandidateHeight != 0 &&
		height-a.LastRandomCandidateHeight < a.ChainParams.DPoSConfiguration.RandomCandidatePeriod {
		for i, p := range votedProducers {
			if common.BytesToHexString(p.info.OwnerKey) == a.LastRandomCandidateOwner {
				if i < unclaimedCount+a.ChainParams.DPoSConfiguration.NormalArbitratorsCount-1 || p.state != Active {
					// need get again at random.
					break
				}
				normalCount := a.ChainParams.DPoSConfiguration.NormalArbitratorsCount - 1
				selectedCandidateIndex := i

				newProducers := make([]*Producer, 0, len(votedProducers))
				newProducers = append(newProducers, votedProducers[:unclaimedCount+normalCount]...)
				newProducers = append(newProducers, p)
				newProducers = append(newProducers, votedProducers[unclaimedCount+normalCount:selectedCandidateIndex]...)
				newProducers = append(newProducers, votedProducers[selectedCandidateIndex+1:]...)
				log.Info("no need random producer, current random producer:",
					p.info.NickName, "current height:", height)
				return newProducers, nil
			}
		}
	}

	candidateIndex, err := a.getCandidateIndexAtRandom(height, unclaimedCount, len(votedProducers))
	if err != nil {
		return nil, err
	}

	normalCount := a.ChainParams.DPoSConfiguration.NormalArbitratorsCount - 1
	selectedCandidateIndex := unclaimedCount + normalCount + candidateIndex
	candidateProducer := votedProducers[selectedCandidateIndex]

	// todo need to use History?
	a.LastRandomCandidateHeight = height
	a.LastRandomCandidateOwner = common.BytesToHexString(candidateProducer.info.OwnerKey)

	newProducers := make([]*Producer, 0, len(votedProducers))
	newProducers = append(newProducers, votedProducers[:unclaimedCount+normalCount]...)
	newProducers = append(newProducers, candidateProducer)
	newProducers = append(newProducers, votedProducers[unclaimedCount+normalCount:selectedCandidateIndex]...)
	newProducers = append(newProducers, votedProducers[selectedCandidateIndex+1:]...)

	log.Info("random producer, current random producer:",
		candidateProducer.info.NickName, "current height:", height)
	return newProducers, nil
}

func (a *Arbiters) getRandomDposV2Producers(height uint32, unclaimedCount int, choosingCRArbiters map[common.Uint168]ArbiterMember) ([]string, error) {
	block, _ := a.getBlockByHeight(height - 1)
	if block == nil {
		return nil, errors.New("block is not found")
	}
	var x = make([]byte, 8)
	blockHash := block.HashWithAux()
	copy(x, blockHash[24:])
	seed, _, ok := Readi64(x)
	if !ok {
		return nil, errors.New("invalid block hash")
	}
	r := rand.New(rand.NewSource(seed))

	votedProducers := a.getSortedProducersDposV2()
	// crc also need to be random selected
	var producerKeys []string
	for _, crc := range choosingCRArbiters {
		if crc.IsNormal() {
			producerKeys = append(producerKeys, hex.EncodeToString(crc.GetOwnerPublicKey()))
		}
	}
	sort.Slice(producerKeys, func(i, j int) bool {
		return strings.Compare(producerKeys[i], producerKeys[j]) < 0
	})
	for _, vp := range votedProducers[unclaimedCount:] {
		producerKeys = append(producerKeys, hex.EncodeToString(vp.info.OwnerKey))
	}
	sortedProducer := make([]string, 0, len(producerKeys))
	count := a.ChainParams.DPoSConfiguration.NormalArbitratorsCount + len(a.ChainParams.DPoSConfiguration.CRCArbiters)

	if len(producerKeys) > count {
		for i := 0; i < count; i++ {
			s := r.Intn(len(producerKeys))
			sortedProducer = append(sortedProducer, producerKeys[s])
			tmpProducers := producerKeys[s+1:]
			producerKeys = producerKeys[0:s]
			producerKeys = append(producerKeys, tmpProducers...)
		}
	}

	for i := 0; i < len(producerKeys); i++ {
		sortedProducer = append(sortedProducer, producerKeys[i])
	}
	return sortedProducer, nil
}

func (a *Arbiters) getCandidateIndexAtRandom(height uint32, unclaimedCount, votedProducersCount int) (int, error) {
	block, _ := a.getBlockByHeight(height - 1)
	if block == nil {
		return 0, errors.New("block is not found")
	}
	var x = make([]byte, 8)
	blockHash := block.Hash()
	copy(x, blockHash[24:])
	seed, _, ok := Readi64(x)
	if !ok {
		return 0, errors.New("invalid block hash")
	}
	// F-202: draw from a private, block-seeded Source instead of the
	// process-global math/rand generator. rand.Seed()+rand.Intn() shares one
	// stream with every other global-rand consumer in the process (p2p,
	// elanet), so a concurrent draw between the Seed and the Intn shifts the
	// selected candidate. This is the same local-Source pattern already used
	// by getRandomDposV2Producers above, and for an undisturbed stream it
	// yields the identical index (see TestF202SeededDrawEquivalence).
	r := rand.New(rand.NewSource(seed))
	normalCount := a.ChainParams.DPoSConfiguration.NormalArbitratorsCount - 1
	count := votedProducersCount - unclaimedCount - normalCount
	if count < 1 {
		return 0, errors.New("producers is not enough")
	}
	candidatesCount := minInt(count, a.ChainParams.DPoSConfiguration.CandidatesCount+1)
	return r.Intn(candidatesCount), nil
}

func (a *Arbiters) isDposV2Active() bool {
	if a.DPoSV2ActiveHeight != math.MaxUint32 {
		return true
	}
	return len(a.DposV2EffectedProducers) >= a.ChainParams.DPoSConfiguration.NormalArbitratorsCount*3/2
}

func (a *Arbiters) UpdateNextArbitrators(versionHeight, height uint32) error {

	if height >= a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
		oriNeedNextTurnDPOSInfo := a.NeedNextTurnDPOSInfo
		a.History.Append(height, func() {
			a.NeedNextTurnDPOSInfo = true
		}, func() {
			a.NeedNextTurnDPOSInfo = oriNeedNextTurnDPOSInfo
		})
	}

	_, recover := a.InactiveModeSwitch(versionHeight, a.IsAbleToRecoverFromInactiveMode)
	if recover {
		a.LeaveEmergency(a.History, height)
	} else {
		a.TryLeaveUnderStaffed(a.IsAbleToRecoverFromUnderstaffedState)
	}

	if a.DPoSV2ActiveHeight == math.MaxUint32 && a.isDposV2Active() {
		a.History.Append(height, func() {
			a.DPoSV2ActiveHeight = height + a.ChainParams.CRConfiguration.MemberCount + uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount)
		}, func() {
			// F-180: the guard above proved the prior value was MaxUint32; restore THAT on
			// rollback, not `height`, so a reorg across activation does not pin
			// DPoSV2ActiveHeight to a wrong (activated) height. Reorg revert-symmetry (F-168 class).
			a.DPoSV2ActiveHeight = math.MaxUint32
		})
	}

	unclaimed, choosingCRArbiters, err := a.resetNextArbiterByCRC(versionHeight, height)
	if err != nil {
		return err
	}

	if !a.IsInactiveMode() && !a.IsUnderstaffedMode() {

		count := a.ChainParams.DPoSConfiguration.NormalArbitratorsCount
		var votedProducers []*Producer
		var crAndVotedProducersStr []string
		if a.isDposV2Active() {
			crAndVotedProducersStr, err = a.getRandomDposV2Producers(height, unclaimed, choosingCRArbiters)
			if err != nil {
				return err
			}
		} else {
			votedProducers, err = a.getSortedProducersWithRandom(height, unclaimed)
			if err != nil {
				return err
			}
		}
		var producers []ArbiterMember
		var err error
		if a.isDposV2Active() {
			producers, err = a.GetDposV2NormalArbitratorsDesc(count+int(a.ChainParams.CRConfiguration.MemberCount), crAndVotedProducersStr, choosingCRArbiters)
		} else {
			producers, err = a.GetNormalArbitratorsDesc(versionHeight, count,
				votedProducers, unclaimed)
		}
		if err != nil {
			if height > a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight {
				return err
			}
			if err := a.tryHandleError(versionHeight, err); err != nil {
				return err
			}
			oriNextCandidates := a.nextCandidates
			oriNextArbitrators := a.nextArbitrators
			oriNextCRCArbiters := a.nextCRCArbiters
			a.History.Append(height, func() {
				a.nextCandidates = make([]ArbiterMember, 0)
				a.updateNextTurnInfo(height, producers, unclaimed)
			}, func() {
				a.nextCandidates = oriNextCandidates
				a.nextArbitrators = oriNextArbitrators
				a.nextCRCArbiters = oriNextCRCArbiters
			})
		} else {
			if !a.isDposV2Active() {
				if height >= a.ChainParams.DPoSConfiguration.NoCRCDPOSNodeHeight {
					count := len(a.ChainParams.DPoSConfiguration.CRCArbiters) + a.ChainParams.DPoSConfiguration.NormalArbitratorsCount
					var newSelected bool
					for _, p := range votedProducers {
						producer := p
						ownerPK := common.BytesToHexString(producer.info.OwnerKey)
						if ownerPK == a.LastRandomCandidateOwner &&
							height-a.LastRandomCandidateHeight == uint32(count) {
							newSelected = true
						}
					}
					if newSelected {
						for _, p := range votedProducers {
							producer := p
							if producer.selected {
								a.History.Append(height, func() {
									producer.selected = false
								}, func() {
									producer.selected = true
								})
							}
							ownerPK := common.BytesToHexString(producer.info.OwnerKey)
							oriRandomInactiveCount := producer.randomCandidateInactiveCount
							if ownerPK == a.LastRandomCandidateOwner {
								a.History.Append(height, func() {
									producer.selected = true
									producer.randomCandidateInactiveCount = 0
								}, func() {
									producer.selected = false
									producer.randomCandidateInactiveCount = oriRandomInactiveCount
								})
							}
						}
					}
				}
			}

			oriNextArbitrators := a.nextArbitrators
			oriNextCRCArbiters := a.nextCRCArbiters
			a.History.Append(height, func() {
				a.updateNextTurnInfo(height, producers, unclaimed)
			}, func() {
				// next Arbiters will rollback in resetNextArbiterByCRC
				a.nextArbitrators = oriNextArbitrators
				a.nextCRCArbiters = oriNextCRCArbiters
			})

			var candidates []ArbiterMember
			if !a.isDposV2Active() {
				candidates, err = a.GetCandidatesDesc(versionHeight, count+unclaimed,
					votedProducers)
			} else {
				candidates, err = a.GetDposV2CandidatesDesc(count+int(a.ChainParams.CRConfiguration.MemberCount),
					crAndVotedProducersStr, choosingCRArbiters)
			}
			if err != nil {
				return err
			}
			oriNextCandidates := a.nextCandidates
			a.History.Append(height, func() {
				a.nextCandidates = candidates
			}, func() {
				a.nextCandidates = oriNextCandidates
			})
		}
	} else {
		oriNextCandidates := a.nextCandidates
		oriNextArbitrators := a.nextArbitrators
		oriNextCRCArbiters := a.nextCRCArbiters
		a.History.Append(height, func() {
			a.nextCandidates = make([]ArbiterMember, 0)
			a.updateNextTurnInfo(height, nil, unclaimed)
		}, func() {
			a.nextCandidates = oriNextCandidates
			a.nextArbitrators = oriNextArbitrators
			a.nextCRCArbiters = oriNextCRCArbiters
		})
	}
	return nil
}

func (a *Arbiters) resetNextArbiterByCRC(versionHeight uint32, height uint32) (int, map[common.Uint168]ArbiterMember, error) {
	var unclaimed int
	var needReset bool
	crcArbiters := map[common.Uint168]ArbiterMember{}
	if a.CRCommittee != nil && a.CRCommittee.IsInElectionPeriod() {
		if versionHeight >= a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight {
			var err error
			if versionHeight < a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight {
				if crcArbiters, err = a.getCRCArbitersV1(height); err != nil {
					return unclaimed, nil, err
				}
			} else {
				if crcArbiters, unclaimed, err = a.getCRCArbitersV2(height); err != nil {
					return unclaimed, nil, err
				}
			}
		} else {
			var err error
			if crcArbiters, err = a.getCRCArbitersV0(); err != nil {
				return unclaimed, nil, err
			}
		}
		needReset = true
	} else if versionHeight >= a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight {
		var votedProducers []*Producer
		if a.isDposV2Active() {
			votedProducers = a.State.GetDposV2ActiveProducers()
		} else {
			votedProducers = a.State.GetVotedProducers()
		}

		if len(votedProducers) < len(a.ChainParams.DPoSConfiguration.CRCArbiters) {
			return unclaimed, nil, errors.New("votedProducers less than CRCArbiters")
		}

		if a.isDposV2Active() {
			sort.Slice(votedProducers, func(i, j int) bool {
				if votedProducers[i].GetTotalDPoSV2VoteRights() == votedProducers[j].GetTotalDPoSV2VoteRights() {
					return bytes.Compare(votedProducers[i].info.NodePublicKey,
						votedProducers[j].NodePublicKey()) < 0
				}
				return votedProducers[i].GetTotalDPoSV2VoteRights() > votedProducers[j].GetTotalDPoSV2VoteRights()
			})
		} else {
			sort.Slice(votedProducers, func(i, j int) bool {
				if votedProducers[i].votes == votedProducers[j].votes {
					return bytes.Compare(votedProducers[i].info.NodePublicKey,
						votedProducers[j].NodePublicKey()) < 0
				}
				return votedProducers[i].Votes() > votedProducers[j].Votes()
			})
		}

		for i := 0; i < len(a.ChainParams.DPoSConfiguration.CRCArbiters); i++ {
			producer := votedProducers[i]
			ar, err := NewDPoSArbiter(producer)
			if err != nil {
				return unclaimed, nil, err
			}
			crcArbiters[ar.GetOwnerProgramHash()] = ar
		}
		unclaimed = len(a.ChainParams.DPoSConfiguration.CRCArbiters)
		needReset = true

	} else if versionHeight >= a.ChainParams.CRConfiguration.CRCommitteeStartHeight {
		for _, pk := range a.ChainParams.DPoSConfiguration.CRCArbiters {
			pubKey, err := hex.DecodeString(pk)
			if err != nil {
				return unclaimed, nil, err
			}
			producer := &Producer{ // here need crc NODE public key
				info: payload.ProducerInfo{
					OwnerKey:      pubKey,
					NodePublicKey: pubKey,
				},
				activateRequestHeight: math.MaxUint32,
			}
			ar, err := NewDPoSArbiter(producer)
			if err != nil {
				return unclaimed, nil, err
			}
			crcArbiters[ar.GetOwnerProgramHash()] = ar
		}
		needReset = true
	}

	if needReset {
		oriNextArbitersMap := a.nextCRCArbitersMap
		oriCRCChangedHeight := a.crcChangedHeight
		a.History.Append(height, func() {
			a.nextCRCArbitersMap = crcArbiters
			a.crcChangedHeight = a.CRCommittee.LastCommitteeHeight
		}, func() {
			a.nextCRCArbitersMap = oriNextArbitersMap
			a.crcChangedHeight = oriCRCChangedHeight
		})
	}

	oriNextArbiters := a.nextArbitrators
	a.History.Append(height, func() {
		a.nextArbitrators = make([]ArbiterMember, 0)
		for _, v := range a.nextCRCArbitersMap {
			a.nextArbitrators = append(a.nextArbitrators, v)
		}
	}, func() {
		a.nextArbitrators = oriNextArbiters
	})

	if len(crcArbiters) == 0 {
		for _, v := range a.nextCRCArbiters {
			crcArbiters[v.GetOwnerProgramHash()] = v
		}
	}

	return unclaimed, crcArbiters, nil
}

func (a *Arbiters) getCRCArbitersV2(height uint32) (map[common.Uint168]ArbiterMember, int, error) {
	crMembers := a.CRCommittee.GetAllMembersCopy()
	if len(crMembers) != len(a.ChainParams.DPoSConfiguration.CRCArbiters) {
		return nil, 0, errors.New("CRC members count mismatch with CRC arbiters")
	}

	// get public key map
	crPublicKeysMap := make(map[string]struct{})
	for _, cr := range crMembers {
		if len(cr.DPOSPublicKey) != 0 {
			crPublicKeysMap[common.BytesToHexString(cr.DPOSPublicKey)] = struct{}{}
		}
	}
	arbitersPublicKeysMap := make(map[string]struct{})
	for _, ar := range a.ChainParams.DPoSConfiguration.CRCArbiters {
		arbitersPublicKeysMap[ar] = struct{}{}
	}

	// get unclaimed arbiter keys list
	unclaimedArbiterKeys := make([]string, 0)
	for k, _ := range arbitersPublicKeysMap {
		if _, ok := crPublicKeysMap[k]; !ok {
			unclaimedArbiterKeys = append(unclaimedArbiterKeys, k)
		}
	}
	sort.Slice(unclaimedArbiterKeys, func(i, j int) bool {
		return strings.Compare(unclaimedArbiterKeys[i], unclaimedArbiterKeys[j]) < 0
	})
	producers, err := a.getProducers(int(a.ChainParams.CRConfiguration.MemberCount), height)
	if err != nil {
		return nil, 0, err
	}
	var unclaimedCount int
	crcArbiters := map[common.Uint168]ArbiterMember{}
	claimHeight := a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight
	for _, cr := range crMembers {
		var pk []byte
		if len(cr.DPOSPublicKey) == 0 {
			if height >= a.ChainParams.DPoSConfiguration.CRDPoSNodeHotFixHeight {
				//if cr.MemberState != state.MemberElected {
				var err error
				pk, err = common.HexStringToBytes(unclaimedArbiterKeys[0])
				if err != nil {
					return nil, 0, err
				}
				unclaimedArbiterKeys = unclaimedArbiterKeys[1:]
				//} else {
				//	pk = producers[unclaimedCount].GetNodePublicKey()
				//	unclaimedCount++
				//}
			} else {
				if cr.MemberState != state.MemberElected {
					var err error
					pk, err = common.HexStringToBytes(unclaimedArbiterKeys[0])
					if err != nil {
						return nil, 0, err
					}
					unclaimedArbiterKeys = unclaimedArbiterKeys[1:]
				} else {
					pk = producers[unclaimedCount].GetNodePublicKey()
					unclaimedCount++
				}
			}
		} else {
			pk = cr.DPOSPublicKey
		}
		crPublicKey := cr.Info.Code[1 : len(cr.Info.Code)-1]
		isNormal := true
		if height >= claimHeight && cr.MemberState != state.MemberElected {
			isNormal = false
		}
		ar, err := NewCRCArbiter(pk, crPublicKey, cr, isNormal)
		if err != nil {
			return nil, 0, err
		}
		crcArbiters[ar.GetOwnerProgramHash()] = ar
	}

	return crcArbiters, unclaimedCount, nil
}

func (a *Arbiters) getCRCArbitersV1(height uint32) (map[common.Uint168]ArbiterMember, error) {
	crMembers := a.CRCommittee.GetAllMembersCopy()
	if len(crMembers) != len(a.ChainParams.DPoSConfiguration.CRCArbiters) {
		return nil, errors.New("CRC members count mismatch with CRC arbiters")
	}

	// get public key map
	crPublicKeysMap := make(map[string]struct{})
	for _, cr := range crMembers {
		if len(cr.DPOSPublicKey) != 0 {
			crPublicKeysMap[common.BytesToHexString(cr.DPOSPublicKey)] = struct{}{}
		}
	}
	arbitersPublicKeysMap := make(map[string]struct{})
	for _, ar := range a.ChainParams.DPoSConfiguration.CRCArbiters {
		arbitersPublicKeysMap[ar] = struct{}{}
	}

	// get unclaimed arbiter keys list
	unclaimedArbiterKeys := make([]string, 0)
	for k, _ := range arbitersPublicKeysMap {
		if _, ok := crPublicKeysMap[k]; !ok {
			unclaimedArbiterKeys = append(unclaimedArbiterKeys, k)
		}
	}
	sort.Slice(unclaimedArbiterKeys, func(i, j int) bool {
		return strings.Compare(unclaimedArbiterKeys[i], unclaimedArbiterKeys[j]) < 0
	})
	crcArbiters := map[common.Uint168]ArbiterMember{}
	claimHeight := a.ChainParams.CRConfiguration.CRClaimDPOSNodeStartHeight
	for _, cr := range crMembers {
		var pk []byte
		if len(cr.DPOSPublicKey) == 0 {
			var err error
			pk, err = common.HexStringToBytes(unclaimedArbiterKeys[0])
			if err != nil {
				return nil, err
			}
			unclaimedArbiterKeys = unclaimedArbiterKeys[1:]
		} else {
			pk = cr.DPOSPublicKey
		}
		crPublicKey := cr.Info.Code[1 : len(cr.Info.Code)-1]
		isNormal := true
		if height >= claimHeight && cr.MemberState != state.MemberElected {
			isNormal = false
		}
		ar, err := NewCRCArbiter(pk, crPublicKey, cr, isNormal)
		if err != nil {
			return nil, err
		}
		crcArbiters[ar.GetOwnerProgramHash()] = ar
	}

	return crcArbiters, nil
}

func (a *Arbiters) getCRCArbitersV0() (map[common.Uint168]ArbiterMember, error) {
	crMembers := a.CRCommittee.GetAllMembersCopy()
	if len(crMembers) != len(a.ChainParams.DPoSConfiguration.CRCArbiters) {
		return nil, errors.New("CRC members count mismatch with CRC arbiters")
	}

	crcArbiters := map[common.Uint168]ArbiterMember{}
	for i, v := range a.ChainParams.DPoSConfiguration.CRCArbiters {
		pk, err := common.HexStringToBytes(v)
		if err != nil {
			return nil, err
		}
		ar, err := NewCRCArbiter(pk, pk, crMembers[i], true)
		if err != nil {
			return nil, err
		}
		crcArbiters[ar.GetOwnerProgramHash()] = ar
	}

	return crcArbiters, nil
}

func (a *Arbiters) GetCandidatesDesc(height uint32, startIndex int,
	producers []*Producer) ([]ArbiterMember, error) {
	// main version >= H2
	if height >= a.ChainParams.PublicDPOSHeight {
		if len(producers) < startIndex {
			return make([]ArbiterMember, 0), nil
		}

		result := make([]ArbiterMember, 0)
		for i := startIndex; i < len(producers) && i < startIndex+a.
			ChainParams.DPoSConfiguration.CandidatesCount; i++ {
			ar, err := NewDPoSArbiter(producers[i])
			if err != nil {
				return nil, err
			}
			result = append(result, ar)
		}
		return result, nil
	}

	// old version [0, H2)
	return nil, nil
}

func (a *Arbiters) GetDposV2CandidatesDesc(startIndex int,
	producers []string, choosingArbiters map[common.Uint168]ArbiterMember) ([]ArbiterMember, error) {
	if len(producers) < startIndex {
		return make([]ArbiterMember, 0), nil
	}

	result := make([]ArbiterMember, 0)
	for i := startIndex; i < len(producers) && i < startIndex+a.
		ChainParams.DPoSConfiguration.CandidatesCount; i++ {
		ownkey, _ := hex.DecodeString(producers[i])
		hash, _ := GetOwnerKeyStandardProgramHash(ownkey)
		crc, exist := choosingArbiters[*hash]
		if exist {
			result = append(result, crc)
		} else {
			ar, err := NewDPoSArbiter(a.getProducer(ownkey))
			if err != nil {
				return nil, err
			}
			result = append(result, ar)
		}
	}
	return result, nil
}

func (a *Arbiters) GetDposV2NormalArbitratorsDesc(
	arbitratorsCount int, producers []string, choosingArbiters map[common.Uint168]ArbiterMember) ([]ArbiterMember, error) {

	return a.getDposV2NormalArbitratorsDescV2(arbitratorsCount, producers, choosingArbiters)
}

func (a *Arbiters) GetNormalArbitratorsDesc(height uint32,
	arbitratorsCount int, producers []*Producer, start int) ([]ArbiterMember, error) {

	// main version >= H2
	if height >= a.ChainParams.PublicDPOSHeight {
		return a.getNormalArbitratorsDescV2(arbitratorsCount, producers, start)
	}

	// version [H1, H2)
	if height >= a.ChainParams.CRCOnlyDPOSHeight {
		return a.getNormalArbitratorsDescV1()
	}

	// version [0, H1)
	return a.getNormalArbitratorsDescV0()
}

func (a *Arbiters) snapshotVotesStates(height uint32) error {
	log.Debugf("snapshotVotesStates height %d begin", height)
	var nextReward RewardData
	recordVotes := func(nodePublicKey []byte) error {
		producer := a.GetProducer(nodePublicKey)
		if producer == nil {
			return errors.New("get producer by node public key failed")
		}
		programHash, err := GetOwnerKeyStandardProgramHash(producer.OwnerPublicKey())
		if err != nil {
			return err
		}
		nextReward.OwnerVotesInRound[*programHash] = producer.Votes()
		nextReward.TotalVotesInRound += producer.Votes()
		return nil
	}

	nextReward.OwnerVotesInRound = make(map[common.Uint168]common.Fixed64, 0)
	nextReward.TotalVotesInRound = 0
	for _, ar := range a.nextArbitrators {
		if height > a.ChainParams.CRConfiguration.ChangeCommitteeNewCRHeight {
			if ar.GetType() == CRC && (!ar.IsNormal() ||
				(len(ar.(*crcArbiter).crMember.DPOSPublicKey) != 0 && ar.IsNormal())) {
				continue
			}
			if err := recordVotes(ar.GetNodePublicKey()); err != nil {
				continue
			}
		} else {
			if !a.isNextCRCArbitrator(ar.GetNodePublicKey()) {
				if err := recordVotes(ar.GetNodePublicKey()); err != nil {
					continue
				}
			}
		}
	}
	log.Debugf("snapshotVotesStates len(a.nextCandidates) %d", len(a.nextCandidates))
	log.Debugf("snapshotVotesStates a.nextCandidates %v", a.nextCandidates)

	for _, ar := range a.nextCandidates {
		if a.isNextCRCArbitrator(ar.GetNodePublicKey()) {
			continue
		}
		producer := a.GetProducer(ar.GetNodePublicKey())
		if producer == nil {
			return errors.New("get producer by node public key failed")
		}
		programHash, err := GetOwnerKeyStandardProgramHash(producer.OwnerPublicKey())
		if err != nil {
			return err
		}
		nextReward.OwnerVotesInRound[*programHash] = producer.Votes()
		nextReward.TotalVotesInRound += producer.Votes()
	}
	log.Debugf("snapshotVotesStates a.NextReward %v", a.NextReward)
	log.Debugf("snapshotVotesStates a.TotalVotesInRound %f", a.NextReward.TotalVotesInRound)

	oriNextReward := a.NextReward
	a.History.Append(height, func() {
		a.NextReward = nextReward
	}, func() {
		a.NextReward = oriNextReward
	})
	return nil
}

func (a *Arbiters) DumpInfo(height uint32) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.dumpInfo(height)
}

func (a *Arbiters) dumpInfo(height uint32) {
	var printer func(string, ...interface{})
	changeType, _ := a.getChangeType(height + 1)
	switch changeType {
	case updateNext:
		fallthrough
	case normalChange:
		printer = log.Infof
	case none:
		printer = log.Debugf
	}

	var crInfo string
	crParams := make([]interface{}, 0)
	if len(a.CurrentArbitrators) != 0 {
		crInfo, crParams = getArbitersInfoWithOnduty("CURRENT ARBITERS",
			a.CurrentArbitrators, a.DutyIndex, a.getOnDutyArbitrator())
	} else {
		crInfo, crParams = getArbitersInfoWithoutOnduty("CURRENT ARBITERS", a.CurrentArbitrators)
	}
	nrInfo, nrParams := getArbitersInfoWithoutOnduty("NEXT ARBITERS", a.nextArbitrators)
	ccInfo, ccParams := getArbitersInfoWithoutOnduty("CURRENT CANDIDATES", a.CurrentCandidates)
	ncInfo, ncParams := getArbitersInfoWithoutOnduty("NEXT CANDIDATES", a.nextCandidates)
	printer(crInfo+nrInfo+ccInfo+ncInfo, append(append(append(crParams, nrParams...), ccParams...), ncParams...)...)
}

// SumBlockTxFees is THE definition of a block's transaction-fee total for the DPoS
// arbiter reward leg. It has exactly two consumers and they must never disagree:
// blockchain.GetBlockDPOSReward (the validator's pre-RevisedDPoSRewardHeight coinbase
// check) and Arbiters.getBlockDPOSReward (the reward STATE, whose output becomes
// claimable ELA). It lives here because dpos/state cannot import blockchain.
//
// XM-04: the F-011/F-086 fix unified the validator onto the ELA-only fee basis at
// RevisedDPoSRewardHeight (blockchain.GetBlockDPOSRewardStrict, fed by checkTxsContext's
// GetTxFeeStrict(ELAAssetID) total) but left the STATE summing the asset-blind tx.Fee().
// The state is the side that mints: accumulateReward -> a.accumulativeReward and
// clearingDPOSReward -> distributeDPOSReward -> a.arbitersRoundReward. So the half that
// was fixed only rejected a bad coinbase, while the half that was missed kept crediting
// arbiters on the wider basis.
//
// The repair has two halves that must land together. XM-03 makes tx.Fee() itself the
// authoritative ELA-only value at and above StrictMoneyRangeHeight, so "sum tx.Fee()" and
// "sum GetTxFeeStrict(ELAAssetID)" are the same number by construction. This function
// makes the remaining shape identical to checkTxsContext's: start at index 1 (the coinbase
// contributes nothing to a fee total; blockchain.CalculateTxsFee skips it too), and refuse
// to let a non-positive fee move the total. Overflow is rejected rather than wrapped.
//
// Gate: RevisedDPoSRewardHeight -- gate 2, the fresh future activation the core engineers
// asked reward-rule changes to take, and the exact height at which the validator already
// switches bases. Below it the legacy expression is returned verbatim (every transaction,
// wrapping addition), so retained history and the window before activation are
// byte-identical. No new gate and no new config literal.
func SumBlockTxFees(txs []interfaces.Transaction, height, revisedGate uint32) common.Fixed64 {
	if height < revisedGate {
		// Legacy, verbatim: bug-compatible with every block validated to date.
		totalTxFx := common.Fixed64(0)
		for _, tx := range txs {
			totalTxFx += tx.Fee()
		}

		return totalTxFx
	}

	totalTxFx := common.Fixed64(0)
	for i := 1; i < len(txs); i++ {
		fee := txs[i].Fee()
		if fee <= 0 {
			// Unreachable once XM-02 is armed (GetTxFeeMapStrict rejects a
			// negative per-asset fee); defence in depth, and it keeps this
			// total identical to checkTxsContext's under every input.
			continue
		}
		sum, err := common.AddFixed64(totalTxFx, fee)
		if err != nil || !common.MoneyRange(sum) {
			return totalTxFx
		}
		totalTxFx = sum
	}

	return totalTxFx
}

func (a *Arbiters) getBlockDPOSReward(block *types.Block) common.Fixed64 {
	totalTxFx := SumBlockTxFees(block.Transactions, block.Height,
		a.ChainParams.RevisedDPoSRewardHeight)

	return common.Fixed64(math.Ceil(float64(totalTxFx+
		a.ChainParams.GetBlockReward(block.Height)) * 0.35))
}

func (a *Arbiters) newCheckPoint(height uint32) *CheckPoint {
	point := &CheckPoint{
		Height:                      height,
		DutyIndex:                   a.DutyIndex,
		CurrentCandidates:           make([]ArbiterMember, 0),
		NextArbitrators:             make([]ArbiterMember, 0),
		NextCandidates:              make([]ArbiterMember, 0),
		CurrentReward:               *NewRewardData(),
		NextReward:                  *NewRewardData(),
		LastDPoSRewards:             make(map[string]map[string]common.Fixed64),
		CurrentCRCArbitersMap:       make(map[common.Uint168]ArbiterMember),
		CurrentOnDutyCRCArbitersMap: make(map[common.Uint168]ArbiterMember),
		NextCRCArbitersMap:          make(map[common.Uint168]ArbiterMember),
		NextCRCArbiters:             make([]ArbiterMember, 0),
		CRCChangedHeight:            a.crcChangedHeight,
		AccumulativeReward:          a.accumulativeReward,
		FinalRoundChange:            a.finalRoundChange,
		ClearingHeight:              a.clearingHeight,
		ForceChanged:                a.forceChanged,
		DegradationState:            byte(a.degradation.state),
		UnderstaffedSince:           a.degradation.understaffedSince,
		InactivateHeight:            a.degradation.inactivateHeight,
		InactiveTxs:                 make(map[common.Uint256]interface{}),
		ArbitersRoundReward:         make(map[common.Uint168]common.Fixed64),
		IllegalBlocksPayloadHashes:  make(map[common.Uint256]interface{}),
		LastArbitrators:             a.LastArbitrators,
		CurrentArbitrators:          a.CurrentArbitrators,
		StateKeyFrame:               *a.State.snapshot(),
	}
	point.LastArbitrators = copyByteList(a.LastArbitrators)
	point.CurrentArbitrators = copyByteList(a.CurrentArbitrators)
	point.CurrentCandidates = copyByteList(a.CurrentCandidates)
	point.NextArbitrators = copyByteList(a.nextArbitrators)
	point.NextCandidates = copyByteList(a.nextCandidates)
	point.CurrentReward = *copyReward(&a.CurrentReward)
	point.NextReward = *copyReward(&a.NextReward)
	point.LastDPoSRewards = copyDPoSRewardMap(a.LastDPoSRewards)
	point.NextCRCArbitersMap = copyCRCArbitersMap(a.nextCRCArbitersMap)
	point.CurrentCRCArbitersMap = copyCRCArbitersMap(a.CurrentCRCArbitersMap)
	point.NextCRCArbiters = copyByteList(a.nextCRCArbiters)

	for k, v := range a.arbitersRoundReward {
		point.ArbitersRoundReward[k] = v
	}
	for k := range a.illegalBlocksPayloadHashes {
		point.IllegalBlocksPayloadHashes[k] = nil
	}
	// F-096: capture the processed-inactive-tx set into the checkpoint.
	for k := range a.degradation.inactiveTxs {
		point.InactiveTxs[k] = nil
	}

	return point
}
func (a *Arbiters) Snapshot() *CheckPoint {
	return a.newCheckPoint(0)
}

func (a *Arbiters) SnapshotByHeight(height uint32) {
	var frames []*CheckPoint
	if v, ok := a.Snapshots[height]; ok {
		frames = v
	} else {
		// remove the oldest keys if SnapshotByHeight capacity is over
		if len(a.SnapshotKeysDesc) >= MaxSnapshotLength {
			for i := MaxSnapshotLength - 1; i < len(a.SnapshotKeysDesc); i++ {
				delete(a.Snapshots, a.SnapshotKeysDesc[i])
			}
			a.SnapshotKeysDesc = a.SnapshotKeysDesc[0 : MaxSnapshotLength-1]
		}

		a.SnapshotKeysDesc = append(a.SnapshotKeysDesc, height)
		sort.Slice(a.SnapshotKeysDesc, func(i, j int) bool {
			return a.SnapshotKeysDesc[i] > a.SnapshotKeysDesc[j]
		})
	}
	checkpoint := a.newCheckPoint(height)
	frames = append(frames, checkpoint)
	a.Snapshots[height] = frames
}

func (a *Arbiters) GetSnapshot(height uint32) []*CheckPoint {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if height > a.bestHeight() {
		return []*CheckPoint{
			{
				CurrentArbitrators: a.CurrentArbitrators,
			},
		}
	} else {
		return a.getSnapshot(height)
	}
}

func (a *Arbiters) getSnapshot(height uint32) []*CheckPoint {
	result := make([]*CheckPoint, 0)
	// F-171: empty snapshot ring -> no valid snapshot answer; return the empty result
	// instead of indexing SnapshotKeysDesc[-1] (crash-harden).
	if len(a.SnapshotKeysDesc) == 0 {
		return result
	}
	if height >= a.SnapshotKeysDesc[len(a.SnapshotKeysDesc)-1] {
		// if height is in range of SnapshotKeysDesc, get the key with the same
		// election as height
		key := a.SnapshotKeysDesc[0]
		for i := 1; i < len(a.SnapshotKeysDesc); i++ {
			if height >= a.SnapshotKeysDesc[i] &&
				height < a.SnapshotKeysDesc[i-1] {
				key = a.SnapshotKeysDesc[i]
			}
		}

		return a.Snapshots[key]
	}
	return result
}

func getArbitersInfoWithOnduty(title string, arbiters []ArbiterMember,
	dutyIndex int, ondutyArbiter []byte) (string, []interface{}) {
	info := "\n" + title + "\nDUTYINDEX: %d\n%5s %66s %6s \n----- " +
		strings.Repeat("-", 66) + " ------\n"
	params := make([]interface{}, 0)
	params = append(params, (dutyIndex+1)%len(arbiters))
	params = append(params, "INDEX", "PUBLICKEY", "ONDUTY")
	for i, arbiter := range arbiters {
		info += "%-5d %-66s %6t\n"
		var publicKey string
		if arbiter.IsNormal() {
			publicKey = common.BytesToHexString(arbiter.GetNodePublicKey())
		}
		params = append(params, i+1, publicKey, bytes.Equal(
			arbiter.GetNodePublicKey(), ondutyArbiter))
	}
	info += "----- " + strings.Repeat("-", 66) + " ------"
	return info, params
}

func getArbitersInfoWithoutOnduty(title string,
	arbiters []ArbiterMember) (string, []interface{}) {

	info := "\n" + title + "\n%5s %66s\n----- " + strings.Repeat("-", 66) + "\n"
	params := make([]interface{}, 0)
	params = append(params, "INDEX", "PUBLICKEY")
	for i, arbiter := range arbiters {
		info += "%-5d %-66s\n"
		var publicKey string
		if arbiter.IsNormal() {
			publicKey = common.BytesToHexString(arbiter.GetNodePublicKey())
		}
		params = append(params, i+1, publicKey)
	}
	info += "----- " + strings.Repeat("-", 66)
	return info, params
}

// initArbitrators is the ONLY constructor the two checkpoint rebuild sites
// (CheckPoint.OnReset and the deep CheckPoint.OnRollbackTo branch, both through
// newBaselineArbiters) run over a hand-built &Arbiters{}. NewArbitrators, by
// contrast, establishes a whole baseline in its composite literal and only THEN
// calls in here -- so every field that literal fills and initArbitrators did not was
// left nil on a rebuild, and recoverFromCheckPoints plants a subset of them straight
// onto the LIVE Arbiters. That is the defect CLASS the guarded block below closes:
// a rebuild must equal a genesis-fresh NewArbitrators field for field, not merely
// avoid whichever dereference happened to crash first.
//
// Every assignment is guarded on nil because the NewArbitrators literal runs FIRST
// and always leaves these non-nil. The guards are therefore provably never taken on
// the NewArbitrators path -- its behaviour is bit-for-bit unchanged -- and an
// already populated field is never wiped. (CRCommittee, CkpManager and
// BlockConfirmProposalSponsors are the literal's only fields that are genesis-time
// INPUTS rather than functions of chainParams; newBaselineArbiters supplies those.)
//
// Fields deliberately left at their zero value are the ones a genesis-fresh
// NewArbitrators ALSO leaves at zero: CurrentCandidates (nil slice), nextCRCArbiters
// (nil slice), arbitersRoundReward (explicitly nil in the literal, and only ever
// wholesale-reassigned, never index-written), DutyIndex, crcChangedHeight,
// accumulativeReward, finalRoundChange, clearingHeight, forceChanged, started,
// pendingSpecialTx and the RegisterFunction closures. Filling those would DIVERGE
// from genesis-fresh, not converge on it.
//
// UNGATED: this only restores the genesis defaults the pristine rebuild always meant
// to produce, so no consensus behaviour moves.
func (a *Arbiters) initArbitrators(chainParams *config.Configuration) error {
	// F-096 made initFromArbitrators READ ar.degradation, so both rebuild sites
	// nil-panicked: DSNormal, no understaffedSince / inactivateHeight, empty
	// processed-inactive-tx set.
	if a.degradation == nil {
		a.degradation = &degradation{
			inactiveTxs:       make(map[common.Uint256]interface{}),
			inactivateHeight:  0,
			understaffedSince: 0,
			state:             DSNormal,
		}
	}

	// HARMFUL when nil, and the reason this commit exists: initFromArbitrators
	// ALIASES this map into the CheckPoint, recoverFromCheckPoints then plants it on
	// the LIVE Arbiters, and ProcessSpecialTxPayload index-writes it unguarded
	// (a.illegalBlocksPayloadHashes[obj.Hash()] = nil) from the two DPoS-gossip entry
	// points ProcessIllegalBlock / ProcessInactiveArbiter -- panicking with
	// "assignment to entry in nil map" in the window between a reset and the first
	// ProcessBlock, which is what re-makes the map. Pre-existing upstream: the
	// rebuild leaves it nil at dcacb82 too, i.e. before F-096 touched this code.
	if a.illegalBlocksPayloadHashes == nil {
		a.illegalBlocksPayloadHashes = make(map[common.Uint256]interface{})
	}

	// Also planted on the LIVE Arbiters by recoverFromCheckPoints. Benign TODAY (only
	// read, and wholesale-reassigned through copyDPoSRewardMap, which maps nil to an
	// empty map), so this converges on genesis-fresh rather than fixing a live crash
	// -- but it removes the standing trap.
	if a.LastDPoSRewards == nil {
		a.LastDPoSRewards = make(map[string]map[string]common.Fixed64)
	}

	// The CheckPoint carries no Snapshots field, so this ring is not planted FROM a
	// checkpoint -- but the earlier claim that the live Arbiters simply "keeps its
	// own" was WRONG as a safety argument: surviving the rebuild is precisely the
	// defect (FV-12), and recoverFromCheckPoints now clears the ring for that reason.
	// Independently, SnapshotByHeight index-writes a.Snapshots[height] unguarded, so a
	// nil here is a crash one refactor away.
	//
	// CORRECTION (campaign close-out), so this guard is not read as load-bearing: on
	// BOTH live rebuild paths it is belt-and-braces, NOT the thing that clears the
	// ring. checkpoint.go OnReset and the OnRollbackTo(height < StartHeight) branch
	// each run newBaselineArbiters -> initArbitrators (here) and then immediately
	// RecoverFromCheckPoints, which UNCONDITIONALLY re-makes both fields. Whatever
	// this guard leaves is replaced before any caller can read it. It earns its place
	// only against a future constructor that reaches initArbitrators WITHOUT a
	// following recoverFromCheckPoints -- there is none today. The FV-12 correctness
	// property lives in recoverFromCheckPoints; do not weaken that one on the
	// strength of this.
	if a.Snapshots == nil {
		a.Snapshots = make(map[uint32][]*CheckPoint)
	}
	if a.SnapshotKeysDesc == nil {
		a.SnapshotKeysDesc = make([]uint32, 0)
	}

	// nil is len/append-safe, so this is purely the genesis-fresh baseline.
	if a.nextCandidates == nil {
		a.nextCandidates = make([]ArbiterMember, 0)
	}

	if a.History == nil {
		a.History = utils.NewHistory(maxHistoryCapacity)
	}

	if a.ChainParams == nil {
		a.ChainParams = chainParams
	}

	originArbiters := make([]ArbiterMember, len(chainParams.DPoSConfiguration.OriginArbiters))
	for i, arbiter := range chainParams.DPoSConfiguration.OriginArbiters {
		b, err := common.HexStringToBytes(arbiter)
		if err != nil {
			return err
		}
		ar, err := NewOriginArbiter(b)
		if err != nil {
			return err
		}

		originArbiters[i] = ar
	}

	crcArbiters := make(map[common.Uint168]ArbiterMember)
	for _, pk := range chainParams.DPoSConfiguration.CRCArbiters {
		pubKey, err := hex.DecodeString(pk)
		if err != nil {
			return err
		}
		producer := &Producer{ // here need crc NODE public key
			info: payload.ProducerInfo{
				OwnerKey:      pubKey,
				NodePublicKey: pubKey,
			},
			activateRequestHeight: math.MaxUint32,
		}
		ar, err := NewDPoSArbiter(producer)
		if err != nil {
			return err
		}
		crcArbiters[ar.GetOwnerProgramHash()] = ar
	}

	a.LastArbitrators = make([]ArbiterMember, 0)
	a.CurrentArbitrators = originArbiters
	a.nextArbitrators = originArbiters
	a.nextCRCArbitersMap = copyCRCArbitersMap(crcArbiters)
	a.CurrentCRCArbitersMap = crcArbiters
	a.CurrentReward = RewardData{
		OwnerVotesInRound: make(map[common.Uint168]common.Fixed64),
		TotalVotesInRound: 0,
	}
	a.NextReward = RewardData{
		OwnerVotesInRound: make(map[common.Uint168]common.Fixed64),
		TotalVotesInRound: 0,
	}
	return nil
}

// LoadBlockConfirmProposalSponsors reads the optional operator "sponsors" file into the
// BlockConfirmProposalSponsors override map.
//
// NX-05. This file is consensus-bearing: Arbiters.ProcessBlock substitutes its entry for
// the sponsor handed to State.ProcessBlock -> countArbitratorsInactivity*, and the
// pre-RecordSponsorStartHeight branch of accumulateReward credits rewards through it. Yet
// it was read from a BARE RELATIVE PATH against the process working directory, so two
// nodes started from different directories loaded different consensus inputs; every read
// failure was swallowed with a single log.Warn; and one malformed line PANICKED the node
// during startup (the old parser indexed field [1] without checking the field count).
//
// It can no longer decide BLOCK VALIDITY at all: NX-01 deleted CheckRecordSponsorBinding,
// which was the map's only validity site, and blockchain/blockvalidator.go
// CheckBlockContext now derives nothing from it. The producer never consulted it
// (pow/service.go GenerateBlock reads the confirm raw), so with the validity site gone
// producer and validator are symmetric by construction -- neither applies the override
// when deciding whether a block is acceptable. What remains here is determinism hardening
// for the two upstream reward/inactivity sites:
//
//  1. a relative path resolves against the configured data directory first, and only
//     then against the working directory, so the CWD stops choosing the file;
//  2. a file that EXISTS but cannot be read or parsed is a hard startup error rather
//     than a warning followed by a silently empty map;
//  3. the byte count, entry count and SHA-256 of the exact bytes loaded are logged, so a
//     fleet can prove every node loaded the same overrides before a coordinated restart.
//
// A genuinely absent file remains a warning, not an error: mainnet ships no sponsors file
// (none exists under the retained chain's data directory and the mainnet config sets no
// path), so an empty map is the correct, and the overwhelmingly common, configuration.
func LoadBlockConfirmProposalSponsors(chainParams *config.Configuration) (map[uint32][]byte, error) {
	sponsors := make(map[uint32][]byte)

	path, data, err := resolveSponsorsFile(chainParams)
	if err != nil {
		return nil, err
	}
	if data == nil {
		log.Warn("sponsors file not exist! block confirm proposal sponsors: 0 -- this node " +
			"applies NO sponsor overrides; every node in the fleet must be configured alike")
		return sponsors, nil
	}

	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 2 {
			return nil, fmt.Errorf("sponsors file %s line %d: want \"<height>,<sponsorHex>\", "+
				"got %q", path, i+1, line)
		}
		height, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sponsors file %s line %d: bad height %q: %v",
				path, i+1, fields[0], err)
		}
		sponsorBytes, err := common.HexStringToBytes(strings.TrimSpace(fields[1]))
		if err != nil {
			return nil, fmt.Errorf("sponsors file %s line %d: bad sponsor %q: %v",
				path, i+1, fields[1], err)
		}
		if prev, ok := sponsors[uint32(height)]; ok && !bytes.Equal(prev, sponsorBytes) {
			return nil, fmt.Errorf("sponsors file %s line %d: height %d declared twice with "+
				"different sponsors", path, i+1, height)
		}
		sponsors[uint32(height)] = sponsorBytes
	}

	digest := sha256.Sum256(data)
	log.Infof("block confirm proposal sponsors: %d entries, %d bytes, loaded from %s "+
		"(sha256 %s) -- every node in the fleet MUST report this same digest and count",
		len(sponsors), len(data), path, hex.EncodeToString(digest[:]))
	return sponsors, nil
}

// resolveSponsorsFile locates the sponsors file deterministically. A relative
// SponsorsFilePath is tried against the configured data directory before the process
// working directory, so nodes started from different directories with the same data
// directory read the same bytes. A nil payload with a nil error means "no sponsors file
// anywhere", which is the mainnet configuration; an existing-but-unreadable file is an
// error, never a silent empty map.
func resolveSponsorsFile(chainParams *config.Configuration) (string, []byte, error) {
	configured := chainParams.DPoSConfiguration.SponsorsFilePath
	if configured == "" {
		return "", nil, nil
	}

	candidates := []string{configured}
	if !filepath.IsAbs(configured) {
		// Mirror main.go's own data-directory resolution exactly (cfg.DataDir when set,
		// otherwise the config.DataDir default), so "the data directory" means the same
		// thing here as it does everywhere else in the node.
		dataDir := chainParams.DataDir
		if dataDir == "" {
			dataDir = config.DataDir
		}
		if dataDir != "" {
			candidates = []string{filepath.Join(dataDir, configured), configured}
		}
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil {
			return path, data, nil
		}
		if !os.IsNotExist(err) {
			return path, nil, fmt.Errorf("sponsors file %s exists but cannot be read: %v",
				path, err)
		}
	}
	return "", nil, nil
}

func NewArbitrators(chainParams *config.Configuration, committee *state.Committee,
	getProducerDepositAmount func(common.Uint168) (common.Fixed64, error),
	tryUpdateCRMemberInactivity func(did common.Uint168, needReset bool, height uint32),
	tryRevertCRMemberInactivityfunc func(did common.Uint168, oriState state.MemberState, oriInactiveCount uint32, height uint32),
	tryUpdateCRMemberIllegal func(did common.Uint168, height uint32, illegalPenalty common.Fixed64),
	tryRevertCRMemberIllegal func(did common.Uint168, oriState state.MemberState, height uint32, illegalPenalty common.Fixed64),
	updateCRInactivePenalty func(cid common.Uint168, height uint32),
	revertUpdateCRInactivePenalty func(cid common.Uint168, height uint32),
	ckpManager *checkpoint.Manager) (*Arbiters, error) {

	blockConfirmProposalSponsors, err := LoadBlockConfirmProposalSponsors(chainParams)
	if err != nil {
		return nil, err
	}

	a := &Arbiters{
		ChainParams:                  chainParams,
		CRCommittee:                  committee,
		CkpManager:                   ckpManager,
		nextCandidates:               make([]ArbiterMember, 0),
		accumulativeReward:           common.Fixed64(0),
		finalRoundChange:             common.Fixed64(0),
		arbitersRoundReward:          nil,
		illegalBlocksPayloadHashes:   make(map[common.Uint256]interface{}),
		Snapshots:                    make(map[uint32][]*CheckPoint),
		SnapshotKeysDesc:             make([]uint32, 0),
		BlockConfirmProposalSponsors: blockConfirmProposalSponsors,
		LastDPoSRewards:              make(map[string]map[string]common.Fixed64),
		crcChangedHeight:             0,
		degradation: &degradation{
			inactiveTxs:       make(map[common.Uint256]interface{}),
			inactivateHeight:  0,
			understaffedSince: 0,
			state:             DSNormal,
		},
		History: utils.NewHistory(maxHistoryCapacity),
	}
	if err := a.initArbitrators(chainParams); err != nil {
		return nil, err
	}
	a.State = NewState(chainParams, a.GetArbitrators, a.CRCommittee.GetCurrentMembers,
		a.CRCommittee.GetNextMembers, a.CRCommittee.IsInElectionPeriod,
		getProducerDepositAmount, tryUpdateCRMemberInactivity, tryRevertCRMemberInactivityfunc,
		tryUpdateCRMemberIllegal, tryRevertCRMemberIllegal,
		updateCRInactivePenalty,
		revertUpdateCRInactivePenalty)
	a.CkpManager.Register(NewCheckpoint(a))
	return a, nil
}
