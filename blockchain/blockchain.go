// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	elaact "github.com/elastos/Elastos.ELA/account"
	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	. "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	crstate "github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/p2p/msg"
	"github.com/elastos/Elastos.ELA/utils"
)

const (
	// maxOrphanBlocks bounds the chain's orphan pool by CARDINALITY.
	//
	// NX-02: this was 10,000 and was the ONLY bound on the pool -- there was no
	// byte counter and no memory ceiling anywhere on the path. A block may be
	// pact.MaxBlockContextSize+pact.MaxBlockHeaderSize = 9,000,000 bytes, so the
	// count cap alone permitted ~85 GiB of attacker-supplied blocks, admitted
	// past a single free gate (CheckBlockSanity, whose work check is against
	// PowLimit) with no ban score charged anywhere on the path. Measured
	// retention was 1.0003x the wire bytes delivered, so a 16 GiB node dies at
	// roughly 1,800 maximum-size orphans.
	//
	// 1024 is still far beyond any honest reorg depth or any legitimate burst of
	// blocks whose parent is momentarily missing (mainnet's average retained
	// block is ~11 KiB, so the byte ceiling below holds ~23,000 of them and this
	// count cap is what binds on honest traffic).
	maxOrphanBlocks = 1024

	// maxOrphanBlockBytes bounds the chain's orphan pool by BYTES, which is the
	// dimension that actually kills the process. 256 MiB is ~28x the largest
	// single block the protocol permits, so no honest orphan is ever rejected
	// for want of room, while the worst case an unauthenticated peer can pin is
	// a fixed, survivable quantity instead of ~85 GiB.
	//
	// UNGATED, on the rationale already recorded in-tree for the shipped
	// F-092/F-117 pool bounds (mempool/blockpool.go:22-41): this is RETENTION
	// policy, not block acceptance. Refusing to RETAIN an orphan cannot change
	// which blocks are valid -- an orphan has by definition not been accepted,
	// CheckBlockContext has never run on it -- and a genuinely connectable block
	// that is dropped is simply re-requested on the next announcement.
	maxOrphanBlockBytes = 256 * 1024 * 1024

	minMemoryNodes     = 20160
	maxBlockLocators   = 500
	medianTimeBlocks   = 11
	maxHistoryCapacity = 720
)

// orphanCountCeiling and orphanByteCeiling are the ceilings AddOrphanBlock
// actually enforces. They are vars rather than consts for one reason only: the
// NX-02 regression test lowers them so that eviction can be driven through the
// real processBlock without moving hundreds of MiB of blocks through a unit
// test. NOTHING IN PRODUCTION ASSIGNS THEM, and
// TestNX02CeilingsDefaultToTheProductionConstants asserts the defaults, so a
// silent weakening of the policy fails the suite.
var (
	orphanCountCeiling = uint64(maxOrphanBlocks)
	orphanByteCeiling  = uint64(maxOrphanBlockBytes)
)

var (
	oneLsh256 = new(big.Int).Lsh(big.NewInt(1), 256)
)

type BlockChain struct {
	chainParams *config.Configuration
	CkpManager  *checkpoint.Manager
	db          IChainStore
	state       *state.State
	crCommittee *crstate.Committee
	UTXOCache   *UTXOCache
	GenesisHash Uint256

	// The following fields are calculated based upon the provided chain
	// parameters.  They are also set when the instance is created and
	// can't be changed afterwards, so there is no need to protect them with
	// a separate mutex.
	minRetargetTimespan int64  // target timespan / adjustment factor
	maxRetargetTimespan int64  // target timespan * adjustment factor
	blocksPerRetarget   uint32 // target timespan / target time per block

	BestChain *BlockNode
	Root      *BlockNode
	index     *blockIndex

	IndexLock sync.RWMutex
	Nodes     []*BlockNode
	DepNodes  map[Uint256][]*BlockNode

	orphanLock     sync.RWMutex
	orphans        map[Uint256]*OrphanBlock
	prevOrphans    map[Uint256][]*OrphanBlock
	oldestOrphan   *OrphanBlock
	orphanConfirms map[Uint256]*payload.Confirm
	// orphanBytes is the running serialized size of every block held in
	// b.orphans (NX-02). Maintained under orphanLock alongside the map itself.
	orphanBytes uint64

	blockCache     map[Uint256]*Block
	confirmCache   map[Uint256]*payload.Confirm
	TimeSource     MedianTimeSource
	MedianTimePast time.Time
	mutex          sync.RWMutex

	AncestorBlock Block
}

func New(db IChainStore, chainParams *config.Configuration, state *state.State,
	committee *crstate.Committee, ckpManager *checkpoint.Manager) (*BlockChain, error) {

	targetTimespan := int64(chainParams.PowConfiguration.TargetTimespan / time.Second)
	targetTimePerBlock := int64(chainParams.PowConfiguration.TargetTimePerBlock / time.Second)
	adjustmentFactor := chainParams.PowConfiguration.AdjustmentFactor
	chain := BlockChain{
		chainParams:         chainParams,
		db:                  db,
		state:               state,
		CkpManager:          ckpManager,
		crCommittee:         committee,
		UTXOCache:           NewUTXOCache(db, chainParams),
		GenesisHash:         chainParams.GenesisBlock.Hash(),
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		blocksPerRetarget:   uint32(targetTimespan / targetTimePerBlock),
		Root:                nil,
		BestChain:           nil,
		Nodes:               make([]*BlockNode, 0),
		index:               newBlockIndex(db, chainParams),
		DepNodes:            make(map[Uint256][]*BlockNode),
		oldestOrphan:        nil,
		orphans:             make(map[Uint256]*OrphanBlock),
		prevOrphans:         make(map[Uint256][]*OrphanBlock),
		blockCache:          make(map[Uint256]*Block),
		confirmCache:        make(map[Uint256]*payload.Confirm),
		orphanConfirms:      make(map[Uint256]*payload.Confirm),
		TimeSource:          NewMedianTime(),
	}

	// Initialize the chain state from the passed database.  When the DB
	// does not yet contain any chain state, both it and the chain state
	// will be initialized to contain only the genesis block.
	if err := chain.initChainState(); err != nil {
		return nil, err
	}

	return &chain, nil
}

func (b *BlockChain) GetDB() IChainStore {
	return b.db
}

func (b *BlockChain) GetParams() *config.Configuration {
	return b.chainParams
}

func (b *BlockChain) Init(interrupt <-chan struct{}) error {
	if err := b.db.GetFFLDB().InitIndex(b, interrupt); err != nil {
		return err
	}
	return nil
}

func (b *BlockChain) MigrateOldDB(
	interrupt <-chan struct{},
	barStart func(total uint32),
	increase func(),
	dataDir string,
	params *config.Configuration) (err error) {

	// No old database need migrate.
	if !utils.FileExisted(filepath.Join(dataDir, oldBlockDbName)) {
		return nil
	}

	oldFFLDB, err := LoadBlockDB(dataDir, oldBlockDbName)
	if err != nil {
		return err
	}
	defer func() {
		oldFFLDB.Close()
		b.db.CloseLeveldb()
	}()
	oldChainStoreFFLDB := &ChainStoreFFLDB{
		db:               oldFFLDB,
		indexManager:     nil,
		blockHashesCache: make([]Uint256, 0, BlocksCacheSize),
		blocksCache:      make(map[Uint256]*DposBlock),
	}
	oldChainStore := &ChainStore{
		fflDB: oldChainStoreFFLDB,
	}
	oldChain, err := New(oldChainStore, params, nil, nil, b.CkpManager)
	if err != nil {
		return err
	}

	endHeight := oldChain.db.GetHeight()
	startHeight := b.GetHeight() + 1

	done := make(chan error)
	go func() {
		log.Info("[MigrateOldDB] start height: ", startHeight, "end height:", endHeight)
		if endHeight < startHeight {
			done <- nil
			return
		}
		if barStart != nil {
			barStart(endHeight - startHeight)
		}
		for start := startHeight; start <= endHeight; start++ {
			hash, err := oldChain.GetBlockHash(start)
			if err != nil {
				done <- fmt.Errorf("GetBlockHash failed : %s", err)
				break
			}
			block, err := oldChain.db.GetFFLDB().GetOldBlock(hash)
			if err != nil {
				done <- fmt.Errorf("GetBlock err: %s", err)
				break
			}
			var confirm *payload.Confirm
			if start >= params.CRCOnlyDPOSHeight {
				confirm, err = b.db.GetConfirm(hash)
				if err != nil {
					done <- fmt.Errorf("get confirm err: %s", err)
					break
				}
			}

			node, err := b.LoadBlockNode(&block.Header, &hash)
			if err != nil {
				done <- fmt.Errorf("load block node err: %s", err)
				break
			}
			b.SetTip(node)

			b.index.SetFlags(&block.Header, statusDataStored)
			err = b.index.flushToDB()
			if err != nil {
				done <- fmt.Errorf("flusht to DB err: %s", err)
				break
			}

			ps, err := GetSaveProcessorsFromBlock(block)
			if err != nil {
				done <- fmt.Errorf("get processors err: %s", err)
				break
			}
			err = b.db.GetFFLDB().SaveBlock(block, node, confirm, CalcPastMedianTime(node), ps)
			if err != nil {
				done <- fmt.Errorf("save block err: %s", err)
				break
			}

			b.index.SetFlags(&block.Header, statusDataStored|statusValid)
			err = b.index.flushToDB()
			if err != nil {
				done <- fmt.Errorf("flush to DB err: %s", err)
				break
			}

			// This node is now the end of the best chain.
			b.BestChain = node
			// Notify process increase.
			if increase != nil {
				increase()
			}
		}
		done <- nil
	}()

	select {
	case err = <-done:
		if err != nil {
			err = fmt.Errorf("process block failed, %s", err)
		} else {
			log.Info("Migrating the old DB finished, then delete the old DB files.")

			// Delete the old database files include "chain", "blocks_ffldb" and "dpos".
			oldFFLDB.Close()
			b.db.CloseLeveldb()
			os.RemoveAll(filepath.Join(dataDir, oldBlockDbName))
			os.RemoveAll(filepath.Join(dataDir, "chain"))
			os.RemoveAll(filepath.Join(dataDir, "dpos"))
		}
	case <-interrupt:
		err = errors.New("process block interrupted")
	}

	return err
}

// restoreCheckpoints loads every checkpoint from its file and re-initializes the
// in-memory state from it.
//
// #4 (R2): CkpManager.Restore -> ICheckPoint.OnInit ->
// Arbiters.RecoverFromCheckPoints REPLACES the whole arbiter set, the degradation
// state, both History objects and the pending special-tx savepoint -- and it swaps
// State.History under a.mtx while a concurrent gossip bracket uses it under s.mtx.
// main.go starts the DPoS arbitrator (main.go:286) BEFORE it calls InitCheckpoint
// (main.go:328), so such a bracket can already be running on another goroutine:
// serialize the restore against it. Nothing below re-acquires specialTxMtx.
func (b *BlockChain) restoreCheckpoints() error {
	DefaultLedger.Arbitrators.LockSpecialTx()
	defer DefaultLedger.Arbitrators.UnlockSpecialTx()

	return b.CkpManager.Restore()
}

// resetCheckpoints throws away all in-memory checkpoint state and rebuilds it from
// the genesis defaults. Only reorganizeChain's recoverFromDefault branch uses it.
//
// #4 (R2): dpos/state CheckPoint.OnReset rebuilds the Arbiters wholesale
// (initArbitrators -> initFromArbitrators -> RecoverFromCheckPoints), so it is its
// own special-tx bracket and must not interleave with a gossip emergency bracket.
// It is reached from reorganizeChain under b.mutex with specialTxMtx free (the
// detach-loop rollback released it), so there is no re-acquisition and the
// [b.mutex ->] specialTxMtx order is preserved.
func (b *BlockChain) resetCheckpoints() {
	DefaultLedger.Arbitrators.LockSpecialTx()
	defer DefaultLedger.Arbitrators.UnlockSpecialTx()

	// Return value discarded exactly as the pristine call site discarded it.
	b.CkpManager.OnReset()
}

// discardStaleCheckpoints is the special-tx BOUNDARY for
// CkpManager.DiscardStaleCheckpoints (FV-01), which reaches ICheckPoint.OnReset and
// therefore rebuilds the Arbiters wholesale exactly as resetCheckpoints does. Same
// lock, same [b.mutex ->] specialTxMtx order, and nothing inside re-acquires it.
func (b *BlockChain) discardStaleCheckpoints(bestHeight uint32) error {
	DefaultLedger.Arbitrators.LockSpecialTx()
	defer DefaultLedger.Arbitrators.UnlockSpecialTx()

	return b.CkpManager.DiscardStaleCheckpoints(bestHeight)
}

// replayCheckpointBlock replays ONE retained-history block into the checkpoints.
//
// #4 (R2): this is a special-tx BRACKET -- PreProcessSpecialTx marks the savepoint
// and applies the emergency ForceChange, CkpManager.OnBlockSaved then mutates the
// very same Arbiters state (dpos/state/checkpoint.go OnBlockSaved ->
// Arbiters.ProcessBlock -> State.ProcessBlock under s.mtx + IncreaseChainHeight
// under a.mtx), and only then is the savepoint committed or undone. N-001 shipped
// this serialization for connectBlock and for the four DPoS-gossip sites but NOT
// for the init/recover replay, which is reachable from main.go:328 (startup, with
// the arbitrator already started at main.go:286) and from reorganizeChain's
// recoverFromDefault branch. Unserialized, a gossip ProcessSpecialTxPayload
// (forceChange reads the producer maps under a.mtx only) races State.ProcessBlock
// (writes them under s.mtx only) -- a genuine cross-mutex data race -- and can also
// mark/commit its own savepoint inside this open bracket.
//
// The lock is taken at the BOUNDARY and released here; nothing inside re-acquires
// it (RollbackTo / RollbackSeekTo deliberately do not self-acquire), so there is no
// self-deadlock. Lock order is [b.mutex ->] specialTxMtx -> {a.mtx, s.mtx,
// CkpManager.mtx, IndexLock} -- reorganizeChain reaches this under b.mutex, the
// startup caller reaches it with no chain lock held, and nothing takes b.mutex
// while holding specialTxMtx, so the order cannot invert.
//
// Pure runtime locking: no decision, no ordering and no stored byte changes, so
// below-gate replay stays identical and the change is UNGATED.
func (b *BlockChain) replayCheckpointBlock(block *DposBlock) error {
	arbiters := DefaultLedger.Arbitrators
	arbiters.LockSpecialTx()
	defer arbiters.UnlockSpecialTx()

	if err := PreProcessSpecialTx(block.Block); err != nil {
		// F-093: the replay aborts here, so the emergency ForceChange this
		// block's special tx just applied must not survive.
		arbiters.UndoPendingSpecialTx()
		return err
	}

	b.CkpManager.OnBlockSaved(block, nil,
		b.state.ConsensusAlgorithm == state.POW, b.state.RevertToPOWBlockHeight, true)
	// F-093: the block is replayed from the retained main chain, so its
	// special-tx effect is committed exactly as it historically was.
	arbiters.CommitPendingSpecialTx()
	return nil
}

// saveBlockCheckpoints is the post-connect checkpoint-save boundary used by the
// reorg attach loop and by processBlock's linear-extend branch.
//
// #4 (R2): CkpManager.OnBlockSaved reaches dpos/state/checkpoint.go OnBlockSaved ->
// Arbiters.ProcessBlock, which mutates exactly the state a concurrent gossip
// emergency bracket mutates (producer maps, arbiter set, DutyIndex, History,
// Snapshots) under a DIFFERENT mutex, so the two must be serialized. connectBlock
// released specialTxMtx in its deferred commit/undo before returning, and
// connectBestChain likewise, so this site never re-acquires a lock it already
// holds.
func (b *BlockChain) saveBlockCheckpoints(block *DposBlock) {
	DefaultLedger.Arbitrators.LockSpecialTx()
	defer DefaultLedger.Arbitrators.UnlockSpecialTx()

	b.CkpManager.OnBlockSaved(block, nil,
		b.state.ConsensusAlgorithm == state.POW, b.state.RevertToPOWBlockHeight, false)
}

// InitCheckpoint goes through all blocks since the genesis block to initialize all
// checkpoints: it restores the checkpoints from disk and replays the retained chain
// forward into them. STARTUP entry point: it keeps a restored checkpoint exactly as
// found, which is what the forced-rollback safety net in main.go then inspects
// through CkpManager.MaxHeight().
func (b *BlockChain) InitCheckpoint(interrupt <-chan struct{},
	barStart func(total uint32), increase func()) error {
	return b.initCheckpoint(interrupt, barStart, increase, false)
}

// InitCheckpointAfterDeepReset is the reorg deep-reset entry point. It is identical
// to InitCheckpoint except that a restored checkpoint sitting ABOVE the post-detach
// best height is discarded and rebuilt rather than trusted -- see
// Manager.DiscardStaleCheckpoints (FV-01). The distinction is deliberate: only the
// reorg branch can restore a snapshot written on a branch the node just abandoned,
// and blanket-discarding at startup would silently convert main.go's
// forced-rollback refusal into a multi-hour full replay.
func (b *BlockChain) InitCheckpointAfterDeepReset() error {
	return b.initCheckpoint(nil, nil, nil, true)
}

// ErrCheckpointInitInterrupted reports that the operator interrupted the
// checkpoint restore-and-replay before it finished.
//
// It exists because the alternative was reporting SUCCESS. The shipped select
// returned the shared `err` variable on the interrupt branch, and on that branch
// the replay goroutine has by definition not finished, so `err` is whatever it
// happened to hold -- nil. MEASURED on the ffldb harness: with the interrupt
// already signalled, InitCheckpoint returned nil having replayed 0 of 9 blocks,
// and the goroutine then replayed all 9 AFTER the caller had been told the
// initialisation succeeded. main.go treats a nil return as "derived state is
// rebuilt" and carries on into the forced-rollback baseline assertion -- which
// reads CkpManager.MaxHeight() while that goroutine is still mutating it -- and
// then starts the P2P server. The DPoS arbiter network is worse still: it is
// started ABOVE this call (main.go, in the `if acc != nil` block, because the
// success path below publishes ETDirectPeersChanged synchronously and that
// subscriber needs a running dpos/p2p server), so the node is ALREADY in the
// arbiter mesh, and a silent nil here leaves it there running on half-derived DPoS
// and CR state. Reading `err` on that branch was also a data race on a variable
// the replay goroutine is concurrently writing.
var ErrCheckpointInitInterrupted = errors.New(
	"checkpoint initialisation interrupted before the derived-state replay finished")

func (b *BlockChain) initCheckpoint(interrupt <-chan struct{},
	barStart func(total uint32), increase func(), discardStale bool) (err error) {
	bestHeight := b.GetHeight()
	log.Info("current block height ->", bestHeight)
	arbiters := DefaultLedger.Arbitrators
	// BUFFERED, and carrying the outcome rather than sharing a variable with the
	// caller. The shipped channel was unbuffered and the goroutine's last statement
	// was a send on it, so on the interrupt branch -- where nobody ever receives --
	// the replay goroutine parked on that send for the lifetime of the process,
	// holding everything it had reached through.
	done := make(chan error, 1)
	go func() {
		var err error
		// Notify initialize process start.
		startHeight := uint32(0)

		if e := b.restoreCheckpoints(); e != nil {
			log.Warn(e)
		}

		// FV-01: the restore above just wrote the on-disk default snapshots into the
		// live checkpoints, height included. On the deep-reset path that file may
		// belong to the branch this reorg is abandoning, and nothing ever lowers a
		// checkpoint height, so a checkpoint left above bestHeight would make both the
		// replay below and the caller's attach loop no-ops for it.
		if discardStale {
			if e := b.discardStaleCheckpoints(bestHeight); e != nil {
				done <- e
				return
			}
		}

		safeHeight := b.CkpManager.SafeHeight()
		if startHeight < safeHeight {
			startHeight = safeHeight + 1
		}

		log.Info("[RecoverFromCheckPoints] recover start height: ", startHeight)
		if barStart != nil && bestHeight >= startHeight {
			barStart(bestHeight - startHeight)
		}

		for i := startHeight; i <= bestHeight; i++ {
			// Stop AT A BLOCK BOUNDARY when the operator interrupts, so the replay
			// does not keep rebuilding derived state behind a caller that has already
			// been told the initialisation did not complete.
			select {
			case <-interrupt:
				done <- ErrCheckpointInitInterrupted
				return
			default:
			}

			hash, e := b.GetBlockHash(i)
			if e != nil {
				err = e
				break
			}
			block, e := b.db.GetFFLDB().GetBlock(hash)
			if e != nil {
				err = e
				break
			}

			if block.Height >= b.chainParams.DPoSV2StartHeight {
				CalculateTxsFee(block.Block)
			} else {
				if block.Height >= bestHeight-uint32(
					b.chainParams.DPoSConfiguration.NormalArbitratorsCount+len(b.chainParams.DPoSConfiguration.CRCArbiters)) {
					CalculateTxsFee(block.Block)
				}
			}

			if e = b.replayCheckpointBlock(block); e != nil {
				err = e
				break
			}

			// Notify process increase.
			if increase != nil {
				increase()
			}
		}

		done <- err
	}()
	select {
	case e := <-done:
		if errors.Is(e, ErrCheckpointInitInterrupted) {
			// The replay stopped itself on the interrupt. Nothing below may run: the
			// arbiter set has not been rebuilt, so starting it and announcing its
			// peers would put a node with half-derived DPoS state into the mesh.
			return e
		}
		err = e
		arbiters.Start()

		currentArbiters := arbiters.GetCurrentNeedConnectArbiters()
		nextArbiters := arbiters.GetNextNeedConnectArbiters()
		crArbiters := arbiters.GetNeedConnectCRArbiters()

		events.Notify(events.ETDirectPeersChanged,
			&peer.PeersInfo{
				CurrentPeers: currentArbiters,
				NextPeers:    nextArbiters,
				CRPeers:      crArbiters})

	case <-interrupt:
		// NOT `return err`. The replay goroutine is still running and still writing
		// that variable; reading it here is both a data race and, because it is
		// almost always still nil, a report of SUCCESS for an initialisation that
		// did not happen.
		return ErrCheckpointInitInterrupted
	}
	return err
}

func (b *BlockChain) createTransaction(pd interfaces.Payload, txType common.TxType,
	fromAddress Uint168, fee Fixed64, lockedUntil uint32,
	utxos []*common.UTXO, outputs ...*common.OutputInfo) (interfaces.Transaction, error) {

	// check output
	if len(outputs) == 0 {
		return nil, errors.New("invalid transaction target")
	}
	// create outputs
	txOutputs, totalAmount, err := b.createNormalOutputs(outputs, fee,
		lockedUntil)
	if err != nil {
		return nil, err
	}
	// create Inputs
	txInputs, changeOutputs, err := b.createInputs(fromAddress, totalAmount, utxos)
	if err != nil {
		return nil, err
	}
	txOutputs = append(txOutputs, changeOutputs...)

	return functions.CreateTransaction(
		common.TxVersion09,
		txType,
		0,
		pd,
		[]*common.Attribute{},
		txInputs,
		txOutputs,
		0,
		[]*program.Program{},
	), nil
}

func (b *BlockChain) createNormalOutputs(outputs []*common.OutputInfo, fee Fixed64,
	lockedUntil uint32) ([]*common.Output, Fixed64, error) {
	var totalAmount = Fixed64(0)   // The total amount will be spend
	var txOutputs []*common.Output // The outputs in transaction
	totalAmount += fee             // Add transaction fee
	for _, output := range outputs {
		txOutput := &common.Output{
			AssetID:     *elaact.SystemAssetID,
			ProgramHash: output.Recipient,
			Value:       output.Amount,
			OutputLock:  lockedUntil,
			Type:        common.OTNone,
			Payload:     &outputpayload.DefaultOutput{},
		}
		totalAmount += output.Amount
		txOutputs = append(txOutputs, txOutput)
	}
	return txOutputs, totalAmount, nil
}

func (b *BlockChain) getUTXOsFromAddress(address Uint168) ([]*common.UTXO, Fixed64, error) {
	var utxoSlice []*common.UTXO
	var lockedAmount Fixed64
	utxos, err := b.db.GetFFLDB().GetUTXO(&address)
	if err != nil {
		return nil, 0, err
	}
	curHeight := b.getHeight()
	for _, utxo := range utxos {
		referTxn, err := b.UTXOCache.GetTransaction(utxo.TxID)
		if err != nil {
			return nil, 0, err
		}
		diff := curHeight - referTxn.LockTime()
		if referTxn.IsCoinBaseTx() && diff < b.chainParams.PowConfiguration.CoinbaseMaturity {
			lockedAmount += utxo.Value
			continue
		}
		utxoSlice = append(utxoSlice, utxo)
	}
	sort.Slice(utxoSlice, func(i, j int) bool {
		if utxoSlice[i].Value == utxoSlice[j].Value {
			return utxoSlice[i].Hash().Compare(utxoSlice[j].Hash()) < 0
		}
		return utxoSlice[i].Value > utxoSlice[j].Value
	})

	return utxoSlice, lockedAmount, nil
}

func (b *BlockChain) createInputs(fromAddress Uint168,
	totalAmount Fixed64, utxos []*common.UTXO) ([]*common.Input, []*common.Output, error) {
	var txInputs []*common.Input
	var changeOutputs []*common.Output
	for _, utxo := range utxos {
		input := &common.Input{
			Previous: common.OutPoint{
				TxID:  utxo.TxID,
				Index: uint16(utxo.Index),
			},
			Sequence: 4294967295,
		}
		txInputs = append(txInputs, input)
		amount := &utxo.Value
		if *amount < totalAmount {
			totalAmount -= *amount
		} else if *amount == totalAmount {
			totalAmount = 0
			break
		} else if *amount > totalAmount {
			change := &common.Output{
				AssetID:     *elaact.SystemAssetID,
				Value:       *amount - totalAmount,
				OutputLock:  uint32(0),
				ProgramHash: fromAddress,
				Type:        common.OTNone,
				Payload:     &outputpayload.DefaultOutput{},
			}
			changeOutputs = append(changeOutputs, change)
			totalAmount = 0
			break
		}
	}
	if totalAmount > 0 {
		return nil, nil, errors.New("[Committee], Available token is not enough")
	}

	return txInputs, changeOutputs, nil
}

func (b *BlockChain) CreateCRCAppropriationTransaction() (interfaces.Transaction, Fixed64, error) {
	utxos, lockedAmount, err := b.getUTXOsFromAddress(*b.chainParams.CRConfiguration.CRAssetsProgramHash)
	if err != nil {
		return nil, 0, err
	}
	var crcFoundationBalance Fixed64
	for _, u := range utxos {
		crcFoundationBalance += u.Value
	}
	p := b.chainParams.CRConfiguration.CRCAppropriatePercentage
	appropriationAmount := Fixed64(float64(crcFoundationBalance) * p / 100.0)

	log.Info("create appropriation transaction amount:", appropriationAmount)
	if appropriationAmount <= 0 {
		return nil, 0, nil
	}
	outputs := []*common.OutputInfo{{*b.chainParams.CRConfiguration.CRExpensesProgramHash,
		appropriationAmount}}

	tx, err := b.createTransaction(&payload.CRCAppropriation{}, common.CRCAppropriation,
		*b.chainParams.CRConfiguration.CRAssetsProgramHash, Fixed64(0), uint32(0), utxos, outputs...)
	if err != nil {
		return nil, 0, err
	}
	return tx, lockedAmount, nil
}

func (b *BlockChain) CreateDposV2RealWithdrawTransaction(
	withdrawTransactionHashes []Uint256, outputs []*common.OutputInfo) (interfaces.Transaction, error) {
	utxos, _, err := b.getUTXOsFromAddress(*b.chainParams.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash)
	if err != nil {
		return nil, err
	}

	wPayload := &payload.DposV2ClaimRewardRealWithdraw{
		WithdrawTransactionHashes: withdrawTransactionHashes,
	}

	for _, v := range outputs {
		v.Amount -= b.chainParams.CRConfiguration.RealWithdrawSingleFee
	}

	txFee := b.chainParams.CRConfiguration.RealWithdrawSingleFee * Fixed64(len(withdrawTransactionHashes))
	var tx interfaces.Transaction
	tx, err = b.createTransaction(wPayload, common.DposV2ClaimRewardRealWithdraw,
		*b.chainParams.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash, txFee, uint32(0), utxos, outputs...)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (b *BlockChain) CreateVotesRealWithdrawTransaction(
	returnVotesTXHashes []Uint256, outputs []*common.OutputInfo) (interfaces.Transaction, error) {
	utxos, _, err := b.getUTXOsFromAddress(*b.chainParams.StakePoolProgramHash)
	if err != nil {
		return nil, err
	}
	var votesRealWithdraw []payload.VotesRealWidhdraw
	for i, output := range outputs {
		withdraw := payload.VotesRealWidhdraw{
			ReturnVotesTXHash: returnVotesTXHashes[i],
			StakeAddress:      output.Recipient,
			Value:             output.Amount,
		}
		votesRealWithdraw = append(votesRealWithdraw, withdraw)
	}

	wPayload := &payload.VotesRealWithdrawPayload{
		VotesRealWithdraw: votesRealWithdraw,
	}

	for _, v := range outputs {
		v.Amount -= b.chainParams.CRConfiguration.RealWithdrawSingleFee
	}
	//todo fee
	txFee := b.chainParams.CRConfiguration.RealWithdrawSingleFee * Fixed64(len(returnVotesTXHashes))
	var tx interfaces.Transaction
	tx, err = b.createTransaction(wPayload, common.VotesRealWithdraw,
		*b.chainParams.StakePoolProgramHash, txFee, uint32(0), utxos, outputs...)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (b *BlockChain) CreateCRRealWithdrawTransaction(
	withdrawTransactionHashes []Uint256, outputs []*common.OutputInfo) (interfaces.Transaction, error) {
	utxos, _, err := b.getUTXOsFromAddress(*b.chainParams.CRConfiguration.CRExpensesProgramHash)
	if err != nil {
		return nil, err
	}

	wPayload := &payload.CRCProposalRealWithdraw{
		WithdrawTransactionHashes: withdrawTransactionHashes,
	}

	for _, v := range outputs {
		v.Amount -= b.chainParams.CRConfiguration.RealWithdrawSingleFee
	}

	txFee := b.chainParams.CRConfiguration.RealWithdrawSingleFee * Fixed64(len(withdrawTransactionHashes))
	tx, err := b.createTransaction(wPayload, common.CRCProposalRealWithdraw,
		*b.chainParams.CRConfiguration.CRExpensesProgramHash, txFee, uint32(0), utxos, outputs...)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (b *BlockChain) CreateCRAssetsRectifyTransaction() (interfaces.Transaction, error) {
	utxos, _, err := b.getUTXOsFromAddress(*b.chainParams.CRConfiguration.CRAssetsProgramHash)
	if err != nil {
		return nil, err
	}
	if len(utxos) < int(b.chainParams.CRConfiguration.MinCRAssetsAddressUTXOCount) {
		return nil, errors.New("Available utxo is less than MinCRAssetsAddressUTXOCount")
	}
	if len(utxos) > int(b.chainParams.CRConfiguration.MaxCRAssetsAddressUTXOCount) {
		utxos = utxos[:b.chainParams.CRConfiguration.MaxCRAssetsAddressUTXOCount]
	}
	var crcFoundationBalance Fixed64
	for i, u := range utxos {
		if i >= int(b.chainParams.CRConfiguration.MaxCRAssetsAddressUTXOCount) {
			break
		}
		crcFoundationBalance += u.Value
	}
	rectifyAmount := crcFoundationBalance - b.chainParams.CRConfiguration.RectifyTxFee

	log.Info("create CR assets rectify amount:", rectifyAmount)
	if rectifyAmount <= 0 {
		return nil, nil
	}
	outputs := []*common.OutputInfo{{*b.chainParams.CRConfiguration.CRAssetsProgramHash,
		rectifyAmount}}

	tx, err := b.createTransaction(&payload.CRAssetsRectify{}, common.CRAssetsRectify,
		*b.chainParams.CRConfiguration.CRAssetsProgramHash,
		b.chainParams.CRConfiguration.RectifyTxFee, uint32(0), utxos, outputs...)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func CalculateTxsFee(block *Block) {
	for _, tx := range block.Transactions {
		if tx.IsCoinBaseTx() {
			continue
		}
		references, err := DefaultLedger.Blockchain.UTXOCache.GetTxReference(tx)
		if err != nil {
			log.Error("get transaction Reference failed")
			return
		}
		// Height-gated to stay bit-identical to unpatched nodes (and to the
		// acceptance-path getTransactionFee) BELOW StrictMoneyRangeHeight: this value
		// feeds tx.Fee() -> DPoS reward derivation, so it must match the network
		// exactly on historical/reindexed blocks. At/above the gate use checked
		// accumulation (an overflowing tx cannot be accepted there anyway).
		var outputValue Fixed64
		var inputValue Fixed64
		if block.Height >= DefaultLedger.Blockchain.chainParams.StrictMoneyRangeHeight {
			var feeAccErr error
			for _, output := range tx.Outputs() {
				if outputValue, feeAccErr = AddFixed64(outputValue, output.Value); feeAccErr != nil {
					break
				}
			}
			for _, output := range references {
				if feeAccErr != nil {
					break
				}
				inputValue, feeAccErr = AddFixed64(inputValue, output.Value)
			}
			if feeAccErr != nil {
				log.Errorf("CalculateTxsFee: value overflow computing fee for tx %s (post-validation, unexpected); skipping fee annotation", tx.Hash())
				continue
			}
		} else {
			for _, output := range tx.Outputs() {
				outputValue += output.Value
			}
			for _, output := range references {
				inputValue += output.Value
			}
		}
		// set Fee and FeePerKB if check has passed
		tx.SetFee(inputValue - outputValue)
		buf := new(bytes.Buffer)
		tx.Serialize(buf)
		tx.SetFeePerKB(tx.Fee() * 1000 / Fixed64(len(buf.Bytes())))
	}
}

// GetState returns the DPOS state instance that stores producers and votes
// information.
func (b *BlockChain) GetState() *state.State {
	return b.state
}
func (b *BlockChain) SetState(s *state.State) {
	b.state = s
}

func (b *BlockChain) GetCRCommittee() *crstate.Committee {
	return b.crCommittee
}
func (b *BlockChain) SetCRCommittee(c *crstate.Committee) {
	b.crCommittee = c
}

func (b *BlockChain) GetBlock(height uint32) (*Block, error) {
	hash, err := b.GetBlockHash(height)
	if err != nil {
		return nil, err
	}
	block, err := b.db.GetFFLDB().GetBlock(hash)
	if err != nil {
		return nil, err
	}
	CalculateTxsFee(block.Block)
	return block.Block, nil
}

func (b *BlockChain) GetBestBlockHash() *Uint256 {
	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()
	if len(b.Nodes) == 0 {
		return nil
	}
	return b.Nodes[len(b.Nodes)-1].Hash
}

func (b *BlockChain) GetHeight() uint32 {
	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()

	return b.getHeight()
}

func (b *BlockChain) getHeight() uint32 {
	if len(b.Nodes) == 0 {
		return 0
	}
	return uint32(len(b.Nodes) - 1)
}

func (b *BlockChain) ProcessBlock(block *Block, confirm *payload.Confirm) (bool, bool, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	return b.processBlock(block, confirm)
}

func (b *BlockChain) GetHeader(hash Uint256) (*common.Header, error) {
	header, err := b.db.GetFFLDB().GetHeader(hash)
	if err != nil {
		return nil, errors.New("[BlockChain], GetHeader failed.")
	}
	return header, nil
}

// Get block with block hash.
func (b *BlockChain) GetBlockByHash(hash Uint256) (*Block, error) {
	dposBlock, err := b.db.GetFFLDB().GetBlock(hash)
	if err != nil {
		return nil, err
	}
	return dposBlock.Block, nil
}

// Get block with block hash.
func (b *BlockChain) GetBlockHash(height uint32) (Uint256, error) {
	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()

	if height >= uint32(len(b.Nodes)) {
		return EmptyHash, errors.New("not found block")
	}
	return *b.Nodes[height].Hash, nil
}

// Get block with block hash.
func (b *BlockChain) GetBlockNode(height uint32) *BlockNode {
	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()

	if height >= uint32(len(b.Nodes)) {
		return nil
	}
	return b.Nodes[height]
}

// Get block by height
func (b *BlockChain) GetBlockByHeight(height uint32) (*Block, error) {
	// Lookup the block height in the best chain.
	node := b.GetBlockNode(height)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return nil, errors.New(str)
	}

	// Load the block from the database and return it.
	var block *Block
	err := b.db.GetFFLDB().View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

// MainChainHasBlock returns whether or not the block with the given hash is in
// the main chain.
func (b *BlockChain) MainChainHasBlock(height uint32, hash *Uint256) bool {
	// Lookup the block height in the best chain.
	node := b.GetBlockNode(height)
	return node != nil && node.Hash.IsEqual(*hash)
}

// Get DPOS block with block hash.
func (b *BlockChain) GetDposBlockByHash(hash Uint256) (*DposBlock, error) {
	if block, _ := b.db.GetFFLDB().GetBlock(hash); block != nil {
		return block, nil
	}

	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	if orphan := b.orphans[hash]; orphan != nil {
		confirm := b.orphanConfirms[hash]
		return &DposBlock{
			Block:       orphan.Block,
			HaveConfirm: confirm != nil,
			Confirm:     confirm,
		}, nil
	}

	return nil, errors.New("not found dpos block in block chain")
}

func (b *BlockChain) ContainsTransaction(hash Uint256) bool {
	//TODO: implement error catch
	_, _, err := b.db.GetTransaction(hash)
	if err != nil {
		return false
	}
	return true
}

func (b *BlockChain) GetCurrentBlockHash() Uint256 {
	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()

	return *b.Nodes[len(b.Nodes)-1].Hash
}

func (b *BlockChain) ProcessIllegalBlock(payload *payload.DPOSIllegalBlocks) {
	// if received inactive when synchronizing, then return
	if payload.GetBlockHeight() > b.GetHeight() {
		log.Info("received inactive tx when synchronizing")
		return
	}
	// #4: hold specialTxMtx across the whole gossip bracket so it cannot interleave
	// with a concurrent block-connect or reorg-detach bracket.
	DefaultLedger.Arbitrators.LockSpecialTx()
	if err := DefaultLedger.Arbitrators.ProcessSpecialTxPayload(payload,
		b.BestChain.Height); err != nil {
		log.Error("process illegal block error: ", err)
	}
	// F-093: the gossip path is not bracketed by a block connect -- its emergency
	// change is permanent, exactly as it was before the fix.
	DefaultLedger.Arbitrators.CommitPendingSpecialTx()
	DefaultLedger.Arbitrators.UnlockSpecialTx()
}

func (b *BlockChain) ProcessInactiveArbiter(payload *payload.InactiveArbitrators) {
	// if received inactive when synchronizing, then return
	if payload.GetBlockHeight() > b.GetHeight()+1 {
		log.Info("received inactive tx when synchronizing")
		return
	}
	// #4: hold specialTxMtx across the whole gossip bracket so it cannot interleave
	// with a concurrent block-connect or reorg-detach bracket.
	DefaultLedger.Arbitrators.LockSpecialTx()
	if err := DefaultLedger.Arbitrators.ProcessSpecialTxPayload(payload,
		b.BestChain.Height); err != nil {
		log.Error("process illegal block error: ", err)
	}
	// F-093: the gossip path is not bracketed by a block connect -- its emergency
	// change is permanent, exactly as it was before the fix.
	DefaultLedger.Arbitrators.CommitPendingSpecialTx()
	DefaultLedger.Arbitrators.UnlockSpecialTx()
}

type OrphanBlock struct {
	Block      *Block
	Expiration time.Time
	// size is the serialized size of Block, captured once at insert so that the
	// running total in BlockChain.orphanBytes is credited and debited with the
	// identical value even if Block were ever mutated (NX-02).
	size uint64
}

func (b *BlockChain) ProcessOrphans(hash *Uint256) error {
	// NX-02: the 1-hour expiry stamped in AddOrphanBlock used to be enforced ONLY
	// by the sweep at the top of AddOrphanBlock itself, so once an attacker
	// stopped sending, the orphans it had pinned were retained for the life of
	// the process -- the pool did not self-heal. ProcessOrphans runs on every
	// successful block connect (processBlock, after maybeAcceptBlock), so
	// sweeping here releases expired orphans at the chain's own cadence without
	// introducing a background goroutine or any new lifecycle to manage.
	b.SweepExpiredOrphans()

	processHashes := make([]*Uint256, 0, 10)
	processHashes = append(processHashes, hash)
	for len(processHashes) > 0 {
		processHash := processHashes[0]
		processHashes[0] = nil // Prevent GC leak.
		processHashes = processHashes[1:]

		for i := 0; i < len(b.prevOrphans[*processHash]); i++ {
			orphan := b.prevOrphans[*processHash][i]
			if orphan == nil {
				continue
			}

			orphanHash := orphan.Block.Hash()
			confirm, _ := b.GetOrphanConfirm(&orphanHash)

			//log.Debug("deal with orphan block %x", orphanHash.ToArrayReverse())
			_, err := b.maybeAcceptBlock(orphan.Block, confirm)
			if err != nil {
				return err
			}

			b.RemoveOrphanBlock(orphan)
			i--
			processHashes = append(processHashes, &orphanHash)

		}
	}
	return nil
}

func (b *BlockChain) RemoveOrphanBlock(orphan *OrphanBlock) {
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	b.removeOrphanBlockLocked(orphan)
}

// removeOrphanBlockLocked drops an orphan from every index and debits its bytes
// from the running total. The caller must hold b.orphanLock for writing.
func (b *BlockChain) removeOrphanBlockLocked(orphan *OrphanBlock) {
	if orphan == nil {
		return
	}

	orphanHash := orphan.Block.Hash()
	// NX-02: an eviction that silently removes nothing is how a count cap gets
	// exceeded. Only debit bytes for the entry that is actually in the map, and
	// compare by identity so a stale pointer can never evict its replacement.
	if cur, exists := b.orphans[orphanHash]; !exists || cur != orphan {
		if b.oldestOrphan == orphan {
			b.oldestOrphan = nil
		}
		return
	}

	delete(b.orphans, orphanHash)
	delete(b.orphanConfirms, orphanHash)
	if b.orphanBytes >= orphan.size {
		b.orphanBytes -= orphan.size
	} else {
		b.orphanBytes = 0
	}

	prevHash := &orphan.Block.Header.Previous
	orphans := b.prevOrphans[*prevHash]
	for i := 0; i < len(orphans); i++ {
		hash := orphans[i].Block.Hash()
		if hash.IsEqual(orphanHash) {
			copy(orphans[i:], orphans[i+1:])
			orphans[len(orphans)-1] = nil
			orphans = orphans[:len(orphans)-1]
			i--
		}
	}
	b.prevOrphans[*prevHash] = orphans

	if len(b.prevOrphans[*prevHash]) == 0 {
		delete(b.prevOrphans, *prevHash)
	}

	if b.oldestOrphan == orphan {
		b.oldestOrphan = nil
	}
}

// SweepExpiredOrphans drops every orphan whose 1-hour expiry has passed. It is
// safe to call at any time and takes no argument, so it can be driven from the
// block-connect path as well as from the insert path (NX-02: before this, the
// expiry fired only inside AddOrphanBlock, so a pool filled by an attacker who
// then went quiet was pinned for the life of the process).
func (b *BlockChain) SweepExpiredOrphans() {
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	b.expireOrphansLocked()
}

// expireOrphansLocked removes expired orphans. Caller must hold b.orphanLock for
// writing. Deleting from a map while ranging over it in the same goroutine is
// well defined in Go.
func (b *BlockChain) expireOrphansLocked() {
	now := time.Now()
	for _, oBlock := range b.orphans {
		if now.After(oBlock.Expiration) {
			b.removeOrphanBlockLocked(oBlock)
		}
	}
}

// oldestOrphanLocked returns the orphan with the earliest expiration, which is
// also the earliest inserted (every orphan is stamped now+1h at insert). Caller
// must hold b.orphanLock for writing.
func (b *BlockChain) oldestOrphanLocked() *OrphanBlock {
	var oldest *OrphanBlock
	for _, oBlock := range b.orphans {
		if oldest == nil || oBlock.Expiration.Before(oldest.Expiration) {
			oldest = oBlock
		}
	}
	b.oldestOrphan = oldest
	return oldest
}

// makeOrphanRoomLocked expires stale orphans and then evicts oldest-first until
// the pool can take another `incoming` bytes while staying under BOTH the count
// ceiling and the byte ceiling. Caller must hold b.orphanLock for writing.
func (b *BlockChain) makeOrphanRoomLocked(incoming uint64) {
	b.expireOrphansLocked()

	for len(b.orphans) > 0 &&
		(uint64(len(b.orphans))+1 > orphanCountCeiling ||
			b.orphanBytes+incoming > orphanByteCeiling) {
		oldest := b.oldestOrphanLocked()
		if oldest == nil {
			break
		}
		b.removeOrphanBlockLocked(oldest)
	}
}

func (b *BlockChain) AddOrphanBlock(block *Block) {
	// Serialize outside the lock. CheckBlockSanity has already called GetSize on
	// this block before processBlock reached us, so this costs no new order of
	// work on the admission path.
	size := block.GetSize()
	if size < 0 {
		// A block that will not serialize cannot be sized; charge it the
		// protocol maximum rather than accounting it as free.
		size = int(pact.MaxBlockContextSize + pact.MaxBlockHeaderSize)
	}

	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	hash := block.Hash()
	if _, exists := b.orphans[hash]; exists {
		// Already retained; re-inserting would double-count its bytes.
		return
	}

	b.makeOrphanRoomLocked(uint64(size))

	// Insert the block into the orphan map with an expiration time
	// 1 hour from now.
	expiration := time.Now().Add(time.Hour)
	oBlock := &OrphanBlock{
		Block:      block,
		Expiration: expiration,
		size:       uint64(size),
	}
	b.orphans[hash] = oBlock
	b.orphanBytes += uint64(size)

	// Add to previous hash lookup index for faster dependency lookups.
	prevHash := &block.Header.Previous
	b.prevOrphans[*prevHash] = append(b.prevOrphans[*prevHash], oBlock)

	// The newest orphan is never the oldest; force a recompute on the next
	// eviction rather than carrying a stale pointer across calls.
	b.oldestOrphan = nil

	return
}

// OrphanPoolStats reports the current occupancy of the chain's orphan pool
// (count, bytes) together with the ceilings it is held under (NX-02).
func (b *BlockChain) OrphanPoolStats() (count int, bytes uint64, maxCount uint64, maxBytes uint64) {
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	return len(b.orphans), b.orphanBytes, orphanCountCeiling, orphanByteCeiling
}

func (b *BlockChain) AddOrphanConfirm(confirm *payload.Confirm) {
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// NX-02: orphanConfirms is only ever DRAINED by removeOrphanBlockLocked,
	// which is keyed by an orphan's hash, so a confirm whose block is not (or is
	// no longer) in the pool would be pinned for the life of the process on the
	// same unauthenticated path. The sole production caller
	// (mempool/blockpool.go:251) reaches here immediately after ProcessBlock
	// reported isOrphan, so in the normal case the block IS present; the race it
	// loses is the one where the byte ceiling evicted the block in between, and
	// in that case the confirm is useless anyway — ProcessOrphans only ever
	// looks a confirm up for an orphan it is holding. Binding admission to
	// membership makes this map bounded by the pool by construction.
	if _, exists := b.orphans[confirm.Proposal.BlockHash]; !exists {
		return
	}

	b.orphanConfirms[confirm.Proposal.BlockHash] = confirm
}

func (b *BlockChain) GetOrphanConfirm(hash *Uint256) (*payload.Confirm, bool) {
	b.orphanLock.RLock()
	confirm, ok := b.orphanConfirms[*hash]
	b.orphanLock.RUnlock()
	return confirm, ok
}

func (b *BlockChain) IsKnownOrphan(hash *Uint256) bool {
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	if _, exists := b.orphans[*hash]; exists {
		return true
	}

	return false
}

func (b *BlockChain) GetOrphan(hash *Uint256) *OrphanBlock {
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	orphan, _ := b.orphans[*hash]
	return orphan
}

func (b *BlockChain) GetOrphanRoot(hash *Uint256) *Uint256 {
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	orphanRoot := hash
	prevHash := hash
	for {
		orphan, exists := b.orphans[*prevHash]
		if !exists {
			break
		}
		orphanRoot = prevHash
		prevHash = &orphan.Block.Header.Previous
	}

	return orphanRoot
}

func compactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes to represent the full 256-bit number.  So,
	// treat the exponent as the number of bytes and shift the mantissa
	// right or left accordingly.  This is equivalent to:
	// N = mantissa * 256^(exponent-3)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	// Make it negative if the sign bit is set.
	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

// (1 << 256) / (difficultyNum + 1)
func CalcWork(bits uint32) *big.Int {
	difficultyNum := compactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	//denominator := new(big.Int).Add(difficultyNum, bigOne)
	denominator := new(big.Int).Add(difficultyNum, big.NewInt(1))

	return new(big.Int).Div(oneLsh256, denominator)
}

func AddChildrenWork(node *BlockNode, work *big.Int) {
	for _, childNode := range node.Children {
		childNode.WorkSum.Add(childNode.WorkSum, work)
		AddChildrenWork(childNode, work)
	}
}

func RemoveChildNode(children []*BlockNode, node *BlockNode) []*BlockNode {
	if node == nil {
		return children
	}

	for i := 0; i < len(children); i++ {
		if (*children[i].Hash).IsEqual(*node.Hash) {
			copy(children[i:], children[i+1:])
			children[len(children)-1] = nil
			return children[:len(children)-1]
		}
	}
	return children

}

func (b *BlockChain) LoadBlockNode(blockHeader *common.Header, hash *Uint256) (*BlockNode, error) {

	// Create the new block node for the block and set the work.
	node := NewBlockNode(blockHeader, hash)
	node.InMainChain = true

	// Add the node to the chain.
	// There are several possibilities here:
	//  1) This node is a child of an existing block node
	//  2) This node is the parent of one or more nodes
	//  3) Neither 1 or 2 is true, and this is not the first node being
	//     added to the tree which implies it's an orphan block and
	//     therefore is an error to insert into the chain
	//  4) Neither 1 or 2 is true, but this is the first node being added
	//     to the tree, so it's the root.
	prevHash := &blockHeader.Previous
	//if parentNode, ok := b.Index[*prevHash]; ok {
	if parentNode, ok := b.index.LookupNode(prevHash); ok {
		// Case 1 -- This node is a child of an existing block node.
		// Update the node's work sum with the sum of the parent node's
		// work sum and this node's work, append the node as a child of
		// the parent node and set this node's parent to the parent
		// node.
		node.WorkSum = node.WorkSum.Add(parentNode.WorkSum, node.WorkSum)
		parentNode.Children = append(parentNode.Children, node)
		node.Parent = parentNode

	} else if childNodes, ok := b.DepNodes[*hash]; ok {
		// Case 2 -- This node is the parent of one or more nodes.
		// Connect this block node to all of its children and update
		// all of the children (and their children) with the new work
		// sums.
		for _, childNode := range childNodes {
			childNode.Parent = node
			node.Children = append(node.Children, childNode)
			childNode.WorkSum.Add(childNode.WorkSum, node.WorkSum)
			AddChildrenWork(childNode, node.WorkSum)
			b.Root = node
		}

	} else {
		// Case 3 -- The node does't have a parent and is not the parent
		// of another node.  This is only acceptable for the first node
		// inserted into the chain.  Otherwise it means an arbitrary
		// orphan block is trying to be loaded which is not allowed.
		if b.Root != nil {
			str := "LoadBlockNode: attempt to insert orphan block %v"
			return nil, fmt.Errorf(str, hash)
		}

		// Case 4 -- This is the root since it's the first and only node.
		b.Root = node
	}

	// Add the new node to the indices for faster lookups.
	//b.Index[*hash] = node
	b.index.addNode(node)
	b.DepNodes[*prevHash] = append(b.DepNodes[*prevHash], node)

	return node, nil
}

func (b *BlockChain) pruneBlockNodes() error {
	if b.BestChain == nil {
		return nil
	}

	newRootNode := b.BestChain
	for i := uint32(0); i < minMemoryNodes-1 && newRootNode != nil; i++ {
		newRootNode = newRootNode.Parent
	}

	// Nothing to do if there are not enough nodes.
	if newRootNode == nil || newRootNode.Parent == nil {
		return nil
	}

	deleteNodes := list.New()
	for node := newRootNode.Parent; node != nil; node = node.Parent {
		deleteNodes.PushFront(node)
	}

	// Loop through each node to prune, unlink its children, remove it from
	// the dependency index, and remove it from the node index.
	for e := deleteNodes.Front(); e != nil; e = e.Next() {
		node := e.Value.(*BlockNode)
		err := b.removeBlockNode(node)
		if err != nil {
			return err
		}
	}

	// Set the new root node.
	b.Root = newRootNode

	return nil
}

func (b *BlockChain) removeBlockNode(node *BlockNode) error {
	if node.Parent != nil {
		return fmt.Errorf("RemoveBlockNode must be called with a "+
			" node at the front of the chain - node %v", node.Hash)
	}

	// Remove the node from the node index.
	//delete(b.Index, *node.Hash)
	b.index.RemoveNode(node)

	// Unlink all of the node's children.
	for _, child := range node.Children {
		child.Parent = nil
	}
	node.Children = nil

	// Remove the Reference from the dependency index.
	prevHash := node.ParentHash
	if children, ok := b.DepNodes[*prevHash]; ok {
		// Find the node amongst the children of the
		// dependencies for the parent hash and remove it.
		b.DepNodes[*prevHash] = RemoveChildNode(children, node)

		// Remove the map entry altogether if there are no
		// longer any nodes which depend on the parent hash.
		if len(b.DepNodes[*prevHash]) == 0 {
			delete(b.DepNodes, *prevHash)
		}
	}

	return nil
}

// getPrevNodeFromBlock returns a block node for the block previous to the
// passed block (the passed block's parent).  When it is already in the memory
// block chain, it simply returns it.  Otherwise, it loads the previous block
// from the block database, creates a new block node from it, and returns it.
// The returned node will be nil if the genesis block is passed.
func (b *BlockChain) getPrevNodeFromBlock(block *Block) (*BlockNode, error) {
	// Genesis block.
	prevHash := block.Header.Previous
	if prevHash.IsEqual(EmptyHash) {
		return nil, nil
	}

	// Return the existing previous block node if it's already there.
	//if bn, ok := b.Index[*prevHash]; ok {
	if bn, ok := b.index.LookupNode(&prevHash); ok {
		return bn, nil
	}

	header, err := b.db.GetFFLDB().GetHeader(prevHash)
	if err != nil {
		return nil, err
	}
	prevBlockNode, err := b.LoadBlockNode(header, &prevHash)
	if err != nil {
		return nil, err
	}
	return prevBlockNode, nil
}

// getPrevNodeFromNode returns a block node for the block previous to the
// passed block node (the passed block node's parent).  When the node is already
// connected to a parent, it simply returns it.  Otherwise, it loads the
// associated block from the database to obtain the previous hash and uses that
// to dynamically create a new block node and return it.  The memory block
// chain is updated accordingly.  The returned node will be nil if the genesis
// block is passed.
func (b *BlockChain) getPrevNodeFromNode(node *BlockNode) (*BlockNode, error) {
	// Return the existing previous block node if it's already there.
	if node.Parent != nil {
		return node.Parent, nil
	}

	// Genesis block.
	if node.Hash.IsEqual(b.GenesisHash) {
		return nil, nil
	}

	header, err := b.db.GetFFLDB().GetHeader(*node.ParentHash)
	if err != nil {
		return nil, err
	}
	prevBlockNode, err := b.LoadBlockNode(header, node.ParentHash)
	if err != nil {
		return nil, err
	}

	return prevBlockNode, nil
}

// getReorganizeNodes finds the fork point between the main chain and the passed
// node and returns a list of block nodes that would need to be detached from
// the main chain and a list of block nodes that would need to be attached to
// the fork point (which will be the end of the main chain after detaching the
// returned list of block nodes) in order to reorganize the chain such that the
// passed node is the new end of the main chain.  The lists will be empty if the
// passed node is not on a side chain.
func (b *BlockChain) getReorganizeNodes(node *BlockNode) (*list.List, *list.List) {
	// Nothing to detach or attach if there is no node.
	attachNodes := list.New()
	detachNodes := list.New()
	if node == nil {
		return detachNodes, attachNodes
	}

	// Find the fork point (if any) adding each block to the list of nodes
	// to attach to the main tree.  Push them onto the list in reverse order
	// so they are attached in the appropriate order when iterating the list
	// later.
	ancestor := node
	nodesMap := make(map[Uint256]*BlockNode)
	for _, n := range b.Nodes {
		nodesMap[*n.Hash] = n
	}

	for ; ancestor.Parent != nil; ancestor = ancestor.Parent {
		if _, ok := nodesMap[*ancestor.Hash]; ok {
			log.Info("ancestor:", ancestor.Height, "hash:", ancestor.Hash.String())
			break
		}
		attachNodes.PushFront(ancestor)
	}

	// TODO(davec): Use prevNodeFromNode function in case the requested
	// node is further back than the what is in memory.  This shouldn't
	// happen in the normal course of operation, but the ability to fetch
	// input transactions of arbitrary blocks will likely to be exposed at
	// some point and that could lead to an issue here.

	// Start from the end of the main chain and work backwards until the
	// common ancestor adding each block to the list of nodes to detach from
	// the main chain.
	log.Info("bestChain:", b.BestChain.Height, "hash:", b.BestChain.Hash.String())
	for n := b.BestChain; n != nil && n.Parent != nil; n = n.Parent {
		if n.Hash.IsEqual(*ancestor.Hash) {
			log.Info("equal hash:", n.Hash.String(), "height:", n.Height)
			break
		}
		detachNodes.PushBack(n)
	}

	log.Info("getReorganizeNodes datachNodes:", detachNodes.Len(), "attachNodes:", attachNodes.Len())
	return detachNodes, attachNodes
}

// reorganizeChain reorganizes the block chain by disconnecting the nodes in the
// detachNodes list and connecting the nodes in the attach list.  It expects
// that the lists are already in the correct order and are in sync with the
// end of the current best chain.  Specifically, nodes that are being
// disconnected must be in reverse order (think of popping them off
// the end of the chain) and nodes the are being attached must be in forwards
// order (think pushing them onto the end of the chain).
func (b *BlockChain) reorganizeChain2(detachNodes *list.List) error {
	// Disconnect blocks from the main chain.
	for e := detachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*BlockNode)
		block, err := b.db.GetFFLDB().GetBlock(*n.Hash)
		if err != nil {
			continue
		}

		log.Info("disconnect block:", block.Height, "hash:", block.Hash())
		err = b.disconnectBlock2(n, block.Block, block.Confirm)
		if err != nil {
			continue
		}
	}

	return nil
}

// reorganizeChain reorganizes the block chain by disconnecting the nodes in the
// detachNodes list and connecting the nodes in the attach list.  It expects
// that the lists are already in the correct order and are in sync with the
// end of the current best chain.  Specifically, nodes that are being
// disconnected must be in reverse order (think of popping them off
// the end of the chain) and nodes the are being attached must be in forwards
// order (think pushing them onto the end of the chain).
func (b *BlockChain) reorganizeChain(detachNodes, attachNodes *list.List) error {
	// Clean the UTXO cache
	b.UTXOCache.CleanCache()

	// Ensure all of the needed side chain blocks are in the cache.
	for e := attachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*BlockNode)
		if _, exists := b.blockCache[*n.Hash]; !exists {
			return fmt.Errorf("block %x is missing from the side "+
				"chain block cache", n.Hash.Bytes())
		}
	}

	forkCount := detachNodes.Len()
	var recoverFromDefault bool
	if forkCount >= maxHistoryCapacity {
		recoverFromDefault = true
	}

	// Disconnect blocks from the main chain.
	for e := detachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*BlockNode)
		block, err := b.db.GetFFLDB().GetBlock(*n.Hash)
		if err != nil {
			return err
		}

		log.Info("disconnect block:", block.Height)
		DefaultLedger.Arbitrators.DumpInfo(block.Height - 1)

		// roll back state about the last block before disconnect
		if !recoverFromDefault &&
			block.Height-1 >= b.chainParams.VoteStartHeight {
			// #4: serialize this standalone reorg-detach rollback -- which reaches
			// Arbiters.RollbackTo -> undoPendingSpecialTx -- against any concurrent
			// gossip emergency bracket. It runs under b.mutex and is NOT nested in a
			// connectBlock bracket (detach precedes the attach/connectBlock loop), and
			// RollbackTo does not re-acquire specialTxMtx, so there is no deadlock.
			DefaultLedger.Arbitrators.LockSpecialTx()
			err = b.CkpManager.OnRollbackTo(
				block.Height-1, b.state.ConsensusAlgorithm == state.POW)
			DefaultLedger.Arbitrators.UnlockSpecialTx()
			if err != nil {
				return err
			}
		}

		err = b.disconnectBlock(n, block.Block, block.Confirm)
		if err != nil {
			return err
		}
	}

	// recover check point from genesis block
	if recoverFromDefault {
		//reset all mem state data
		// #4 (R2): resetCheckpoints holds the bracket lock; the replay that follows
		// re-acquires it ONCE PER REPLAYED BLOCK inside replayCheckpointBlock -- the
		// same per-block granularity connectBlock already uses -- so the lock is
		// released before InitCheckpoint and there is no self-deadlock.
		b.resetCheckpoints()
		// FV-01: (a) discard any restored checkpoint that is ahead of the post-detach
		// chain instead of freezing derived state on it, and (b) stop DISCARDING the
		// rebuild error -- a failed derived-state rebuild must fail the reorg rather
		// than let it continue with unknown DPoS/CR state.
		if err := b.InitCheckpointAfterDeepReset(); err != nil {
			log.Error("[reorganizeChain] deep-reset checkpoint rebuild failed: ", err)
			return err
		}
	}

	// Connect the new best chain blocks.
	for e := attachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*BlockNode)
		block := b.blockCache[*n.Hash]
		confirm := b.confirmCache[*n.Hash]

		log.Info("connect block:", block.Height)
		err := b.connectBlock(n, block, confirm)
		if err != nil {
			return err
		}

		// update state after connected block
		b.saveBlockCheckpoints(&DposBlock{
			Block:       block,
			HaveConfirm: confirm != nil,
			Confirm:     confirm,
		})
		DefaultLedger.Arbitrators.DumpInfo(block.Height)
		delete(b.blockCache, *n.Hash)
		delete(b.confirmCache, *n.Hash)
	}
	return nil
}

// // disconnectBlock handles disconnecting the passed node/block from the end of
// // the main (best) chain.
func (b *BlockChain) disconnectBlock2(node *BlockNode, block *Block, confirm *payload.Confirm) error {
	log.Info("disconnect block:", block.Height, "hash:", block.Hash())

	// Remove the block from the database which houses the main chain.
	prevNode, err := b.getPrevNodeFromNode(node)
	if err != nil {
		return err
	}

	b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
		log.Info("DBRemoveBlockNode start")
		return DBRemoveBlockNode(dbTx, &block.Header)
	})

	err = b.db.RollbackBlock(block, node, confirm, CalcPastMedianTime(prevNode))
	if err != nil {
		return err
	}

	return nil
}

// // disconnectBlock handles disconnecting the passed node/block from the end of
// // the main (best) chain.
func (b *BlockChain) disconnectBlock(node *BlockNode, block *Block, confirm *payload.Confirm) error {
	// Make sure the node being disconnected is the end of the best chain.
	if b.BestChain == nil || !node.Hash.IsEqual(*b.BestChain.Hash) {
		return fmt.Errorf("disconnectBlock must be called with the " +
			"block at the end of the main chain")
	}

	// Remove the block from the database which houses the main chain.
	prevNode, err := b.getPrevNodeFromNode(node)
	if err != nil {
		return err
	}

	err = b.db.RollbackBlock(block, node, confirm, CalcPastMedianTime(prevNode))
	if err != nil {
		return err
	}

	// Put block in the side chain cache.
	node.InMainChain = false
	b.blockCache[*node.Hash] = block
	b.confirmCache[*node.Hash] = confirm

	//// This node's parent is now the end of the best chain.
	b.SetTip(node.Parent)
	b.BestChain = node.Parent
	b.MedianTimePast = CalcPastMedianTime(b.BestChain)

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	events.Notify(events.ETBlockDisconnected, block)

	return nil
}

// connectBlock handles connecting the passed node/block to the end of the main
// (best) chain.
//
// G1: the ETBlockConnected notification is delivered here, OUTSIDE the special-tx
// bracket that connectBlockBracketed opens and closes. events.Notify runs every
// registered subscriber while holding the process-wide events.mtx, so notifying
// while specialTxMtx is held creates a specialTxMtx -> events.mtx edge on EVERY
// connected block; paired with a subscriber that blocks on specialTxMtx that is an
// AB-BA deadlock that wedges both block connect and the whole event bus. The
// bracket is not shortened by one instruction of state work -- everything
// F-093/F-094/N-001 must keep atomic (mark -> mutate -> commit/undo) is inside
// connectBlockBracketed, and its deferred commit/undo has already run by the time
// this function resumes. No subscriber of ETBlockConnected reads the special-tx
// savepoint (they clean the tx/block pools and push to websocket clients), so
// committing before the broadcast rather than after is observationally identical.
func (b *BlockChain) connectBlock(node *BlockNode, block *Block, confirm *payload.Confirm) error {
	if err := b.connectBlockBracketed(node, block, confirm); err != nil {
		return err
	}

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	events.Notify(events.ETBlockConnected, block)

	return nil
}

// connectBlockBracketed is connectBlock's body: every step that must run inside the
// F-093/F-094/N-001 special-tx bracket, and nothing else.
func (b *BlockChain) connectBlockBracketed(node *BlockNode, block *Block, confirm *payload.Confirm) (err error) {
	var revertToPOW bool
	for _, tx := range block.Transactions {
		if tx.IsRevertToPOW() {
			revertToPOW = true
			break
		}
	}

	// confirmValidated is the SINGLE expression that decides whether a peer-supplied
	// Confirm is membership/quorum-checked (checkBlockWithConfirmation -> ConfirmContextCheck)
	// before it is persisted and served. It is computed once here and consumed twice: by
	// the NX-06 refusal immediately below and by the check itself further down, so the two
	// can never drift apart.
	confirmValidated := confirm != nil &&
		block.Height >= b.chainParams.CRCOnlyDPOSHeight && !revertToPOW &&
		b.state.ConsensusAlgorithm != state.POW

	// NX-06: on the legs where confirmValidated is false, a Confirm that arrives with the
	// block is stored and served WITHOUT any membership or quorum check. ConfirmSanityCheck
	// (mempool/blockpool.go:192) is pure self-signature -- a wholly fresh keypair satisfies
	// it at 0, 1 or 25 votes -- and ConfirmContextCheck, the only membership/quorum check on
	// the block path, is reached from exactly one call site (checkBlockWithConfirmation)
	// behind this same predicate. The Confirm is outside Block.Hash(), so an attacker needs
	// no hashpower and no keys: he takes an honest block off the wire, staples any Confirm to
	// it and serves it to peers that have not stored that block yet. connectBlockBracketed
	// then persists it (dbStoreBlock below, SaveBlock after it) and Arbiters.ProcessBlock
	// reads confirm.Proposal.Sponsor out of it. One block later the RecordSponsor rule in
	// CheckBlockContext (live since RecordSponsorStartHeight) splits on Confirm presence:
	// poisoned nodes then either halt (no valid successor exists) or partition.
	//
	// POW-mode and revertToPOW blocks legitimately carry NO confirm -- that is the
	// confirm-exempt rescue-block design -- so refusing the block is the faithful reading of
	// the exemption: exempt from REQUIRING a confirm is not licence to accept an unchecked
	// one. Refusing is safe for liveness: the node is not marked bad (the block node is only
	// added to the index after a successful connect, and nothing sets statusValidateFailed),
	// so the honest confirm-less copy of the very same block is still accepted afterwards.
	//
	// CENSUS (executed over the read-only retained mainnet copy, 2,260,597 records, 0 crc
	// and 0 parse failures): ZERO stored blocks carry a confirm on ANY of the three legs --
	// 0 confirms below CRCOnlyDPOSHeight (lowest confirm anywhere is exactly 343400), 0 of
	// the 30 RevertToPOW-carrying blocks have one, and the four maximal no-confirm runs above
	// CRCOnlyDPOSHeight ([1184559..1184571], [1405191..1405965], [1407423..1407542],
	// [2128711..2129101], 1299 blocks) cover every height at which the dpos state was POW. In
	// all 46 RevertToDPOS cases the block AT DPOSWorkHeight -- the last block validated while
	// ConsensusAlgorithm is still POW, because State.ProcessBlock flips it only after that
	// block is connected (saveBlockCheckpoints runs after connectBestChain) -- carries no
	// confirm; the first confirm-carrying block is DPOSWorkHeight+1, validated in DPOS mode.
	// So this rule rejects nothing the real chain ever produced, and in particular it does
	// NOT fire at the POW->DPoS transition the recovery fork has to cross.
	//
	// Gate 1 (StrictMoneyRangeHeight), the existing coordinated activation -- no third gate.
	// Below the gate the legs stay open for replay-safety; see the residual note in the
	// batch report (a malicious sync peer can still poison a node replaying the historical
	// POW windows, all of which sit below 2129102).
	if confirm != nil && !confirmValidated &&
		block.Height >= b.chainParams.StrictMoneyRangeHeight {
		return fmt.Errorf("block %s at height %d carries a confirm on an acceptance "+
			"leg that performs no membership or quorum check (revertToPOW=%v, "+
			"consensus is POW=%v): refusing the block", block.Hash(), block.Height,
			revertToPOW, b.state.ConsensusAlgorithm == state.POW)
	}

	// F-093/F-094: PreProcessSpecialTx applies the emergency ForceChange (arbiter
	// rotation, forceChanged flag, processed-payload marker, snapshot frame) BEFORE
	// the block is context-checked, confirm-checked and stored -- and it commits that
	// change at block.Height-1. History.RollbackTo is strictly-greater-than, so the
	// rollback performed on failure (checkBlockWithConfirmation -> OnRollbackTo(H-1))
	// could not reverse it: the node stayed rotated onto an arbiter set the network
	// had rejected, and the payload hash stayed marked processed so the same special
	// tx could never force-change again on the surviving chain. Bracket the whole
	// connect: commit on success, undo on every failure exit.
	//
	// Fail-path only -- a block that connects takes the commit branch, which is the
	// pristine behaviour. Blocks in the retained history all connect, so replay is
	// bit-identical and the change needs no height gate.
	// #4: hold specialTxMtx across the WHOLE bracket (mark in PreProcessSpecialTx ->
	// commit/undo in the defer), so no concurrent DPoS-gossip emergency can mark or
	// commit its own savepoint into this open bracket. The confirm-failure path
	// below reaches Arbiters.RollbackTo (checkBlockWithConfirmation -> OnRollbackTo),
	// which intentionally does NOT re-acquire specialTxMtx, so there is no
	// self-deadlock. Released at the very end of the deferred commit/undo.
	DefaultLedger.Arbitrators.LockSpecialTx()
	defer func() {
		if err != nil {
			DefaultLedger.Arbitrators.UndoPendingSpecialTx()
		} else {
			DefaultLedger.Arbitrators.CommitPendingSpecialTx()
		}
		DefaultLedger.Arbitrators.UnlockSpecialTx()
	}()
	if err := PreProcessSpecialTx(block); err != nil {
		return err
	}
	// The block must pass all of the validation rules which depend on the
	// position of the block within the block chain.
	if err := b.CheckBlockContext(block, node.Parent); err != nil {
		log.Error("PowCheckBlockContext error!", err)
		return err
	}
	if confirmValidated {
		if err := checkBlockWithConfirmation(block, confirm,
			b.CkpManager, b.state.ConsensusAlgorithm == state.POW); err != nil {
			return fmt.Errorf("block confirmation validate failed: %s", err)
		}
	}
	// Make sure it's extending the end of the best chain.
	prevHash := &block.Header.Previous
	if b.BestChain != nil && !prevHash.IsEqual(*b.BestChain.Hash) {
		return fmt.Errorf("connectBlock must be called with a block " +
			"that extends the main chain")
	}
	// Insert the block into the database if it's not already there.  Even
	// though it is possible the block will ultimately fail to connect, it
	// has already passed all proof-of-work and validity tests which means
	// it would be prohibitively expensive for an attacker to fill up the
	// disk with a bunch of blocks that fail to connect.  This is necessary
	// since it allows block download to be decoupled from the much more
	// expensive connection logic.  It also has some other nice properties
	// such as making blocks that never become part of the main chain or
	// blocks that fail to connect available for further analysis.
	err = b.db.GetFFLDB().Update(func(dbTx database.Tx) error {
		return dbStoreBlock(dbTx, &DposBlock{
			Block:       block,
			HaveConfirm: confirm != nil,
			Confirm:     confirm,
		})
	})
	if err != nil {
		return fmt.Errorf("fflDB store block failed: %s", err)
	}
	medianTime := CalcPastMedianTime(b.BestChain)
	// Insert the block into the database which houses the main chain.
	if err := b.db.SaveBlock(block, node, confirm, medianTime); err != nil {
		return err
	}

	// Add the new node to the memory main chain indices for faster
	// lookups.
	node.InMainChain = true
	node.Status = statusDataStored | statusValid
	//b.Index[*node.Hash] = node
	b.SetTip(node)
	b.index.AddNode(node, &block.Header)
	if err := b.index.flushToDB(); err != nil {
		return err
	}
	b.DepNodes[*prevHash] = append(b.DepNodes[*prevHash], node)

	// This node is now the end of the best chain.
	b.BestChain = node
	b.MedianTimePast = medianTime

	// G1: ETBlockConnected is NOT notified here -- connectBlock notifies it after
	// this function returns, i.e. after the deferred commit/undo registered at the
	// top has released specialTxMtx.
	return nil
}

func (b *BlockChain) GetBestChain() *BlockNode {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	chain := b.BestChain
	return chain
}

func (b *BlockChain) HaveBlock(hash *Uint256) (bool, error) {
	return b.BlockExists(hash) || b.IsKnownOrphan(hash), nil
}

func (b *BlockChain) BlockExists(hash *Uint256) bool {
	// Check memory chain first (could be main chain or side chain blocks).
	//if _, ok := b.Index[*hash]; ok {
	if _, ok := b.index.LookupNode(hash); ok {
		// Check in database (rest of main chain not in memory).
		return true
	}

	// Check in database (rest of main chain not in memory).
	exist, height, _ := b.db.GetFFLDB().BlockExists(hash)
	if !exist {
		return false
	}

	b.IndexLock.RLock()
	defer b.IndexLock.RUnlock()
	if uint32(len(b.Nodes)) <= height || !b.Nodes[height].Hash.IsEqual(*hash) {
		return false
	}
	return true
}

func (b *BlockChain) maybeAcceptBlock(block *Block, confirm *payload.Confirm) (bool, error) {
	// Get a block node for the block previous to this one.  Will be nil
	// if this is the genesis block.
	prevNode, err := b.getPrevNodeFromBlock(block)
	if err != nil {
		log.Errorf("getPrevNodeFromBlock: %v", err)
		return false, err
	}
	// The height of this block is one more than the referenced previous
	// block.
	blockHeight := uint32(0)
	if prevNode != nil {
		blockHeight = prevNode.Height + 1
	}

	if block.Header.Height != blockHeight {
		return false, fmt.Errorf("wrong block height!")
	}

	// Prune block nodes which are no longer needed before creating
	// a new node.
	err = b.pruneBlockNodes()
	if err != nil {
		return false, err
	}

	// Create a new block node for the block and add it to the in-memory
	// block chain (could be either a side chain or the main chain).
	blockhash := block.Hash()
	newNode := NewBlockNode(&block.Header, &blockhash)
	newNode.Status = statusDataStored
	if prevNode != nil {
		newNode.Parent = prevNode
		newNode.Height = blockHeight
		newNode.WorkSum.Add(prevNode.WorkSum, newNode.WorkSum)
	}

	// Connect the passed block to the chain while respecting proper chain
	// selection according to the chain with the most proof of work.  This
	// also handles validation of the transaction scripts.
	inMainChain, reorganized, err := b.connectBestChain(newNode, block, confirm)
	if err != nil {
		return false, err
	}

	if inMainChain && !reorganized {
		b.saveBlockCheckpoints(&DposBlock{
			Block:       block,
			HaveConfirm: confirm != nil,
			Confirm:     confirm,
		})
		DefaultLedger.Arbitrators.DumpInfo(block.Height)
	}

	events.Notify(events.ETBlockProcessed, block)

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	if block.Height >= b.chainParams.CRCOnlyDPOSHeight {
		if confirm != nil {
			events.Notify(events.ETBlockConfirmAccepted, block)
		} else {
			events.Notify(events.ETNewBlockReceived, &DposBlock{
				Block:       block,
				HaveConfirm: false,
			})
			events.Notify(events.ETBlockAccepted, block)
		}
	} else if block.Height == b.chainParams.CRCOnlyDPOSHeight-1 {
		events.Notify(events.ETNewBlockReceived, &DposBlock{
			Block:       block,
			HaveConfirm: true,
		})
		events.Notify(events.ETBlockAccepted, block)
	} else {
		events.Notify(events.ETBlockAccepted, block)
	}
	return inMainChain, nil
}

func (b *BlockChain) connectBestChain(node *BlockNode, block *Block, confirm *payload.Confirm) (bool, bool, error) {
	// We haven't selected a best chain yet or we are extending the main
	// (best) chain with a new block.  This is the most common case.
	if b.BestChain == nil || (node.Parent.Hash.IsEqual(*b.BestChain.Hash)) {
		// Perform several checks to verify the block can be connected
		// to the main chain (including whatever reorganization might
		// be necessary to get this node to the main chain) without
		// violating any rules and without actually connecting the
		// block.
		//err := s.CheckConnectBlock(node, block)
		//if err != nil {
		//	return err
		//}

		// Connect the block to the main chain.
		err := b.connectBlock(node, block, confirm)
		if err != nil {
			if err := b.state.RollbackTo(block.Height); err != nil {
				log.Debug("state rollback failed: ", err)
			}
			return false, false, err
		}

		// Connect the parent node to this node.
		if node.Parent != nil {
			node.Parent.Children = append(node.Parent.Children, node)
		}
		return true, false, nil
	}
	// We're extending (or creating) a side chain which may or may not
	// become the main chain, but in either case we need the block stored
	// for future processing, so add the block to the side chain holding
	// cache.
	log.Debugf("Adding block %x to side chain cache", node.Hash.Bytes())

	b.blockCache[*node.Hash] = block
	b.confirmCache[*node.Hash] = confirm
	//b.Index[*node.Hash] = node
	node.Status = statusInvalidAncestor
	b.index.AddNode(node, &block.Header)

	// Connect the parent node to this node.
	node.InMainChain = false
	node.Parent.Children = append(node.Parent.Children, node)

	// We're extending (or creating) a side chain, but the cumulative
	// work for this new side chain is not enough to make it the new chain.
	if node.WorkSum.Cmp(b.BestChain.WorkSum) <= 0 {

		// Find the fork point.
		fork := node
		for ; fork.Parent != nil; fork = fork.Parent {
			if fork.InMainChain {
				break
			}
		}

		// Log information about how the block is forking the chain.
		if fork.Hash.IsEqual(*node.Parent.Hash) {
			log.Infof("FORK: Block %x forks the chain at height %d"+
				"/block %x, but does not cause a reorganize",
				node.Hash.Bytes(), fork.Height, fork.Hash.Bytes())
		} else {
			log.Infof("EXTEND FORK: Block %x extends a side chain "+
				"which forks the chain at height %d/block %x",
				node.Hash.Bytes(), fork.Height, fork.Hash.Bytes())
		}

		return false, false, nil
	}
	// We're extending (or creating) a side chain and the cumulative work
	// for this new side chain is more than the old best chain, so this side
	// chain needs to become the main chain.  In order to accomplish that,
	// find the common ancestor of both sides of the fork, disconnect the
	// blocks that form the (now) old fork from the main chain, and attach
	// the blocks that form the new chain to the main chain starting at the
	// common ancenstor (the point where the chain forked).
	detachNodes, attachNodes := b.getReorganizeNodes(node)
	// forbid reorganize if detaching nodes more than IrreversibleHeight
	if b.state.IsIrreversible(b.BestChain.Height, detachNodes.Len()) {
		return false, false, nil
	}
	//for e := detachNodes.Front(); e != nil; e = e.Next() {
	//	n := e.Value.(*BlockNode)
	//	fmt.Println("detach", n.Hash)
	//}

	//for e := attachNodes.Front(); e != nil; e = e.Next() {
	//	n := e.Value.(*BlockNode)
	//	fmt.Println("attach", n.Hash)
	//}

	// Reorganize the chain.
	log.Infof("REORGANIZE: Block %v is causing a reorganize.", node.Hash)
	err := b.reorganizeChain(detachNodes, attachNodes)
	if err != nil {
		return false, false, err
	}

	return true, true, nil
}

// ReorganizeChain reorganize chain by specify a block, this method shall not
// be called normally because it can cause reorganizing without node work sum
// checking
func (b *BlockChain) ReorganizeChain(block *Block) error {
	hash := block.Hash()
	node, ok := b.index.LookupNode(&hash)
	if !ok {
		return errors.New("node of the reorganizing block does not exist")
	}

	detachNodes, attachNodes := b.getReorganizeNodes(node)
	// forbid reorganize if detaching nodes more than IrreversibleHeight
	if b.state.IsIrreversible(block.Height, detachNodes.Len()) {
		return nil
	}

	log.Info("[ReorganizeChain] begin reorganize chain")
	err := b.reorganizeChain(detachNodes, attachNodes)
	if err != nil {
		return err
	}

	return nil
}

// ReorganizeChain reorganize chain by specify a block, this method shall not
// be called normally because it can cause reorganizing without node work sum
// checking
func (b *BlockChain) ReorganizeChain2(block *Block) error {
	hash := block.Hash()
	node, ok := b.index.LookupNode(&hash)
	if !ok {
		return errors.New("node of the reorganizing block does not exist")
	}

	detachNodes, attachNodes := b.getReorganizeNodes(node)

	for _, v := range b.DepNodes {
		for _, n := range v {
			if n.Height > block.Height {
				detachNodes.PushFront(n)
			}
		}
	}

	log.Info("[ReorganizeChain] begin reorganize chain, detachNodes count:",
		detachNodes.Len(), "attachNodes count:", attachNodes.Len())
	err := b.reorganizeChain2(detachNodes)
	if err != nil {
		return err
	}

	return nil
}

// (bool, bool, error)
// 1. inMainChain
// 2. isOphan
// 3. error
func (b *BlockChain) processBlock(block *Block, confirm *payload.Confirm) (bool, bool, error) {
	blockHash := block.Hash()

	log.Debugf("[ProcessBLock] height = %d, hash = %x", block.Header.Height, blockHash.Bytes())

	// The block must not already exist in the main chain or side chains.
	exists := b.BlockExists(&blockHash)
	if exists {
		str := fmt.Sprintf("already have block %x height %d\n ", blockHash.Bytes(), block.Height)
		return false, false, fmt.Errorf(str)
	}

	// The block must not already exist as an orphan.
	if _, exists := b.orphans[blockHash]; exists {
		log.Debugf("already have block (orphan) %v", blockHash)
		return false, true, nil
	}

	log.Debugf("[ProcessBLock] orphan already exist= %v", exists)

	// Perform preliminary sanity checks on the block and its transactions.
	//err = PowCheckBlockSanity(block, powLimit, b.TimeSource)
	err := b.CheckBlockSanity(block)
	if err != nil {
		log.Errorf("PowCheckBlockSanity error %s", err.Error())
		return false, false, err
	}

	blockHeader := block.Header

	// Handle orphan blocks.
	prevHash := blockHeader.Previous
	if !prevHash.IsEqual(EmptyHash) && !b.BlockExists(&prevHash) {
		log.Debugf("Adding orphan block %x with parent %x", blockHash.Bytes(), prevHash.Bytes())
		b.AddOrphanBlock(block)

		return false, true, nil
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	inMainChain, err := b.maybeAcceptBlock(block, confirm)
	if err != nil {

		return false, true, err
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err = b.ProcessOrphans(&blockHash)
	if err != nil {
		//TODO inMainChain or not
		return false, false, err
	}

	//log.Debugf("Accepted block %v", blockHash)

	return inMainChain, false, nil
}

// length of inv need to be >= 2
func (b *BlockChain) GetOrphanBlockLocator(inv []*msg.InvVect) []*Uint256 {
	locator := make([]*Uint256, 0)
	locator = append(locator, &inv[len(inv)-1].Hash)
	locator = append(locator, &inv[0].Hash)
	return locator
}

func (b *BlockChain) LatestBlockLocator() ([]*Uint256, error) {
	if b.BestChain == nil {
		// Get the latest block hash for the main chain from the
		// database.

		// Get Current Block
		blockHash := b.GetCurrentBlockHash()
		return b.BlockLocatorFromHash(&blockHash), nil
	}

	// The best chain is set, so use its hash.
	return b.BlockLocatorFromHash(b.BestChain.Hash), nil
}

// SetTip sets the block chain to use the provided block node as the current tip
// and ensures the view is consistent by populating it with the nodes obtained
// by walking backwards all the way to genesis block as necessary.  Further
// calls will only perform the minimum work needed, so switching between chain
// tips is efficient.
//
// This function is safe for concurrent access.
func (b *BlockChain) SetTip(node *BlockNode) {
	b.IndexLock.Lock()
	b.setTip(node)
	b.IndexLock.Unlock()
}

// This only differs from the exported version in that it is up to the caller
// to ensure the lock is held.
//
// This function MUST be called with the block chain mutex locked (for writes).
func (b *BlockChain) setTip(node *BlockNode) {
	if node == nil {
		// Keep the backing array around for potential future use.
		b.Nodes = b.Nodes[:0]
		return
	}

	// Create or resize the slice that will hold the block nodes to the
	// provided tip height.  When creating the slice, it is created with
	// some additional capacity for the underlying array as append would do
	// in order to reduce overhead when extending the chain later.  As long
	// as the underlying array already has enough capacity, simply expand or
	// contract the slice accordingly.  The additional capacity is chosen
	// such that the array should only have to be extended about once a
	// week.
	needed := node.Height + 1
	if uint32(cap(b.Nodes)) < needed {
		nodes := make([]*BlockNode, needed, needed+approxNodesPerWeek)
		copy(nodes, b.Nodes)
		b.Nodes = nodes
	} else {
		prevLen := uint32(len(b.Nodes))
		b.Nodes = b.Nodes[0:needed]
		for i := prevLen; i < needed; i++ {
			b.Nodes[i] = nil
		}
	}

	for node != nil && b.Nodes[node.Height] != node {
		b.Nodes[node.Height] = node
		node = node.Parent
	}
}

func (b *BlockChain) LookupNodeInIndex(hash *Uint256) (*BlockNode, bool) {
	return b.index.LookupNode(hash)
}

func (b *BlockChain) BlockLocatorFromHash(inhash *Uint256) []*Uint256 {
	// The locator contains the requested hash at the very least.
	var hash Uint256
	copy(hash[:], inhash[:])
	//locator := make(Locator, 0, MaxBlockLocatorsPerMsg)
	locator := make([]*Uint256, 0)
	locator = append(locator, &hash)

	// Nothing more to do if a locator for the genesis hash was requested.
	if hash.IsEqual(b.GenesisHash) {
		return locator
	}

	// Attempt to find the height of the block that corresponds to the
	// passed hash, and if it's on a side chain, also find the height at
	// which it forks from the main chain.
	blockHeight := int32(-1)
	//node, exists := b.Index[*hash]
	node, exists := b.index.LookupNode(&hash)
	if !exists {
		// Try to look up the height for passed block hash.  Assume an
		// error means it doesn't exist and just return the locator for
		// the block itself.

		exist, height, err := b.db.GetFFLDB().BlockExists(&hash)
		if err != nil || !exist {
			return locator
		}
		blockHeight = int32(height)
	} else {
		blockHeight = int32(node.Height)
	}

	// Generate the block locators according to the algorithm described in
	// in the Locator comment and make sure to leave room for the
	// final genesis hash.
	increment := int32(1)
	for len(locator) < maxBlockLocators-1 {
		// Once there are 10 locators, exponentially increase the
		// distance between each block locator.
		if len(locator) > 10 {
			increment *= 2
		}
		blockHeight -= increment
		if blockHeight < 1 {
			break
		}

		// The desired block height is in the main chain, so look it up
		// from the main chain database.
		h, err := b.GetBlockHash(uint32(blockHeight))
		if err != nil {
			log.Debugf("Lookup of known valid height failed %v", blockHeight)
			continue
		}

		locator = append(locator, &h)
	}

	// Append the appropriate genesis block.
	locator = append(locator, &b.GenesisHash)

	return locator
}

func (b *BlockChain) locateStartBlock(locator []*Uint256) *Uint256 {
	var startHash Uint256
	for _, hash := range locator {
		exist, _, err := b.db.GetFFLDB().BlockExists(hash)
		if err == nil && exist {
			startHash = *hash
			break
		}
	}
	return &startHash
}

func (b *BlockChain) locateBlocks(startHash *Uint256, stopHash *Uint256, maxBlockHashes uint32) ([]*Uint256, error) {
	var count = uint32(0)
	var startHeight uint32
	var stopHeight uint32
	curHeight := b.GetHeight()
	if stopHash.IsEqual(EmptyHash) {
		if startHash.IsEqual(EmptyHash) {
			if curHeight > maxBlockHashes {
				count = maxBlockHashes
			} else {
				count = curHeight
			}
		} else {
			startHeader, err := b.db.GetFFLDB().GetHeader(*startHash)
			if err != nil {
				return nil, err
			}
			startHeight = startHeader.Height
			count = curHeight - startHeight
			if count > maxBlockHashes {
				count = maxBlockHashes
			}
		}
	} else {
		stopHeader, err := b.db.GetFFLDB().GetHeader(*stopHash)
		if err != nil {
			return nil, err
		}
		stopHeight = stopHeader.Height
		if !startHash.IsEqual(EmptyHash) {
			startHeader, err := b.db.GetFFLDB().GetHeader(*startHash)
			if err != nil {
				return nil, err
			}
			startHeight = startHeader.Height

			// avoid unsigned integer underflow
			if stopHeight < startHeight {
				return nil, fmt.Errorf("do not have header to send")
			}
			count = stopHeight - startHeight

			if count >= maxBlockHashes {
				count = maxBlockHashes
			}
		} else {
			if stopHeight > maxBlockHashes {
				count = maxBlockHashes
			} else {
				count = stopHeight
			}
		}
	}

	hashes := make([]*Uint256, 0)
	for i := uint32(1); i <= count; i++ {
		hash, err := b.GetBlockHash(startHeight + i)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, &hash)
	}

	return hashes, nil
}

// LocateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// In addition, there are two special cases:
//
//   - When no locators are provided, the stop hash is treated as a request for
//     that block, so it will either return the stop hash itself if it is known,
//     or nil if it is unknown
//   - When locators are provided, but none of them are known, hashes starting
//     after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateBlocks(locator []*Uint256, hashStop *Uint256, maxHashes uint32) []*Uint256 {
	startHash := b.locateStartBlock(locator)
	blocks, err := b.locateBlocks(startHash, hashStop, maxHashes)
	if err != nil {
		log.Errorf("LocateBlocks error %s", err)
	}
	return blocks
}

func (b *BlockChain) MedianAdjustedTime() time.Time {
	newTimestamp := b.TimeSource.AdjustedTime()
	minTimestamp := b.MedianTimePast.Add(time.Second)

	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	return newTimestamp
}

type timeSorter []int64

func (s timeSorter) Len() int {
	return len(s)
}

func (s timeSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s timeSorter) Less(i, j int) bool {
	return s[i] < s[j]
}

func CalcPastMedianTime(node *BlockNode) time.Time {
	timestamps := make([]int64, medianTimeBlocks)
	numNodes := 0
	iterNode := node
	for i := 0; i < medianTimeBlocks && iterNode != nil; i++ {
		timestamps[i] = int64(iterNode.Timestamp)
		numNodes++

		iterNode = iterNode.Parent
	}

	timestamps = timestamps[:numNodes]
	sort.Sort(timeSorter(timestamps))

	medianTimestamp := timestamps[numNodes/2]
	return time.Unix(medianTimestamp, 0)
}
