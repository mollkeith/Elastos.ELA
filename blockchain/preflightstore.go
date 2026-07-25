// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	. "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/database"

	"github.com/btcsuite/btcd/wire"
)

// This file is the READ-ONLY way into a node's chain store.
//
// `NewChainStore`, which cmd/purgeresidue and cmd/rollback use, cannot be reused
// for a pre-flight and cannot be made non-mutating. Measured on this tree, it:
//
//  1. opens <datadir>/data/chain with leveldb.OpenFile in read-write mode, which
//     replays the journal, writes a new MANIFEST and LOG and starts compaction,
//     and which CREATES the whole directory when it is absent;
//  2. opens <datadir>/data/blocks the same way through database.Open("ffldb"),
//     with the same consequences plus an EXCLUSIVE flock; and
//  3. runs ffldb's reconcileDB, which TRUNCATES and DELETES flat block files
//     when the store was left by an unclean shutdown.
//
// Every one of those is a write to consensus data, on a store an operator has been
// told to leave alone until the coordinated restart. So the pre-flight opens the
// block store through the "ffldb-ro" driver instead (database/ffldb/readonly.go)
// and does not open the leveldb "chain" store AT ALL -- nothing the forced-rollback
// state lives in is kept there.

// ErrChainStoreLocked reports that another process -- almost always the node
// itself -- holds the block store's exclusive lock.
var ErrChainStoreLocked = errors.New(
	"the chain store is locked by another process (the node is running)")

// ErrChainStoreMissing reports that there is no chain store at the given path.
var ErrChainStoreMissing = errors.New("no chain store at this path")

// ErrChainStoreUninitialised reports a block database that exists but carries no
// chain state, i.e. a node that has never stored a block.
var ErrChainStoreUninitialised = errors.New(
	"the block database carries no chain state yet")

// ErrReadOnlyStoreWrite is what a read-only chain store reports when something
// asks it to write. Nothing on the pre-flight path does; it exists so that a
// future caller that does gets an error rather than a silent mutation.
var ErrReadOnlyStoreWrite = errors.New(
	"blockchain: this chain store is open READ-ONLY and cannot write")

// readOnlyChainStore is the IChainStore a pre-flight runs against.
//
// The embedded IChainStore is deliberately nil. Only the four methods the
// read-only load path actually calls are implemented; ANY other method call
// panics immediately with a nil-pointer dereference rather than reaching a store
// that could write. That is a fail-fast, not an oversight -- TestReadOnlyChainStoreRefusesWrites
// pins it -- and cmd/preflight converts the panic into a distinct exit code.
type readOnlyChainStore struct {
	IChainStore

	fflDB IFFLDBChainStore
	// height mirrors ChainStore.currentBlockHeight: initChainState assigns it and
	// nothing persists it.
	height uint32
}

// GetFFLDB returns the read-only block store.
func (s *readOnlyChainStore) GetFFLDB() IFFLDBChainStore { return s.fflDB }

// SetHeight records the loaded tip in memory, exactly as ChainStore does.
func (s *readOnlyChainStore) SetHeight(height uint32) { s.height = height }

// GetHeight returns the in-memory tip.
func (s *readOnlyChainStore) GetHeight() uint32 { return s.height }

// Close releases the block store.
func (s *readOnlyChainStore) Close() {
	if s.fflDB != nil {
		_ = s.fflDB.Close()
	}
}

// CloseLeveldb is a no-op: the read-only store never opened the leveldb half.
func (s *readOnlyChainStore) CloseLeveldb() {}

// SaveBlock refuses. It is implemented (rather than left to the nil embed) because
// it is the one write the block-store path could otherwise reach.
func (s *readOnlyChainStore) SaveBlock(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	return ErrReadOnlyStoreWrite
}

// RollbackBlock refuses, for the same reason as SaveBlock.
func (s *readOnlyChainStore) RollbackBlock(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	return ErrReadOnlyStoreWrite
}

// SaveSmallCrossTransferTx refuses.
func (s *readOnlyChainStore) SaveSmallCrossTransferTx(tx interfaces.Transaction) error {
	return ErrReadOnlyStoreWrite
}

// ChainStoreLockedByRunningNode reports whether some other process holds the block
// store's exclusive lock.
//
// It takes a SHARED flock on the store's existing LOCK file and releases it
// immediately. A shared lock is refused only by a holder of an EXCLUSIVE one, and
// the only thing that takes an exclusive lock on this file is a read-write leveldb
// open -- a running node, or an `ela-cli rollback`/`purgeresidue` in flight. Two
// concurrent pre-flights do not collide, and NOTHING here can break, steal or wait
// on the node's lock: the probe is non-blocking and read-only, and the file is
// opened O_RDONLY without O_CREAT so a missing LOCK is reported, never created.
func ChainStoreLockedByRunningNode(dataDir string) (bool, error) {
	lockPath := filepath.Join(dataDir, blockDbName, "metadata", "LOCK")
	f, err := os.OpenFile(lockPath, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Errorf("%w: %s", ErrChainStoreMissing, lockPath)
		}
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return true, nil
		}
		return false, err
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
}

// NewReadOnlyChainStore opens the block store at <dataDir>/blocks for reading only.
//
// dataDir is the CHAIN DATA directory (main.go's filepath.Join(cfg.DataDir, "data")),
// the same value cmd/rollback and cmd/purgeresidue pass to NewChainStore.
func NewReadOnlyChainStore(dataDir string, params *config.Configuration) (
	IChainStore, error) {
	locked, err := ChainStoreLockedByRunningNode(dataDir)
	if err != nil {
		return nil, err
	}
	if locked {
		return nil, fmt.Errorf("%w: %s", ErrChainStoreLocked,
			filepath.Join(dataDir, blockDbName))
	}

	fflDB, err := database.Open("ffldb-ro", blockDbPath(dataDir, blockDbName),
		wire.MainNet)
	if err != nil {
		return nil, err
	}
	store := &ChainStoreFFLDB{
		db:               fflDB,
		blockHashesCache: make([]Uint256, 0, BlocksCacheSize),
		blocksCache:      make(map[Uint256]*DposBlock),
		params:           params,
	}
	// indexManager is deliberately left nil: every method that uses it
	// (InitIndex, SaveBlock, RollbackBlock) is a write path, and none is
	// reachable from a read-only load.
	return &readOnlyChainStore{fflDB: store}, nil
}

// PendingUncleanShutdownRepair returns a description of the flat-block-file
// rollback the node WILL perform on its next read-write open, or "" when there is
// none. It reads the record the read-only open made instead of performing it.
func PendingUncleanShutdownRepair(store IChainStore) string {
	// Asserted structurally so package blockchain does not import database/ffldb.
	type reporter interface {
		PendingUncleanShutdownRepair() string
	}
	ffl, ok := store.GetFFLDB().(*ChainStoreFFLDB)
	if !ok {
		return ""
	}
	r, ok := ffl.db.(reporter)
	if !ok {
		return ""
	}
	return r.PendingUncleanShutdownRepair()
}

// LoadChainForPreflight builds a BlockChain over a read-only store, with the block
// index loaded from the persisted header index exactly as a boot does.
//
// It refuses on an UNINITIALISED database rather than calling through to
// blockchain.New. That is the whole safety argument for reusing initChainState: on
// a store with no chain-state record initChainState calls createChainState, which
// WRITES the genesis block. Establishing that the record exists first makes that
// branch unreachable, and TestPreflightNeverCreatesChainState proves it by running
// against an empty directory and comparing a checksum manifest.
func LoadChainForPreflight(store IChainStore, params *config.Configuration) (
	*BlockChain, error) {
	var initialised bool
	if err := store.GetFFLDB().View(func(dbTx database.Tx) error {
		initialised = dbTx.Metadata().Get(chainStateKeyName) != nil
		return nil
	}); err != nil {
		return nil, err
	}
	if !initialised {
		return nil, ErrChainStoreUninitialised
	}
	return New(store, params, nil, nil, nil)
}
