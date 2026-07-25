// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package ffldb

import (
	"fmt"
	"path/filepath"

	"github.com/elastos/Elastos.ELA/database"

	"github.com/btcsuite/btcd/wire"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// This file adds a SECOND driver, "ffldb-ro", that opens an existing database
// without any path that can write to it.
//
// WHY IT HAS TO BE A DIFFERENT OPEN, not "just be careful". The ordinary open is
// destructive by design and three separate mechanisms make it so:
//
//   - goleveldb, opened read-write, REPLAYS the journal into a fresh table file,
//     writes a new MANIFEST, truncates/creates LOG, and starts the two compaction
//     goroutines. None of that is conditional on the caller ever issuing a write.
//   - reconcileDB TRUNCATES and DELETES flat block files when the write cursor
//     scanned off disk is ahead of the metadata (the ordinary unclean-shutdown
//     repair). On a store an operator was told to leave alone before a coordinated
//     restart, that is a real mutation of consensus data.
//   - the storage layer takes an EXCLUSIVE flock, so an ordinary open against a
//     store a running node holds either fails or -- worse, had the lock been
//     forced -- corrupts it.
//
// The read-only driver removes all three: opt.ReadOnly makes goleveldb recover the
// journal into RAM and never spawn a compactor, reconcileDB records the repair it
// would have done instead of doing it, and the storage flock is SHARED, so a
// running node's exclusive lock makes the open fail cleanly (which is exactly the
// signal a pre-flight tool wants) and two readers can run at once.
//
// Belt and braces on top of that: begin(writable=true) is refused outright, so no
// caller of this database can reach the flat-file write path even by mistake, and
// the cache never flushes.

// dbTypeReadOnly is the driver type of the read-only opener.
const dbTypeReadOnly = "ffldb-ro"

// ErrReadOnlyDatabase is returned when a writable transaction is requested on a
// database opened through the read-only driver.
var ErrReadOnlyDatabase = fmt.Errorf("ffldb: the database is open READ-ONLY; " +
	"no writable transaction can be started")

// UncleanShutdownRepair records the flat-block-file truncation that the ordinary
// (read-write) open WOULD have performed on this store, and that the read-only
// open deliberately did not.
//
// Its presence means the store was left by a process that died between writing
// block bytes and committing the metadata that describes them. A read-write open
// rolls the flat files back to the metadata's cursor; until that happens the store
// on disk is unchanged.
type UncleanShutdownRepair struct {
	// MetaFileNum/MetaOffset is the write cursor the metadata records.
	MetaFileNum, MetaOffset uint32
	// DiskFileNum/DiskOffset is the write cursor found by scanning the flat
	// block files, which is ahead of the metadata.
	DiskFileNum, DiskOffset uint32
}

// String renders the pending repair for an operator-facing message.
func (r *UncleanShutdownRepair) String() string {
	return fmt.Sprintf("metadata cursor file %d offset %d, block data on disk at "+
		"file %d offset %d", r.MetaFileNum, r.MetaOffset, r.DiskFileNum, r.DiskOffset)
}

// ReadOnlyDB is the extra behaviour a database opened with the read-only driver
// exposes. Callers type-assert for it; the interface is structural, so nothing has
// to import this package to use it.
type ReadOnlyDB interface {
	database.DB

	// PendingUncleanShutdownRepair describes the flat-file rollback a read-write
	// open would perform on this store, or "" when there is none.
	//
	// It returns a STRING rather than the struct so that a caller can
	// type-assert for it structurally, without importing this package -- Go
	// interface satisfaction is by exact signature, so a concrete pointer
	// return would force every reader to take the import.
	PendingUncleanShutdownRepair() string
}

// PendingUncleanShutdownRepair implements ReadOnlyDB.
func (db *db) PendingUncleanShutdownRepair() string {
	if db.pendingRepair == nil {
		return ""
	}
	return db.pendingRepair.String()
}

// openReadOnlyDBDriver is the driver callback for the read-only type.
func openReadOnlyDBDriver(args ...interface{}) (database.DB, error) {
	dbPath, network, err := parseArgs("Open", args...)
	if err != nil {
		return nil, err
	}
	return openDBReadOnly(dbPath, network)
}

// createReadOnlyDBDriver refuses: creating a database is a write.
func createReadOnlyDBDriver(args ...interface{}) (database.DB, error) {
	return nil, ErrReadOnlyDatabase
}

// openDBReadOnly opens an existing database for reading only.
//
// It refuses rather than creates when the database is missing, and it never
// creates a directory: a pre-flight tool that CREATES the store it was asked to
// inspect has already failed at its one job.
func openDBReadOnly(dbPath string, network wire.BitcoinNet) (database.DB, error) {
	metadataDbPath := filepath.Join(dbPath, metadataDbName)
	if !fileExists(metadataDbPath) {
		str := fmt.Sprintf("database %q does not exist", metadataDbPath)
		return nil, makeDbErr(database.ErrDbDoesNotExist, str, nil)
	}
	// goleveldb's read-only open still CREATES the LOCK file when it is absent
	// (storage.newFileLock passes O_CREATE on the not-exist retry). That is the
	// one byte this whole path could otherwise write, so refuse instead: a
	// leveldb directory without a LOCK file is not one this tool should touch.
	if !fileExists(filepath.Join(metadataDbPath, "LOCK")) {
		str := fmt.Sprintf("database %q has no LOCK file, so it is not an "+
			"initialised leveldb directory; refusing to open it read-only "+
			"because doing so would create one", metadataDbPath)
		return nil, makeDbErr(database.ErrDbDoesNotExist, str, nil)
	}

	opts := opt.Options{
		ErrorIfMissing: true,
		ReadOnly:       true,
		Strict:         opt.DefaultStrict,
		Compression:    opt.NoCompression,
		Filter:         filter.NewBloomFilter(10),
	}
	ldb, err := leveldb.OpenFile(metadataDbPath, &opts)
	if err != nil {
		return nil, convertErr(err.Error(), err)
	}

	store := newBlockStore(dbPath, network)
	cache := newDbCache(ldb, store, defaultCacheSize, defaultFlushSecs)
	cache.readOnly = true
	pdb := &db{store: store, cache: cache, readOnly: true}

	return reconcileDB(pdb, false)
}

func init() {
	driver := database.Driver{
		DbType:    dbTypeReadOnly,
		Create:    createReadOnlyDBDriver,
		Open:      openReadOnlyDBDriver,
		UseLogger: useLogger,
	}
	if err := database.RegisterDriver(driver); err != nil {
		panic(fmt.Sprintf("Failed to register database driver '%s': %v",
			dbTypeReadOnly, err))
	}
}
