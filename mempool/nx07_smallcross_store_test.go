// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// FAIL-ON-PRISTINE for NX-07.
//
// SaveSmallCrossTransferTx writes a PERSISTENT leveldb record on mempool
// admission. On the pristine tree CleanSmallCrossTransferTx had exactly one
// caller in the whole repository -- cleanTransactionList, i.e. the block path --
// so every other mempool exit left a record that nothing ever pruned, that node
// start re-injected, and that every arbiter re-downloaded and re-parsed once per
// second. The two functions driven here, doRemoveTransaction and onPopBack, are
// the production eviction paths: doRemoveTransaction is reached from
// cleanTransactions (a mined block spends the same input) and from
// checkAndCleanAllTransactions (the post-reorg re-check), and onPopBack is the
// fee-ordered eviction callback wired into txFees by newTxPoolCheckpoint.

// nx07Store builds a real ChainStore in a temp directory and installs it as the
// package ledger, because the production clean path resolves the store through
// blockchain.DefaultLedger. Returns a cleanup that restores the previous ledger.
func nx07Store(t *testing.T) (blockchain.IChainStore, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "ela-nx07-smallcross")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}

	params := config.GetDefaultParams()
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	store, err := blockchain.NewChainStore(filepath.Join(dir, "chain"), params)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("open chain store: %v", err)
	}

	previous := blockchain.DefaultLedger
	blockchain.DefaultLedger = &blockchain.Ledger{
		Store: store,
		// The pool's conflict slots resolve inputs through the UTXO cache, so
		// admission and eviction both need one.
		Blockchain: &blockchain.BlockChain{
			UTXOCache: blockchain.NewUTXOCache(utxoCacheDB, params),
		},
	}

	return store, func() {
		blockchain.DefaultLedger = previous
		store.Close()
		store.CloseLeveldb()
		os.RemoveAll(dir)
	}
}

// nx07Funding publishes a transaction whose outputs the small-cross transfers
// below spend, so the conflict manager can resolve their inputs.
func nx07Funding(t *testing.T) interfaces.Transaction {
	t.Helper()

	outputs := make([]*common2.Output, 0, 64)
	for i := 0; i < 64; i++ {
		outputs = append(outputs, &common2.Output{Value: common.Fixed64(100000000)})
	}
	tx := functions.CreateTransaction(
		0, common2.TransferAsset, 0, &payload.TransferAsset{},
		[]*common2.Attribute{}, []*common2.Input{}, outputs, 0,
		[]*program.Program{},
	)
	utxoCacheDB.PutTransaction(tx)

	return tx
}

// smallCrossTransferTx builds a transaction the PRODUCTION predicates classify
// as a small cross-chain transfer -- that classification is asserted below, so
// this cannot drift into testing a transaction the real admission branch would
// never have stored.
func smallCrossTransferTx(t *testing.T, funding interfaces.Transaction,
	nonce byte) interfaces.Transaction {
	t.Helper()

	var programHash common.Uint168
	programHash[0] = byte(contract.PrefixCrossChain)
	programHash[1] = nonce

	var fundingHash common.Uint256
	if funding != nil {
		fundingHash = funding.Hash()
	}

	tx := functions.CreateTransaction(
		0,
		common2.TransferCrossChainAsset,
		payload.TransferCrossChainVersionV1,
		&payload.TransferCrossChainAsset{},
		[]*common2.Attribute{{Usage: common2.Nonce, Data: []byte{nonce}}},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: fundingHash, Index: uint16(nonce)},
			Sequence: 0,
		}},
		[]*common2.Output{{
			ProgramHash: programHash,
			Value:       common.Fixed64(10000),
		}},
		0,
		[]*program.Program{},
	)

	if !tx.IsTransferCrossChainAssetTx() {
		t.Fatalf("setup: transaction is not a cross chain transfer")
	}
	if !tx.IsSmallTransfer(config.DefaultParams.SmallCrossTransferThreshold) {
		t.Fatalf("setup: transaction is not classified as a SMALL transfer, " +
			"so the admission branch under test would never have stored it")
	}

	return tx
}

// admit reproduces, verbatim, the admission side effect appendToPool performs
// for a small cross-chain transfer: AppendTx + doAddTransaction, then the
// persistent record and its in-memory twin.
func admit(t *testing.T, mp *TxPool, tx interfaces.Transaction, height uint32) {
	t.Helper()

	if err := mp.AppendTx(tx); err != nil {
		t.Fatalf("AppendTx: %v", err)
	}
	if err := mp.doAddTransaction(tx); err != nil {
		t.Fatalf("doAddTransaction: %v", err)
	}
	if err := blockchain.DefaultLedger.Store.SaveSmallCrossTransferTx(tx); err != nil {
		t.Fatalf("SaveSmallCrossTransferTx: %v", err)
	}
	mp.crossChainHeightList[tx.Hash()] = height
	mp.txReceivingInfo[tx.Hash()] = TxReceivingInfo{Height: height}
}

func storedRecords(t *testing.T, store blockchain.IChainStore) int {
	t.Helper()

	records, err := store.GetSmallCrossTransferTx()
	if err != nil {
		t.Fatalf("GetSmallCrossTransferTx: %v", err)
	}
	return len(records)
}

// TestNX07ConflictEvictionClearsPersistentRecord drives doRemoveTransaction,
// the eviction path taken when a mined block spends the same input. On the
// pristine tree it deletes crossChainHeightList and leaves the leveldb record.
func TestNX07ConflictEvictionClearsPersistentRecord(t *testing.T) {
	store, cleanup := nx07Store(t)
	defer cleanup()

	mp := NewTxPool(&config.DefaultParams, checkpoint.NewManager(&config.DefaultParams))
	funding := nx07Funding(t)
	tx := smallCrossTransferTx(t, funding, 1)
	admit(t, mp, tx, 1032841)

	if got := storedRecords(t, store); got != 1 {
		t.Fatalf("setup: %d persistent records after admission, want 1", got)
	}

	mp.doRemoveTransaction(tx)

	if got := storedRecords(t, store); got != 0 {
		t.Fatalf("NX-07: %d persistent small-cross records survived "+
			"doRemoveTransaction; the transaction was never mined, so nothing "+
			"will ever call CleanSmallCrossTransferTx for it", got)
	}
	if _, ok := mp.crossChainHeightList[tx.Hash()]; ok {
		t.Fatalf("the in-memory twin also has to go (F-120)")
	}
}

// TestNX07FeeEvictionClearsPersistentRecord drives onPopBack, the fee-ordered
// eviction callback. F-120 extended this path to the two in-memory maps and
// said so in its own comment; the persistent twin was never in its scope.
func TestNX07FeeEvictionClearsPersistentRecord(t *testing.T) {
	store, cleanup := nx07Store(t)
	defer cleanup()

	mp := NewTxPool(&config.DefaultParams, checkpoint.NewManager(&config.DefaultParams))
	funding := nx07Funding(t)
	tx := smallCrossTransferTx(t, funding, 2)
	admit(t, mp, tx, 1032841)

	if got := storedRecords(t, store); got != 1 {
		t.Fatalf("setup: %d persistent records after admission, want 1", got)
	}

	mp.onPopBack(tx.Hash())

	if got := storedRecords(t, store); got != 0 {
		t.Fatalf("NX-07: %d persistent small-cross records survived "+
			"onPopBack", got)
	}
}

// TestNX07OrdinaryTransactionIsUntouched is the over-reach guard: the clean is
// keyed on the in-memory twin, which exists only for transactions the admission
// branch actually persisted, so an ordinary eviction must not touch the bucket
// (and must not pay for a leveldb lookup either).
func TestNX07OrdinaryTransactionIsUntouched(t *testing.T) {
	store, cleanup := nx07Store(t)
	defer cleanup()

	mp := NewTxPool(&config.DefaultParams, checkpoint.NewManager(&config.DefaultParams))
	funding := nx07Funding(t)

	kept := smallCrossTransferTx(t, funding, 3)
	admit(t, mp, kept, 1032841)

	other := smallCrossTransferTx(t, funding, 4)
	if err := mp.AppendTx(other); err != nil {
		t.Fatalf("AppendTx: %v", err)
	}
	if err := mp.doAddTransaction(other); err != nil {
		t.Fatalf("doAddTransaction: %v", err)
	}

	mp.doRemoveTransaction(other)

	if got := storedRecords(t, store); got != 1 {
		t.Fatalf("evicting a transaction with no persistent record changed "+
			"the bucket: %d records, want 1", got)
	}
}

// TestNX07BucketIsHardCapped is the defence-in-depth half: even with every exit
// path cleaned, an unclean shutdown leaves records behind, and it is the cap
// that makes the arbiters' once-per-second parse of the whole bucket
// independent of an attacker. Sizing is measured, not guessed -- all of
// mainchain history holds 954 small transfers, at most 6 in any 30-block
// window.
func TestNX07BucketIsHardCapped(t *testing.T) {
	store, cleanup := nx07Store(t)
	defer cleanup()

	var refused int
	for i := 0; i < maxSmallCrossTransferRecordsForTest+16; i++ {
		tx := smallCrossTransferTx(t, nil, byte(i%251))
		// Distinct hashes: the attribute nonce above repeats every 251
		// records, so vary the input index too.
		tx.Inputs()[0].Previous.Index = uint16(i)
		if err := store.SaveSmallCrossTransferTx(tx); err != nil {
			refused++
		}
	}

	if refused == 0 {
		t.Fatalf("NX-07: the persistent small-cross bucket accepted %d "+
			"records with no cap; an attacker sets the arbiters' steady-state "+
			"load", maxSmallCrossTransferRecordsForTest+16)
	}
	if got := storedRecords(t, store); got > maxSmallCrossTransferRecordsForTest {
		t.Fatalf("NX-07: bucket holds %d records, above the cap %d",
			got, maxSmallCrossTransferRecordsForTest)
	}
}

// maxSmallCrossTransferRecordsForTest mirrors blockchain.maxSmallCrossTransferTxs,
// which is unexported. Spelled out so this file also compiles against a tree
// where the constant does not exist.
const maxSmallCrossTransferRecordsForTest = 1000
