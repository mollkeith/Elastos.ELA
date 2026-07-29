// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	. "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/database"
	_ "github.com/elastos/Elastos.ELA/database/ffldb"
)

type ProducerState byte

var SMALL_CROSS_TRANSFER_RPEFIX = []byte("SMALL_CROSS_TRANSFER")

// maxSmallCrossTransferTxs hard-caps the persistent small-cross-transfer
// bucket.
//
// This bucket is written on mempool admission. Cleaning it only when the
// transaction appears in a connected block leaves a record behind on every other
// mempool exit, conflict eviction, fee-ordered eviction and the post-reorg
// re-check, and no code prunes those. Records are re-injected into the mempool on
// every node start, and every arbiter downloads and parses the whole bucket once
// per second through getsmallcrosstransfertxs, so an attacker who plants records
// sets the arbiters' steady-state load. Cleaning the other exits
// (mempool/txpool.go) removes the leak; this cap is the defence in depth that
// survives an unclean shutdown, and it is what makes the arbiters' load
// independent of an attacker.
//
// The size is derived from real traffic: across the whole retained mainchain there
// are 954 transfers the production IsSmallTransfer classifies as small, at most 2
// in any single block, and at most 6 in any 30-block window
// (broadcastCrossChainTransactionInterval). The bucket only ever holds unconfirmed
// transfers, so 1,000 is more than two orders of magnitude above the busiest window
// real history has produced.
const maxSmallCrossTransferTxs = 1000

type ProducerInfo struct {
	Payload   *payload.ProducerInfo
	RegHeight uint32
	Vote      Fixed64
}

type ChainStore struct {
	levelDB            IStore
	fflDB              IFFLDBChainStore
	currentBlockHeight uint32
	persistMutex       sync.Mutex

	// smallCrossMutex guards the small-cross-transfer bucket count below.
	// smallCrossCounted records whether smallCrossCount has been seeded by the
	// one-off iteration of the on-disk bucket.
	smallCrossMutex   sync.Mutex
	smallCrossCount   int
	smallCrossCounted bool
}

func NewChainStore(dataDir string, params *config.Configuration) (IChainStore, error) {
	db, err := NewLevelDB(filepath.Join(dataDir, "chain"))
	if err != nil {
		return nil, err
	}
	fflDB, err := NewChainStoreFFLDB(dataDir, params)
	if err != nil {
		return nil, err
	}
	s := &ChainStore{
		levelDB: db,
		fflDB:   fflDB,
	}

	return s, nil
}

func smallCrossTransferKey(txHash Uint256) []byte {
	var key bytes.Buffer
	key.Write(SMALL_CROSS_TRANSFER_RPEFIX)
	key.Write(txHash.Bytes())
	return key.Bytes()
}

func (c *ChainStore) CleanSmallCrossTransferTx(txHash Uint256) error {
	key := smallCrossTransferKey(txHash)

	c.smallCrossMutex.Lock()
	defer c.smallCrossMutex.Unlock()

	// Only decrement the count when a record was actually there. leveldb's
	// Delete succeeds on a missing key, and this function is called from
	// every mempool exit path, most of which have no record.
	if _, err := c.levelDB.Get(key); err != nil {
		return nil
	}
	if err := c.levelDB.Delete(key); err != nil {
		return err
	}
	if c.smallCrossCounted && c.smallCrossCount > 0 {
		c.smallCrossCount--
	}

	return nil
}

func (c *ChainStore) SaveSmallCrossTransferTx(tx interfaces.Transaction) error {
	buf := new(bytes.Buffer)
	if err := tx.Serialize(buf); err != nil {
		return err
	}
	key := smallCrossTransferKey(tx.Hash())

	c.smallCrossMutex.Lock()
	defer c.smallCrossMutex.Unlock()

	// An overwrite of a record we already hold is not new occupancy, so it must
	// not be refused and must not be counted -- node start re-injects the whole
	// bucket into the mempool, which re-saves every record it holds.
	if _, err := c.levelDB.Get(key); err != nil {
		c.censusSmallCrossTransferTxsLocked()
		if c.smallCrossCount >= maxSmallCrossTransferTxs {
			log.Warnf("small cross chain transfer store is full (%d records), "+
				"refusing %s", c.smallCrossCount, tx.Hash())
			return errors.New("small cross chain transfer store is full")
		}
		if err := c.levelDB.Put(key, buf.Bytes()); err != nil {
			return err
		}
		c.smallCrossCount++
		return nil
	}

	return c.levelDB.Put(key, buf.Bytes())
}

// censusSmallCrossTransferTxsLocked seeds smallCrossCount from disk exactly
// once per process. The caller must hold smallCrossMutex.
func (c *ChainStore) censusSmallCrossTransferTxsLocked() {
	if c.smallCrossCounted {
		return
	}

	it := c.levelDB.NewIterator(SMALL_CROSS_TRANSFER_RPEFIX)
	defer it.Release()
	count := 0
	for it.Next() {
		count++
	}
	c.smallCrossCount = count
	c.smallCrossCounted = true
	log.Infof("small cross chain transfer store holds %d records (cap %d)",
		count, maxSmallCrossTransferTxs)
}

func (c *ChainStore) GetSmallCrossTransferTxs() ([]interfaces.Transaction, error) {
	Iter := c.levelDB.NewIterator(SMALL_CROSS_TRANSFER_RPEFIX)
	// Release the iterator: each leveldb iterator pins a snapshot, and
	// GetSmallCrossTransferTx below is served once per second to every arbiter
	// through the getsmallcrosstransfertxs RPC, so a leaked iterator is one
	// pinned snapshot per second for the life of the process.
	defer Iter.Release()
	txs := make([]interfaces.Transaction, 0)
	for Iter.Next() {
		val := Iter.Value()
		r := bytes.NewReader(val)

		tx, err := functions.GetTransactionByBytes(r)
		if err != nil {
			return nil, err
		}
		if err := tx.Deserialize(r); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func (c *ChainStore) GetSmallCrossTransferTx() ([]string, error) {
	Iter := c.levelDB.NewIterator(SMALL_CROSS_TRANSFER_RPEFIX)
	// Release the iterator: see GetSmallCrossTransferTxs above.
	defer Iter.Release()
	txns := make([]string, 0)
	for Iter.Next() {
		val := Iter.Value()
		txns = append(txns, hex.EncodeToString(val))
	}
	return txns, nil
}

func (c *ChainStore) CloseLeveldb() {
	c.levelDB.Close()
}

func (c *ChainStore) Close() {
	c.persistMutex.Lock()
	defer c.persistMutex.Unlock()
	if err := c.fflDB.Close(); err != nil {
		log.Error("fflDB close failed:", err)
	}
}

func (c *ChainStore) IsTxHashDuplicate(txID Uint256) bool {
	txn, _, err := c.fflDB.GetTransaction(txID)
	if err != nil || txn == nil {
		return false
	}

	return true
}

func (c *ChainStore) IsSidechainTxHashDuplicate(sidechainTxHash Uint256) bool {
	return c.GetFFLDB().IsTx3Exist(&sidechainTxHash)
}

func (c *ChainStore) IsSidechainReturnDepositTxHashDuplicate(sidechainReturnDepositTxHash Uint256) bool {
	return c.GetFFLDB().IsSideChainReturnDepositExist(&sidechainReturnDepositTxHash)
}

func (c *ChainStore) IsDoubleSpend(txn interfaces.Transaction) bool {
	if len(txn.Inputs()) == 0 {
		return false
	}
	for i := 0; i < len(txn.Inputs()); i++ {
		txID := txn.Inputs()[i].Previous.TxID
		unspents, err := c.GetFFLDB().GetUnspent(txID)
		if err != nil {
			return true
		}
		findFlag := false
		for k := 0; k < len(unspents); k++ {
			if unspents[k] == txn.Inputs()[i].Previous.Index {
				findFlag = true
				break
			}
		}
		if !findFlag {
			return true
		}
	}

	return false
}

func (c *ChainStore) RollbackBlock(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	now := time.Now()
	err := c.handleRollbackBlockTask(b, node, confirm, medianTimePast)
	tcall := float64(time.Now().Sub(now)) / float64(time.Second)
	log.Debugf("handle block rollback exetime: %g", tcall)
	return err
}

func (c *ChainStore) GetTransaction(txID Uint256) (interfaces.Transaction, uint32, error) {
	return c.fflDB.GetTransaction(txID)
}

func (c *ChainStore) GetProposalDraftDataByDraftHash(draftHash *Uint256) ([]byte, error) {
	return c.fflDB.GetProposalDraftDataByDraftHash(draftHash)
}

func (c *ChainStore) GetTxReference(tx interfaces.Transaction) (map[*common.Input]*common.Output, error) {
	if tx.TxType() == common.RegisterAsset {
		return nil, nil
	}
	txOutputsCache := make(map[Uint256][]*common.Output)
	//UTXO input /  Outputs
	reference := make(map[*common.Input]*common.Output)
	// Key index，v UTXOInput
	for _, input := range tx.Inputs() {
		txID := input.Previous.TxID
		index := input.Previous.Index
		if outputs, ok := txOutputsCache[txID]; ok {
			reference[input] = outputs[index]
		} else {
			transaction, _, err := c.GetTransaction(txID)

			if err != nil {
				return nil, errors.New("GetTxReference failed, previous transaction not found")
			}
			if int(index) >= len(transaction.Outputs()) {
				return nil, errors.New("GetTxReference failed, refIdx out of range.")
			}
			reference[input] = transaction.Outputs()[index]
			txOutputsCache[txID] = transaction.Outputs()
		}
	}
	return reference, nil
}

func (c *ChainStore) rollback(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {

	ps, err := GetRollbackProcessorsFromBlock(b)
	if err != nil {
		return err
	}
	if err := c.fflDB.RollbackBlock(b, node, confirm, medianTimePast, ps); err != nil {
		return err
	}
	atomic.StoreUint32(&c.currentBlockHeight, b.Height-1)

	return nil
}

func GetSaveProcessorsFromBlock(b *Block) ([]database.TXProcessor, error) {
	ps := make([]database.TXProcessor, 0)
	for _, t := range b.Transactions {
		processor, err := t.GetSaveProcessor()
		if err != nil {
			return nil, err
		}
		if processor != nil {
			ps = append(ps, processor)
		}
	}
	return ps, nil
}

func GetRollbackProcessorsFromBlock(b *Block) ([]database.TXProcessor, error) {
	ps := make([]database.TXProcessor, 0)
	for _, t := range b.Transactions {
		processor, err := t.GetRollbackProcessor()
		if err != nil {
			return nil, err
		}
		if processor != nil {
			ps = append(ps, processor)
		}
	}
	return ps, nil
}

func (c *ChainStore) persist(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	c.persistMutex.Lock()
	defer c.persistMutex.Unlock()

	ps, err := GetSaveProcessorsFromBlock(b)
	if err != nil {
		return err
	}
	if err := c.fflDB.SaveBlock(b, node, confirm, medianTimePast, ps); err != nil {
		return err
	}
	return nil
}

func (c *ChainStore) GetFFLDB() IFFLDBChainStore {
	return c.fflDB
}

func (c *ChainStore) SaveBlock(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	log.Info("SaveBlock ", b.Height)

	now := time.Now()
	err := c.handlePersistBlockTask(b, node, confirm, medianTimePast)

	tcall := float64(time.Now().Sub(now)) / float64(time.Second)
	log.Debugf("handle block exetime: %g num transactions:%d",
		tcall, len(b.Transactions))
	return err
}

func (c *ChainStore) handleRollbackBlockTask(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	_, err := c.fflDB.GetBlock(b.Hash())
	if err != nil {
		log.Errorf("block %x can't be found", BytesToHexString(b.Hash().Bytes()))
		return err
	}
	return c.rollback(b, node, confirm, medianTimePast)
}

func (c *ChainStore) handlePersistBlockTask(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	if b.Header.Height <= c.currentBlockHeight {
		return errors.New("block height less than current block height")
	}

	return c.persistBlock(b, node, confirm, medianTimePast)
}

func (c *ChainStore) persistBlock(b *Block, node *BlockNode,
	confirm *payload.Confirm, medianTimePast time.Time) error {
	err := c.persist(b, node, confirm, medianTimePast)
	if err != nil {
		log.Fatal("[persistBlocks]: error to persist block:", err.Error())
		return err
	}

	atomic.StoreUint32(&c.currentBlockHeight, b.Height)
	return nil
}

func (c *ChainStore) GetConfirm(hash Uint256) (*payload.Confirm, error) {
	var confirm = new(payload.Confirm)
	prefix := []byte{byte(DATAConfirm)}
	confirmBytes, err := c.levelDB.Get(append(prefix, hash.Bytes()...))
	if err != nil {
		return nil, err
	}

	if err = confirm.Deserialize(bytes.NewReader(confirmBytes)); err != nil {
		return nil, err
	}

	return confirm, nil
}

func (c *ChainStore) GetHeight() uint32 {
	return atomic.LoadUint32(&c.currentBlockHeight)
}

func (c *ChainStore) SetHeight(height uint32) {
	atomic.StoreUint32(&c.currentBlockHeight, height)
}
