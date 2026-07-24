// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/elastos/Elastos.ELA/blockchain"
	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	. "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
	"github.com/elastos/Elastos.ELA/events"
)

const broadcastCrossChainTransactionInterval = 30

type TxPool struct {
	conflictManager
	*txPoolCheckpoint
	chainParams *config.Configuration
	//proposal of txpool used amout
	proposalsUsedAmount  Fixed64
	crossChainHeightList map[Uint256]uint32
	CkpManager           *checkpoint.Manager
	txReceivingInfo      map[Uint256]TxReceivingInfo

	sync.RWMutex
}

// TxReceivingInfo record the tx receiving info detail, can expend it's field in the future need
type TxReceivingInfo struct {
	Height uint32
}

// append transaction to txnpool when check ok, and broadcast the transaction.
// 1.check  2.check with ledger(db) 3.check with pool
func (mp *TxPool) AppendToTxPool(tx interfaces.Transaction) elaerr.ELAError {
	// Defensive: the global event bus delivers ETAppendTxToTxPool asynchronously
	// (dpos/state notifyNextTurnDPOSInfoTx -> go events.Notify -> netsync handler). A
	// SyncManager with an unwired/torn-down pool (test harness, shutdown race) must not
	// crash the process on a nil receiver; production always wires the pool.
	if mp == nil {
		return nil
	}
	mp.Lock()
	defer mp.Unlock()
	err := mp.appendToTxPool(tx)
	if err != nil {
		return err
	}

	go events.Notify(events.ETTransactionAccepted, tx)
	return nil
}

// append transaction to txnpool when check ok.
// 1.check  2.check with ledger(db) 3.check with pool
func (mp *TxPool) AppendToTxPoolWithoutEvent(tx interfaces.Transaction) elaerr.ELAError {
	mp.Lock()
	defer mp.Unlock()
	err := mp.appendToTxPool(tx)
	if err != nil {
		return err
	}
	return nil
}

func (mp *TxPool) removeCRAppropriationConflictTransactions() {
	for _, tx := range mp.txnList {
		if tx.IsCRAssetsRectifyTx() {
			mp.doRemoveTransaction(tx)
		}
	}
}

func (mp *TxPool) appendToTxPool(tx interfaces.Transaction) elaerr.ELAError {

	if tx.IsRecordSponorTx() {
		return elaerr.Simple(elaerr.ErrTxValidation, nil)
	}

	txHash := tx.Hash()

	// If the transaction is CR appropriation transaction, need to remove
	// transactions that conflict with it.
	if tx.IsCRCAppropriationTx() {
		mp.removeCRAppropriationConflictTransactions()
	}

	chain := blockchain.DefaultLedger.Blockchain
	bestHeight := chain.GetHeight()

	// Don't accept the transaction if it already exists in the pool.  This
	// applies to orphan transactions as well.  This check is intended to
	// be a quick check to weed out duplicates.
	if _, ok := mp.txnList[txHash]; ok {
		return elaerr.Simple(elaerr.ErrTxDuplicate, nil)
	}

	if tx.IsCoinBaseTx() {
		log.Warnf("coinbase tx %s cannot be added into transaction pool", tx.Hash())
		return elaerr.Simple(elaerr.ErrBlockIneffectiveCoinbase, nil)
	}

	// F-019: block assembly skips unfinalized transactions (pow.GenerateBlock)
	// and block validation rejects any block carrying one (CheckBlockContext),
	// but nothing checked finality on the way INTO the pool - so a
	// future-LockTime transaction was admitted, relayed, and re-relayed by the
	// outdated-tx timer while occupying pool capacity it could never spend.
	// Admission policy only: a transaction that fails this test cannot be part
	// of a valid block at this height anyway, so no block acceptance decision
	// changes. The height used is the one every other caller uses.
	if !blockchain.IsFinalizedTransaction(tx, bestHeight+1) {
		log.Warnf("[TxPool] tx %s is not finalized, lock time %d, height %d",
			tx.Hash(), tx.LockTime(), bestHeight+1)
		return elaerr.SimpleWithMessage(elaerr.ErrTxValidation, nil,
			"transaction is not finalized")
	}

	if err := chain.CheckTransactionSanity(bestHeight+1, tx); err != nil {
		log.Warn("[TxPool CheckTransactionSanity] failed", tx.Hash())
		return err
	}
	if _, err := chain.CheckTransactionContext(
		bestHeight+1, tx, mp.proposalsUsedAmount, 0); err != nil {
		log.Warnf("[TxPool CheckTransactionContext] failed, hash: %s, err: %s", tx.Hash(),
			err)
		return err
	}
	//verify transaction by pool with lock
	if err := mp.verifyTransactionWithTxnPool(tx); err != nil {
		log.Error("[TxPool verifyTransactionWithTxnPool] err", err)
		log.Warn("[TxPool verifyTransactionWithTxnPool] failed", tx.Hash())
		return err
	}

	// F-060: this gate used to reject on OverSize alone, which returned before
	// txFees.AddTx could ever run - so the complete fee-ordered eviction path
	// inside AddTx was dead code and a low-fee squatter could never be
	// displaced. Ask the fee-ordered list the question it can actually answer:
	// can this tx be admitted, evicting only the entries paying strictly less?
	// It stays here, after CheckTransactionContext, because that is what sets
	// the fee (blockchain.CheckTransactionFee -> tx.SetFee) - asked any earlier
	// every relayed tx would price itself at zero.
	size := tx.GetSize()
	if !mp.txFees.CanAccept(uint64(size), float64(tx.Fee())/float64(size)) {
		log.Warn("TxPool check transactions size failed", tx.Hash())
		return elaerr.Simple(elaerr.ErrTxPoolOverCapacity, nil)
	}
	if err := mp.AppendTx(tx); err != nil {
		log.Error("[TxPool AppendTx] err", err)
		log.Warn("[TxPool AppendTx] failed", tx.Hash())
		return err
	}
	// Add the transaction to mem pool
	if err := mp.doAddTransaction(tx); err != nil {
		mp.removeTx(tx)
		return err
	}

	if bestHeight > mp.chainParams.NewCrossChainStartHeight &&
		tx.IsTransferCrossChainAssetTx() &&
		tx.IsSmallTransfer(mp.chainParams.SmallCrossTransferThreshold) {
		err := blockchain.DefaultLedger.Store.SaveSmallCrossTransferTx(tx)
		if err != nil {
			log.Warnf("failed to save small cross chain transaction %s: %s",
				tx.Hash(), err)
			// NX-07: this arm rejects the transaction, so it must leave the
			// pool with it. It never could before -- SaveSmallCrossTransferTx
			// swallowed leveldb errors and always returned nil -- but the
			// bucket cap makes it reachable, and a transaction the caller was
			// told was rejected must not stay in txnList, txFees and the
			// conflict slots. Mirrors the doAddTransaction arm just above.
			mp.doRemoveTransaction(tx)
			return elaerr.Simple(elaerr.ErrTxValidation, nil)
		}
		mp.crossChainHeightList[tx.Hash()] = bestHeight
	}

	// record the tx receiving info
	mp.txReceivingInfo[tx.Hash()] = TxReceivingInfo{
		Height: bestHeight,
	}

	return nil
}

// GetUsedUTXO returns all used refer keys of inputs.
func (mp *TxPool) GetUsedUTXOs() map[string]struct{} {
	mp.RLock()
	defer mp.RUnlock()
	usedUTXOs := make(map[string]struct{})
	for _, v := range mp.txnList {
		for _, input := range v.Inputs() {
			usedUTXOs[input.ReferKey()] = struct{}{}
		}
	}
	return usedUTXOs
}

// HaveTransaction returns if a transaction is in transaction pool by the given
// transaction id. If no transaction match the transaction id, return false
func (mp *TxPool) HaveTransaction(txId Uint256) bool {
	mp.RLock()
	_, ok := mp.txnList[txId]
	mp.RUnlock()
	return ok
}

// GetTxsInPool returns a slice of all transactions in the mp.
//
// This function is safe for concurrent access.
func (mp *TxPool) GetTxsInPool() []interfaces.Transaction {
	mp.RLock()
	txs := make([]interfaces.Transaction, 0, len(mp.txnList))
	for _, tx := range mp.txnList {
		txs = append(txs, tx)
	}
	mp.RUnlock()
	return txs
}

// clean the transaction Pool with committed block.
func (mp *TxPool) CleanSubmittedTransactions(block *Block) {
	mp.Lock()
	mp.cleanTransactions(block.Transactions)
	mp.cleanSideChainPowTx()
	if err := mp.cleanCanceledProducerAndCR(block.Transactions); err != nil {
		log.Warn("error occurred when clean canceled producer and cr", err)
	}
	mp.Unlock()
}

// ResendOutdatedTransactions Resend outdated transactions
func (mp *TxPool) ResendOutdatedTransactions(block *Block) {
	mp.Lock()
	txs := make([]interfaces.Transaction, 0)
	for txHash, info := range mp.txReceivingInfo {
		if block.Height-info.Height > mp.chainParams.MemoryPoolTxMaximumStayHeight {
			tx, ok := mp.txnList[txHash]
			if !ok {
				log.Warn("ResendOutdatedTransactions invalid transaction")
				continue
			}
			txs = append(txs, tx)
		}
	}

	if len(txs) != 0 {
		go events.Notify(events.ETOutdatedTxRelay, txs)
	}
	mp.Unlock()
}

func (mp *TxPool) CheckAndCleanAllTransactions() {
	mp.Lock()
	mp.checkAndCleanAllTransactions()
	mp.Unlock()
}

func (mp *TxPool) BroadcastSmallCrossChainTransactions(bestHeight uint32) {
	mp.Lock()
	txs := make([]interfaces.Transaction, 0)
	for txHash, height := range mp.crossChainHeightList {
		if bestHeight >= height+broadcastCrossChainTransactionInterval {
			mp.crossChainHeightList[txHash] = bestHeight
			tx, ok := mp.txnList[txHash]
			if !ok {
				log.Warn("BroadcastSmallCrossChainTransactions invalid cross chain transaction")
				continue
			}
			txs = append(txs, tx)
		}
	}

	if len(txs) != 0 {
		go events.Notify(events.ETSmallCrossChainNeedRelay, txs)
	}
	mp.Unlock()
}

func (mp *TxPool) cleanTransactions(blockTxs []interfaces.Transaction) {
	txsInPool := len(mp.txnList)
	deleteCount := 0
	for _, blockTx := range blockTxs {
		if blockTx.TxType() == common.CoinBase {
			continue
		}

		if blockTx.IsNewSideChainPowTx() || blockTx.IsUpdateVersion() || blockTx.IsNextTurnDPOSInfoTx() {
			if _, ok := mp.txnList[blockTx.Hash()]; ok {
				mp.doRemoveTransaction(blockTx)
				deleteCount++
			}
			if blockTx.IsNextTurnDPOSInfoTx() {
				payloadHash, err := blockTx.GetSpecialTxHash()
				if err != nil {
					continue
				}
				blockchain.DefaultLedger.Blockchain.GetState().RemoveSpecialTx(payloadHash)
			}
			continue
		}

		inputUtxos, err := blockchain.DefaultLedger.Blockchain.UTXOCache.GetTxReference(blockTx)
		if err != nil {
			log.Infof("BaseTransaction=%s not exist when deleting, %s.",
				blockTx.Hash(), err)
			continue
		}
		for input := range inputUtxos {
			// we search transactions in transaction pool which have the same utxos with those transactions
			// in block. That is, if a transaction in the new-coming block uses the same utxo which a transaction
			// in transaction pool uses, then the latter one should be deleted, because one of its utxos has been used
			// by a confirmed transaction packed in the new-coming block.
			if tx := mp.getInputUTXOList(input); tx != nil {
				if tx.Hash() == blockTx.Hash() {
					// it is evidently that two transactions with the same transaction id has exactly the same utxos with each
					// other. This is a special case of what we've said above.
					log.Debugf("duplicated transactions detected when adding a new block. "+
						" Delete transaction in the transaction pool. BaseTransaction id: %s", tx.Hash())
				} else {
					log.Debugf("double spent UTXO inputs detected in transaction pool when adding a new block. "+
						"Delete transaction in the transaction pool. "+
						"block transaction hash: %s, transaction hash: %s, the same input: %s, index: %d",
						blockTx.Hash(), tx.Hash(), input.Previous.TxID, input.Previous.Index)
				}

				//1.remove from txnList
				mp.doRemoveTransaction(tx)

				deleteCount++
			}
		}

		// F-193: a transaction with no inputs (every zero-input special tx)
		// matches nothing in the loop above, so this used to clear only its
		// conflict slots and leave the transaction itself stranded in txnList,
		// txFees and txReceivingInfo. Anything that just appeared in a block
		// must leave the pool outright.
		if _, ok := mp.txnList[blockTx.Hash()]; ok {
			mp.doRemoveTransaction(blockTx)
			deleteCount++
		} else if err := mp.removeTx(blockTx); err != nil {
			log.Warnf("remove tx %s when delete", blockTx.Hash())
		}

		if blockTx.IsTransferCrossChainAssetTx() && blockTx.IsSmallTransfer(mp.chainParams.SmallCrossTransferThreshold) {
			blockchain.DefaultLedger.Store.CleanSmallCrossTransferTx(blockTx.Hash())
		}
	}
	log.Debug(fmt.Sprintf("[cleanTransactionList],transaction %d in block, %d in transaction pool before, %d deleted,"+
		" Remains %d in TxPool",
		len(blockTxs), txsInPool, deleteCount, len(mp.txnList)))
}

func (mp *TxPool) cleanCanceledProducerAndCR(txs []interfaces.Transaction) error {
	for _, txn := range txs {
		if txn.TxType() == common.CancelProducer {
			cpPayload, ok := txn.Payload().(*payload.ProcessProducer)
			if !ok {
				return errors.New("invalid cancel producer payload")
			}
			if err := mp.cleanVoteAndUpdateProducer(cpPayload.OwnerKey); err != nil {
				log.Error(err)
			}
		}
		if txn.TxType() == common.UnregisterCR {
			crPayload, ok := txn.Payload().(*payload.UnregisterCR)
			if !ok {
				return errors.New("invalid cancel producer payload")
			}
			if err := mp.cleanVoteAndUpdateCR(crPayload.CID); err != nil {
				log.Error(err)
			}
		}
	}

	return nil
}

func (mp *TxPool) checkAndCleanAllTransactions() {
	chain := blockchain.DefaultLedger.Blockchain
	bestHeight := blockchain.DefaultLedger.Blockchain.GetHeight()

	txCount := len(mp.txnList)
	var deleteCount int
	var proposalsUsedAmount Fixed64
	for _, tx := range mp.txnList {
		_, err := chain.CheckTransactionContext(bestHeight+1, tx, proposalsUsedAmount, 0)
		if err != nil {
			log.Warn("[checkAndCleanAllTransactions] check transaction context failed,", err)
			deleteCount++
			mp.doRemoveTransaction(tx)
			continue
		}
		if tx.IsCRCProposalTx() {
			blockchain.RecordCRCProposalAmount(&proposalsUsedAmount, tx)
		}
	}

	log.Debug(fmt.Sprintf("[checkAndCleanAllTransactions],transaction %d "+
		"in transaction pool before, %d deleted. Remains %d in TxPool", txCount,
		deleteCount, txCount-deleteCount))
}

func (mp *TxPool) cleanVoteAndUpdateProducer(ownerPublicKey []byte) error {
	for _, txn := range mp.txnList {
		if txn.TxType() == common.TransferAsset {
		end:
			for _, output := range txn.Outputs() {
				if output.Type == common.OTVote {
					opPayload, ok := output.Payload.(*outputpayload.VoteOutput)
					if !ok {
						return errors.New("invalid vote output payload")
					}
					for _, content := range opPayload.Contents {
						if content.VoteType == outputpayload.Delegate {
							for _, cv := range content.CandidateVotes {
								if bytes.Equal(ownerPublicKey, cv.Candidate) {
									mp.removeTransaction(txn)
									break end
								}
							}
						}
					}
				}
			}
		} else if txn.TxType() == common.UpdateProducer {
			upPayload, ok := txn.Payload().(*payload.ProducerInfo)
			if !ok {
				return errors.New("invalid update producer payload")
			}
			if bytes.Equal(upPayload.OwnerKey, ownerPublicKey) {
				mp.removeTransaction(txn)
				if err := mp.RemoveKey(
					BytesToHexString(upPayload.OwnerKey),
					slotDPoSOwnerPublicKey); err != nil {
					return err
				}
				if err := mp.RemoveKey(
					BytesToHexString(upPayload.NodePublicKey),
					slotDPoSNodePublicKey); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (mp *TxPool) cleanVoteAndUpdateCR(cid Uint168) error {
	for _, txn := range mp.txnList {
		if txn.TxType() == common.TransferAsset {
			for _, output := range txn.Outputs() {
				if output.Type == common.OTVote {
					opPayload, ok := output.Payload.(*outputpayload.VoteOutput)
					if !ok {
						return errors.New("invalid vote output payload")
					}
					for _, content := range opPayload.Contents {
						if content.VoteType == outputpayload.CRC {
							for _, cv := range content.CandidateVotes {
								if bytes.Equal(cid.Bytes(), cv.Candidate) {
									mp.removeTransaction(txn)
								}
							}
						}
					}
				}
			}
		} else if txn.TxType() == common.UpdateCR {
			crPayload, ok := txn.Payload().(*payload.CRInfo)
			if !ok {
				return errors.New("invalid update CR payload")
			}
			if cid.IsEqual(crPayload.CID) {
				mp.removeTransaction(txn)
				if err := mp.RemoveKey(crPayload.CID, slotCRDID); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// get the transaction by hash
func (mp *TxPool) GetTransaction(hash Uint256) interfaces.Transaction {
	mp.RLock()
	defer mp.RUnlock()
	return mp.txnList[hash]
}

// verify transaction with txnpool
func (mp *TxPool) verifyTransactionWithTxnPool(
	txn interfaces.Transaction) elaerr.ELAError {
	if txn.IsSideChainPowTx() {
		// check and replace the duplicate sidechainpow tx
		mp.replaceDuplicateSideChainPowTx(txn)
	}

	return mp.VerifyTx(txn)
}

// remove from associated map
func (mp *TxPool) removeTransaction(tx interfaces.Transaction) {
	//1.remove from txnList
	if _, ok := mp.txnList[tx.Hash()]; ok {
		mp.doRemoveTransaction(tx)
	}
}

func (mp *TxPool) IsDuplicateSidechainTx(sidechainTxHash Uint256) bool {
	mp.RLock()
	defer mp.RUnlock()
	return mp.ContainsKey(sidechainTxHash, slotSidechainTxHashes)
}

func (mp *TxPool) IsDuplicateSidechainReturnDepositTx(sidechainReturnDepositTxHash Uint256) bool {
	mp.RLock()
	defer mp.RUnlock()
	return mp.ContainsKey(sidechainReturnDepositTxHash, slotSidechainReturnDepositTxHashes)
}

// check and replace the duplicate sidechainpow tx
func (mp *TxPool) replaceDuplicateSideChainPowTx(txn interfaces.Transaction) {
	var replaceList []interfaces.Transaction

	for _, v := range mp.txnList {
		if v.TxType() == common.SideChainPow {
			oldPayload := v.Payload().Data(payload.SideChainPowVersion)
			oldGenesisHashData := oldPayload[32:64]

			newPayload := txn.Payload().Data(payload.SideChainPowVersion)
			newGenesisHashData := newPayload[32:64]

			if bytes.Equal(oldGenesisHashData, newGenesisHashData) {
				replaceList = append(replaceList, v)
			}
		}
	}

	for _, txn := range replaceList {
		txid := txn.Hash()
		log.Info("replace sidechainpow transaction, txid=", txid.String())
		mp.removeTransaction(txn)
	}
}

// clean the sidechainpow tx pool
func (mp *TxPool) cleanSideChainPowTx() {
	for _, txn := range mp.txnList {
		if txn.IsSideChainPowTx() {
			arbiter := blockchain.DefaultLedger.Arbitrators.GetOnDutyCrossChainArbitrator()
			if err := blockchain.CheckSideChainPowConsensus(txn, arbiter); err != nil {
				// delete tx
				mp.doRemoveTransaction(txn)
			}
		}
	}
}

func (mp *TxPool) GetTransactionCount() int {
	mp.RLock()
	defer mp.RUnlock()
	return len(mp.txnList)
}

func (mp *TxPool) getInputUTXOList(input *common.Input) interfaces.Transaction {
	return mp.GetTx(input.ReferKey(), slotTxInputsReferKeys)
}

func (mp *TxPool) MaybeAcceptTransaction(tx interfaces.Transaction) error {
	mp.Lock()
	defer mp.Unlock()
	return mp.appendToTxPool(tx)
}

func (mp *TxPool) RemoveTransaction(txn interfaces.Transaction) {
	mp.Lock()
	txHash := txn.Hash()
	for i := range txn.Outputs() {
		input := common.Input{
			Previous: common.OutPoint{
				TxID:  txHash,
				Index: uint16(i),
			},
		}

		tx := mp.getInputUTXOList(&input)
		if tx != nil {
			mp.removeTransaction(tx)
		}
	}
	mp.Unlock()
}

func (mp *TxPool) dealAddProposalTx(txn interfaces.Transaction) {
	proposal, ok := txn.Payload().(*payload.CRCProposal)
	if !ok {
		return
	}
	for _, b := range proposal.Budgets {
		mp.proposalsUsedAmount += b.Amount
	}
}

func (mp *TxPool) dealDelProposalTx(txn interfaces.Transaction) {
	proposal, ok := txn.Payload().(*payload.CRCProposal)
	if !ok {
		return
	}
	for _, b := range proposal.Budgets {
		mp.proposalsUsedAmount -= b.Amount
	}
}

func (mp *TxPool) doAddTransaction(tx interfaces.Transaction) elaerr.ELAError {
	if err := mp.txFees.AddTx(tx); err != nil {
		return err
	}
	mp.txnList[tx.Hash()] = tx
	if tx.IsCRCProposalTx() {
		mp.dealAddProposalTx(tx)
	}
	return nil
}

func (mp *TxPool) doRemoveTransaction(tx interfaces.Transaction) {
	hash := tx.Hash()
	txSize := tx.GetSize()
	feeRate := float64(tx.Fee()) / float64(txSize)

	if _, exist := mp.txnList[hash]; exist {
		delete(mp.txnList, hash)
		if tx.IsCRCProposalTx() {
			mp.dealDelProposalTx(tx)
		}
		if _, ok := mp.crossChainHeightList[hash]; ok {
			delete(mp.crossChainHeightList, hash)
			mp.cleanSmallCrossTransferRecord(hash)
		}
		if _, ok := mp.txReceivingInfo[hash]; ok {
			delete(mp.txReceivingInfo, hash)
		}
		mp.txFees.RemoveTx(hash, uint64(txSize), feeRate)
		mp.removeTx(tx)
	}
}

func (mp *TxPool) onPopBack(hash Uint256) {
	tx, ok := mp.txnList[hash]
	if !ok {
		log.Warnf("cannot find tx %s when try to delete", hash)
		return
	}
	if err := mp.removeTx(tx); err != nil {
		log.Warnf(err.Error())
		return
	}
	delete(mp.txnList, hash)
	// F-120: doRemoveTransaction clears these two maps, this eviction path did
	// not - so every fee-ordered eviction leaked one crossChainHeightList and
	// one txReceivingInfo entry. Harmless only while F-060 kept this function
	// unreachable; not harmless now that eviction is live.
	if _, ok := mp.crossChainHeightList[hash]; ok {
		delete(mp.crossChainHeightList, hash)
		mp.cleanSmallCrossTransferRecord(hash)
	}
	delete(mp.txReceivingInfo, hash)
	mp.dealDelProposalTx(tx)
}

// cleanSmallCrossTransferRecord drops the PERSISTENT small-cross-transfer
// record written on admission, for a transaction that is leaving the pool
// without having been mined.
//
// NX-07: SaveSmallCrossTransferTx writes a leveldb record on mempool admission
// and, until this change, CleanSmallCrossTransferTx had exactly ONE caller in
// the whole tree - cleanTransactionList, i.e. the block path. Conflict eviction
// (doRemoveTransaction, reached from cleanTransactions), fee-ordered eviction
// (onPopBack) and the post-reorg re-check (checkAndCleanAllTransactions, which
// funnels into doRemoveTransaction) each cleared only the IN-MEMORY twin, so
// every transaction that was admitted and then evicted without being mined left
// a permanent record. Nothing pruned it, node start re-injected all of it, and
// every arbiter re-downloaded and re-parsed the whole bucket once per second.
// This finishes what F-120 started: F-120 extended the eviction path to the two
// in-memory maps, and this extends it to the persistent twin.
//
// The caller must already have established that a record exists, by finding the
// transaction in crossChainHeightList - written in the same branch that writes
// the leveldb record, so it is an exact predicate and costs ordinary
// transactions nothing.
func (mp *TxPool) cleanSmallCrossTransferRecord(hash Uint256) {
	if err := blockchain.DefaultLedger.Store.
		CleanSmallCrossTransferTx(hash); err != nil {
		log.Warnf("failed to clean small cross chain transaction %s: %s",
			hash, err)
	}
}

func NewTxPool(params *config.Configuration, ckpManager *checkpoint.Manager) *TxPool {
	rtn := &TxPool{
		conflictManager:      newConflictManager(),
		chainParams:          params,
		CkpManager:           ckpManager,
		proposalsUsedAmount:  0,
		crossChainHeightList: make(map[Uint256]uint32),
		txReceivingInfo:      make(map[Uint256]TxReceivingInfo),
	}
	rtn.txPoolCheckpoint = newTxPoolCheckpoint(
		rtn, func(m map[Uint256]interfaces.Transaction) {
			for _, v := range m {
				if err := rtn.conflictManager.AppendTx(v); err != nil {
					return
				}
			}
		})
	rtn.CkpManager.Register(rtn.txPoolCheckpoint)
	return rtn
}
