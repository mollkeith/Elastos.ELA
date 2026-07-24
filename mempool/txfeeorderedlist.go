// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package mempool

import (
	"fmt"
	"io"
	"sort"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/errors"
)

type PopBackEvent func(common.Uint256)
type AppendToTxPoolEvent func(tx interfaces.Transaction) errors.ELAError

var (
	addingTxExcluded = errors.SimpleWithMessage(errors.ErrTxPoolFailure,
		nil, "new tx excluded")
)

// txItem defines essential data about ordering a tx
type txItem struct {
	Hash    common.Uint256
	FeeRate float64
	Size    uint32
}

// txFeeOrderedList maintains a list of tx hashes order
type txFeeOrderedList struct {
	list      []txItem
	totalSize uint64
	maxSize   uint64
	onPopBack PopBackEvent
}

func (l *txFeeOrderedList) AddTx(tx interfaces.Transaction) errors.ELAError {
	size := uint32(tx.GetSize())
	if size <= 0 {
		return errors.SimpleWithMessage(errors.ErrTxPoolFailure, nil,
			fmt.Sprintf("tx %s got illegal size", common.ToReversedString(tx.Hash())))
	}

	feeRate := float64(tx.Fee()) / float64(size)

	// F-060: the old admission guard only compared the incoming fee rate with
	// the single lowest entry, which does not answer the question being asked.
	// Eviction may only free the entries paying strictly less, so a tx could
	// pass that guard, be inserted, evict paying entries and then be popped
	// itself - leaving a hash in TxPool.txnList this list no longer accounts
	// for. CanAccept decides exactly what the eviction loop can deliver.
	if !l.CanAccept(uint64(size), feeRate) {
		return addingTxExcluded
	}

	l.compareAndInsert(txItem{
		Hash:    tx.Hash(),
		FeeRate: feeRate,
		Size:    size,
	})

	for l.OverSize(0) && len(l.list) > 0 {
		item := l.popBack()
		l.totalSize -= uint64(item.Size)
		l.onPopBack(item.Hash)
	}
	return nil
}

// CanAccept reports whether a tx of the given size and fee rate can be admitted
// to the list, counting only the entries admission is allowed to evict - those
// paying strictly less than the incoming tx. It is a pure query and mutates
// nothing, so the pool can ask the same question before it starts validating.
func (l *txFeeOrderedList) CanAccept(size uint64, feeRate float64) bool {
	if size > l.maxSize {
		return false
	}
	if !l.OverSize(size) {
		return true
	}

	var evictable uint64
	for i := len(l.list) - 1; i >= 0; i-- {
		if l.list[i].FeeRate >= feeRate {
			break
		}
		evictable += uint64(l.list[i].Size)
	}

	remaining := l.totalSize
	if evictable >= remaining {
		remaining = 0
	} else {
		remaining -= evictable
	}
	return remaining+size <= l.maxSize
}

func (l *txFeeOrderedList) RemoveTx(hash common.Uint256, txSize uint64,
	feeRate float64) bool {
	index := sort.Search(len(l.list), func(i int) bool {
		return l.list[i].FeeRate < feeRate
	})

	i := l.locate(index, hash)
	if i < 0 {
		return false
	}

	copy(l.list[i:], l.list[i+1:])
	l.list = l.list[:len(l.list)-1]
	l.totalSize -= txSize
	return true
}

func (l *txFeeOrderedList) locate(givenIndex int, hash common.Uint256) int {
	if givenIndex == len(l.list) {
		// we assume givenIndex equals length of l.list means hit the last one
		givenIndex -= 1
	}

	for i := givenIndex; i >= 0; i-- {
		if hash.IsEqual(l.list[i].Hash) {
			return i
		}
	}
	return -1
}

func (l *txFeeOrderedList) GetSize() int {
	return len(l.list)
}

func (l *txFeeOrderedList) OverSize(size uint64) bool {
	return l.totalSize+size > l.maxSize
}

func (l *txFeeOrderedList) Serialize(w io.Writer) (err error) {
	if err = common.WriteVarUint(w, uint64(len(l.list))); err != nil {
		return
	}
	for _, v := range l.list {
		if err = v.Serialize(w); err != nil {
			return
		}
	}

	return common.WriteElements(w, l.totalSize)
}

func (l *txFeeOrderedList) Deserialize(r io.Reader) (err error) {
	var count uint64
	if count, err = common.ReadVarUint(r, 0); err != nil {
		return
	}
	l.list = make([]txItem, 0, count)
	for i := uint64(0); i < count; i++ {
		item := txItem{}
		if err = item.Deserialize(r); err != nil {
			return
		}
		l.list = append(l.list, item)
	}

	return common.ReadElements(r, &l.totalSize)
}

func (l *txFeeOrderedList) compareAndInsert(item txItem) {
	index := sort.Search(len(l.list), func(i int) bool {
		return l.list[i].FeeRate < item.FeeRate
	})
	l.list = append(l.list, txItem{})
	copy(l.list[index+1:], l.list[index:])
	l.list[index] = item

	l.totalSize += uint64(item.Size)
}

func (l *txFeeOrderedList) popBack() txItem {
	rtn := l.list[len(l.list)-1]
	l.list = l.list[:len(l.list)-1]
	return rtn
}

func newTxFeeOrderedList(onPopBack PopBackEvent,
	maxSize uint64) *txFeeOrderedList {
	return &txFeeOrderedList{
		list:      []txItem{},
		totalSize: 0,
		onPopBack: onPopBack,
		maxSize:   maxSize,
	}
}

func (i *txItem) Serialize(w io.Writer) error {
	if err := i.Hash.Serialize(w); err != nil {
		return err
	}

	return common.WriteElements(w, i.FeeRate, i.Size)
}

func (i *txItem) Deserialize(r io.Reader) error {
	if err := i.Hash.Deserialize(r); err != nil {
		return err
	}

	return common.ReadElements(r, &i.FeeRate, &i.Size)
}
