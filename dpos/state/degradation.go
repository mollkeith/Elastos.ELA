// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

type degradationState byte

const (
	DSNormal       degradationState = 0x00
	DSUnderstaffed degradationState = 0x01
	DSInactive     degradationState = 0x02
)

// degradation maintains states which will take effect during
// degradation period.
type degradation struct {
	mtx sync.Mutex

	state             degradationState
	understaffedSince uint32
	inactivateHeight  uint32
	inactiveTxs       map[common.Uint256]interface{}
}

func (d *degradation) IsUnderstaffedMode() bool {
	d.mtx.Lock()
	result := d.state == DSUnderstaffed
	d.mtx.Unlock()

	return result
}

func (d *degradation) IsInactiveMode() bool {
	d.mtx.Lock()
	result := d.state == DSInactive
	d.mtx.Unlock()

	return result
}

func (d *degradation) RollbackTo(height uint32) {
	d.mtx.Lock()
	// if rollback to the height before abnormal mode was set,
	// then reset inactive related state
	needReset := height < d.inactivateHeight || height < d.understaffedSince
	d.mtx.Unlock()

	if needReset {
		d.Reset()
	}
}

func (d *degradation) InactiveModeSwitch(height uint32,
	isAbleToRecover func() bool) (bool, bool) {

	d.mtx.Lock()
	if d.state != DSNormal {
		d.mtx.Unlock()
		return false, false
	}
	if len(d.inactiveTxs) >= MaxNormalInactiveChangesCount {
		d.state = DSInactive
		d.inactivateHeight = height
		d.mtx.Unlock()

		return true, false
	}
	d.mtx.Unlock()

	if d.IsInactiveMode() && isAbleToRecover() {
		d.Reset()

		return false, true
	}

	return false, false
}

func (d *degradation) TrySetUnderstaffed(height uint32) bool {
	d.mtx.Lock()
	if d.state != DSNormal {
		d.mtx.Unlock()
		return false
	}
	d.understaffedSince = height
	d.state = DSUnderstaffed
	d.mtx.Unlock()
	return true
}

func (d *degradation) TryLeaveUnderStaffed(isAbleToRecover func() bool) bool {
	if isAbleToRecover() {
		d.Reset()
		return true
	}
	return false
}

// Reset method reset all
func (d *degradation) Reset() {
	d.mtx.Lock()
	d.state = DSNormal
	d.inactivateHeight = 0
	d.understaffedSince = 0
	d.mtx.Unlock()
}

// specialTxDegradationState is the degradation bookkeeping captured and restored
// around a block's special transactions (F-093/F-094). inactiveTxs in particular
// lives outside utils.History, so no RollbackTo has ever been able to un-mark a
// payload processed by a block that then failed to connect.
type specialTxDegradationState struct {
	state             degradationState
	understaffedSince uint32
	inactivateHeight  uint32
	inactiveTxs       map[common.Uint256]interface{}
}

// captureForSpecialTx snapshots the degradation bookkeeping. Read-only.
func (d *degradation) captureForSpecialTx() specialTxDegradationState {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	return specialTxDegradationState{
		state:             d.state,
		understaffedSince: d.understaffedSince,
		inactivateHeight:  d.inactivateHeight,
		inactiveTxs:       copyInactiveTxs(d.inactiveTxs),
	}
}

// restoreForSpecialTx puts back a snapshot taken by captureForSpecialTx.
func (d *degradation) restoreForSpecialTx(s specialTxDegradationState) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.state = s.state
	d.understaffedSince = s.understaffedSince
	d.inactivateHeight = s.inactivateHeight
	d.inactiveTxs = copyInactiveTxs(s.inactiveTxs)
}

func (d *degradation) AddInactivePayload(p *payload.InactiveArbitrators) bool {
	hash := p.Hash()
	d.mtx.Lock()
	_, exist := d.inactiveTxs[hash]
	if !exist {
		d.inactiveTxs[hash] = nil
	}
	d.mtx.Unlock()

	return !exist
}
