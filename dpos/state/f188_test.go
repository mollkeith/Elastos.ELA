// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// TestF188RemoveSpecialTxLocked — F-188: RemoveSpecialTx DELETES from SpecialTxHashes (a
// map write) but originally held only RLock, so it raced concurrent readers/writers ->
// Go fatal "concurrent map read and map write" (os.Exit, uncatchable, unrecoverable node
// crash). Run under `go test -race`: pre-fix this reports a data race (RLock delete vs
// RLock read on the same map); post-fix (exclusive Lock) it is clean.
func TestF188RemoveSpecialTxLocked(t *testing.T) {
	s := &State{StateKeyFrame: &StateKeyFrame{
		SpecialTxHashes: make(map[common.Uint256]struct{}),
	}}
	for i := 0; i < 256; i++ {
		var h common.Uint256
		h[0] = byte(i)
		s.SpecialTxHashes[h] = struct{}{}
	}

	const iters = 20000
	var wg sync.WaitGroup
	wg.Add(2)
	// Writer: RemoveSpecialTx (delete) then re-add under exclusive lock.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			var h common.Uint256
			h[0] = byte(i)
			s.RemoveSpecialTx(h)
			s.mtx.Lock()
			s.SpecialTxHashes[h] = struct{}{}
			s.mtx.Unlock()
		}
	}()
	// Reader: read the map under RLock (mimics SpecialTxExists at state.go:1229).
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			s.mtx.RLock()
			_ = len(s.SpecialTxHashes)
			s.mtx.RUnlock()
		}
	}()
	wg.Wait()
}
