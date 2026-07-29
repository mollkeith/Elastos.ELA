// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain_test

import (
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/core/types"
)

// TestF137DposBlockRecoveryStubsFailLoudly proves F-137: Ledger.GetDposBlocks and
// Ledger.AppendDposBlocks were `//todo complete me` stubs that returned a NIL
// error, so DPOSManager.OnResponseBlocks (dpos/manager/dposmanager.go:368) was
// told the block recovery had SUCCEEDED while absolutely nothing was appended.
// The stubs stay unimplemented on purpose - reviving a dormant consensus-recovery
// protocol is an owner decision - but they must report failure instead of a
// silent success. Deliberately asserts only on the error contract (never on an
// identifier that exists solely post-fix) so it compiles, and fails, on pristine.
func TestF137DposBlockRecoveryStubsFailLoudly(t *testing.T) {
	l := &blockchain.Ledger{}

	blocks, err := l.GetDposBlocks(0, 0)
	if err == nil {
		t.Fatal("GetDposBlocks reported success for an unimplemented recovery path (F-137)")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("GetDposBlocks error does not name the cause: %v", err)
	}
	if blocks != nil {
		t.Fatalf("GetDposBlocks returned %d blocks alongside its error", len(blocks))
	}

	err = l.AppendDposBlocks([]*types.DposBlock{})
	if err == nil {
		t.Fatal("AppendDposBlocks reported success while appending nothing (F-137)")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("AppendDposBlocks error does not name the cause: %v", err)
	}
}
