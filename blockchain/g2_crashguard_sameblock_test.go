// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Bounds guards inside CheckSameBlockConflicts — the remote node-kill class.
//
// THE EVIDENCE GAP THIS CLOSES. CheckSameBlockConflicts runs from CheckBlockSanity, which
// is reached BEFORE any per-transaction payload validation. Its key-extraction arms index
// txn.Programs()[0] and txn.Outputs()[0], so each is preceded by a length guard. A mutation
// battery neutered the four of them in turn and the whole shipping gate stayed green:
//
//	blockvalidator.go:381  ReturnDepositCoin      len(txn.Programs()) == 0
//	blockvalidator.go:795  stakeVoteConflictKey   len(txn.Outputs()) < 1 || Outputs()[0].Payload == nil
//	blockvalidator.go:804  stakeVoteConflictKey   len(txn.Programs()) < 1
//	blockvalidator.go:826  claimRewardConflictKey len(txn.Programs()) < 1
//
// Neutered, each one turns a malformed transaction into an index-out-of-range PANIC inside
// block validation. A block is attacker-supplied and gossiped, so that is an unauthenticated
// remote node kill, not a cosmetic defect. Nothing in the tree exercised any of the four.
//
// Each case below packs one deliberately malformed transaction into a block at the gate and
// requires CheckSameBlockConflicts to REJECT it and NOT panic. With the guard armed the
// rejection is an error; with it neutered the same input panics and the subtest fails with
// the recovered value. The production call site into CheckSameBlockConflicts is proven
// separately and end to end by blockchain/f118_sameblock_nftdup_test.go and by
// test/unit/wiring_errconsumed_test.go.
//
// Reuses the f028_sameblock_test.go helpers. No new height literal.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// g2NoPanic runs CheckSameBlockConflicts on a one-transaction block and requires a plain
// error return. A panic is reported as the node-kill it is.
func g2NoPanic(t *testing.T, name string, txn interfaces.Transaction) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("REMOTE NODE KILL: CheckSameBlockConflicts PANICKED on a malformed "+
					"%s transaction instead of rejecting it. A block is attacker-supplied "+
					"and this runs before any per-transaction payload check. recovered: %v",
					name, r)
			}
		}()
		err := blockchain.CheckSameBlockConflicts(f028Block(f028Gate, txn), f028Gate)
		if err == nil {
			t.Fatalf("MALFORMED %s ACCEPTED: the bounds guard did not reject a transaction "+
				"whose indexed field is absent", name)
		}
		t.Logf("rejected as expected: %v", err)
	})
}

// TestG2SameBlockBoundsGuardsRejectMalformedTxs is the fail-on-pristine test for all four.
func TestG2SameBlockBoundsGuardsRejectMalformedTxs(t *testing.T) {
	// blockvalidator.go:381 — ReturnDepositCoin keyed on Programs()[0].Code.
	g2NoPanic(t, "ReturnDepositCoin-without-program",
		f028Tx(common2.ReturnDepositCoin, 0, &payload.ReturnDepositCoin{}, nil))
	g2NoPanic(t, "ReturnCRDepositCoin-without-program",
		f028Tx(common2.ReturnCRDepositCoin, 0, &payload.ReturnDepositCoin{}, nil))

	// blockvalidator.go:795 — ExchangeVotes keyed on Outputs()[0].Payload.
	g2NoPanic(t, "ExchangeVotes-without-outputs",
		f028Tx(common2.ExchangeVotes, 0, &payload.ExchangeVotes{}, nil))

	// blockvalidator.go:804 — the vote family keyed on Programs()[0].Code.
	g2NoPanic(t, "ReturnVotes-without-program",
		f028Tx(common2.ReturnVotes, byte(0x01), &payload.ReturnVotes{}, nil))
	g2NoPanic(t, "Voting-without-program",
		f028Tx(common2.Voting, 0, &payload.Voting{}, nil))

	// blockvalidator.go:826 — DposV2ClaimReward keyed on Programs()[0].Code.
	g2NoPanic(t, "DposV2ClaimReward-without-program",
		f028Tx(common2.DposV2ClaimReward, payload.DposV2ClaimRewardVersionV1,
			&payload.DPoSV2ClaimReward{}, nil))
}
