// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
)

// entriesToWrap is the number of MaxELAMoney-sized vote entries whose sum
// exceeds MaxInt64: 93 * 1e17 = 9.3e18 > 9.223372036854775807e18.
const entriesToWrap = 93

func voteTotalTx(height, strictHeight uint32) *VotingTransaction {
	tx := &VotingTransaction{}
	tx.SetParameters(&TransactionParameters{
		BlockHeight: height,
		Config:      &config.Configuration{StrictMoneyRangeHeight: strictHeight},
	})
	return tx
}

// TestVoteTotalAggregateWrap is the regression test for the vote-total
// accumulation wrap.
//
// Bounding each entry to MoneyRange is NOT sufficient on its own. The
// per-content decode cap admits up to MaxVoteCandidatesPerContent (1024)
// entries; the 36-entry MaxVoteProducersPerTransaction cap gates only the
// Delegate branch, and the DposV2 / CRC / CRCImpeachment branches accept
// duplicate candidates. So 93 entries at MaxELAMoney each -- all individually
// valid -- sum past MaxInt64, wrap the running total NEGATIVE, and invert the
// `totalVotes > voteRights` gate that is the only thing binding cast votes to
// staked rights.
//
// This is the same shape as the block-2260451 output-sum wrap: every value fit
// int64 individually while their sum did not.
func TestVoteTotalAggregateWrap(t *testing.T) {
	const strictHeight uint32 = 100

	// 1. Pin the premise: the unguarded arithmetic really does wrap negative.
	var legacy common.Fixed64
	for i := 0; i < entriesToWrap; i++ {
		legacy += common.MaxELAMoney
	}
	if legacy >= 0 {
		t.Fatalf("premise broken: %d x MaxELAMoney should wrap negative, got %d",
			entriesToWrap, legacy)
	}

	// 2. At/above the gate the wrap is rejected BEFORE it can happen, and the
	//    running total never goes negative.
	tx := voteTotalTx(strictHeight, strictHeight)
	var total common.Fixed64
	var err error
	rejectedAt := -1
	for i := 0; i < entriesToWrap; i++ {
		total, err = tx.addVoteTotal(total, common.MaxELAMoney)
		if err != nil {
			rejectedAt = i
			break
		}
		if total < 0 {
			t.Fatalf("running total went negative at entry %d: %d", i, total)
		}
	}
	if rejectedAt < 0 {
		t.Fatalf("strict path accepted %d x MaxELAMoney (total=%d); the wrap is NOT closed",
			entriesToWrap, total)
	}

	// 3. Below the gate, legacy wrapping is preserved VERBATIM. Historical
	//    blocks were validated under it and must replay bit-identically.
	old := voteTotalTx(strictHeight-1, strictHeight)
	var legacyPath common.Fixed64
	for i := 0; i < entriesToWrap; i++ {
		legacyPath, err = old.addVoteTotal(legacyPath, common.MaxELAMoney)
		if err != nil {
			t.Fatalf("legacy path must never error (replay safety); errored at %d: %v", i, err)
		}
	}
	if legacyPath != legacy {
		t.Fatalf("legacy path diverged from historical arithmetic: got %d, want %d",
			legacyPath, legacy)
	}
}

// TestVoteTotalNoFalsePositive proves the bound rejects nothing legitimate. A
// single transaction's vote total is capped by that voter's own rights, which
// are capped by their stake, which cannot exceed total supply (~26.29M ELA =
// 2.628e15 sela). MaxELAMoney (1e17) leaves ~38x headroom over that ceiling.
func TestVoteTotalNoFalsePositive(t *testing.T) {
	const strictHeight uint32 = 100
	const totalSupplySela = common.Fixed64(2628776200000000) // ~26.29M ELA

	tx := voteTotalTx(strictHeight, strictHeight)

	// The extreme legitimate case: a voter staking the ENTIRE supply, split
	// across the maximum Delegate-branch entry count.
	perEntry := totalSupplySela / 36
	var total common.Fixed64
	var err error
	for i := 0; i < 36; i++ {
		total, err = tx.addVoteTotal(total, perEntry)
		if err != nil {
			t.Fatalf("legitimate vote aggregate rejected at entry %d (total=%d): %v",
				i, total, err)
		}
	}
	if total > common.MaxELAMoney {
		t.Fatalf("sanity: legitimate total %d exceeded the bound", total)
	}

	// Report the actual headroom so a future supply change surfaces here.
	headroom := float64(common.MaxELAMoney) / float64(totalSupplySela)
	if headroom < 10 {
		t.Fatalf("headroom over total supply has fallen to %.1fx; re-evaluate the bound", headroom)
	}
	t.Logf("headroom over total supply: %.1fx", headroom)
}
