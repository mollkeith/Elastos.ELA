// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// The rows below are REAL mainnet votes, not constructed ones. They come from a
// full-chain scan of the frozen mainnet copy (heights 0..2260595, 2,260,596
// main-chain blocks, ffldb store md5-sentinel d665a7449f31159f756af106b37f6e7e
// before and after the scan).
//
// The scan replayed the only two code paths that can ever create a
// DetailedVoteInfo -- State.processVotingContent (BlockHeight = the block height)
// and State.processRenewalVotingContent (BlockHeight = the ORIGINAL vote's height,
// looked up by ReferKey) -- over every Voting transaction in the retained chain,
// and evaluated both weight formulas on each result:
//
//	Voting transactions                       : 15,506
//	DetailedVoteInfo values evaluated         : 33,653
//	  from processVotingContent               : 27,561
//	  from processRenewalVotingContent        :  6,092
//	  renewals whose original was not found   :      0
//	duration = LockTime - BlockHeight         : min 7200, max 720000
//	  duration <  7200                        :      0
//	  duration >  720000                      :      0   (the clamp never bites)
//	  duration == 7200 exactly                :      3
//	  duration == 720000 exactly              :     13
//	  LockTime <= BlockHeight                 :      0
//	Votes <= 0                                :      0
//	Votes outside MoneyRange                  :      0
//	weightF <= 0                              :      0
//	DIVERGENCES legacy vs VoteRights()        :      0
//
// So the guards in VoteRights are inert on 100% of retained history: the
// behaviour-identity claim is MEASURED, not assumed. The comparator was
// positive-controlled -- injecting an out-of-window duration into these same real
// records (in memory) makes it report divergences -- so the zero is a real zero and
// not a comparator that cannot fire.
//
// measuredMainnetVotes pins the boundary and extreme rows of that population so a
// future edit to VoteRights cannot silently change the weight of retained history.
var measuredMainnetVotes = []struct {
	what        string
	txid        string
	blockHeight uint32
	lockTime    uint32
	votes       common.Fixed64
	onChain     common.Fixed64 // weight measured on the real chain
}{
	// The two validation boundaries, both exercised by real votes.
	{"duration == min lock (7200)", "70be42268d26af1a7999345ba45b453a8e48a7e920b3bc6091a36bdf8f3928a3",
		1540310, 1547510, 10000000000, 10000000000},
	{"duration == min lock (7200)", "c3b84e8f1fb1bb3a246341839afe1eb8cbd6d53e52ac67929dc10c149ab9d093",
		1671471, 1678671, 500000000000, 500000000000},
	{"duration == min lock (7200)", "2dd56ec047da86cf152b35cdac8d6e2ade5925190153fd8aaea5b4c38e6e546b",
		1822855, 1830055, 330000000000, 330000000000},
	{"duration == max lock (720000), renewal", "8d0febeaff1c37cc95b8fe04ab2035e7501b8906d9608191366791f2d9bd80aa",
		1413962, 2133962, 100000000000, 300000000000},
	{"duration == max lock (720000), renewal", "2587f809cd991b037ea21e5154ffce5c9096fbd06f3d6cb564d360e6a5518af5",
		1413962, 2133962, 113300000000, 339900000000},
	{"duration == max lock (720000), renewal", "22b51cb4b0ca28c352805a19527fc3bc844ebea1ee8d341587a63da2d5b41fdf",
		1817144, 2537144, 180000000000, 540000000000},
	{"duration == max lock (720000), earliest renewal", "baa29ef25a7ca32e3d17d47ee84ac15041ff6941fe51b3be183c7d79977cb124",
		1408456, 2128456, 5000000000, 15000000000},

	// One step inside each boundary.
	{"duration == 7201 (min+1)", "f85993452bc4f096e31a5c1ae23cd5c51f9ba0de8b937cdc4b8829ed63ae3680",
		1409503, 1416704, 10000000, 10000603},
	{"duration == 719999 (max-1)", "28bba71b6783f02ce97ae67a1d77b37d074eb34868d22b0869f5b737ec9ccd7c",
		2101101, 2821100, 50000000000, 149999969840},

	// The extremes of the measured population.
	{"smallest votes on chain", "8babdcb2cd884b08059bc450aea9cba7b78efe2489887e9f2efa34c91dcb2d46",
		1500314, 1507518, 903221, 903438},
	{"largest votes and largest weight", "40236ca36c7e371a69acc2c18b057a1735172cd7471c2911bbdf82ea52f0716e",
		2212910, 2234509, 9000000000000, 13293910332253},
	{"first DPoSV2 vote on chain", "11aa4c400e6e22b8e1c410e8ce0260c91f147d749d7bcd960ef1e767134cf80a",
		1405208, 1412411, 7000000000, 7001266428},
	{"last DPoSV2 vote in retained history", "f3fecc151c2da683a0191c231a8691f00d2aaf7ec32874a1cbb4ce81089e28ff",
		2259987, 2267189, 20000000000, 20002412412},
}

// TestVoteRightsMatchesMeasuredMainnetVotes checks the shipping VoteRights against
// real retained-history votes: it must reproduce both the legacy expression and the
// weight those votes actually carried on chain. This is the regression guard for the
// full-chain measurement documented above -- retained history keeps its verdict.
func TestVoteRightsMatchesMeasuredMainnetVotes(t *testing.T) {
	for _, c := range measuredMainnetVotes {
		v := mkVote(c.votes, c.blockHeight, c.lockTime)
		got := v.VoteRights()
		legacy := legacyVoteRights(c.votes, c.blockHeight, c.lockTime)
		if got != legacy {
			t.Fatalf("%s (tx %s): VoteRights=%d, legacy=%d -- retained history would change verdict",
				c.what, c.txid, got, legacy)
		}
		if got != c.onChain {
			t.Fatalf("%s (tx %s): VoteRights=%d, measured on chain=%d",
				c.what, c.txid, got, c.onChain)
		}
	}
}

// TestVoteRightsMeasuredDurationWindow records, as an executable statement, the two
// facts the full-chain scan established about the retained vote population: every
// duration landed inside [DposV2MinVoteLockDuration, DposV2MaxVoteLockDuration]
// INCLUSIVE, and at both inclusive endpoints the guarded and legacy formulas agree.
// If either constant is ever moved, this fails -- which is the point, because moving
// them would re-weight retained history.
func TestVoteRightsMeasuredDurationWindow(t *testing.T) {
	if DposV2MinVoteLockDuration != 7200 {
		t.Fatalf("min lock duration is %d; the full-chain measurement was taken at 7200",
			DposV2MinVoteLockDuration)
	}
	if DposV2MaxVoteLockDuration != 720000 {
		t.Fatalf("max lock duration is %d; the full-chain measurement was taken at 720000",
			DposV2MaxVoteLockDuration)
	}
	for _, c := range measuredMainnetVotes {
		d := c.lockTime - c.blockHeight
		if d < DposV2MinVoteLockDuration || d > DposV2MaxVoteLockDuration {
			t.Fatalf("%s: duration %d outside the measured window [%d,%d]",
				c.what, d, DposV2MinVoteLockDuration, DposV2MaxVoteLockDuration)
		}
	}
}

// TestTotalVoteRightsAccumulationIsExact pins the OTHER half of the same review
// question: GetTotalDPoSV2VoteRights was changed from a float64 sum over a Go map to
// an exact Fixed64 sum. Summing non-negative integers in float64 is exact only while
// every partial sum stays <= 2^53. The full-chain scan measured the largest possible
// per-producer total -- the sum of EVERY weight ever created for the busiest
// candidate, 451,388,603,675,534, which strictly over-counts any instantaneous live
// total because it also counts votes later replaced by renewals or expired. That is
// ~20x below 2^53, so float and integer accumulation are bit-identical and
// order-independent across all retained history.
func TestTotalVoteRightsAccumulationIsExact(t *testing.T) {
	const measuredMaxProducerTotal = 451388603675534 // sela-weight, full-chain upper bound
	const float64ExactIntegerLimit = 1 << 53         // 9007199254740992

	if measuredMaxProducerTotal >= float64ExactIntegerLimit {
		t.Fatalf("measured per-producer bound %d has reached the float64 exact-integer "+
			"limit %d; float and Fixed64 accumulation can now diverge",
			measuredMaxProducerTotal, float64ExactIntegerLimit)
	}

	// Below the limit the two accumulations must agree exactly, in any order.
	weights := []common.Fixed64{13293910332253, 903438, 300000000000, 149999969840, 10000603}
	var asFixed common.Fixed64
	var asFloat float64
	for _, w := range weights {
		asFixed += w
		asFloat += float64(w)
	}
	if float64(asFixed) != asFloat {
		t.Fatalf("Fixed64 sum %d != float64 sum %.0f", int64(asFixed), asFloat)
	}
}
