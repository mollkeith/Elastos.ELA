// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// G2 WIRING TEST — F-089 (BIP30 coinbase re-mint). INFLATION CLASS.
//
// The blocker: both existing F-089 tests are helper/oracle tests.
// blockchain/f089_test.go calls checkCoinbaseBIP30 directly with an injected oracle;
// test/unit/f089_realstore_test.go proves the ORACLE (db.IsTxHashDuplicate) works on a
// real store. Neither proves the guard is CALLED. Mutation at HEAD deleted the single
// call site in checkTxsContext and the whole suite stayed green — and both F-089 tests
// still passed with the commit fully reverted.
//
// This test drives the REAL (*BlockChain).checkTxsContext — the production function that
// owns the call site — against a store whose IsTxHashDuplicate is under test control and
// which RECORDS every hash it is asked about. The coinbase reward is made exactly correct
// so that checkTxsContext returns nil for a clean block; the ONLY way a rejection can
// appear is the BIP30 call site.
package blockchain

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// -----------------------------------------------------------------------------
// A store whose only real behaviour is IsTxHashDuplicate, and which records what it
// was asked. Everything else is an unused stub: if production ever starts calling one
// of them on this path the test fails loudly rather than silently doing something.
// -----------------------------------------------------------------------------

// bip30Arbiters keeps checkCoinbaseTransactionContext on its simple (non-DPoSV2) branch:
// GetDPoSV2ActiveHeight()==MaxUint32 is the "not yet activated" sentinel the production
// code tests for. Any method this test does not stub panics rather than silently
// returning a zero value.
type bip30Arbiters struct{ state.Arbitrators }

func (bip30Arbiters) GetDPoSV2ActiveHeight() uint32       { return math.MaxUint32 }
func (bip30Arbiters) GetFinalRoundChange() common.Fixed64 { return 0 }
func (bip30Arbiters) GetArbitersRoundReward() map[common.Uint168]common.Fixed64 {
	return nil
}

type bip30Store struct {
	IChainStore // nil embedded interface: any un-stubbed call panics visibly
	dup         map[common.Uint256]bool
	asked       []common.Uint256
}

func (s *bip30Store) IsTxHashDuplicate(h common.Uint256) bool {
	s.asked = append(s.asked, h)
	return s.dup[h]
}

// -----------------------------------------------------------------------------

// bip30Chain builds a BlockChain wired to the recording store, with an arbiters mock
// that keeps checkCoinbaseTransactionContext on its simple (non-DPoSV2) branch.
func bip30Chain(t *testing.T, store *bip30Store) *BlockChain {
	t.Helper()
	if functions.CreateTransaction == nil {
		t.Fatal("transaction constructor registry not populated — see wiring_support_test.go")
	}
	// The production error path in checkTxsContext logs; without a logger that is a nil
	// deref that would mask the assertion being made here.
	log.NewDefault(test.NodeLogPath, 0, 0, 0)
	params := config.GetDefaultParams()
	params.StrictMoneyRangeHeight = wiringGate

	prev := DefaultLedger
	DefaultLedger = &Ledger{Arbitrators: bip30Arbiters{}}
	t.Cleanup(func() { DefaultLedger = prev })

	return &BlockChain{chainParams: params, db: store, TimeSource: NewMedianTime()}
}

// bip30Block returns a single-coinbase block at `height` whose coinbase reward split is
// exactly what checkCoinbaseTransactionContext expects, so a clean block yields nil.
// `content` varies the coinbase txid without touching any validated field.
func bip30Block(t *testing.T, b *BlockChain, height uint32, content []byte) *types.Block {
	t.Helper()
	total, err := b.coinbaseTotalReward(height, 0)
	if err != nil {
		t.Fatalf("coinbaseTotalReward: %v", err)
	}
	// Mirror checkCoinbaseTransactionContext exactly so a clean block is ACCEPTED and the
	// BIP30 call site is the only thing that can produce a rejection.
	expected := total - common.Fixed64(math.Ceil(float64(total)*0.35))

	cb := functions.CreateTransaction(
		common2.TxVersion09,
		common2.CoinBase,
		payload.CoinBaseVersion,
		&payload.CoinBase{Content: content},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 65535},
			Sequence: 4294967295,
		}},
		[]*common2.Output{
			{AssetID: core.ELAAssetID, Value: expected, ProgramHash: common.Uint168{},
				Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 0, ProgramHash: common.Uint168{},
				Type: common2.OTNone, Payload: &outputpayload.DefaultOutput{}},
		},
		height,
		[]*program.Program{},
	)
	return &types.Block{
		Header:       common2.Header{Height: height, Timestamp: uint32(time.Now().Unix())},
		Transactions: []interfaces.Transaction{cb},
	}
}

func bip30Err(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// -----------------------------------------------------------------------------

// TestWiringBIP30BaselineAcceptsCleanCoinbase is the positive control: with the store
// reporting "not a duplicate", checkTxsContext accepts the block outright. Every
// rejection below is therefore attributable to the BIP30 call site alone.
func TestWiringBIP30BaselineAcceptsCleanCoinbase(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)
	for _, h := range []uint32{wiringBelowGate, wiringGate, wiringGate + 1} {
		blk := bip30Block(t, b, h, []byte{1, 2, 3})
		if err := b.checkTxsContext(blk, nil); err != nil {
			t.Fatalf("baseline block at height %d must pass checkTxsContext, got: %v", h, err)
		}
	}
}

// TestWiringBIP30ReachedFromCheckTxsContext is the F-089 wiring proof.
//
// MUTATION PROOF: delete the checkCoinbaseBIP30 call from checkTxsContext
// (blockvalidator.go) -> the at/above-gate cases return nil -> this test FAILS. The
// existing blockchain/f089_test.go and test/unit/f089_realstore_test.go both still pass
// under that mutation, which is exactly the gap this closes.
func TestWiringBIP30ReachedFromCheckTxsContext(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)

	// Build the block first, then declare ITS coinbase txid already present in the ledger.
	for _, h := range []uint32{wiringGate, wiringGate + 1} {
		blk := bip30Block(t, b, h, []byte{9, byte(h & 0xff)})
		store.dup[blk.Transactions[0].Hash()] = true

		err := b.checkTxsContext(blk, nil)
		if err == nil {
			t.Fatalf("INFLATION-CLASS WIRING SEVERED at height %d: checkTxsContext accepted a "+
				"block whose coinbase txid already exists in the ledger — the F-089 BIP30 "+
				"guard is not called on the connect path (spent coinbase outputs resurrect)", h)
		}
		if !strings.Contains(bip30Err(err), "coinbase transaction hash already exists (BIP30)") {
			t.Fatalf("WIRING SEVERED at height %d: rejected for the wrong reason: %v", h, err)
		}
	}

	// The guard must key on the COINBASE's own hash, taken from Transactions[0].
	if len(store.asked) == 0 {
		t.Fatal("WIRING SEVERED: the duplicate oracle (db.IsTxHashDuplicate) was never consulted")
	}
	last := store.asked[len(store.asked)-1]
	blk := bip30Block(t, b, wiringGate+1, []byte{9, byte((wiringGate + 1) & 0xff)})
	if !last.IsEqual(blk.Transactions[0].Hash()) {
		t.Fatalf("WIRING SEVERED: the oracle was asked about %s, not the block's coinbase txid %s",
			last, blk.Transactions[0].Hash())
	}
}

// TestWiringBIP30BelowGateStaysLegacy pins the height argument the call site passes.
// A duplicate coinbase below StrictMoneyRangeHeight must still be ACCEPTED — that is the
// byte-identical-replay property for retained history [0, 2260450]. A call site that
// passed a literal 0 gate (always strict) would break the replay of retained history and
// is caught here; one that passed MaxUint32 is caught by the test above.
func TestWiringBIP30BelowGateStaysLegacy(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)

	// Both heights are above PublicDPOSHeight so the reward layout built by bip30Block is
	// the accepted one; the only variable under test is the duplicate coinbase.
	for _, h := range []uint32{wiringBelowGate - 1_000_000, wiringBelowGate} {
		blk := bip30Block(t, b, h, []byte{7, byte(h & 0xff)})
		store.dup[blk.Transactions[0].Hash()] = true
		if err := b.checkTxsContext(blk, nil); err != nil {
			t.Fatalf("REPLAY BREAK at height %d: a duplicate coinbase below the gate must be "+
				"accepted (legacy behaviour), got: %v", h, err)
		}
	}
}

// TestWiringBIP30GateArgumentIsTheCampaignGate moves the chain's own
// StrictMoneyRangeHeight and asserts the decision boundary moves with it — i.e. the call
// site passes b.chainParams.StrictMoneyRangeHeight and the block's OWN height, not a
// constant or the current tip.
func TestWiringBIP30GateArgumentIsTheCampaignGate(t *testing.T) {
	store := &bip30Store{dup: map[common.Uint256]bool{}}
	b := bip30Chain(t, store)
	moved := uint32(900_000)
	b.chainParams.StrictMoneyRangeHeight = moved

	below := bip30Block(t, b, moved-1, []byte{5, 1})
	store.dup[below.Transactions[0].Hash()] = true
	if err := b.checkTxsContext(below, nil); err != nil {
		t.Fatalf("below the moved gate a duplicate coinbase must be accepted, got: %v", err)
	}

	at := bip30Block(t, b, moved, []byte{5, 2})
	store.dup[at.Transactions[0].Hash()] = true
	if err := b.checkTxsContext(at, nil); err == nil {
		t.Fatal("at the moved gate a duplicate coinbase must be rejected: the call site does " +
			"not pass b.chainParams.StrictMoneyRangeHeight")
	}
}
