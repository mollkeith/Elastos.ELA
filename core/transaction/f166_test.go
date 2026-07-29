package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// F-166: a CR-member ActivateProducer (end=true skips CheckTransactionFee) with
// value outputs and 0 inputs mints net-new ELA above the gate. The fix
// (checkActivateValueCreation) re-applies the fee==0 invariant above the gate.
// Also asserts the CheckTransactionOutput gap that enabled it. Run -count=20.
func TestF166ActivateNoValueCreation(t *testing.T) {
	const nft = uint32(1405000)
	const gate = uint32(2260451)
	ela := core.ELAAssetID

	cfg := func() *config.Configuration {
		c := &config.Configuration{StrictMoneyRangeHeight: gate}
		c.DPoSConfiguration.NFTStartHeight = nft
		return c
	}
	mkOut := func(v int64) *common2.Output {
		return &common2.Output{AssetID: ela, Value: common.Fixed64(v), Type: common2.OTNone,
			ProgramHash: common.Uint168{}, Payload: &outputpayload.DefaultOutput{}}
	}
	build := func(h uint32, outs []*common2.Output, refs map[*common2.Input]common2.Output) *ActivateProducerTransaction {
		txn := functions.CreateTransaction(
			common2.TxVersion09, common2.ActivateProducer, 0,
			&payload.ActivateProducer{}, []*common2.Attribute{},
			[]*common2.Input{}, outs, 0, []*program.Program{})
		txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: cfg()})
		ap := txn.(*ActivateProducerTransaction)
		ap.references = refs
		return ap
	}
	emptyRefs := map[*common2.Input]common2.Output{}

	// ---- PoC: the CheckTransactionOutput gap (value outputs allowed above NFTStartHeight) ----
	t.Run("poc-output-gap-above-nft", func(t *testing.T) {
		ap := build(nft+1, []*common2.Output{mkOut(100_000_000_000)}, emptyRefs)
		if err := ap.CheckTransactionOutput(); err != nil {
			t.Fatalf("PoC setup drift: value output should pass CheckTransactionOutput above NFTStartHeight, got %v", err)
		}
	})
	t.Run("poc-output-blocked-below-nft", func(t *testing.T) {
		ap := build(nft-1, []*common2.Output{mkOut(100_000_000_000)}, emptyRefs)
		if err := ap.CheckTransactionOutput(); err == nil {
			t.Fatal("PoC setup drift: value output should be blocked at/below NFTStartHeight")
		}
	})

	// ---- the fix: value creation rejected above the gate, legacy below, legit unaffected ----
	t.Run("mint-above-gate-REJECTED", func(t *testing.T) {
		ap := build(gate, []*common2.Output{mkOut(10_000_000_000_000_000)}, emptyRefs) // 1e16 sela, 0 inputs
		if e := ap.checkActivateValueCreation(); e == nil {
			t.Fatal("BREACH: value-output ActivateProducer (0 inputs) accepted above gate -> MINT")
		}
	})
	t.Run("mint-far-above-gate-REJECTED", func(t *testing.T) {
		ap := build(gate+5_000_000, []*common2.Output{mkOut(1_000_000_000_000)}, emptyRefs)
		if e := ap.checkActivateValueCreation(); e == nil {
			t.Fatal("BREACH: mint accepted far above gate")
		}
	})
	t.Run("mint-below-gate-ALLOWED-legacy", func(t *testing.T) {
		ap := build(gate-1, []*common2.Output{mkOut(10_000_000_000_000_000)}, emptyRefs)
		if e := ap.checkActivateValueCreation(); e != nil {
			t.Fatalf("REPLAY BREAK: below gate must stay legacy (allowed): %v", e)
		}
	})
	t.Run("nocost-above-gate-ALLOWED", func(t *testing.T) {
		ap := build(gate, []*common2.Output{}, emptyRefs) // 0 outputs, 0 inputs -> fee 0
		if e := ap.checkActivateValueCreation(); e != nil {
			t.Fatalf("FALSE POSITIVE: no-cost ActivateProducer rejected above gate: %v", e)
		}
	})
	t.Run("balanced-above-gate-ALLOWED", func(t *testing.T) {
		in := &common2.Input{Previous: common2.OutPoint{TxID: common.EmptyHash, Index: 0}}
		refs := map[*common2.Input]common2.Output{in: {AssetID: ela, Value: common.Fixed64(10_000_000_000_000_000)}}
		ap := build(gate, []*common2.Output{mkOut(10_000_000_000_000_000)}, refs) // in==out -> fee 0
		if e := ap.checkActivateValueCreation(); e != nil {
			t.Fatalf("FALSE POSITIVE: balanced (fee==0) ActivateProducer rejected above gate: %v", e)
		}
	})
}
