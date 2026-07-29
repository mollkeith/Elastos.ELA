package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

func mkCrossOut(v common.Fixed64) *common2.Output {
	o := &common2.Output{Value: v}
	o.ProgramHash[0] = byte(contract.PrefixCrossChain)
	return o
}

// newCrossTx builds a tx that routes through the else-branch summation of
// IsSmallTransfer (payloadVersion != TransferCrossChainVersion(0x00)), which
// sums every cross-chain-prefixed output directly — the path carrying the wrap.
func newCrossTx(outs ...*common2.Output) *BaseTransaction {
	tx := &BaseTransaction{outputs: outs}
	tx.payloadVersion = payload.TransferCrossChainVersionV1 // 0x01 -> else branch
	return tx
}

// TestF001IsSmallTransferOverflow proves the F-001 fix: an overflowing sum of
// cross-chain output values must NOT be misclassified as a small transfer.
//
// Fail-on-pristine: with the plain `+=` accumulation, two ~4.7e18 outputs wrap
// totalCrossAmt negative, so `totalCrossAmt <= min` is true and IsSmallTransfer
// returns true (misclassified). The overflow-checked add returns false instead.
func TestF001IsSmallTransferOverflow(t *testing.T) {
	// 4.7e18 + 4.7e18 = 9.4e18 > math.MaxInt64 (9.223e18) -> int64 wrap.
	huge := common.Fixed64(4_700_000_000_000_000_000)
	tx := newCrossTx(mkCrossOut(huge), mkCrossOut(huge))

	if tx.IsSmallTransfer(common.Fixed64(100000000)) {
		t.Fatal("overflowing cross-chain sum must NOT be classified as a small transfer")
	}
}

// TestF001IsSmallTransferNormal guards the fix from regressing the happy path:
// a genuinely small cross-chain sum is still classified as small, and a normal
// large (non-overflowing) sum is not.
func TestF001IsSmallTransferNormal(t *testing.T) {
	min := common.Fixed64(100000000) // 1 ELA

	if !newCrossTx(mkCrossOut(50000000)).IsSmallTransfer(min) {
		t.Fatal("a 0.5 ELA cross-chain transfer must be classified as small")
	}

	if newCrossTx(mkCrossOut(200000000)).IsSmallTransfer(min) {
		t.Fatal("a 2 ELA cross-chain transfer must NOT be classified as small")
	}
}
