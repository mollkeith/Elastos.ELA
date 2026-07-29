// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// XM-04 parity -- the block validator and the DPoS reward state must compute the SAME
// fee total for the same block, using production code on both sides.
//
// Validator side: blockchain checkTxsContext sums blockchain.GetTxFeeStrict(tx, ELA, refs)
// over block.Transactions[1:].
// State side: dpos/state SumBlockTxFees sums tx.Fee(), where Fee() is whatever
// core/transaction DefaultChecker.CheckTransactionFee stored during validation.
//
// Pre-fix those were two different numbers whenever a transaction carried a non-ELA leg:
// the validator's ELA-filtered total versus the state's asset-blind aggregate. The
// difference went straight into the claimable arbiter pool.
package blockchain_test

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
)

const (
	xmpStrictGate  = uint32(2260451)
	xmpRevisedGate = uint32(2265000)
	xmpELA         = common.Fixed64(1_0000_0000)
)

func xmpConfig() *config.Configuration {
	cfg := *config.GetDefaultParams()
	cfg.StrictMoneyRangeHeight = xmpStrictGate
	cfg.RevisedDPoSRewardHeight = xmpRevisedGate
	return &cfg
}

func xmpNonELA() common.Uint256 {
	var a common.Uint256
	a[0] = 0x99
	a[31] = 0x11
	return a
}

type xmpLeg struct {
	asset common.Uint256
	value common.Fixed64
}

func xmpTx(seed byte, in, out []xmpLeg) (interfaces.Transaction, map[*common2.Input]common2.Output) {
	inputs := make([]*common2.Input, 0, len(in))
	refs := make(map[*common2.Input]common2.Output, len(in))
	for i, leg := range in {
		input := &common2.Input{Previous: common2.OutPoint{
			TxID: common.Uint256{seed, byte(i + 1)}, Index: uint16(i)}}
		inputs = append(inputs, input)
		refs[input] = common2.Output{
			AssetID: leg.asset, Value: leg.value, Type: common2.OTNone,
			ProgramHash: common.Uint168{0x21}, Payload: &outputpayload.DefaultOutput{}}
	}
	outputs := make([]*common2.Output, 0, len(out))
	for _, leg := range out {
		outputs = append(outputs, &common2.Output{
			AssetID: leg.asset, Value: leg.value, Type: common2.OTNone,
			ProgramHash: common.Uint168{0x21}, Payload: &outputpayload.DefaultOutput{}})
	}
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.TransferAsset, 0, &payload.TransferAsset{},
		[]*common2.Attribute{}, inputs, outputs, 0, []*program.Program{})
	return txn, refs
}

func xmpCoinbase(height uint32) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.CoinBase, payload.CoinBaseVersion, &payload.CoinBase{},
		[]*common2.Attribute{},
		[]*common2.Input{{
			Previous: common2.OutPoint{TxID: common.EmptyHash, Index: math.MaxUint16},
			Sequence: math.MaxUint32}},
		[]*common2.Output{
			{AssetID: core.ELAAssetID, Value: 22831050, Type: common2.OTNone,
				ProgramHash: common.Uint168{1}, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 26636225, Type: common2.OTNone,
				ProgramHash: common.Uint168{2}, Payload: &outputpayload.DefaultOutput{}},
			{AssetID: core.ELAAssetID, Value: 26636225, Type: common2.OTNone,
				ProgramHash: common.Uint168{3}, Payload: &outputpayload.DefaultOutput{}},
		},
		height, []*program.Program{})
}

// TestXM04ValidatorAndStateAgreeOnTheFeeBasis is the required parity proof. It builds a
// block whose transactions carry non-ELA legs -- the exact F-011 wedge -- runs the REAL
// per-transaction fee check to populate Fee(), then compares the validator's fee total
// with the state's.
// FAILS ON PRISTINE: the state total exceeds the validator total by the whole non-ELA
// leg, and the arbiter reward by 0.35x that.
func TestXM04ValidatorAndStateAgreeOnTheFeeBasis(t *testing.T) {
	fake := xmpNonELA()
	cfg := xmpConfig()

	wedges := []common.Fixed64{1, 100, 100000, xmpELA, 5000 * xmpELA}
	heights := []uint32{xmpRevisedGate, xmpRevisedGate + 1, 3000000}

	for _, h := range heights {
		for _, wedge := range wedges {
			// tx1: an ordinary ELA payment paying a 10000 sela fee.
			tx1, refs1 := xmpTx(0x01,
				[]xmpLeg{{core.ELAAssetID, 100 * xmpELA}},
				[]xmpLeg{{core.ELAAssetID, 100*xmpELA - 10000}})
			// tx2: the wedge -- an ELA fee of 5000 plus a whole non-ELA leg kept as "fee".
			tx2, refs2 := xmpTx(0x02,
				[]xmpLeg{{core.ELAAssetID, 50 * xmpELA}, {fake, wedge}},
				[]xmpLeg{{core.ELAAssetID, 50*xmpELA - 5000}})

			block := &types.Block{
				Header:       common2.Header{Height: h},
				Transactions: []interfaces.Transaction{xmpCoinbase(h), tx1, tx2},
			}
			refs := []map[*common2.Input]common2.Output{nil, refs1, refs2}

			// --- validator side: exactly what checkTxsContext computes.
			var validatorTotal common.Fixed64
			for i := 1; i < len(block.Transactions); i++ {
				fee, err := blockchain.GetTxFeeStrict(block.Transactions[i],
					core.ELAAssetID, refs[i])
				assert.NoError(t, err)
				validatorTotal += fee
			}

			// --- state side: run the REAL fee check, then read what the state reads.
			for i := 1; i < len(block.Transactions); i++ {
				txn := block.Transactions[i]
				txn.SetParameters(&transaction.TransactionParameters{
					Transaction: txn, BlockHeight: h, Config: cfg})
				assert.NoError(t, txn.CheckTransactionFee(refs[i]))
			}
			stateTotal := state.SumBlockTxFees(block.Transactions, h,
				cfg.RevisedDPoSRewardHeight)

			assert.Equal(t, validatorTotal, stateTotal,
				"height %d, non-ELA leg %d: the validator and the DPoS state must compute "+
					"the SAME fee total (validator=%d state=%d)",
				h, wedge, int64(validatorTotal), int64(stateTotal))
			assert.Equal(t, common.Fixed64(15000), validatorTotal,
				"sanity: only the two ELA fees may count")

			// The reward legs derived from those totals must therefore agree too.
			reward := func(total common.Fixed64) common.Fixed64 {
				return common.Fixed64(math.Ceil(float64(total+cfg.GetBlockReward(h)) * 0.35))
			}
			assert.Equal(t, reward(validatorTotal), reward(stateTotal),
				"height %d: the arbiter reward leg must be identical on both sides", h)
		}
	}
}

// TestXM04ParityHoldsForOrdinaryBlocks -- no wedge at all: the parity must hold for
// honest traffic too, which is what makes activation a provable no-op on a chain whose
// fees are all ELA.
func TestXM04ParityHoldsForOrdinaryBlocks(t *testing.T) {
	cfg := xmpConfig()
	for _, h := range []uint32{xmpRevisedGate, 2400000, 3000000} {
		var validatorTotal common.Fixed64
		txs := []interfaces.Transaction{xmpCoinbase(h)}
		refs := []map[*common2.Input]common2.Output{nil}
		for i := 1; i <= 5; i++ {
			fee := common.Fixed64(1000 * i)
			tx, r := xmpTx(byte(i),
				[]xmpLeg{{core.ELAAssetID, 10 * xmpELA}},
				[]xmpLeg{{core.ELAAssetID, 10*xmpELA - fee}})
			txs = append(txs, tx)
			refs = append(refs, r)
		}
		block := &types.Block{Header: common2.Header{Height: h}, Transactions: txs}

		for i := 1; i < len(txs); i++ {
			f, err := blockchain.GetTxFeeStrict(txs[i], core.ELAAssetID, refs[i])
			assert.NoError(t, err)
			validatorTotal += f
			txs[i].SetParameters(&transaction.TransactionParameters{
				Transaction: txs[i], BlockHeight: h, Config: cfg})
			assert.NoError(t, txs[i].CheckTransactionFee(refs[i]))
		}
		assert.Equal(t, common.Fixed64(15000), validatorTotal)
		assert.Equal(t, validatorTotal,
			state.SumBlockTxFees(block.Transactions, h, cfg.RevisedDPoSRewardHeight))
	}
}
