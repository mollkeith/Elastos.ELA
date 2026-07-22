// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Crosschain same-block cluster (F-016 sidechain-return double-refund, F-017/F-051
// sidechain-withdraw double-credit) — empirical in-block conflict proofs. The
// committed-state dedup (IsSidechainReturnDepositTxHashDuplicate /
// IsSidechainTxHashDuplicate) is not mirrored at block level, and the V1/V2 withdraw
// hash lives in output payloads that CheckDuplicateTx never inspects, so two same-block
// txs crediting/refunding ONE sidechain hash both pass. These mirror the mempool
// slotSidechainTxHashes / slotSidechainReturnDepositTxHashes. Reuses the f028 helpers.
// Value DRAINs stay NEEDS-SIM (a 2nd arbiter-signed set is required) per the HARD RULE.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	program "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
)

func xcTx(txType common2.TxType, pv byte, pld interfaces.Payload, outs []*common2.Output) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09, txType, pv, pld,
		[]*common2.Attribute{}, []*common2.Input{}, outs, 0, []*program.Program{})
}

func withdrawOut(h common.Uint256) *common2.Output {
	return &common2.Output{Type: common2.OTWithdrawFromSideChain,
		Payload: &outputpayload.Withdraw{SideChainTransactionHash: h}}
}

func returnDepositOut(h common.Uint256) *common2.Output {
	return &common2.Output{Type: common2.OTReturnSideChainDepositCoin,
		Payload: &outputpayload.ReturnSideChainDeposit{DepositTransactionHash: h}}
}

// TestF016ReturnSideChainDepositConflict — two returns for the SAME deposit hash.
func TestF016ReturnSideChainDepositConflict(t *testing.T) {
	h := common.Uint256{1, 6}
	other := common.Uint256{1, 7}
	r1 := xcTx(common2.ReturnSideChainDepositCoin, 0, &payload.ReturnSideChainDepositCoin{}, []*common2.Output{returnDepositOut(h)})
	r2 := xcTx(common2.ReturnSideChainDepositCoin, 0, &payload.ReturnSideChainDepositCoin{}, []*common2.Output{returnDepositOut(h)})
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, r1, r2), f028Gate),
		"two same-deposit-hash returns in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, r1, r2), f028Gate),
		"below the gate the block must validate byte-identically")
	rOther := xcTx(common2.ReturnSideChainDepositCoin, 0, &payload.ReturnSideChainDepositCoin{}, []*common2.Output{returnDepositOut(other)})
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, r1, rOther), f028Gate),
		"returns for DIFFERENT deposits are legitimate and must pass")
}

// TestF017WithdrawV1Conflict — two V1 withdraws (hash in output payload) for one burn.
func TestF017WithdrawV1Conflict(t *testing.T) {
	h := common.Uint256{1, 7, 1}
	other := common.Uint256{1, 7, 2}
	w1 := xcTx(common2.WithdrawFromSideChain, payload.WithdrawFromSideChainVersionV1, &payload.WithdrawFromSideChain{}, []*common2.Output{withdrawOut(h)})
	w2 := xcTx(common2.WithdrawFromSideChain, payload.WithdrawFromSideChainVersionV1, &payload.WithdrawFromSideChain{}, []*common2.Output{withdrawOut(h)})
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, w2), f028Gate),
		"two same-hash V1 withdraws in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, w1, w2), f028Gate),
		"below the gate the block must validate byte-identically")
	wOther := xcTx(common2.WithdrawFromSideChain, payload.WithdrawFromSideChainVersionV1, &payload.WithdrawFromSideChain{}, []*common2.Output{withdrawOut(other)})
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, wOther), f028Gate),
		"withdraws for DIFFERENT sidechain hashes are legitimate and must pass")
}

// TestF017WithdrawV0Conflict — two V0 withdraws (hash in payload) exercise the V0 path.
func TestF017WithdrawV0Conflict(t *testing.T) {
	h := common.Uint256{1, 7, 0}
	w1 := xcTx(common2.WithdrawFromSideChain, payload.WithdrawFromSideChainVersion,
		&payload.WithdrawFromSideChain{SideChainTransactionHashes: []common.Uint256{h}}, nil)
	w2 := xcTx(common2.WithdrawFromSideChain, payload.WithdrawFromSideChainVersion,
		&payload.WithdrawFromSideChain{SideChainTransactionHashes: []common.Uint256{h}}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, w2), f028Gate),
		"two same-hash V0 withdraws in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, w1, w2), f028Gate),
		"below the gate the block must validate byte-identically")
}
