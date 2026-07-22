// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"errors"
	"fmt"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type DposV2ClaimRewardRealWithdrawTransaction struct {
	BaseTransaction
}

func (t *DposV2ClaimRewardRealWithdrawTransaction) CheckAttributeProgram() error {
	if len(t.Programs()) != 0 {
		return errors.New("txs should have no programs")
	}
	if len(t.Attributes()) != 0 {
		return errors.New("txs should have no attributes")
	}
	return nil
}

func (t *DposV2ClaimRewardRealWithdrawTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.DposV2ClaimRewardRealWithdraw:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *DposV2ClaimRewardRealWithdrawTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *DposV2ClaimRewardRealWithdrawTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if blockHeight < chainParams.DPoSV2StartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before DPoSV2StartHeight", t.TxType().Name()))
	}
	return nil
}

func (t *DposV2ClaimRewardRealWithdrawTransaction) SpecialContextCheck() (result elaerr.ELAError, end bool) {
	dposv2RealWithdraw, ok := t.Payload().(*payload.DposV2ClaimRewardRealWithdraw)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}
	txsCount := len(dposv2RealWithdraw.WithdrawTransactionHashes)
	// check WithdrawTransactionHashes count and output count
	if txsCount != len(t.Outputs()) && txsCount != len(t.Outputs())-1 {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid real withdraw transaction hashes count")), true
	}

	// F-015: real-withdraw txs are EXEMPT from RunPrograms, so the ONLY authorization is
	// that the inputs come from the treasury. Bind every input AND the change output to the
	// DPoSV2 reward accumulate pool (the source honest DposV2 real-withdraws draw from),
	// else an attacker funds the withdraw from a VICTIM UTXO and pockets the unbound change.
	// Gated for replay-safety.
	if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
		rewardPool := t.parameters.Config.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash
		for _, ref := range t.references {
			if !ref.ProgramHash.IsEqual(*rewardPool) {
				return elaerr.Simple(elaerr.ErrTxPayload,
					errors.New("dposv2 reward real withdraw input not from reward pool")), true
			}
		}
		if txsCount == len(t.Outputs())-1 {
			if !t.Outputs()[txsCount].ProgramHash.IsEqual(*rewardPool) {
				return elaerr.Simple(elaerr.ErrTxPayload,
					errors.New("dposv2 reward real withdraw change output not to reward pool")), true
			}
		}
	}

	// check other outputs, need to match with WithdrawTransactionHashes
	txs := t.parameters.BlockChain.GetState().GetRealWithdrawTransactions()
	txsMap := make(map[common.Uint256]struct{})
	for i, hash := range dposv2RealWithdraw.WithdrawTransactionHashes {
		txInfo, ok := txs[hash]
		if !ok {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid withdraw transaction hash")), true
		}
		output := t.Outputs()[i]
		if !output.ProgramHash.IsEqual(txInfo.Recipient) {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid real withdraw output address")), true
		}
		if output.Value != txInfo.Amount-t.parameters.Config.CRConfiguration.RealWithdrawSingleFee {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New(fmt.Sprintf("invalid real withdraw output "+
				"amount:%s, need to be:%s",
				output.Value, txInfo.Amount-t.parameters.Config.CRConfiguration.RealWithdrawSingleFee))), true
		}
		if _, ok := txsMap[hash]; ok {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("duplicated real withdraw transactions hash")), true
		}
		txsMap[hash] = struct{}{}
	}

	// check transaction fee
	var inputAmount common.Fixed64
	for _, v := range t.references {
		inputAmount += v.Value
	}
	var outputAmount common.Fixed64
	for _, o := range t.Outputs() {
		outputAmount += o.Value
	}
	if inputAmount-outputAmount != t.parameters.Config.CRConfiguration.RealWithdrawSingleFee*common.Fixed64(txsCount) {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New(fmt.Sprintf("invalid real withdraw transaction"+
			" fee:%s, need to be:%s, txsCount:%d", inputAmount-outputAmount,
			t.parameters.Config.CRConfiguration.RealWithdrawSingleFee*common.Fixed64(txsCount), txsCount))), true
	}

	return nil, false
}
