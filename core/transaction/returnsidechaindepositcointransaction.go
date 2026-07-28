// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"errors"
	"fmt"
	"math"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type ReturnSideChainDepositCoinTransaction struct {
	BaseTransaction
}

func (t *ReturnSideChainDepositCoinTransaction) CheckTransactionOutput() error {
	blockHeight := t.parameters.BlockHeight
	if len(t.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}

	if len(t.Outputs()) < 1 {
		return errors.New("transaction has no outputs")
	}

	// check if output address is valid
	specialOutputCount := 0
	for _, output := range t.Outputs() {
		if output.AssetID != core.ELAAssetID {
			return errors.New("asset ID in output is invalid")
		}

		// output value must >= 0
		if output.Value < common.Fixed64(0) {
			return errors.New("invalid transaction UTXO output")
		}

		if err := checkOutputProgramHash(blockHeight, output.ProgramHash); err != nil {
			return err
		}

		if t.Version() >= common2.TxVersion09 {
			if output.Type != common2.OTNone {
				specialOutputCount++
			}
			if err := checkReturnSideChainDepositOutputPayload(output); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkReturnSideChainDepositOutputPayload(output *common2.Output) error {
	switch output.Type {
	case common2.OTNone:
	case common2.OTReturnSideChainDepositCoin:
	default:
		return errors.New("transaction type dose not match the output payload type")
	}

	return output.Payload.Validate()
}

func (t *ReturnSideChainDepositCoinTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.ReturnSideChainDepositCoin:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *ReturnSideChainDepositCoinTransaction) IsAllowedInPOWConsensus() bool {
	return false
}

func (t *ReturnSideChainDepositCoinTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if blockHeight < chainParams.ReturnCrossChainCoinStartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before ReturnCrossChainCoinStartHeight", t.TxType().Name()))
	}
	return nil
}

func (t *ReturnSideChainDepositCoinTransaction) SpecialContextCheck() (result elaerr.ELAError, end bool) {
	_, ok := t.Payload().(*payload.ReturnSideChainDepositCoin)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}

	if t.parameters.BlockHeight >= t.parameters.Config.CrossChainUTXORestrictionHeight &&
		hasCrossChainUTXO(t.references) {
		if err := checkCrossChainArbiterPrograms(t, t.parameters.BlockHeight,
			t.parameters.Config); err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}
	}

	// check outputs
	fee := t.parameters.Config.ReturnDepositCoinFee
	for _, o := range t.Outputs() {
		if o.Type != common2.OTReturnSideChainDepositCoin {
			continue
		}
		py, ok := o.Payload.(*outputpayload.ReturnSideChainDeposit)
		if !ok {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid ReturnSideChainDeposit output payload")), true
		}

		if exist := blockchain.DefaultLedger.Store.IsSidechainReturnDepositTxHashDuplicate(py.DepositTransactionHash); exist {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("duplicated ReturnSideChainDeposit transaction hash")), true
		}

		tx, _, err := t.parameters.BlockChain.GetDB().GetTransaction(py.DepositTransactionHash)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid deposit tx:"+py.DepositTransactionHash.String())), true
		}
		// Fail closed instead of panicking. py.DepositTransactionHash is an
		// attacker-controlled output-payload field: ReturnSideChainDeposit.Validate
		// checks only the payload version and a non-empty GenesisBlockAddress, so the
		// hash may name any transaction in the (unconditionally enabled) tx index,
		// including ELA's zero-input transaction family. The genesis RegisterAsset
		// transaction is built with []*common.Input{} (core/manager.go:43-61) and its
		// hash is the compiled-in constant core.ELAAssetID, so
		// GetTransaction(core.ELAAssetID) resolves to a zero-input transaction on every
		// node with no chain lookup at all. Indexing Inputs()[0] then panics at step 10
		// of ContextCheck, before CheckTransactionFee, checkTransactionSignature and
		// checkInvalidUTXO, and on the P2P leg (OnTx -> handleTxMsg -> AppendToTxPool)
		// that panic runs on the bare netsync blockHandler goroutine, which has no
		// recover(), so it terminates the process. (The JSON-RPC leg survives only
		// because net/http recovers.)
		//
		// Ungated, deliberately: a panic is not an acceptance decision, so converting it
		// to a rejection is byte-identical for every block the chain has ever accepted.
		// Any retained transaction that reached these two lines necessarily had an input
		// and an in-range index, or replaying it would kill the node. Gating behind
		// StrictMoneyRangeHeight would instead leave the kill live on testnet/regnet
		// (gate = MaxUint32 there) and on any node syncing below the gate, while the
		// delivery works at any height >= ReturnCrossChainCoinStartHeight (1032840).
		// A legitimate ReturnSideChainDepositCoin names a real TransferCrossChainAsset
		// deposit, which by construction has inputs and an in-range index.
		if len(tx.Inputs()) == 0 {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("deposit tx has no inputs")), true
		}
		prev := tx.Inputs()[0].Previous
		refTx, _, err := t.parameters.BlockChain.GetDB().GetTransaction(prev.TxID)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}
		if int(prev.Index) >= len(refTx.Outputs()) {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("deposit tx input index out of range")), true
		}

		// need to return the deposit coin to first input address
		refOutput := refTx.Outputs()[prev.Index]
		if o.ProgramHash != refOutput.ProgramHash {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid output address")), true
		}

		// side chain deposit address
		crossChainHash, err := common.Uint168FromAddress(py.GenesisBlockAddress)
		if err != nil {
			return elaerr.Simple(elaerr.ErrTxPayload, err), true
		}
		var crossChainAmount common.Fixed64
		switch tx.PayloadVersion() {
		case payload.TransferCrossChainVersion:
			p, ok := tx.Payload().(*payload.TransferCrossChainAsset)
			if !ok {
				log.Error("Invalid payload type need TransferCrossChainAsset")
				continue
			}

			for _, idx := range p.OutputIndexes {
				// output to current side chain
				if !crossChainHash.IsEqual(tx.Outputs()[idx].ProgramHash) {
					continue
				}
				crossChainAmount += tx.Outputs()[idx].Value
			}
		case payload.TransferCrossChainVersionV1:
			_, ok := tx.Payload().(*payload.TransferCrossChainAsset)
			if !ok {
				log.Error("Invalid payload type need TransferCrossChainAsset")
				continue
			}
			for _, o := range tx.Outputs() {
				if o.Type != common2.OTCrossChain {
					continue
				}
				// output to current side chain
				if !crossChainHash.IsEqual(o.ProgramHash) {
					continue
				}
				_, ok := o.Payload.(*outputpayload.CrossChainOutput)
				if !ok {
					continue
				}
				crossChainAmount += o.Value
			}
		}

		if o.Value+fee != crossChainAmount {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid output amount")), true
		}
	}

	return nil, false
}
