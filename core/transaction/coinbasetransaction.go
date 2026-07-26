// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"errors"
	"math"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type CoinBaseTransaction struct {
	BaseTransaction
}

func (t *CoinBaseTransaction) CheckTransactionInput() error {
	if len(t.Inputs()) != 1 {
		return errors.New("coinbase must has only one input")
	}
	inputHash := t.Inputs()[0].Previous.TxID
	inputIndex := t.Inputs()[0].Previous.Index
	sequence := t.Inputs()[0].Sequence
	if !inputHash.IsEqual(common.EmptyHash) ||
		inputIndex != math.MaxUint16 || sequence != math.MaxUint32 {
		return errors.New("invalid coinbase input")
	}

	return nil
}

func (t *CoinBaseTransaction) CheckTransactionOutput() error {

	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config

	if len(t.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}
	if len(t.Outputs()) < 2 {
		return errors.New("coinbase output is not enough, at least 2")
	}

	foundationReward := t.Outputs()[0].Value
	var totalReward = common.Fixed64(0)
	if blockHeight < chainParams.PublicDPOSHeight {
		for _, output := range t.Outputs() {
			if output.AssetID != core.ELAAssetID {
				return errors.New("asset ID in coinbase is invalid")
			}
			totalReward += output.Value
		}

		if foundationReward < common.Fixed64(float64(totalReward)*0.3) {
			return errors.New("reward to foundation in coinbase < 30%")
		}
	} else {
		// XM-01: restore the per-output AssetID guard that the post-PublicDPOSHeight
		// branch dropped. See checkCoinbaseOutputAssets.
		if err := checkCoinbaseOutputAssets(t.Outputs(), blockHeight,
			chainParams.StrictMoneyRangeHeight); err != nil {
			return err
		}
		// check the ratio of FoundationAddress reward with miner reward
		totalReward = t.Outputs()[0].Value + t.Outputs()[1].Value
		if len(t.Outputs()) == 2 && foundationReward <
			common.Fixed64(float64(totalReward)*0.3/0.65) {
			return errors.New("reward to foundation in coinbase < 30%")
		}
	}

	return nil
}

// checkCoinbaseOutputAssets closes XM-01: the coinbase is the ONE transaction that can
// create outputs with no inputs backing them, and above PublicDPOSHeight it was the one
// transaction with NO AssetID constraint at all. The pre-PublicDPOSHeight branch of
// CheckTransactionOutput loops every output demanding core.ELAAssetID; the branch taken by
// every block since height 402,680 simply has no such loop, and nothing downstream restores
// it -- blockchain.CheckTransactionOutput carries the identical asymmetry, and
// checkCoinbaseTransactionContext pins the reward VALUES and (most of) the addresses but
// never the asset. A block producer could therefore stamp any 32-byte AssetID onto a
// coinbase reward output. That output is then indexed as an ordinary spendable UTXO
// (blockchain/indexers/unspentindex.go ConnectBlock appends every output index of every
// transaction; its IsCoinBaseTx() branch only skips INPUT retirement, and only RegisterAsset
// transactions are excluded), and UTXOCache.GetTxReference resolves it by txid+index with no
// asset validation -- so the fabricated asset is real, spendable chain state. Combined with
// the per-asset fee accounting (GetTxFeeMapStrict) it is the entry point for turning a
// fabricated asset into ELA, which is why "RegisterAsset is banned, so non-ELA is
// unreachable" is not a sound argument.
//
// This method is NOT dead, unlike the coinbase's SpecialContextCheck/ContextCheck (see the
// note above SpecialContextCheck): CheckBlockSanity (blockchain/blockvalidator.go) iterates
// block.Transactions from index 0 and calls BlockChain.CheckTransactionSanity ->
// txn.SanityCheck -> DefaultChecker.SanityCheck -> Transaction.CheckTransactionOutput, which
// dispatches here for the coinbase. It also carries the block height, so the guard can be
// gated where it stands rather than relocated.
//
// Gate: StrictMoneyRangeHeight -- gate 1, the coordinated recovery gate that already carries
// the other coinbase guards (F-013 frozen outputs, F-031/FV-19 locktime pin, F-089 BIP30).
// No new gate and no new config literal. Below it the expression is left exactly as it was,
// so retained history replays byte-identically; a full scan of all 2,260,597 retained blocks
// found ZERO outputs carrying a non-ELA AssetID, so the guard rejects no retained block
// either way.
func checkCoinbaseOutputAssets(outputs []*common2.Output, blockHeight, gate uint32) error {
	if blockHeight < gate {
		return nil
	}
	for _, output := range outputs {
		if output.AssetID != core.ELAAssetID {
			return errors.New("asset ID in coinbase is invalid")
		}
	}
	return nil
}

func (t *CoinBaseTransaction) CheckAttributeProgram() error {
	// no need to check attribute and program
	if len(t.Programs()) != 0 {
		return errors.New("transaction should have no programs")
	}
	return nil
}

func (t *CoinBaseTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.CoinBase:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *CoinBaseTransaction) IsAllowedInPOWConsensus() bool {

	return true
}

// SpecialContextCheck is DEAD ON THE BLOCK-CONNECT PATH and no consensus guard may be
// added to it. Its only caller is this type's ContextCheck override, whose only non-test
// caller is BlockChain.CheckTransactionContext, and all four call sites of that function
// structurally exclude the coinbase (blockchain/blockvalidator.go checkTxsContext and
// pow/service.go both iterate transactions from index 1; mempool/txpool.go rejects a
// coinbase outright). The same is true of the duplicate-txid check in ContextCheck below.
//
// FV-19: the F-031 coinbase LockTime pin used to live HERE and was therefore never
// evaluated by any validator, while the tracker recorded it as armed. It now lives on the
// path that actually runs, as blockchain.checkCoinbaseLockTimePin, called from
// checkCoinbaseTransactionContext at the same gate (StrictMoneyRangeHeight) -- exactly
// where F-089's BIP30 guard and F-013's frozen-output guard had already been relocated for
// this same reason. It is deliberately NOT duplicated here: one consensus rule, one site.
// The address rules below are likewise enforced, differently, by
// checkCoinbaseTransactionContext; they are left untouched so that nothing about the
// coinbase's acceptance changes with this relocation.
func (a *CoinBaseTransaction) SpecialContextCheck() (result elaerr.ELAError, end bool) {
	para := a.parameters
	if para.BlockHeight >= para.Config.CRConfiguration.CRCommitteeStartHeight {
		if para.BlockChain.GetState().GetConsensusAlgorithm() == 0x01 {
			if !a.outputs[0].ProgramHash.IsEqual(*para.Config.DestroyELAProgramHash) {
				return elaerr.Simple(elaerr.ErrTxInvalidOutput,
					errors.New("first output address should be "+
						"DestroyAddress in POW consensus algorithm")), true
			}
		} else {
			if !a.outputs[0].ProgramHash.IsEqual(*para.Config.CRConfiguration.CRAssetsProgramHash) {
				return elaerr.Simple(elaerr.ErrTxInvalidOutput,
					errors.New("first output address should be CR assets address")), true
			}
		}
	} else if !a.outputs[0].ProgramHash.IsEqual(*para.Config.FoundationProgramHash) {
		return elaerr.Simple(elaerr.ErrTxInvalidOutput,
			errors.New("first output address should be foundation address")), true
	}

	return nil, true
}

func (a *CoinBaseTransaction) ContextCheck(paras interfaces.Parameters) (map[*common2.Input]common2.Output, elaerr.ELAError) {

	if err := a.SetParameters(paras); err != nil {
		log.Warn("[CheckTransactionContext] set parameters failed.")
		return nil, elaerr.Simple(elaerr.ErrTxDuplicate, errors.New("invalid parameters"))
	}

	if err := a.HeightVersionCheck(); err != nil {
		log.Warn("[CheckTransactionContext] height version check failed.")
		return nil, elaerr.Simple(elaerr.ErrTxHeightVersion, nil)
	}

	// check if duplicated with transaction in ledger
	if exist := a.IsTxHashDuplicate(*a.txHash); exist {
		log.Warn("[CheckTransactionContext] duplicate transaction check failed.")
		return nil, elaerr.Simple(elaerr.ErrTxDuplicate, nil)
	}

	err, end := a.SpecialContextCheck()
	if end {
		log.Warn("[CheckTransactionContext] SpecialContextCheck failed:", err)
		return nil, err
	}

	return nil, nil
}
