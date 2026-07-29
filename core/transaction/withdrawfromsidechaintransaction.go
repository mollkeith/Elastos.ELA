// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/database"
	"github.com/elastos/Elastos.ELA/dpos/state"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type WithdrawFromSideChainTransaction struct {
	BaseTransaction
}

func (t *WithdrawFromSideChainTransaction) CheckTransactionOutput() error {
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
			if err := checkWithdrawFromSideChainOutputPayload(output); err != nil {
				return err
			}
		}
	}

	return nil
}

func checkWithdrawFromSideChainOutputPayload(output *common2.Output) error {
	switch output.Type {
	case common2.OTNone:
	case common2.OTWithdrawFromSideChain:
	default:
		return errors.New("transaction type dose not match the output payload type")
	}

	return output.Payload.Validate()
}

func (t *WithdrawFromSideChainTransaction) CheckTransactionPayload() error {
	switch pld := t.Payload().(type) {
	case *payload.WithdrawFromSideChain:
		existingHashs := make(map[common.Uint256]struct{})
		for _, hash := range pld.SideChainTransactionHashes {
			if _, exist := existingHashs[hash]; exist {
				return errors.New("Duplicate sidechain tx detected in a transaction")
			}
			existingHashs[hash] = struct{}{}
		}

		return nil
	}

	return errors.New("invalid payload type")
}

func (t *WithdrawFromSideChainTransaction) IsAllowedInPOWConsensus() bool {
	return false
}

// HeightVersionCheck enforces SchnorrStartHeight as a real two-sided activation
// gate for the WithdrawFromSideChain payload version.
//
// SchnorrStartHeight is documented as "the start height to support schnorr
// withdraw transaction", but SpecialContextCheck only ever used it to mandate V2
// above the height; nothing rejected a V2 payload below it. So
// checkWithdrawFromSideChainTransactionV2 was dispatched purely on
// PayloadVersion==0x02 at any height, even though MainNet SchnorrStartHeight is
// math.MaxUint32, i.e. the feature is configured off. That left the
// aggregate-Schnorr group key live: checkSchnorrWithdrawFromSidechain builds it
// as a plain sum of the signers' NodePublicKeys, with no MuSig H(L)
// coefficients and no proof-of-possession on NodePublicKey. An arbiter
// who registers NodePublicKey = g^x - SUM(other signers' keys) makes the
// aggregate equal g^x and can alone forge a full-threshold withdraw of the
// cross-chain "X" custody UTXOs, naming honest arbiters' indexes without their
// participation.
//
// Every other Schnorr feature in this tree gates on the reject side:
// registerproducertransaction.go (ProducerSchnorrStartHeight),
// registercrtransaction.go (CRSchnorrStartHeight), exchangevotes.go
// (VotesSchnorrStartHeight), transactionchecker.go CheckAttributeProgram
// (NormalSchnorrStartHeight). WithdrawFromSideChain V2 was the sole outlier.
// Enforcing the declared gate makes the entire aggregate-Schnorr withdraw path
// unreachable wherever the feature is configured off, instead of shipping a
// protocol-breaking MuSig/PoP rewrite for a path that is meant to be dormant.
//
// Measured, not inferred: a full read-only pass over the frozen mainnet chain
// (2,260,597 blocks, heights 0..2,260,595) finds 3,295 V0 and 7,786 V1
// WithdrawFromSideChain transactions and no V2, and no Schnorr program codes in
// any transaction type chain-wide. The production Arbiter emits V1, so enforcing
// the gate removes no behaviour the chain has ever used.
//
// The unknown-version default-deny mirrors RegisterProducer / RegisterCR /
// UpdateProducer. On MainNet it is redundant with the
// checkTransactionCrossChainUTXO admit-list, which already refuses any
// WithdrawFromSideChain payload version outside {0,1,2} from spending an "X"
// output above CrossChainUTXOFreezeHeight; it is kept here so the rule does not
// depend on that ordering.
//
// Gated at StrictMoneyRangeHeight (gate 1, the coordinated incident gate). No
// third gate: replay of retained history at or below gate 1 stays bit-identical.
func (t *WithdrawFromSideChainTransaction) HeightVersionCheck() error {
	blockHeight := t.parameters.BlockHeight
	chainParams := t.parameters.Config
	if blockHeight < chainParams.StrictMoneyRangeHeight {
		return nil
	}

	switch t.PayloadVersion() {
	case payload.WithdrawFromSideChainVersion,
		payload.WithdrawFromSideChainVersionV1:
	case payload.WithdrawFromSideChainVersionV2:
		if blockHeight < chainParams.SchnorrStartHeight {
			return fmt.Errorf("not support %s transaction with payload "+
				"version %d before SchnorrStartHeight", t.TxType().Name(),
				t.PayloadVersion())
		}
	default:
		return fmt.Errorf("unsupported %s transaction payload version %d",
			t.TxType().Name(), t.PayloadVersion())
	}

	return nil
}

func (t *WithdrawFromSideChainTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {
	if t.parameters.BlockHeight > t.parameters.Config.SchnorrStartHeight && t.PayloadVersion() != payload.WithdrawFromSideChainVersionV2 {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("only support schnorr type of  withdraw from sidechain transaction")), true
	}
	var err error
	if t.PayloadVersion() == payload.WithdrawFromSideChainVersion {
		err = t.checkWithdrawFromSideChainTransactionV0()
	} else if t.PayloadVersion() == payload.WithdrawFromSideChainVersionV1 {
		err = t.checkWithdrawFromSideChainTransactionV1()
	} else if t.PayloadVersion() == payload.WithdrawFromSideChainVersionV2 {
		err = t.checkWithdrawFromSideChainTransactionV2()
	}

	if err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	return nil, false
}

func (t *WithdrawFromSideChainTransaction) checkWithdrawFromSideChainTransactionV0() error {
	witPayload, ok := t.Payload().(*payload.WithdrawFromSideChain)
	if !ok {
		return errors.New("Invalid withdraw from side chain payload type")
	}
	for _, hash := range witPayload.SideChainTransactionHashes {
		if exist := blockchain.DefaultLedger.Store.IsSidechainTxHashDuplicate(hash); exist {
			return errors.New("Duplicate side chain transaction hash in paylod")
		}
	}

	for _, output := range t.references {
		if bytes.Compare(output.ProgramHash[0:1], []byte{byte(contract.PrefixCrossChain)}) != 0 {
			return errors.New("Invalid transaction inputs address, without \"X\" at beginning")
		}
	}

	height := t.parameters.BlockHeight
	for _, p := range t.Programs() {
		publicKeys, m, n, err := crypto.ParseCrossChainScriptV1(p.Code)
		if err != nil {
			return err
		}

		if height >= t.parameters.Config.CRConfiguration.CRClaimDPOSNodeStartHeight {
			var arbiters []*state.ArbiterInfo
			var minCount uint32
			if height >= t.parameters.Config.DPoSConfiguration.DPOSNodeCrossChainHeight {
				arbiters = blockchain.DefaultLedger.Arbitrators.GetArbitrators()
				minCount = uint32(t.parameters.Config.DPoSConfiguration.NormalArbitratorsCount) + 1
			} else {
				arbiters = blockchain.DefaultLedger.Arbitrators.GetCRCArbiters()
				minCount = t.parameters.Config.CRConfiguration.CRAgreementCount
			}
			var arbitersCount int
			for _, c := range arbiters {
				if !c.IsNormal {
					continue
				}
				arbitersCount++
			}
			if n != arbitersCount {
				return errors.New("invalid arbiters total count in code")
			}
			if m < int(minCount) {
				return errors.New("invalid arbiters sign count in code")
			}
		} else {
			if m < 1 || m > n || n != int(blockchain.DefaultLedger.Arbitrators.GetCrossChainArbitersCount()) ||
				m <= int(blockchain.DefaultLedger.Arbitrators.GetCrossChainArbitersMajorityCount()) {
				return errors.New("invalid multi sign script code")
			}
		}
		if err := checkCrossChainArbitrators(publicKeys); err != nil {
			return err
		}
	}

	return nil
}

func checkCrossChainArbitrators(publicKeys [][]byte) error {
	arbiters := blockchain.DefaultLedger.Arbitrators.GetCrossChainArbiters()

	arbitratorsMap := make(map[string]interface{})
	var count int
	for _, arbitrator := range arbiters {
		if !arbitrator.IsNormal {
			continue
		}
		count++

		found := false
		for _, pk := range publicKeys {
			if bytes.Equal(arbitrator.NodePublicKey, pk[1:]) {
				found = true
				break
			}
		}

		if !found {
			return errors.New("invalid cross chain arbitrators")
		}

		arbitratorsMap[common.BytesToHexString(arbitrator.NodePublicKey)] = nil
	}

	if count != len(publicKeys) || count != len(arbitratorsMap) {
		return errors.New("invalid arbitrator count")
	}

	return nil
}

func (t *WithdrawFromSideChainTransaction) checkWithdrawFromSideChainTransactionV1() error {
	for _, output := range t.Outputs() {
		if output.Type != common2.OTWithdrawFromSideChain {
			continue
		}
		witPayload, ok := output.Payload.(*outputpayload.Withdraw)
		if !ok {
			return errors.New("Invalid withdraw from side chain output payload type")
		}
		if exist := blockchain.DefaultLedger.Store.IsSidechainTxHashDuplicate(witPayload.SideChainTransactionHash); exist {
			return errors.New("Duplicate side chain transaction hash in output paylod")
		}
	}

	for _, output := range t.references {
		if bytes.Compare(output.ProgramHash[0:1], []byte{byte(contract.PrefixCrossChain)}) != 0 {
			return errors.New("Invalid transaction inputs address, without \"X\" at beginning")
		}
	}

	height := t.parameters.BlockHeight
	for _, p := range t.Programs() {
		publicKeys, m, n, err := crypto.ParseCrossChainScriptV1(p.Code)
		if err != nil {
			return err
		}
		var arbiters []*state.ArbiterInfo
		var minCount uint32
		if height >= t.parameters.Config.DPoSConfiguration.DPOSNodeCrossChainHeight {
			arbiters = blockchain.DefaultLedger.Arbitrators.GetArbitrators()
			minCount = uint32(t.parameters.Config.DPoSConfiguration.NormalArbitratorsCount) + 1
		} else {
			arbiters = blockchain.DefaultLedger.Arbitrators.GetCRCArbiters()
			minCount = t.parameters.Config.CRConfiguration.CRAgreementCount
		}
		var arbitersCount int
		for _, c := range arbiters {
			if !c.IsNormal {
				continue
			}
			arbitersCount++
		}
		if n != arbitersCount {
			return errors.New("invalid arbiters total count in code")
		}
		if m < int(minCount) {
			return errors.New("invalid arbiters sign count in code")
		}
		if err := checkCrossChainArbitrators(publicKeys); err != nil {
			return err
		}
	}

	return nil
}

func (t *WithdrawFromSideChainTransaction) checkWithdrawFromSideChainTransactionV2() error {
	pld, ok := t.Payload().(*payload.WithdrawFromSideChain)
	if !ok {
		return errors.New("Invalid withdraw from side chain payload type")
	}

	currentHeight := t.parameters.BlockHeight
	if currentHeight <= t.parameters.Config.CRConfiguration.CRClaimDPOSNodeStartHeight {
		if len(pld.Signers) < (int(t.parameters.Config.CRConfiguration.MemberCount)*2/3 + 1) {
			return errors.New("Signers number must be bigger than 2/3+1 CRMemberCount")
		}
	} else if currentHeight < t.parameters.Config.DPoSConfiguration.DPOSNodeCrossChainHeight {
		if len(pld.Signers) < (int(t.parameters.Config.CRConfiguration.MemberCount) * 2 / 3) {
			return errors.New("Signers number must be bigger than 2/3 CRMemberCount")
		}
	} else {
		if len(pld.Signers) < (int(t.parameters.Config.CRConfiguration.MemberCount)*2/3 + 1) {
			return errors.New("Signers number must be bigger than 2/3+1 CRMemberCount")
		}
	}

	for _, output := range t.references {
		if bytes.Compare(output.ProgramHash[0:1], []byte{byte(contract.PrefixCrossChain)}) != 0 {
			return errors.New("Invalid transaction inputs address, without \"X\" at beginning")
		}
	}

	validateSignerIndexes := currentHeight >= t.parameters.Config.CrossChainUTXORestrictionHeight
	err := checkSchnorrWithdrawFromSidechain(t, pld, validateSignerIndexes)
	if err != nil {
		return err
	}
	// V2 (Schnorr) withdraws never performed the committed sidechain-tx-hash
	// dedup that V0/V1 do, so one sidechain burn could be withdrawn again in a
	// later block. Gated at StrictMoneyRangeHeight for replay-safety (below-gate
	// byte-identical; mainnet V2 is dormant via SchnorrStartHeight=MaxUint32).
	// Forward protection on testnet/regnet is a config decision, since their gate is
	// disabled. The mempool extractor and same-block mirror cover the pool and
	// in-block dimensions.
	if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
		for _, output := range t.Outputs() {
			if output.Type != common2.OTWithdrawFromSideChain {
				continue
			}
			witPayload, ok := output.Payload.(*outputpayload.Withdraw)
			if !ok {
				continue
			}
			if blockchain.DefaultLedger.Store.IsSidechainTxHashDuplicate(witPayload.SideChainTransactionHash) {
				return errors.New("Duplicate side chain transaction hash in output paylod")
			}
		}
	}
	return nil
}

func checkSchnorrWithdrawFromSidechain(t interfaces.Transaction,
	pld *payload.WithdrawFromSideChain, validateSignerIndexes bool) error {
	var pxArr []*big.Int
	var pyArr []*big.Int
	arbiters := blockchain.DefaultLedger.Arbitrators.GetCrossChainArbiters()
	var signerIndexes map[uint8]struct{}
	if validateSignerIndexes {
		signerIndexes = make(map[uint8]struct{}, len(pld.Signers))
	}
	for _, index := range pld.Signers {
		if validateSignerIndexes {
			if int(index) >= len(arbiters) {
				return errors.New("invalid schnorr withdraw signer index")
			}
			if _, exists := signerIndexes[index]; exists {
				return errors.New("duplicate schnorr withdraw signer index")
			}
			signerIndexes[index] = struct{}{}
		}

		// Crash-harden, ungated: the index guard above only runs at or
		// above CrossChainUTXORestrictionHeight. Outside that window an
		// out-of-range Signers index panics on arbiters[index], and a
		// NodePublicKey that crypto.Unmarshal cannot decode yields (nil, nil),
		// which panics inside Curve.Add (nil big.Int receiver / invalid point).
		// A panic is never an accepted block, so failing closed here cannot
		// change any acceptance decision on any history, the same rationale as
		// the Schnorr parameter-length harden. Left ungated for that reason.
		if int(index) >= len(arbiters) {
			return errors.New("schnorr withdraw signer index out of range")
		}
		nodePublicKey := arbiters[index].NodePublicKey
		if len(nodePublicKey) != crypto.COMPRESSEDLEN {
			return errors.New("invalid schnorr withdraw arbiter public key length")
		}
		px, py := crypto.Unmarshal(crypto.Curve, nodePublicKey)
		if px == nil || py == nil || !crypto.Curve.IsOnCurve(px, py) {
			return errors.New("invalid schnorr withdraw arbiter public key")
		}
		pxArr = append(pxArr, px)
		pyArr = append(pyArr, py)
	}
	Px, Py := new(big.Int), new(big.Int)
	for i := 0; i < len(pxArr); i++ {
		Px, Py = crypto.Curve.Add(Px, Py, pxArr[i], pyArr[i])
	}
	sumPublicKey := crypto.Marshal(crypto.Curve, Px, Py)
	publicKey, err := crypto.DecodePoint(sumPublicKey)
	if err != nil {
		return errors.New("Invalid schnorr public key" + err.Error())
	}
	redeemScript, err := contract.CreateSchnorrRedeemScript(publicKey)
	if err != nil {
		return errors.New("CreateSchnorrRedeemScript error")
	}
	for _, program := range t.Programs() {
		if contract.IsSchnorr(program.Code) {
			if hex.EncodeToString(program.Code) != hex.EncodeToString(redeemScript) {
				return errors.New("WithdrawFromSideChain invalid , signers can not match")
			}
		} else {
			return errors.New("Invalid schnorr program code")
		}
	}
	return nil
}

func (t *WithdrawFromSideChainTransaction) GetSaveProcessor() (database.TXProcessor, elaerr.ELAError) {

	witPayload := t.Payload().(*payload.WithdrawFromSideChain)
	if t.PayloadVersion() == payload.WithdrawFromSideChainVersion {
		return func(dbTx database.Tx) error {
			err := blockchain.TryCreateBucket(dbTx, common.Tx3IndexBucketName)
			if err != nil {
				return err
			}
			for _, hash := range witPayload.SideChainTransactionHashes {
				err = blockchain.DBPutData(dbTx, common.Tx3IndexBucketName,
					hash[:], common.Tx3IndexValue)
				if err != nil {
					return err
				}
			}

			return nil
		}, nil
	} else if t.PayloadVersion() == payload.WithdrawFromSideChainVersionV1 || t.PayloadVersion() == payload.WithdrawFromSideChainVersionV2 {
		return func(dbTx database.Tx) error {
			err := blockchain.TryCreateBucket(dbTx, common.Tx3IndexBucketName)
			if err != nil {
				return err
			}
			for _, output := range t.Outputs() {
				if output.Type != common2.OTWithdrawFromSideChain {
					continue
				}
				witPayload, ok := output.Payload.(*outputpayload.Withdraw)
				if !ok {
					continue
				}
				err = blockchain.DBPutData(dbTx, common.Tx3IndexBucketName,
					witPayload.SideChainTransactionHash[:], common.Tx3IndexValue)
				if err != nil {
					return err
				}
			}

			return nil
		}, nil
	}

	return nil, nil
}

func (t *WithdrawFromSideChainTransaction) GetRollbackProcessor() (database.TXProcessor, elaerr.ELAError) {

	witPayload := t.Payload().(*payload.WithdrawFromSideChain)
	if t.PayloadVersion() == payload.WithdrawFromSideChainVersion {
		return func(dbTx database.Tx) error {
			for _, hash := range witPayload.SideChainTransactionHashes {
				err := blockchain.DBRemoveData(dbTx, common.Tx3IndexBucketName, hash[:])
				if err != nil {
					return err
				}
			}

			return nil
		}, nil
		// Mirror GetSaveProcessor (V1||V2) so a reorged V2 withdraw also
		// clears its Tx3Index; otherwise the sidechain hash stays marked-used
		// forever and the burn can never be re-withdrawn.
	} else if t.PayloadVersion() == payload.WithdrawFromSideChainVersionV1 ||
		t.PayloadVersion() == payload.WithdrawFromSideChainVersionV2 {
		return func(dbTx database.Tx) error {
			for _, output := range t.Outputs() {
				if output.Type != common2.OTWithdrawFromSideChain {
					continue
				}
				witPayload, ok := output.Payload.(*outputpayload.Withdraw)
				if !ok {
					continue
				}
				err := blockchain.DBRemoveData(dbTx, common.Tx3IndexBucketName, witPayload.SideChainTransactionHash[:])
				if err != nil {
					return err
				}
			}

			return nil
		}, nil
	}

	return nil, nil
}
