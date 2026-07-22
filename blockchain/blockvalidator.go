// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"time"

	. "github.com/elastos/Elastos.ELA/auxpow"
	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract"
	. "github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

const (
	MaxTimeOffsetSeconds = 2 * 60 * 60
)

func (b *BlockChain) CheckBlockSanity(block *Block) error {
	header := block.Header
	hash := header.Hash()
	if !header.AuxPow.Check(&hash, AuxPowChainID) {
		return errors.New("[PowCheckBlockSanity] block check aux pow failed")
	}
	if CheckProofOfWork(&header, b.chainParams.PowConfiguration.PowLimit) != nil {
		return errors.New("[PowCheckBlockSanity] block check proof of work failed")
	}

	// A block timestamp must not have a greater precision than one second.
	tempTime := time.Unix(int64(header.Timestamp), 0)
	if !tempTime.Equal(time.Unix(tempTime.Unix(), 0)) {
		return errors.New("[PowCheckBlockSanity] block timestamp of has a higher precision than one second")
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := b.TimeSource.AdjustedTime().Add(time.Second * MaxTimeOffsetSeconds)
	if tempTime.After(maxTimestamp) {
		return errors.New("[PowCheckBlockSanity] block timestamp of is too far in the future")
	}

	// A block must have at least one transaction.
	numTx := len(block.Transactions)
	if numTx == 0 {
		return errors.New("[PowCheckBlockSanity]  block does not contain any transactions")
	}

	// A block must not have more transactions than the max block payload.
	if uint32(numTx) > pact.MaxTxPerBlock {
		return errors.New("[PowCheckBlockSanity]  block contains too many" +
			" transactions, tx count: " + strconv.FormatInt(int64(numTx), 10))
	}

	// A block header must not exceed the maximum allowed block payload when
	//serialized.
	headerSize := block.Header.GetSize()
	if headerSize > int(pact.MaxBlockHeaderSize) {
		return errors.New(
			"[PowCheckBlockSanity] serialized block header is too big")
	}

	// A block must not exceed the maximum allowed block payload when serialized.
	blockSize := block.GetSize()
	if blockSize > int(pact.MaxBlockContextSize+pact.MaxBlockHeaderSize) {
		return errors.New("[PowCheckBlockSanity] serialized block is too big")
	}

	transactions := block.Transactions
	// The first transaction in a block must be a coinbase.
	if !transactions[0].IsCoinBaseTx() {
		return errors.New("[PowCheckBlockSanity] first transaction in block is not a coinbase")
	}

	// A block must not have more than one coinbase.
	for _, tx := range transactions[1:] {
		if tx.IsCoinBaseTx() {
			return errors.New("[PowCheckBlockSanity] block contains second coinbase")
		}
	}

	txIDs := make([]Uint256, 0, len(block.Transactions))
	existingTxIDs := make(map[Uint256]struct{})
	existingTxInputs := make(map[string]struct{})
	for _, txn := range block.Transactions {
		txID := txn.Hash()
		// Check for duplicate transactions.
		if _, exists := existingTxIDs[txID]; exists {
			return errors.New("[PowCheckBlockSanity] block contains duplicate transaction")
		}
		existingTxIDs[txID] = struct{}{}

		// Check for transaction sanity
		if err := b.CheckTransactionSanity(block.Height, txn); err != nil {
			return elaerr.SimpleWithMessage(elaerr.ErrBlockValidation, err,
				"CheckTransactionSanity failed when verifiy block")
		}

		// Check for duplicate UTXO Inputs in a block
		for _, input := range txn.Inputs() {
			referKey := input.ReferKey()
			if _, exists := existingTxInputs[referKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate UTXO")
			}
			existingTxInputs[referKey] = struct{}{}
		}

		// Append transaction to list
		txIDs = append(txIDs, txID)
	}
	if err := CheckDuplicateTx(block); err != nil {
		return err
	}
	if err := CheckSameBlockConflicts(block,
		b.chainParams.StrictMoneyRangeHeight); err != nil {
		return err
	}
	calcTransactionsRoot, err := crypto.ComputeRoot(txIDs)
	if err != nil {
		return errors.New("[PowCheckBlockSanity] merkleTree compute failed")
	}
	if !header.MerkleRoot.IsEqual(calcTransactionsRoot) {
		return errors.New("[PowCheckBlockSanity] block merkle root is invalid")
	}

	return nil
}

func CheckDuplicateTx(block *Block) error {
	existingSideTxs := make(map[Uint256]struct{})
	existingProducer := make(map[string]struct{})
	existingProducerNode := make(map[string]struct{})
	existingCR := make(map[Uint168]struct{})
	recordSponsorCount := 0
	for _, txn := range block.Transactions {
		switch txn.TxType() {
		case common.RecordSponsor:
			recordSponsorCount++
			if recordSponsorCount > 1 {
				return errors.New("[PowCheckBlockSanity] block contains duplicate record sponsor Tx")
			}

		case common.WithdrawFromSideChain:
			witPayload := txn.Payload().(*payload.WithdrawFromSideChain)

			// Check for duplicate sidechain tx in a block
			for _, hash := range witPayload.SideChainTransactionHashes {
				if _, exists := existingSideTxs[hash]; exists {
					return errors.New("[PowCheckBlockSanity] block contains duplicate sidechain Tx")
				}
				existingSideTxs[hash] = struct{}{}
			}
		case common.RegisterProducer:
			producerPayload, ok := txn.Payload().(*payload.ProducerInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid register producer payload")
			}

			producer := BytesToHexString(producerPayload.OwnerKey)
			// Check for duplicate producer in a block
			if _, exists := existingProducer[producer]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate producer")
			}
			existingProducer[producer] = struct{}{}

			producerNode := BytesToHexString(producerPayload.NodePublicKey)
			// Check for duplicate producer node in a block
			if _, exists := existingProducerNode[producerNode]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate producer node")
			}
			existingProducerNode[producerNode] = struct{}{}
		case common.UpdateProducer:
			producerPayload, ok := txn.Payload().(*payload.ProducerInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid update producer payload")
			}

			producer := BytesToHexString(producerPayload.OwnerKey)
			// Check for duplicate producer in a block
			if _, exists := existingProducer[producer]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate producer")
			}
			existingProducer[producer] = struct{}{}

			producerNode := BytesToHexString(producerPayload.NodePublicKey)
			// Check for duplicate producer node in a block
			if _, exists := existingProducerNode[BytesToHexString(producerPayload.NodePublicKey)]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate producer node")
			}
			existingProducerNode[producerNode] = struct{}{}
		case common.CancelProducer:
			processProducerPayload, ok := txn.Payload().(*payload.ProcessProducer)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid cancel producer payload")
			}

			producer := BytesToHexString(processProducerPayload.OwnerKey)
			// Check for duplicate producer in a block
			if _, exists := existingProducer[producer]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate producer")
			}
			existingProducer[producer] = struct{}{}
		case common.RegisterCR:
			crPayload, ok := txn.Payload().(*payload.CRInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid register CR payload")
			}

			// Check for duplicate CR in a block
			if _, exists := existingCR[crPayload.CID]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR")
			}
			existingCR[crPayload.CID] = struct{}{}
		case common.UpdateCR:
			crPayload, ok := txn.Payload().(*payload.CRInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid update CR payload")
			}

			// Check for duplicate  CR in a block
			if _, exists := existingCR[crPayload.CID]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR")
			}
			existingCR[crPayload.CID] = struct{}{}
		case common.UnregisterCR:
			unregisterCR, ok := txn.Payload().(*payload.UnregisterCR)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid unregister CR payload")
			}
			// Check for duplicate  CR in a block
			if _, exists := existingCR[unregisterCR.CID]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR")
			}
			existingCR[unregisterCR.CID] = struct{}{}
		}
	}
	return nil
}

// checkSameBlockConflicts closes the same-block double-pay/race cluster
// (F-028, F-066, F-067, F-078, F-088). The mempool conflictmanager rejects two
// conflicting stake/reward/withdraw/tracking txs, but the block-level validation never
// mirrored those slots — so an on-duty block producer could pack two conflicting txs
// into ONE block (bypassing its own mempool) and cause a double ReturnVotes/ClaimReward
// payout, a double RealWithdraw, a double unused-budget return, or cloned renewal votes.
// This mirrors the relevant mempool conflict slots at the block level, keyed on the
// EXACT conflict identity (stake program hash / claim program hash / pending withdraw
// hash / proposal hash), so two DIFFERENT identities of the same tx type in one block
// remain legitimate. Gated at StrictMoneyRangeHeight: below the coordinated-upgrade gate
// this is a no-op, so the frozen chain re-derives byte-identically.
func CheckSameBlockConflicts(block *Block, gate uint32) error {
	if block.Height < gate {
		return nil
	}
	stakeVotes := make(map[Uint168]struct{})            // mempool slotExchangeVotes
	claimReward := make(map[Uint168]struct{})           // mempool slotDposV2ClaimReward
	tracking := make(map[Uint256]struct{})              // mempool slotCRCProposalTrackingHash
	crcRealWithdraw := make(map[Uint256]struct{})       // mempool slotCRCProposalRealWithdrawKey
	dposClaimRealWithdraw := make(map[Uint256]struct{}) // mempool slotDposV2ClaimRewardRealWithdrawKey
	votesRealWithdrawCount := 0                          // mempool slotVotesRealWithdraw (singleton)
	proposalWithdraw := make(map[Uint256]struct{})      // F-047: mempool slotCRCProposalHash (queue side)
	returnDeposit := make(map[string]struct{})          // F-068: mempool slotProgramCode (return-deposit)
	claimNodeKeys := make(map[string]struct{})          // F-071: mempool slotCRCouncilMemberNodePublicKey
	proposalDraft := make(map[Uint256]struct{})         // F-072: mempool slotCRCProposalDraftHash
	sidechainWithdraw := make(map[Uint256]struct{})      // F-017/F-051: mempool slotSidechainTxHashes
	sidechainReturnDeposit := make(map[Uint256]struct{}) // F-016: mempool slotSidechainReturnDepositTxHashes
	for _, txn := range block.Transactions {
		switch txn.TxType() {
		case common.ExchangeVotes, common.Voting, common.ReturnVotes, common.CreateNFT:
			key, err := stakeVoteConflictKey(txn)
			if err != nil {
				return err
			}
			if _, exists := stakeVotes[key]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-stake vote transaction")
			}
			stakeVotes[key] = struct{}{}
		case common.DposV2ClaimReward:
			key, err := claimRewardConflictKey(txn)
			if err != nil {
				return err
			}
			if _, exists := claimReward[key]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-stake claim reward transaction")
			}
			claimReward[key] = struct{}{}
		case common.CRCProposalTracking:
			p, ok := txn.Payload().(*payload.CRCProposalTracking)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposalTracking payload")
			}
			if _, exists := tracking[p.ProposalHash]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate proposal tracking")
			}
			tracking[p.ProposalHash] = struct{}{}
		case common.CRCProposalRealWithdraw:
			p, ok := txn.Payload().(*payload.CRCProposalRealWithdraw)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposalRealWithdraw payload")
			}
			if err := addWithdrawHashes(crcRealWithdraw, p.WithdrawTransactionHashes); err != nil {
				return err
			}
		case common.DposV2ClaimRewardRealWithdraw:
			p, ok := txn.Payload().(*payload.DposV2ClaimRewardRealWithdraw)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid DposV2ClaimRewardRealWithdraw payload")
			}
			if err := addWithdrawHashes(dposClaimRealWithdraw, p.WithdrawTransactionHashes); err != nil {
				return err
			}
		case common.VotesRealWithdraw:
			// The mempool slotVotesRealWithdraw keys on a constant singleton, so at most
			// one VotesRealWithdraw is ever in flight; mirror that (reject the second).
			votesRealWithdrawCount++
			if votesRealWithdrawCount > 1 {
				return errors.New("[PowCheckBlockSanity] block contains duplicate votes real withdraw")
			}
		case common.CRCProposalWithdraw:
			// F-047: mirror mempool slotCRCProposalHash (queue side). Two same-block
			// V1 withdraws for the same proposal both pass ContextCheck (the first's
			// WithdrawnBudgets update commits only post-validation) and each queue a
			// WithdrawableTxInfo entry keyed by tx hash -> double CRExpenses payout.
			p, ok := txn.Payload().(*payload.CRCProposalWithdraw)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposalWithdraw payload")
			}
			if _, exists := proposalWithdraw[p.ProposalHash]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-proposal withdraw")
			}
			proposalWithdraw[p.ProposalHash] = struct{}{}
		case common.ReturnDepositCoin, common.ReturnCRDepositCoin:
			// F-068: mirror mempool slotProgramCode. Two same-block deposit returns
			// with the same program code (producer/CR) but disjoint deposit UTXOs both
			// read the same committed availableAmount and each refund up to it,
			// escaping the block dup-UTXO check -> over-refund of the forfeited bond.
			// (The mempool already forbids this pairing, so no honest mempool-built
			// block is affected; this catches a malicious producer.)
			if len(txn.Programs()) == 0 {
				return errors.New("[PowCheckBlockSanity] return deposit tx without program")
			}
			codeKey := BytesToHexString(txn.Programs()[0].Code)
			if _, exists := returnDeposit[codeKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-code deposit return")
			}
			returnDeposit[codeKey] = struct{}{}
		case common.CRCouncilMemberClaimNode:
			// F-071: mirror mempool slotCRCouncilMemberNodePublicKey. Two same-block
			// claims of the same node public key by distinct members both pass (the key
			// is absent from pre-block ClaimedDPoSKeys) -> two CR members bound to one
			// DPoS node key, breaking the node-key uniqueness invariant.
			p, ok := txn.Payload().(*payload.CRCouncilMemberClaimNode)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCouncilMemberClaimNode payload")
			}
			nodeKey := BytesToHexString(p.NodePublicKey)
			if _, exists := claimNodeKeys[nodeKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR claim DPOS node public key")
			}
			claimNodeKeys[nodeKey] = struct{}{}
		case common.CRCProposal:
			// F-072 (DraftHash only): mirror mempool slotCRCProposalDraftHash. A
			// same-block duplicate DraftHash is never legitimate (the draft hash is a
			// hash over the draft data) and breaks the ExistDraft uniqueness invariant
			// + shares a ProposalDraftDataBucketName key (rollback corruption). DID /
			// CustomID uniqueness is NOT promoted here (a member may legitimately file
			// multiple distinct-draft proposals) - see INFERRED-ITEMS.
			p, ok := txn.Payload().(*payload.CRCProposal)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposal payload")
			}
			if _, exists := proposalDraft[p.DraftHash]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate proposal draft hash")
			}
			proposalDraft[p.DraftHash] = struct{}{}
		case common.WithdrawFromSideChain:
			// F-017/F-051: mirror mempool slotSidechainTxHashes. The committed
			// IsSidechainTxHashDuplicate read does not see an earlier same-block tx
			// (Tx3Index is written post-validation), and V1/V2 carry the hash in
			// output payloads that CheckDuplicateTx never inspects, so two same-block
			// withdraws crediting one sidechain burn both pass -> double main-chain
			// credit. Reject a repeated sidechain tx hash.
			for _, h := range sidechainWithdrawHashes(txn) {
				if _, exists := sidechainWithdraw[h]; exists {
					return errors.New("[PowCheckBlockSanity] block contains duplicate sidechain withdraw hash")
				}
				sidechainWithdraw[h] = struct{}{}
			}
		case common.ReturnSideChainDepositCoin:
			// F-016: mirror mempool slotSidechainReturnDepositTxHashes. The committed
			// IsSidechainReturnDepositTxHashDuplicate read does not see an earlier
			// same-block tx, so two same-block returns refunding one sidechain deposit
			// both pass -> double refund. Reject a repeated deposit tx hash.
			for _, h := range sidechainReturnDepositHashes(txn) {
				if _, exists := sidechainReturnDeposit[h]; exists {
					return errors.New("[PowCheckBlockSanity] block contains duplicate sidechain return-deposit hash")
				}
				sidechainReturnDeposit[h] = struct{}{}
			}
		}
	}
	return nil
}

// addWithdrawHashes rejects a block that references the same pending withdraw hash twice
// (mirrors the mempool hashArray real-withdraw slots).
func addWithdrawHashes(seen map[Uint256]struct{}, hashes []Uint256) error {
	for _, h := range hashes {
		if _, exists := seen[h]; exists {
			return errors.New("[PowCheckBlockSanity] block contains duplicate real withdraw pending hash")
		}
		seen[h] = struct{}{}
	}
	return nil
}

// sidechainWithdrawHashes extracts the sidechain transaction hashes a
// WithdrawFromSideChain credits, across payload versions (mirrors the mempool
// key hashArraySidechainTransactionHashes). V1/V2 carry each hash in the
// OTWithdrawFromSideChain output payloads; V0 carries them in the tx payload.
func sidechainWithdrawHashes(txn interfaces.Transaction) []Uint256 {
	if txn.PayloadVersion() == payload.WithdrawFromSideChainVersion {
		if p, ok := txn.Payload().(*payload.WithdrawFromSideChain); ok {
			return p.SideChainTransactionHashes
		}
		return nil
	}
	var hashes []Uint256
	for _, output := range txn.Outputs() {
		if output.Type != common.OTWithdrawFromSideChain {
			continue
		}
		w, ok := output.Payload.(*outputpayload.Withdraw)
		if !ok {
			continue
		}
		hashes = append(hashes, w.SideChainTransactionHash)
	}
	return hashes
}

// sidechainReturnDepositHashes extracts the deposit tx hashes a
// ReturnSideChainDepositCoin refunds (mirrors the mempool key
// hashArraySidechainReturnDepositTransactionHashes).
func sidechainReturnDepositHashes(txn interfaces.Transaction) []Uint256 {
	var hashes []Uint256
	for _, output := range txn.Outputs() {
		if output.Type != common.OTReturnSideChainDepositCoin {
			continue
		}
		w, ok := output.Payload.(*outputpayload.ReturnSideChainDeposit)
		if !ok {
			continue
		}
		hashes = append(hashes, w.DepositTransactionHash)
	}
	return hashes
}

// stakeVoteConflictKey mirrors the mempool slotExchangeVotes key extraction
// (strStake / strVoting / strReturnVotes / strCreateNFT): the stake program hash.
func stakeVoteConflictKey(txn interfaces.Transaction) (Uint168, error) {
	if txn.TxType() == common.ExchangeVotes {
		if len(txn.Outputs()) < 1 || txn.Outputs()[0].Payload == nil {
			return Uint168{}, errors.New("[PowCheckBlockSanity] invalid exchange votes outputs")
		}
		pld, ok := txn.Outputs()[0].Payload.(*outputpayload.ExchangeVotesOutput)
		if !ok {
			return Uint168{}, errors.New("[PowCheckBlockSanity] invalid exchange votes output payload")
		}
		return pld.StakeAddress, nil
	}
	if len(txn.Programs()) < 1 {
		return Uint168{}, errors.New("[PowCheckBlockSanity] invalid vote transaction programs")
	}
	code := txn.Programs()[0].Code
	if rv, ok := txn.Payload().(*payload.ReturnVotes); ok &&
		txn.PayloadVersion() == payload.ReturnVotesVersionV0 {
		code = rv.Code
	}
	ct, err := contract.CreateStakeContractByCode(code)
	if err != nil {
		return Uint168{}, errors.New("[PowCheckBlockSanity] invalid vote transaction code")
	}
	return *ct.ToProgramHash(), nil
}

// claimRewardConflictKey mirrors the mempool slotDposV2ClaimReward key extraction
// (programHashDposV2ClaimReward): the claimer's stake program hash.
func claimRewardConflictKey(txn interfaces.Transaction) (Uint168, error) {
	pld, ok := txn.Payload().(*payload.DPoSV2ClaimReward)
	if !ok {
		return Uint168{}, errors.New("[PowCheckBlockSanity] invalid DposV2ClaimReward payload")
	}
	if len(txn.Programs()) < 1 {
		return Uint168{}, errors.New("[PowCheckBlockSanity] invalid DposV2ClaimReward programs")
	}
	code := txn.Programs()[0].Code
	if txn.PayloadVersion() == payload.DposV2ClaimRewardVersionV0 {
		code = pld.Code
	}
	ct, err := contract.CreateStakeContractByCode(code)
	if err != nil {
		return Uint168{}, errors.New("[PowCheckBlockSanity] invalid DposV2ClaimReward code")
	}
	return *ct.ToProgramHash(), nil
}

func RecordCRCProposalAmount(usedAmount *Fixed64, txn interfaces.Transaction) {
	proposal, ok := txn.Payload().(*payload.CRCProposal)
	if !ok {
		return
	}
	for _, b := range proposal.Budgets {
		*usedAmount += b.Amount
	}
}

// checkCoinbaseBIP30 closes F-089: the coinbase carries its own IsTxHashDuplicate
// guard (coinbasetransaction.go) but it is DEAD on connect -- checkTxsContext
// validates only txs[1:], so the coinbase (index 0) never runs it. A malicious
// block producer could replay a prior identical coinbase (same txid) to resurrect
// already-spent coinbase outputs (BIP30). At/above the gate we reject a block whose
// coinbase txid already exists in the ledger. Below the gate: legacy (no check),
// for replay-safety. isDuplicate is injected for testability.
func checkCoinbaseBIP30(coinbaseHash Uint256, height, gate uint32, isDuplicate func(Uint256) bool) error {
	if height < gate {
		return nil
	}
	if isDuplicate(coinbaseHash) {
		return errors.New("coinbase transaction hash already exists (BIP30)")
	}
	return nil
}

func (b *BlockChain) checkTxsContext(block *Block) error {
	if len(block.Transactions) > 0 {
		if err := checkCoinbaseBIP30(block.Transactions[0].Hash(), block.Height,
			b.chainParams.StrictMoneyRangeHeight, b.db.IsTxHashDuplicate); err != nil {
			return elaerr.SimpleWithMessage(elaerr.ErrBlockValidation, nil, err.Error())
		}
	}
	var totalTxFee = Fixed64(0)

	var proposalsUsedAmount Fixed64
	for i := 1; i < len(block.Transactions); i++ {
		references, errCode := b.CheckTransactionContext(block.Height,
			block.Transactions[i], proposalsUsedAmount, block.Timestamp)
		if errCode != nil {
			return elaerr.SimpleWithMessage(elaerr.ErrBlockValidation, errCode,
				"CheckTransactionContext failed when verify block")
		}

		// Calculate transaction fee. Below StrictMoneyRangeHeight the original
		// wrapping arithmetic is preserved verbatim so historical blocks
		// continue to validate; at and above it, overflow is rejected.
		if block.Height >= b.chainParams.StrictMoneyRangeHeight {
			fee, err := GetTxFeeStrict(block.Transactions[i], core.ELAAssetID, references)
			if err != nil {
				return elaerr.Simple(elaerr.ErrBlockValidation, err)
			}
			totalTxFee, err = AddFixed64(totalTxFee, fee)
			if err != nil {
				return elaerr.Simple(elaerr.ErrBlockValidation, err)
			}
		} else {
			totalTxFee += GetTxFee(block.Transactions[i], core.ELAAssetID, references)
		}
		if block.Transactions[i].IsCRCProposalTx() {
			if b.StrictMoneyActive(block.Height) {
				if err := RecordCRCProposalAmountStrict(&proposalsUsedAmount,
					block.Transactions[i]); err != nil {
					return elaerr.Simple(elaerr.ErrBlockValidation, err)
				}
			} else {
				RecordCRCProposalAmount(&proposalsUsedAmount, block.Transactions[i])
			}
		}
	}
	var dposReward Fixed64
	// F-011/086 (re-gated per Q-B6): derive the arbiter reward leg from the ELA-filtered
	// totalTxFee (same basis as the CR/miner legs) instead of the all-asset tx.Fee() sum,
	// else a non-ELA fee inflates coinbase[2] above its ELA backing. The core engineers
	// asked that this reward-rule change activate at a FRESH future height
	// (RevisedDPoSRewardHeight), NOT the incident-recovery gate (StrictMoneyRangeHeight).
	// On the ELA-only mainnet (Q-B1) it is byte-identical to the legacy GetBlockDPOSReward
	// path either way (tx.Fee() sum == totalTxFee), so re-gating changes no mainnet block.
	if block.Height >= b.chainParams.RevisedDPoSRewardHeight {
		var err error
		dposReward, err = b.GetBlockDPOSRewardStrict(block.Height, totalTxFee)
		if err != nil {
			return elaerr.Simple(elaerr.ErrBlockValidation, err)
		}
	} else {
		dposReward = b.GetBlockDPOSReward(block)
	}
	err := b.checkCoinbaseTransactionContext(block.Height,
		block.Transactions[0], totalTxFee, dposReward)
	if err != nil {
		buf := new(bytes.Buffer)
		if block.Height < b.chainParams.CheckRewardHeight {
			if err = block.Serialize(buf); err != nil {
				return err
			}
		} else {
			if e := block.Serialize(buf); e != nil {
				return e
			}
		}
		log.Errorf("checkCoinbaseTransactionContext failed,"+
			"block:%s", BytesToHexString(buf.Bytes()))
		log.Error("checkCoinbaseTransactionContext failed,round reward:",
			DefaultLedger.Arbitrators.GetArbitersRoundReward())
		log.Error("checkCoinbaseTransactionContext failed,final round change:",
			DefaultLedger.Arbitrators.GetFinalRoundChange())
	}
	return err
}

func (b *BlockChain) CheckBlockContext(block *Block, prevNode *BlockNode) error {
	// The genesis block is valid by definition.
	if prevNode == nil {
		return nil
	}

	header := block.Header
	expectedDifficulty, err := b.CalcNextRequiredDifficulty(prevNode,
		time.Unix(int64(header.Timestamp), 0))
	if err != nil {
		return err
	}

	if header.Bits != expectedDifficulty {
		return errors.New("block difficulty is not the expected")
	}

	// Ensure the timestamp for the block header is after the
	// median time of the last several blocks (medianTimeBlocks).
	medianTime := CalcPastMedianTime(prevNode)
	tempTime := time.Unix(int64(header.Timestamp), 1)

	if !tempTime.After(medianTime) {
		return errors.New("block timestamp is not after expected")
	}

	var recordSponsorExist bool
	var recordedSponsor []byte
	for _, tx := range block.Transactions[1:] {
		if !IsFinalizedTransaction(tx, block.Height) {
			return errors.New("block contains unfinalized transaction")
		}
		if tx.IsRecordSponorTx() {
			recordSponsorExist = true
			if pld, ok := tx.Payload().(*payload.RecordSponsor); ok {
				recordedSponsor = pld.Sponsor
			}
		}
	}

	// check if need to record sponsor
	if block.Height >= b.chainParams.DPoSConfiguration.RecordSponsorStartHeight {
		lastBlock, err := b.GetDposBlockByHash(*prevNode.Hash)
		if err != nil {
			// try get block from cache
			lastBlockInCache, ok := b.blockCache[*prevNode.Hash]
			if !ok {
				return errors.New("get last block failed")
			}
			lastConfirmInCache, ok := b.confirmCache[*prevNode.Hash]
			if !ok {
				return errors.New("get last block confirm failed")
			}
			lastBlock = &DposBlock{
				Block:       lastBlockInCache,
				HaveConfirm: lastConfirmInCache != nil,
				Confirm:     lastConfirmInCache,
			}
		}

		if lastBlock.Confirm == nil && recordSponsorExist {
			return errors.New("record sponsor transaction must be confirmed")
		}
		if lastBlock.Confirm != nil && !recordSponsorExist {
			return errors.New("confirmed block must have record sponsor transaction")
		}

		// F-032: bind the RecordSponsor tx's Sponsor to the ACTUAL sponsor of the
		// confirmed previous block. recordsponsortransaction.go SpecialContextCheck only
		// checks the Sponsor is SOME current/last arbiter (membership), so a block
		// producer could name any arbiter and redirect the DPoS sponsor-reward
		// (a.LastDPoSRewards[recordedSponsor] in accumulateReward) away from the true
		// sponsor -- conserved between arbiters, no inflation. The confirm-presence check
		// above guarantees lastBlock.Confirm != nil whenever a RecordSponsor tx is
		// present, so reading its sponsor is safe. Override-aware (operator sponsors file)
		// and gated at RevisedDPoSRewardHeight -> below-gate byte-identical.
		if recordSponsorExist {
			if err := DefaultLedger.Arbitrators.CheckRecordSponsorBinding(
				recordedSponsor, lastBlock.Height,
				lastBlock.Confirm.Proposal.Sponsor, block.Height); err != nil {
				return err
			}
		}
	}

	if err := DefaultLedger.Arbitrators.CheckDPOSIllegalTx(block); err != nil {
		return err
	}

	if err := DefaultLedger.Arbitrators.CheckCRCAppropriationTx(block); err != nil {
		return err
	}
	if err := DefaultLedger.Arbitrators.CheckNextTurnDPOSInfoTx(block); err != nil {
		return err
	}
	if err := DefaultLedger.Arbitrators.CheckCustomIDResultsTx(block); err != nil {
		return err
	}
	return b.checkTxsContext(block)
}

func (b *BlockChain) CheckTransactions(block *Block) error {
	if err := DefaultLedger.Arbitrators.CheckNextTurnDPOSInfoTx(block); err != nil {
		return err
	}

	return nil
}

func CheckProofOfWork(header *common.Header, powLimit *big.Int) error {
	// The target difficulty must be larger than zero.
	target := CompactToBig(header.Bits)
	if target.Sign() <= 0 {
		return errors.New("[BlockValidator], block target difficulty is too low.")
	}

	// The target difficulty must be less than the maximum allowed.
	if target.Cmp(powLimit) > 0 {
		return errors.New("[BlockValidator], block target difficulty is higher than max of limit.")
	}

	// The block hash must be less than the claimed target.
	hash := header.AuxPow.ParBlockHeader.Hash()

	hashNum := HashToBig(&hash)
	if hashNum.Cmp(target) > 0 {
		return errors.New("[BlockValidator], block target difficulty is higher than expected difficulty.")
	}

	return nil
}

func IsFinalizedTransaction(msgTx interfaces.Transaction, blockHeight uint32) bool {
	// Lock time of zero means the transaction is finalized.
	lockTime := msgTx.LockTime()
	if lockTime == 0 {
		return true
	}

	//FIXME only height
	if lockTime < blockHeight {
		return true
	}

	// At this point, the transaction's lock time hasn't occurred yet, but
	// the transaction might still be finalized if the sequence number
	// for all transaction Inputs is maxed out.
	for _, txIn := range msgTx.Inputs() {
		if txIn.Sequence != math.MaxUint16 {
			return false
		}
	}
	return true
}

// GetTxFeeMapStrict is the post-activation fee calculation. Unlike
// GetTxFeeMap it rejects negative amounts, per-amount money-range breaches and
// signed 64-bit overflow instead of wrapping.
func GetTxFeeMapStrict(tx interfaces.Transaction,
	references map[*common.Input]common.Output) (map[Uint256]Fixed64, error) {
	feeMap := make(map[Uint256]Fixed64)
	inputs := make(map[Uint256]Fixed64)
	outputs := make(map[Uint256]Fixed64)

	for _, output := range references {
		if !MoneyRange(output.Value) {
			return nil, fmt.Errorf("transaction input amount: %w", ErrMoneyRange)
		}
		amount, err := AddFixed64(inputs[output.AssetID], output.Value)
		if err != nil {
			return nil, fmt.Errorf("transaction input amount: %w", err)
		}
		if !MoneyRange(amount) {
			return nil, fmt.Errorf("transaction input total: %w", ErrMoneyRange)
		}
		inputs[output.AssetID] = amount
	}
	for _, v := range tx.Outputs() {
		if !MoneyRange(v.Value) {
			return nil, fmt.Errorf("transaction output amount: %w", ErrMoneyRange)
		}
		amount, err := AddFixed64(outputs[v.AssetID], v.Value)
		if err != nil {
			return nil, fmt.Errorf("transaction output amount: %w", err)
		}
		if !MoneyRange(amount) {
			return nil, fmt.Errorf("transaction output total: %w", ErrMoneyRange)
		}
		outputs[v.AssetID] = amount
	}

	for outputAssetID, outputValue := range outputs {
		fee, err := SubtractFixed64(inputs[outputAssetID], outputValue)
		if err != nil {
			return nil, fmt.Errorf("transaction fee amount: %w", err)
		}
		feeMap[outputAssetID] = fee
	}
	for inputAssetID, inputValue := range inputs {
		if _, exist := feeMap[inputAssetID]; !exist {
			feeMap[inputAssetID] = inputValue
		}
	}

	return feeMap, nil
}

// GetTxFeeStrict returns the post-activation checked fee for one asset.
func GetTxFeeStrict(tx interfaces.Transaction, assetID Uint256,
	references map[*common.Input]common.Output) (Fixed64, error) {
	feeMap, err := GetTxFeeMapStrict(tx, references)
	if err != nil {
		return 0, err
	}

	return feeMap[assetID], nil
}

// GetTxFee is the pre-activation fee calculation.
//
// DO NOT "FIX" THE ARITHMETIC BELOW. Its signed 64-bit wrapping is
// bug-compatible with the consensus rules that validated every block before
// StrictMoneyRangeHeight. Historical coinbase outputs were validated against
// these wrapped totals, so reproducing them exactly is required for a node to
// replay the chain and sync past block 2260451. Post-activation callers must
// use GetTxFeeStrict instead.
func GetTxFee(tx interfaces.Transaction, assetId Uint256, references map[*common.Input]common.Output) Fixed64 {
	feeMap, err := GetTxFeeMap(tx, references)
	if err != nil {
		return 0
	}

	return feeMap[assetId]
}

func GetTxFeeMap(tx interfaces.Transaction, references map[*common.Input]common.Output) (map[Uint256]Fixed64, error) {
	feeMap := make(map[Uint256]Fixed64)
	var inputs = make(map[Uint256]Fixed64)
	var outputs = make(map[Uint256]Fixed64)

	for _, output := range references {
		amount, ok := inputs[output.AssetID]
		if ok {
			inputs[output.AssetID] = amount + output.Value
		} else {
			inputs[output.AssetID] = output.Value
		}
	}
	for _, v := range tx.Outputs() {
		amount, ok := outputs[v.AssetID]
		if ok {
			outputs[v.AssetID] = amount + v.Value
		} else {
			outputs[v.AssetID] = v.Value
		}
	}

	//calc the balance of input vs output
	for outputAssetid, outputValue := range outputs {
		if inputValue, ok := inputs[outputAssetid]; ok {
			feeMap[outputAssetid] = inputValue - outputValue
		} else {
			feeMap[outputAssetid] -= outputValue
		}
	}
	for inputAssetId, inputValue := range inputs {
		if _, exist := feeMap[inputAssetId]; !exist {
			feeMap[inputAssetId] += inputValue
		}
	}

	return feeMap, nil
}

// StrictMoneyActive reports whether strict monetary validation binds at height.
func (b *BlockChain) StrictMoneyActive(blockHeight uint32) bool {
	return blockHeight >= b.chainParams.StrictMoneyRangeHeight
}

// coinbaseTotalReward computes totalTxFee + block issuance.
//
// This is the single shared entry point for BOTH the AuxPoW (PoW consensus) and
// BPoS (DPoS v2) coinbase branches, so the two consensus modes enforce one
// identical rule set. At and above StrictMoneyRangeHeight the sum is checked and
// money-range bounded; below it the historical wrapping arithmetic is preserved
// verbatim so existing blocks continue to validate.
//
// Bounding the total here is sufficient for the downstream share arithmetic:
// every share is a fraction of a money-range-bounded value, so the subsequent
// multiplications and subtractions cannot overflow.
func (b *BlockChain) coinbaseTotalReward(blockHeight uint32,
	totalTxFee Fixed64) (Fixed64, error) {
	blockReward := b.chainParams.GetBlockReward(blockHeight)
	if !b.StrictMoneyActive(blockHeight) {
		return totalTxFee + blockReward, nil
	}

	totalReward, err := AddFixed64(totalTxFee, blockReward)
	if err != nil {
		return 0, fmt.Errorf("coinbase total reward: %w", err)
	}
	if !MoneyRange(totalReward) {
		return 0, fmt.Errorf("coinbase total reward: %w", ErrMoneyRange)
	}

	return totalReward, nil
}

// GetBlockDPOSRewardStrict is the post-activation form of GetBlockDPOSReward.
// GetBlockDPOSRewardStrict returns the DPoS arbiter reward leg for the coinbase
// at/above the gate. F-011/086: it takes the ELA-filtered totalTxFee (the same
// value the CR/miner legs use) rather than summing all-asset tx.Fee(), so a
// non-ELA fee can no longer inflate coinbase[2] above its ELA backing. For any
// all-ELA block totalTxFee == sum tx.Fee(), so this is byte-identical for every
// honest block (coinbase.Fee() is always 0).
func (b *BlockChain) GetBlockDPOSRewardStrict(blockHeight uint32, totalTxFee Fixed64) (Fixed64, error) {
	totalReward, err := b.coinbaseTotalReward(blockHeight, totalTxFee)
	if err != nil {
		return 0, err
	}

	return Fixed64(math.Ceil(float64(totalReward) * 0.35)), nil
}

// RecordCRCProposalAmountStrict is the post-activation form of
// RecordCRCProposalAmount; it rejects rather than wraps.
func RecordCRCProposalAmountStrict(usedAmount *Fixed64,
	txn interfaces.Transaction) error {
	proposal, ok := txn.Payload().(*payload.CRCProposal)
	if !ok {
		return nil
	}
	for _, bg := range proposal.Budgets {
		amount, err := AddFixed64(*usedAmount, bg.Amount)
		if err != nil {
			return fmt.Errorf("crc proposal budget: %w", err)
		}
		if !MoneyRange(amount) {
			return fmt.Errorf("crc proposal budget: %w", ErrMoneyRange)
		}
		*usedAmount = amount
	}

	return nil
}

func (b *BlockChain) GetBlockDPOSReward(block *Block) Fixed64 {
	totalTxFx := Fixed64(0)
	for _, tx := range block.Transactions {
		totalTxFx += tx.Fee()
	}
	return Fixed64(math.Ceil(float64(totalTxFx+
		b.chainParams.GetBlockReward(block.Height)) * 0.35))
}

func (b *BlockChain) checkCoinbaseTransactionContext(blockHeight uint32, coinbase interfaces.Transaction, totalTxFee, dposReward Fixed64) error {
	activeHeight := DefaultLedger.Arbitrators.GetDPoSV2ActiveHeight()
	if activeHeight != math.MaxUint32 && blockHeight > activeHeight+1 {
		totalReward, err := b.coinbaseTotalReward(blockHeight, totalTxFee)
		if err != nil {
			return err
		}
		rewardCyberRepublic := Fixed64(math.Ceil(float64(totalReward) * 0.3))
		rewardDposArbiter := Fixed64(math.Ceil(float64(totalReward) * 0.35))
		rewardMergeMiner := Fixed64(totalReward) - rewardCyberRepublic - rewardDposArbiter
		if coinbase.Outputs()[0].Value != rewardCyberRepublic {
			return errors.New("rewardCyberRepublic value not correct")
		}
		if coinbase.Outputs()[1].Value != rewardMergeMiner {
			return errors.New("rewardMergeMiner value not correct")
		}
		if len(coinbase.Outputs()) != 3 {
			return errors.New("coinbase only can have 3 outputs at the most when it is DPoS v2")
		}
		if coinbase.Outputs()[2].Value != dposReward {
			return errors.New("last DPoS reward value not correct")
		}

		if b.state.GetConsensusAlgorithm() == state.POW {
			if !coinbase.Outputs()[2].ProgramHash.IsEqual(*b.chainParams.DestroyELAProgramHash) {
				return errors.New("DPoS reward address not correct")
			}
			if !coinbase.Outputs()[0].ProgramHash.IsEqual(*b.chainParams.DestroyELAProgramHash) {
				return errors.New("rewardCyberRepublic address not correct")
			}
		} else {
			if !coinbase.Outputs()[0].ProgramHash.IsEqual(*b.chainParams.CRConfiguration.CRAssetsProgramHash) {
				return errors.New("rewardCyberRepublic address not correct")
			}
			if !coinbase.Outputs()[2].ProgramHash.IsEqual(*b.chainParams.DPoSConfiguration.DPoSV2RewardAccumulateProgramHash) {
				return errors.New("DPoS reward address not correct")
			}
		}

		return nil
	}

	// main version >= H2
	if blockHeight >= b.chainParams.PublicDPOSHeight {
		totalReward, err := b.coinbaseTotalReward(blockHeight, totalTxFee)
		if err != nil {
			return err
		}
		rewardDPOSArbiter := Fixed64(math.Ceil(float64(totalReward) * 0.35))
		if b.StrictMoneyActive(blockHeight) {
			// Checked form: GetFinalRoundChange() is otherwise unbounded and added
			// to a bounded reward, and the coinbase reward outputs skip the tx-level
			// money bound (checkTxsContext starts at index 1). Bound them here and
			// reject overflow rather than wrapping.
			expected, err := SubtractFixed64(totalReward, rewardDPOSArbiter)
			if err != nil {
				return fmt.Errorf("coinbase expected reward: %w", err)
			}
			expected, err = AddFixed64(expected, DefaultLedger.Arbitrators.GetFinalRoundChange())
			if err != nil {
				return fmt.Errorf("coinbase final round change: %w", err)
			}
			o0, o1 := coinbase.Outputs()[0].Value, coinbase.Outputs()[1].Value
			if !MoneyRange(o0) || !MoneyRange(o1) {
				return errors.New("coinbase reward output out of money range")
			}
			actual, err := AddFixed64(o0, o1)
			if err != nil {
				return fmt.Errorf("coinbase actual reward: %w", err)
			}
			if expected != actual {
				return errors.New("reward amount in coinbase not correct")
			}
		} else if totalReward-rewardDPOSArbiter+DefaultLedger.Arbitrators.
			GetFinalRoundChange() != coinbase.Outputs()[0].Value+
			coinbase.Outputs()[1].Value {

			return errors.New("reward amount in coinbase not correct")
		}

		if err := CheckCoinbaseArbitratorsReward(coinbase); err != nil {
			return err
		}
	} else { // old version [0, H2)
		// Branch reachable only below PublicDPOSHeight, which is far below any
		// StrictMoneyRangeHeight, so the checked path here is defensive: it keeps
		// one rule set if activation is ever configured lower on a test network.
		var rewardInCoinbase = Fixed64(0)
		for _, output := range coinbase.Outputs() {
			if !b.StrictMoneyActive(blockHeight) {
				rewardInCoinbase += output.Value
				continue
			}
			var err error
			rewardInCoinbase, err = AddFixed64(rewardInCoinbase, output.Value)
			if err != nil {
				return fmt.Errorf("coinbase output reward: %w", err)
			}
			if !MoneyRange(rewardInCoinbase) {
				return fmt.Errorf("coinbase output reward: %w", ErrMoneyRange)
			}
		}

		// Reward in coinbase must match inflation 4% per year
		if rewardInCoinbase-totalTxFee != b.chainParams.GetBlockReward(blockHeight) {
			return errors.New("Reward amount in coinbase not correct, " +
				"height:" + strconv.FormatUint(uint64(blockHeight),
				10) + "dposheight: " + strconv.FormatUint(uint64(config.
				DefaultParams.PublicDPOSHeight), 10))
		}
	}

	return nil
}

func CheckCoinbaseArbitratorsReward(coinbase interfaces.Transaction) error {
	rewards := DefaultLedger.Arbitrators.GetArbitersRoundReward()
	if len(rewards) != len(coinbase.Outputs())-2 {
		return errors.New("coinbase output count not match")
	}

	for i := 2; i < len(coinbase.Outputs()); i++ {
		amount, ok := rewards[coinbase.Outputs()[i].ProgramHash]
		if !ok {
			return errors.New("unknown dpos reward address")
		}
		if amount != coinbase.Outputs()[i].Value {
			return errors.New("incorrect dpos reward amount")
		}
	}

	return nil
}
