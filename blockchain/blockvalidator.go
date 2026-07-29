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
	"github.com/elastos/Elastos.ELA/vm"
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
	// At and above StrictMoneyRangeHeight, require the single canonical AuxPow
	// encoding so Header.HashWithAux() (the DPoSV2 committee seed) cannot be
	// malleated into a consensus split. ParentHash and the high bits of
	// ParMerkleIndex are unvalidated by AuxPow.Check yet feed HashWithAux(), while
	// the block identity Header.Hash() excludes the AuxPow, so two encodings of the
	// same block can seed two different committees at zero PoW cost. Below the gate
	// the check is skipped and retained history replays byte-identically: the last
	// non-canonical block on the retained chain is height 2,090,418, well below the
	// gate.
	if b.auxPowMalleationActive(header.Height) && !header.AuxPow.IsCanonical() {
		return errors.New("[PowCheckBlockSanity] non-canonical (malleable) AuxPow encoding")
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

// CheckSameBlockConflicts mirrors the mempool conflict slots at block level. The
// mempool conflictmanager rejects two conflicting stake/reward/withdraw/tracking
// transactions, but block validation does not consult the mempool, so an on-duty block
// producer can pack two conflicting transactions into one block and cause a double
// ReturnVotes/ClaimReward payout, a double RealWithdraw, a double unused-budget return,
// or cloned renewal votes. Each slot is keyed on the exact conflict identity (stake
// program hash, claim program hash, pending withdraw hash, proposal hash), so two
// different identities of the same transaction type in one block remain legitimate.
// Gated at StrictMoneyRangeHeight: below the gate this returns nil, so retained history
// re-derives byte-identically.
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
	proposalWithdraw := make(map[Uint256]struct{})      // mempool slotCRCProposalHash (queue side)
	returnDeposit := make(map[string]struct{})          // mempool slotProgramCode (return-deposit)
	claimNodeKeys := make(map[string]struct{})          // mempool slotCRCouncilMemberNodePublicKey
	proposalDraft := make(map[Uint256]struct{})         // mempool slotCRCProposalDraftHash
	sidechainWithdraw := make(map[Uint256]struct{})      // mempool slotSidechainTxHashes
	sidechainReturnDeposit := make(map[Uint256]struct{}) // mempool slotSidechainReturnDepositTxHashes
	nftDestroyIDs := make(map[Uint256]struct{})          // mempool slotNFTDestroyFromSideChainHash
	producerCRKeys := make(map[string]struct{})          // mempool slotDPoSOwnerPublicKey/slotDPoSNodePublicKey (producer/CR overlap)
	claimNodeDIDs := make(map[Uint168]struct{})          // mempool slotCRCouncilMemberDID
	specialTxHashes := make(map[Uint256]struct{})        // mempool slotSpecialTxHash (illegal-evidence / inactive-arbitrators)
	producerNicknames := make(map[string]struct{})       // mempool slotDPoSNickname
	// Block-scope accumulators for the NFTDestroy owner/NFT stake-address alias. The
	// per-transaction guard in nftdestroytransaction.go sees one payload at a time, and the
	// NFTDestroy arm below keys on the NFT id, so a two-transaction split is invisible to
	// both. Collected across the whole block and intersected after the loop, because the
	// naming transaction may precede the destroying transaction in block order.
	nftDestroyedStakeAddrs := make(map[Uint168]struct{}) // derived stake addr of every NFT destroyed anywhere in this block
	nftNamedOwners := make([]Uint168, 0)                 // every OwnerStakeAddresses entry named anywhere in this block
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
			// Mirror mempool slotCRCProposalHash (queue side). Two same-block V1 withdraws
			// for the same proposal both pass ContextCheck (the first's WithdrawnBudgets
			// update commits only post-validation) and each queue a WithdrawableTxInfo entry
			// keyed by tx hash, which pays CRExpenses twice.
			p, ok := txn.Payload().(*payload.CRCProposalWithdraw)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposalWithdraw payload")
			}
			if _, exists := proposalWithdraw[p.ProposalHash]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-proposal withdraw")
			}
			proposalWithdraw[p.ProposalHash] = struct{}{}
		case common.ReturnDepositCoin, common.ReturnCRDepositCoin:
			// Mirror mempool slotProgramCode. Two same-block deposit returns with the same
			// program code (producer or CR) but disjoint deposit UTXOs both read the same
			// committed availableAmount and each refund up to it, escaping the block
			// dup-UTXO check, which over-refunds the forfeited bond. The mempool already
			// forbids this pairing, so no honest mempool-built block is affected; this
			// catches a malicious producer.
			if len(txn.Programs()) == 0 {
				return errors.New("[PowCheckBlockSanity] return deposit tx without program")
			}
			codeKey := BytesToHexString(txn.Programs()[0].Code)
			if _, exists := returnDeposit[codeKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting same-code deposit return")
			}
			returnDeposit[codeKey] = struct{}{}
		case common.CRCouncilMemberClaimNode:
			// Mirror mempool slotCRCouncilMemberNodePublicKey. Two same-block claims of the
			// same node public key by distinct members both pass, since the key is absent
			// from pre-block ClaimedDPoSKeys, binding two CR members to one DPoS node key
			// and breaking the node-key uniqueness invariant.
			p, ok := txn.Payload().(*payload.CRCouncilMemberClaimNode)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCouncilMemberClaimNode payload")
			}
			nodeKey := BytesToHexString(p.NodePublicKey)
			if _, exists := claimNodeKeys[nodeKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR claim DPOS node public key")
			}
			claimNodeKeys[nodeKey] = struct{}{}
			// CRCouncilMemberClaimNode is the fifth member of the single mempool
			// slotDPoSNodePublicKey slot, but at block level its node key reaches only
			// claimNodeKeys, the claim-vs-claim map, which is never compared against the
			// producer/CR key map. Without the entry below, RegisterProducer or
			// UpdateProducer(node=X) together with CRCouncilMemberClaimNode(X) in one block both
			// pass: the producer side's ProducerOrCRNodePublicKeyExists and the claim side's
			// ClaimedDPoSKeys / ProducerAndCurrentCRNodePublicKeyExists are all committed-state
			// reads that cannot see the sibling transaction, and no block-level structure compared
			// the two. Feed the shared producerCRKeys map as well. claimNodeKeys stays: it is the
			// claim-vs-claim guard and carries its own distinct error.
			//
			// producerCRKeys is a single map holding producer owner keys, producer node keys,
			// RegisterCR keys and claimed node keys, mirroring the mempool's
			// strDPoSOwnerNodePublicKeys array slot. The mempool keeps owner keys and node keys in
			// two separate slots and CRCouncilMemberClaimNode belongs to the node slot only, so a
			// block pairing a producer owner key with a claimed node key is rejected here although
			// it is not a mempool conflict. That asymmetry is stricter than the mempool, never
			// looser, and deterministic, which is what makes it safe: nothing the mempool rejects
			// is accepted here, and every node reaches the same verdict on the same block.
			if _, exists := producerCRKeys[nodeKey]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting producer/CR public key")
			}
			producerCRKeys[nodeKey] = struct{}{}
			// Mirror mempool slotCRCouncilMemberDID. processCRCouncilMemberClaimNode captures
			// the member's old DPoS key and member state outside the History forward closure
			// (oriPublicKey/oriMemberState/oriInactiveCount are read at process time, so they
			// hold pre-block state). A second claim by the same council member in one block,
			// with a different node key so the node-key guard above does not catch it, touches
			// that member twice; the History comment states such capture-outside-revert patterns
			// are only safe if no two same-block changes touch the same key. The mempool forbids
			// this pairing (slotCRCouncilMemberDID), so no honest mempool-built block is
			// affected; this catches a malicious block-packer. Reject a repeated council-member
			// DID.
			if _, exists := claimNodeDIDs[p.CRCouncilCommitteeDID]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate CR claim council member DID")
			}
			claimNodeDIDs[p.CRCouncilCommitteeDID] = struct{}{}
		case common.CRCProposal:
			// Mirror mempool slotCRCProposalDraftHash, DraftHash only. A same-block duplicate
			// DraftHash is never legitimate (the draft hash is a hash over the draft data), it
			// breaks the ExistDraft uniqueness invariant and it shares a
			// ProposalDraftDataBucketName key, which corrupts rollback. DID and CustomID
			// uniqueness are not promoted here: a member may legitimately file multiple proposals
			// with distinct drafts.
			p, ok := txn.Payload().(*payload.CRCProposal)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid CRCProposal payload")
			}
			if _, exists := proposalDraft[p.DraftHash]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate proposal draft hash")
			}
			proposalDraft[p.DraftHash] = struct{}{}
		case common.WithdrawFromSideChain:
			// Mirror mempool slotSidechainTxHashes. The committed IsSidechainTxHashDuplicate
			// read does not see an earlier same-block tx (Tx3Index is written
			// post-validation), and V1/V2 carry the hash in output payloads that
			// CheckDuplicateTx never inspects, so two same-block withdraws crediting one
			// sidechain burn both pass and the main chain is credited twice. Reject a
			// repeated sidechain tx hash.
			for _, h := range sidechainWithdrawHashes(txn) {
				if _, exists := sidechainWithdraw[h]; exists {
					return errors.New("[PowCheckBlockSanity] block contains duplicate sidechain withdraw hash")
				}
				sidechainWithdraw[h] = struct{}{}
			}
		case common.ReturnSideChainDepositCoin:
			// Mirror mempool slotSidechainReturnDepositTxHashes. The committed
			// IsSidechainReturnDepositTxHashDuplicate read does not see an earlier same-block
			// tx, so two same-block returns refunding one sidechain deposit both pass and the
			// deposit is refunded twice. Reject a repeated deposit tx hash.
			for _, h := range sidechainReturnDepositHashes(txn) {
				if _, exists := sidechainReturnDeposit[h]; exists {
					return errors.New("[PowCheckBlockSanity] block contains duplicate sidechain return-deposit hash")
				}
				sidechainReturnDeposit[h] = struct{}{}
			}
		case common.NFTDestroyFromSideChain:
			// Mirror mempool slotNFTDestroyFromSideChainHash. NFTDestroy SpecialContextCheck
			// reads committed state only, so two same-block NFTDestroy txs sharing an NFT id
			// both pass and double-apply the destroy. Reject a repeated id. Gated with the
			// function, which returns nil below `gate`.
			if p, ok := txn.Payload().(*payload.NFTDestroyFromSideChain); ok {
				for _, id := range p.IDs {
					if _, exists := nftDestroyIDs[id]; exists {
						return errors.New("[PowCheckBlockSanity] block contains duplicate NFTDestroy id")
					}
					nftDestroyIDs[id] = struct{}{}
					// Record this NFT's derived stake address, the key
					// processNFTDestroyFromSideChain folds DPoSV2RewardInfo out of. Derivation is
					// identical to the per-transaction guard in nftdestroytransaction.go. A derivation
					// error is left to the per-transaction SpecialContextCheck, which reports the
					// canonical error, exactly as the RegisterCR arm below leaves a malformed code to
					// its own checker.
					if ct, err := contract.CreateStakeContractByCode(id.Bytes()); err == nil {
						nftDestroyedStakeAddrs[*ct.ToProgramHash()] = struct{}{}
					}
				}
				nftNamedOwners = append(nftNamedOwners, p.OwnerStakeAddresses...)
			}
		case common.RegisterProducer:
			// Mirror mempool slotDPoSOwnerPublicKey and slotDPoSNodePublicKey, the
			// producer/CR-overlap slots. RegisterProducer.SpecialContextCheck rejects a key
			// already registered as a producer (ProducerOwnerPublicKeyExists /
			// ProducerOrCRNodePublicKeyExists) or as a CR (ExistCR), but those read committed
			// state only, so two same-block registrations sharing a key, or a RegisterProducer
			// and a RegisterCR keyed on the same public key, both pass and bind one key to two
			// identities. Reject a repeated producer owner or node public key.
			p, ok := txn.Payload().(*payload.ProducerInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid RegisterProducer payload")
			}
			for _, k := range dedupHexKeys(p.OwnerKey, p.NodePublicKey) {
				if _, exists := producerCRKeys[k]; exists {
					return errors.New("[PowCheckBlockSanity] block contains conflicting producer/CR public key")
				}
				producerCRKeys[k] = struct{}{}
			}
			// The RegisterProducer half of mempool slotDPoSNickname. See addProducerNickname
			// for what the block level enforces.
			if err := addProducerNickname(producerNicknames, p.NickName); err != nil {
				return err
			}
		case common.UpdateProducer:
			// UpdateProducer is one of the five transaction types the mempool holds in a single
			// slotDPoSNodePublicKey slot (mempool/conflictmanager.go:175-199) and is also a member
			// of slotDPoSOwnerPublicKey and slotDPoSOwnerNodePublicKeys.
			//
			// CheckDuplicateTx (upstream, ungated, runs on every block) already shares
			// existingProducer across RegisterProducer/UpdateProducer/CancelProducer and
			// existingProducerNode across RegisterProducer/UpdateProducer, so a repeated producer
			// owner key and a repeated producer node key are rejected there.
			//
			// What this arm adds is the cross-identity pairing, which CheckDuplicateTx cannot see
			// because it has no RegisterCR and no CRCouncilMemberClaimNode arm:
			// UpdateProducer(node=X) plus RegisterCR(key=X) in one block otherwise both pass, since
			// UpdateProducer's ExistCR(nodeCode) read (updateproducertransaction.go) and
			// RegisterCR's ProducerExists read (registercrtransaction.go) are both committed-state
			// reads and neither can see the sibling transaction. One DPoS node public key would end
			// up bound to a producer identity and a CR identity, the uniqueness invariant that
			// arbiter-membership resolution, reward attribution and illegal-evidence slashing all
			// rest on. The corruption is deterministic, so it does not fork the chain.
			//
			// Feed the same shared producerCRKeys map the RegisterProducer and RegisterCR arms use,
			// keyed on owner and node key through dedupHexKeys, which mirrors the mempool's
			// strDPoSOwnerNodePublicKeys owner==node dedup so a producer whose owner key equals its
			// own node key does not self-collide.
			p, ok := txn.Payload().(*payload.ProducerInfo)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid UpdateProducer payload")
			}
			for _, k := range dedupHexKeys(p.OwnerKey, p.NodePublicKey) {
				if _, exists := producerCRKeys[k]; exists {
					return errors.New("[PowCheckBlockSanity] block contains conflicting producer/CR public key")
				}
				producerCRKeys[k] = struct{}{}
			}
			// The UpdateProducer half of mempool slotDPoSNickname.
			if err := addProducerNickname(producerNicknames, p.NickName); err != nil {
				return err
			}
		case common.RegisterCR:
			// The RegisterCR side of the same two mempool slots. RegisterCR rejects a public key
			// already in the producer list (ProducerExists) but reads committed state only, so a
			// same-block RegisterCR plus RegisterProducer, or a second RegisterCR, sharing one key
			// both pass. Extract the CR registration public key exactly as the RegisterCR check
			// derives the key it feeds to ProducerExists.
			key, ok := registerCRConflictKey(txn)
			if !ok {
				// Malformed / unsupported CR code: leave rejection to the per-tx
				// SpecialContextCheck (canonical error); do not seed the shared map.
				break
			}
			if _, exists := producerCRKeys[key]; exists {
				return errors.New("[PowCheckBlockSanity] block contains conflicting producer/CR public key")
			}
			producerCRKeys[key] = struct{}{}
		case common.IllegalProposalEvidence, common.IllegalVoteEvidence,
			common.IllegalBlockEvidence, common.IllegalSidechainEvidence,
			common.InactiveArbitrators:
			// Mirror mempool slotSpecialTxHash for the illegal-evidence and
			// inactive-arbitrators special txs. The committed-state dedup
			// GetState().SpecialTxExists reads pre-block state, so it never sees an earlier
			// same-block evidence tx; CheckDuplicateTx keys on the full tx hash, which two AuxPow
			// re-encodings of one logical illegal block, or any two txs wrapping one logical
			// evidence payload with differing tx-level bytes, do not share. Both txs would
			// otherwise pass and processIllegalEvidence / processEmergencyInactiveArbitrators
			// would run twice, applying the illegal penalty twice to a guilty double-signer
			// (bounded by block size, deterministic and non-forking). Key by the same logical
			// identity the committed dedup uses (payload.SpecialTxDedupKey at
			// StrictMoneyRangeHeight == gate) so the re-encodings collide within the block, and
			// reject the second. The mempool slot this mirrors covers all five special-tx types,
			// so all five share this arm.
			//
			// The arm covers five types; the fold covers three. At and above the gate
			// SpecialTxDedupKey folds DPOSIllegalBlocks to an AuxPow-independent block identity,
			// and DPOSIllegalProposals / DPOSIllegalVotes to a BlockHeader-independent evidence
			// identity, because one appended byte to the raw header blob otherwise mints a fresh
			// key and so one equivocation mints unbounded distinct evidence transactions.
			// SidechainIllegalData and InactiveArbitrators keep the raw payload Hash(); neither
			// carries a malleable raw header blob.
			//
			// Evidence whose own BlockHeight is below the gate but which is included above it
			// stays raw-keyed, matching SpecialTxExists and recordSpecialTx exactly: read and
			// write must agree, so this guard must not re-key independently.
			illegalData, ok := txn.Payload().(payload.DPOSIllegalData)
			if !ok {
				return errors.New("[PowCheckBlockSanity] invalid illegal-evidence special tx payload")
			}
			key := payload.SpecialTxDedupKey(illegalData, gate)
			if _, exists := specialTxHashes[key]; exists {
				return errors.New("[PowCheckBlockSanity] block contains duplicate illegal-evidence special tx")
			}
			specialTxHashes[key] = struct{}{}
		}
	}
	// The per-transaction guard in nftdestroytransaction.go rejects only an
	// OwnerStakeAddresses entry that aliases an NFT stake address destroyed by the same
	// payload, so the vector splits across two same-block NFTDestroy txs: tx1 destroys NFT
	// A naming NFT B's derived stake address, tx2 destroys NFT B. Each payload passes the
	// per-transaction guard trivially (the sets are disjoint) and the NFTDestroy arm above
	// passes too (A != B), yet the state-apply forwards compose at Commit: state.go's
	// `DPoSV2RewardInfo[owner] += DPoSV2RewardInfo[nftStake]` is a live lookup, so tx2
	// reads B's key after tx1 folded A's reward into it, and a reorg then misallocates A's
	// claimable reward. This misallocates a claimable balance; no mint and no supply
	// inflation is involved. The block is the only scope at which the composition is
	// visible, so reject it here. This is a post-loop intersection rather than an in-loop
	// check because the naming tx may come first in block order, before the aliased NFT's
	// id has been seen. A legitimate new owner is a user stake address, never a derived NFT
	// stake address, so this rejects only the attack. Gated with the function, which
	// returns nil below `gate` == StrictMoneyRangeHeight, so retained history re-derives
	// byte-identically.
	if len(nftDestroyedStakeAddrs) != 0 {
		for _, owner := range nftNamedOwners {
			if _, clash := nftDestroyedStakeAddrs[owner]; clash {
				return errors.New("[PowCheckBlockSanity] block contains NFTDestroy owner stake address aliasing an NFT stake address destroyed in the same block")
			}
		}
	}
	return nil
}

// addProducerNickname mirrors the mempool slotDPoSNickname slot
// (mempool/conflictmanager.go:235-248, RegisterProducer plus UpdateProducer, keyed on
// ProducerInfo.NickName) at block level.
//
// Both producer transactions check nickname uniqueness with GetState().NicknameExists, a
// committed-state read that cannot see an earlier transaction in the same block, so two
// same-block registrations or updates binding one nickname to two different owner keys
// both pass. StateKeyFrame.Nicknames is a set (dpos/state/keyframe.go), so the two forward
// inserts are idempotent while the two reverts each delete once: one cancel or one reorg
// then frees a nickname another live producer still holds, breaking the uniqueness
// invariant in the durable direction.
//
// An empty nickname is not keyed. checkStringField(NickName, allowEmpty=false) rejects it
// per transaction anyway, and keying it would let two malformed payloads collide here and
// be reported as a conflict rather than as the malformed payloads they are.
func addProducerNickname(seen map[string]struct{}, nickname string) error {
	if nickname == "" {
		return nil
	}
	if _, exists := seen[nickname]; exists {
		return errors.New("[PowCheckBlockSanity] block contains conflicting producer nickname")
	}
	seen[nickname] = struct{}{}
	return nil
}

// dedupHexKeys returns the hex encodings of the given public keys with duplicates
// removed, so a producer whose owner key equals its own node key contributes a single
// shared-map entry (mirrors the mempool strDPoSOwnerNodePublicKeys owner==node dedup) and
// does not self-collide.
func dedupHexKeys(keys ...[]byte) []string {
	out := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		s := BytesToHexString(k)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// registerCRConflictKey extracts the RegisterCR registration public key the same way the
// RegisterCR SpecialContextCheck derives the key it feeds to GetState().ProducerExists
// (and the same way the mempool strRegisterCRPublicKey keys slotDPoSOwnerPublicKey), so a
// collision with a producer owner/node key is detected. It is bounds-safe against a
// crafted short code (CheckSameBlockConflicts runs before the per-tx payload check) and
// returns false for a malformed / unsupported code, leaving rejection to that per-tx check.
func registerCRConflictKey(txn interfaces.Transaction) (string, bool) {
	p, ok := txn.Payload().(*payload.CRInfo)
	if !ok {
		return "", false
	}
	var code []byte
	if txn.PayloadVersion() == payload.CRInfoSchnorrVersion ||
		txn.PayloadVersion() == payload.CRInfoMultiSignVersion {
		if len(txn.Programs()) == 0 || txn.Programs()[0] == nil {
			return "", false
		}
		code = txn.Programs()[0].Code
	} else {
		code = p.Code
	}
	if contract.IsSchnorr(code) {
		return BytesToHexString(code[2:]), true
	}
	if len(code) < 2 {
		return "", false
	}
	switch code[len(code)-1] {
	case vm.CHECKSIG:
		return BytesToHexString(code[1 : len(code)-1]), true
	case vm.CHECKMULTISIG:
		return BytesToHexString(code), true
	default:
		return "", false
	}
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

// checkCoinbaseBIP30 enforces the coinbase BIP30 rule on the block-connect path. The
// coinbase carries its own IsTxHashDuplicate guard (coinbasetransaction.go) but that
// guard is dead on connect: checkTxsContext validates only txs[1:], so the coinbase at
// index 0 never runs it, and a malicious block producer could replay a prior identical
// coinbase (same txid) to resurrect already-spent coinbase outputs. At and above the
// gate, reject a block whose coinbase txid already exists in the ledger. Below the gate
// the check is skipped so retained history replays byte-identically. isDuplicate is
// injected so the rule can be tested without a ledger.
func checkCoinbaseBIP30(coinbaseHash Uint256, height, gate uint32, isDuplicate func(Uint256) bool) error {
	if height < gate {
		return nil
	}
	if isDuplicate(coinbaseHash) {
		return errors.New("coinbase transaction hash already exists (BIP30)")
	}
	return nil
}

// checkTxsContext validates every non-coinbase transaction of block in the context
// of the chain ending at prevNode, the block's own parent, not the validating
// node's best tip.
func (b *BlockChain) checkTxsContext(block *Block, prevNode *BlockNode) error {
	if len(block.Transactions) > 0 {
		if err := checkCoinbaseBIP30(block.Transactions[0].Hash(), block.Height,
			b.chainParams.StrictMoneyRangeHeight, b.db.IsTxHashDuplicate); err != nil {
			return elaerr.SimpleWithMessage(elaerr.ErrBlockValidation, nil, err.Error())
		}
	}
	var totalTxFee = Fixed64(0)

	var proposalsUsedAmount Fixed64
	for i := 1; i < len(block.Transactions); i++ {
		references, errCode := b.CheckTransactionContextWithPrev(prevNode,
			block.Height, block.Transactions[i], proposalsUsedAmount, block.Timestamp)
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
	// At and above RevisedDPoSRewardHeight the arbiter reward leg derives from the
	// ELA-filtered totalTxFee, the same basis as the CR and miner legs, rather than from the
	// all-asset tx.Fee() sum, so a non-ELA fee cannot inflate coinbase[2] above its ELA
	// backing. This is a reward-rule change and activates at RevisedDPoSRewardHeight, not at
	// the incident-recovery gate StrictMoneyRangeHeight.
	//
	// Activating at RevisedDPoSRewardHeight cannot split the fleet: no output anywhere on the
	// retained chain carries a non-ELA AssetID, and RegisterAsset is rejected at and above
	// StrictMoneyRangeHeight, so no non-ELA asset can appear after the restart either. With
	// every fee in ELA the two bases are the same number, and the coinbase contributes 0 to
	// both, since CalculateTxsFee skips it and this loop sums from i=1. No over-issue has
	// occurred and the precondition is unreachable after the restart; the strict form stays so
	// that a future asset type cannot reopen it.
	//
	// The reward split itself is unchanged: ceil(0.3R) to CR, ceil(0.35R) to arbiters,
	// remainder to the miner, at halving factor 3 (R = 76,103,500 sela; the next halving is at
	// height 3,153,600, far outside this window).
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

		// The in-block RecordSponsor payload is not compared against
		// lastBlock.Confirm.Proposal.Sponsor as a validity rule, and must not be. That
		// comparand is not a function of the chain:
		//   * nothing commits to it. Block.Hash() covers only the header; the Confirm
		//     rides alongside in types.DposBlock and is persisted per node by
		//     dbStoreBlock (blockchain.go connectBlockBracketed).
		//   * producer and validator derive it by different rules. The miner reads it
		//     raw (pow/service.go GenerateBlock -> bestBlock.Confirm.Proposal.Sponsor);
		//     a validator resolving it through the operator-local
		//     BlockConfirmProposalSponsors override map would turn any override entry
		//     for a height at or above the gate into a deterministic self-inflicted
		//     halt: every node holding the file rejects the block every miner produces.
		//   * honest nodes legitimately disagree about it. On a DPoS view change
		//     DPOSOnDutyHandler.ChangeView re-proposes the same block hash under a new
		//     Sponsor (proposaldispatcher.go StartProposal), and
		//     IllegalBehaviorMonitor.isProposalsIllegal returns false the instant the two
		//     proposals share a BlockHash, so two valid confirms with different sponsors
		//     can exist, mempool/blockpool.go appendConfirm keeps whichever arrived last,
		//     and each node then re-serves its own via pushConfirmedBlockMsg.
		// Bound as a validity rule at RevisedDPoSRewardHeight, a few thousand blocks past the
		// restart tip, this would be a permanent, unrecoverable consensus split.
		//
		// It is not re-expressed as a reward rule either. Upstream's RecordSponsor design
		// (live from RecordSponsorStartHeight) exists precisely to move sponsor
		// attribution off the node-local confirm and into the block: above that height
		// accumulateReward keys on the in-block payload, and only the pre-RecordSponsor
		// branch still reads confirm.Proposal.Sponsor with the override applied. Crediting
		// from the confirm again would push node-local state back into DPoSV2RewardInfo,
		// which DPoSV2ClaimRewardTransaction validates against, trading a fast fork for a
		// slow one. The residual exposure is accepted: a block producer may name any
		// current or last arbiter (recordsponsortransaction.go SpecialContextCheck still
		// enforces membership) and redistribute a conserved, non-inflationary sponsor
		// reward between arbiters. There is no supply effect.
		//
		// The confirm-presence checks above are upstream (d8488bf) and stay: presence is
		// agreed by every node in the view-change case, where both competing confirms are
		// present, whereas identity is not. Forged-confirm presence in PoW mode is a
		// separate concern and is not handled here.
		//
		// What is left is a diagnostic. It returns no error, is reached on every block, and
		// can never reject one, but it is the only fleet-visible signal that this node's
		// stored confirm disagrees with the block producer's, which is the partition
		// symptom.
		if recordSponsorExist && !bytes.Equal(recordedSponsor, lastBlock.Confirm.Proposal.Sponsor) {
			log.Warnf("[CheckBlockContext] RECORD SPONSOR DIVERGENCE at height %d: the block "+
				"records sponsor %s for height %d, but this node's stored confirm names %s. "+
				"This is NOT a validity failure (NX-01) and the block is accepted; if it "+
				"persists, this node holds a different confirm from the block producer.",
				block.Height, BytesToHexString(recordedSponsor),
				lastBlock.Height, BytesToHexString(lastBlock.Confirm.Proposal.Sponsor))
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
	return b.checkTxsContext(block, prevNode)
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
//
// It also rejects a negative per-asset fee. SubtractFixed64 guards overflow but not
// sign, so an asset that appears in the outputs with no, or insufficient, input
// backing would simply produce feeMap[asset] < 0 and no error. Because every caller
// asks only for feeMap[core.ELAAssetID], a negative entry for some other asset would
// be silently discarded, which is the missing per-asset conservation rule: a
// transaction could emit value in an asset it never spent. It is also the leg that
// turns a fabricated coinbase asset into ELA: inputs {FAKE:X, ELA:Y} -> outputs
// {ELA:Y+X-fee} leaves feeMap[ELA] = -(X-fee), accepted without this check, and
// feeMap[FAKE] = X, minting X-fee ELA that no ELA input backs. Rejecting the negative
// entry makes conservation explicit and per-asset: for every asset, outputs <=
// inputs, with the coinbase, the one transaction allowed to create value,
// structurally excluded from this path (checkTxsContext iterates from index 1, and
// mempool/txpool.go rejects a coinbase outright).
//
// No documented tx type needs an exception: every non-coinbase type either has zero
// outputs (illegal-evidence, UpdateVersion, ActivateProducer, RevertToPOW/DPOS,
// CustomIDResult, DposV2ClaimReward, NextTurnDPOSInfo) or spends real UTXOs for its
// outputs (transfer, CRCAppropriation, CRCProposal*Withdraw, ReturnSideChainDepositCoin,
// ExchangeVotes/ReturnVotes), so none legitimately runs an asset negative.
//
// The function itself carries no block height, but it does not need one: BOTH of its
// production call sites are already inside `>= StrictMoneyRangeHeight` branches
// (checkTxsContext above, and DefaultChecker.ContextCheck in
// core/transaction/transactionchecker.go), and the pre-gate paths use GetTxFeeMap /
// GetTxFee, which are untouched. Below the gate nothing about fee acceptance changes.
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
		// Per-asset conservation. A negative fee means this transaction
		// emitted more of outputAssetID than it spent, that is, created value
		// out of nothing in that asset.
		if !MoneyRange(fee) {
			return nil, fmt.Errorf("transaction fee amount for asset %s: %w",
				outputAssetID.String(), ErrMoneyRange)
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

// auxPowMalleationActive reports whether the canonical-AuxPow requirement binds at
// the given height: true at and above StrictMoneyRangeHeight. It shares that gate so
// no third activation height is introduced.
func (b *BlockChain) auxPowMalleationActive(blockHeight uint32) bool {
	return blockHeight >= b.chainParams.StrictMoneyRangeHeight
}

// IllegalEvidenceStrictActive reports whether the strict illegal-evidence validation
// binds at the given height: true at and above StrictMoneyRangeHeight. It gates the
// evidence signer set-equality check and the height-scoped confirm voter universe
// inside CheckDPOSIllegalBlocks. It shares the same gate so no third activation height
// is introduced; below it, illegal-evidence transactions validate exactly as before and
// replay byte-identically. The dedup-key canonicalization is gated separately, on the
// evidence's own BlockHeight, in payload.SpecialTxDedupKey.
func (b *BlockChain) IllegalEvidenceStrictActive(blockHeight uint32) bool {
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

// GetBlockDPOSRewardStrict is the post-activation form of GetBlockDPOSReward. It
// returns the DPoS arbiter reward leg for the coinbase at and above
// RevisedDPoSRewardHeight, taking the ELA-filtered totalTxFee (the same value the CR
// and miner legs use) rather than summing all-asset tx.Fee(), so a non-ELA fee cannot
// inflate coinbase[2] above its ELA backing. For any all-ELA block totalTxFee equals
// the sum of tx.Fee(), so this is byte-identical for every honest block; the coinbase's
// own Fee() is always 0.
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

// GetBlockDPOSReward is the pre-RevisedDPoSRewardHeight arbiter reward leg. The fee
// total is not summed here: it comes from state.SumBlockTxFees, the single definition
// shared with the DPoS reward state (dpos/state/arbitrators.go getBlockDPOSReward), so
// the validator and the state cannot drift apart. Below the gate SumBlockTxFees returns
// the legacy expression verbatim, so this is byte-identical.
func (b *BlockChain) GetBlockDPOSReward(block *Block) Fixed64 {
	totalTxFx := state.SumBlockTxFees(block.Transactions, block.Height,
		b.chainParams.RevisedDPoSRewardHeight)
	return Fixed64(math.Ceil(float64(totalTxFx+
		b.chainParams.GetBlockReward(block.Height)) * 0.35))
}

// checkCoinbaseFrozenOutputs applies the frozen-address rule to the coinbase, which is
// the one transaction that never runs checkFrozenAddresses. checkTxsContext validates
// only txs[1:], and the coinbase's own ContextCheck / SpecialContextCheck are dead on
// connect (the same reason the coinbase BIP30 guard lives in this file), so the "no
// sends to a frozen address" half of the frozen-address rule was unenforced on the
// coinbase path. The coinbase merge-miner output (Outputs[1]) carries no address
// constraint in checkCoinbaseTransactionContext, so a producer could direct the block
// reward into a quarantined exploit address. At and above the gate any coinbase output
// paying a frozen address is rejected; below the gate the check is skipped so
// retained-history replay stays byte-identical.
func checkCoinbaseFrozenOutputs(coinbase interfaces.Transaction, blockHeight, gate uint32,
	frozenAddresses []config.FrozenAddress) error {
	if blockHeight < gate {
		return nil
	}
	for _, frozen := range frozenAddresses {
		if frozen.ProgramHash == nil || blockHeight < frozen.DisableStartHeight {
			continue
		}
		for _, output := range coinbase.Outputs() {
			if output.ProgramHash.IsEqual(*frozen.ProgramHash) {
				return fmt.Errorf("cannot send to the frozen address %s in coinbase", frozen.Address)
			}
		}
	}
	return nil
}

// checkCoinbaseLockTimePin pins the coinbase LockTime on the block-connect path. The pin
// also exists in CoinBaseTransaction.SpecialContextCheck, where nothing on the
// block-connect path reaches it: that method's only caller is the coinbase's own
// ContextCheck override, whose only non-test caller is BlockChain.CheckTransactionContext
// (blockchain/txvalidator.go), and every one of that function's four call sites
// structurally excludes the coinbase. checkTxsContext and pow/service.go both iterate from
// index 1, and the mempool rejects a coinbase outright (mempool/txpool.go, "coinbase tx
// cannot be added into transaction pool"). checkCoinbaseBIP30 and
// checkCoinbaseFrozenOutputs live in this file for the same reason. A test that calls the
// coinbase method directly does not exercise the connect path and cannot show the pin is
// armed.
//
// Why the pin matters: checkInvalidUTXO (core/transaction/transactionchecker.go) derives
// the CoinbaseMaturity window from the coinbase's own LockTime, so a block producer, which
// already chooses its coinbase and whose Outputs[1] pays an address of its choosing, can
// set LockTime = 0 (mature immediately) or any value above the spending height (the uint32
// subtraction underflows to about 4e9, also mature) and spend its reward before the
// 100-block reorg-safety window. The reward amount is unchanged and is separately
// validated by checkCoinbaseTransactionContext below, so no inflation is involved.
//
// Gated at StrictMoneyRangeHeight; no new gate is introduced. Over the retained chain no
// coinbase has a LockTime different from its own block height, none has LockTime 0 and
// none has LockTime above its height, so arming the pin on the real path rejects no
// retained block and replays byte-identically.
func checkCoinbaseLockTimePin(coinbase interfaces.Transaction, blockHeight, gate uint32) error {
	if blockHeight < gate {
		return nil
	}
	if coinbase.LockTime() != blockHeight {
		return errors.New("coinbase locktime must equal block height")
	}
	return nil
}

func (b *BlockChain) checkCoinbaseTransactionContext(blockHeight uint32, coinbase interfaces.Transaction, totalTxFee, dposReward Fixed64) error {
	// Enforce the frozen-address "no sends to" rule on the coinbase path, which
	// otherwise bypasses checkFrozenAddresses entirely (see checkCoinbaseFrozenOutputs).
	if err := checkCoinbaseFrozenOutputs(coinbase, blockHeight,
		b.chainParams.StrictMoneyRangeHeight, b.chainParams.FrozenAddresses); err != nil {
		return err
	}
	// The coinbase LockTime pin, applied on the path that runs on block connect rather
	// than in the coinbase's own unreachable SpecialContextCheck. Same gate, same rule
	// (see checkCoinbaseLockTimePin).
	if err := checkCoinbaseLockTimePin(coinbase, blockHeight,
		b.chainParams.StrictMoneyRangeHeight); err != nil {
		return err
	}
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
