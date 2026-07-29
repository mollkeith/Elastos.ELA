// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// CR/CRC same-block cluster (F-047 dup proposal-withdraw, F-068 return-deposit overspend,
// F-071 ClaimNode node-key collision, F-072 dup proposal draft) — empirical in-block
// conflict proofs. Each mirrors an unmirrored mempool conflict slot at block level:
//   - EXPLOIT/FIX: two conflicting txs (same ProposalHash / program code / NodePublicKey /
//     DraftHash) in one block at/above the gate -> rejected.
//   - REPLAY: the same block below the gate -> accepted (byte-identical legacy).
//   - RELATED-TX: two DISTINCT identities of the same tx type in one block -> accepted.
// The downstream value DRAINs (2xAmount CRExpenses payout, over-refunded bond, reward
// miscount) are NEEDS-SIM and stay DEFERRED per the never-infer-inflation rule; these
// tests prove ONLY the in-block-conflict ADD. Reuses the f028_sameblock_test.go helpers.
package blockchain_test

import (
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/contract"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"

	"github.com/stretchr/testify/assert"
)

// f047Code returns a fresh valid standard redeem script (distinct program hash per call).
func f047Code(t *testing.T) []byte {
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	code, err := contract.CreateStandardRedeemScript(pub)
	assert.NoError(t, err)
	return code
}

// f047NodeKey returns a fresh compressed public key ([]byte) for ClaimNode.
func f047NodeKey(t *testing.T) []byte {
	_, pub, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pk, err := pub.EncodePoint(true)
	assert.NoError(t, err)
	return pk
}

// TestF047ProposalWithdrawConflict — two CRCProposalWithdraw for the SAME proposal.
func TestF047ProposalWithdrawConflict(t *testing.T) {
	h := common.Uint256{4, 7}
	other := common.Uint256{4, 8}
	w1 := f028Tx(common2.CRCProposalWithdraw, 1, &payload.CRCProposalWithdraw{ProposalHash: h}, nil)
	w2 := f028Tx(common2.CRCProposalWithdraw, 1, &payload.CRCProposalWithdraw{ProposalHash: h}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, w2), f028Gate),
		"two same-proposal withdraws in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, w1, w2), f028Gate),
		"below the gate the block must validate byte-identically")
	wOther := f028Tx(common2.CRCProposalWithdraw, 1, &payload.CRCProposalWithdraw{ProposalHash: other}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, w1, wOther), f028Gate),
		"withdraws for DIFFERENT proposals are legitimate and must pass")
}

// TestF068ReturnDepositConflict — two ReturnDepositCoin with the SAME program code.
func TestF068ReturnDepositConflict(t *testing.T) {
	code := f047Code(t)
	r1 := f028Tx(common2.ReturnDepositCoin, 0, &payload.ReturnDepositCoin{}, code)
	r2 := f028Tx(common2.ReturnDepositCoin, 0, &payload.ReturnDepositCoin{}, code)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, r1, r2), f028Gate),
		"two same-code deposit returns in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, r1, r2), f028Gate),
		"below the gate the block must validate byte-identically")
	rOther := f028Tx(common2.ReturnDepositCoin, 0, &payload.ReturnDepositCoin{}, f047Code(t))
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, r1, rOther), f028Gate),
		"deposit returns for DIFFERENT producers are legitimate and must pass")
}

// TestF071ClaimNodeConflict — two CRCouncilMemberClaimNode for the SAME node public key.
func TestF071ClaimNodeConflict(t *testing.T) {
	nk := f047NodeKey(t)
	// Distinct council members (DIDs) so this test isolates the node-key dimension; the
	// council-member-DID dimension is exercised separately by TestF083SameMemberDifferentNodeKey.
	didA := common.Uint168{0x07, 0x01, 0x0a}
	didB := common.Uint168{0x07, 0x01, 0x0b}
	didC := common.Uint168{0x07, 0x01, 0x0c}
	c1 := f028Tx(common2.CRCouncilMemberClaimNode, 0, &payload.CRCouncilMemberClaimNode{NodePublicKey: nk, CRCouncilCommitteeDID: didA}, nil)
	c2 := f028Tx(common2.CRCouncilMemberClaimNode, 0, &payload.CRCouncilMemberClaimNode{NodePublicKey: nk, CRCouncilCommitteeDID: didB}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, c2), f028Gate),
		"two claims of the same node key (distinct members) in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, c1, c2), f028Gate),
		"below the gate the block must validate byte-identically")
	cOther := f028Tx(common2.CRCouncilMemberClaimNode, 0, &payload.CRCouncilMemberClaimNode{NodePublicKey: f047NodeKey(t), CRCouncilCommitteeDID: didC}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, c1, cOther), f028Gate),
		"claims of DIFFERENT node keys by DIFFERENT members are legitimate and must pass")
}

// TestF072ProposalDraftConflict — two CRCProposal with the SAME draft hash.
func TestF072ProposalDraftConflict(t *testing.T) {
	h := common.Uint256{7, 2}
	other := common.Uint256{7, 3}
	p1 := f028Tx(common2.CRCProposal, 0, &payload.CRCProposal{DraftHash: h}, nil)
	p2 := f028Tx(common2.CRCProposal, 0, &payload.CRCProposal{DraftHash: h}, nil)
	assert.Error(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, p1, p2), f028Gate),
		"two proposals with the same draft hash in one block must be rejected at/above the gate")
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate-1, p1, p2), f028Gate),
		"below the gate the block must validate byte-identically")
	pOther := f028Tx(common2.CRCProposal, 0, &payload.CRCProposal{DraftHash: other}, nil)
	assert.NoError(t, blockchain.CheckSameBlockConflicts(f028Block(f028Gate, p1, pOther), f028Gate),
		"proposals with DIFFERENT draft hashes are legitimate and must pass")
}
