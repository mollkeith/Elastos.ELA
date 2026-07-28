// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package mempool

import (
	"testing"

	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// TestNX10bOwnerKeyVsCRClaimedNodeKeyConflicts is the fail-on-pristine proof for the
// durable halt reachable by an attacker holding one CR council seat and one producer
// deposit.
//
// THE ASYMMETRY. blockchain.CheckSameBlockConflicts folds producer OWNER keys, producer
// NODE keys, RegisterCR keys and CRCouncilMemberClaimNode NODE keys into a SINGLE map
// (producerCRKeys, blockvalidator.go) and rejects any collision. The mempool mirrors most
// of that through slotDPoSOwnerNodePublicKeys, a strArray slot whose getter returns BOTH
// the owner and the node key of a producer transaction -- so producer-owner vs
// producer-node is already a cross-transaction mempool conflict.
//
// CRCouncilMemberClaimNode was the one member of the block-level union missing from that
// slot; it appeared only in slotDPoSNodePublicKey and slotCRCouncilMemberNodePublicKey.
// So this pairing was a BLOCK conflict but not a MEMPOOL conflict:
//
//	RegisterProducer.OwnerKey == CRCouncilMemberClaimNode.NodePublicKey
//
// THE HALT. Both transactions pass admission. pow.Service.GenerateBlock never calls
// CheckSameBlockConflicts, so an honest on-duty producer packs both. The assembled block
// then fails its own CheckBlockSanity. Nothing evicts either transaction -- there is no
// TTL and the pool is a persisted checkpoint -- so the next proposer packs them again, and
// the next. Block production stops and stays stopped.
//
// FAIL-ON-PRISTINE: without the NX-10b pair in slotDPoSOwnerNodePublicKeys the two
// transactions occupy different slots, no conflict is reported, and this test fails on the
// first assertion. It is not an equivalent mutant: every other slot leaves this pairing
// unnoticed, so only the union slot distinguishes the two builds.
//
// This drives the production conflict manager through the same entry point txpool.go uses.
func TestNX10bOwnerKeyVsCRClaimedNodeKeyConflicts(t *testing.T) {
	conflictTestProc(func(db *UtxoCacheDB) {
		// The single key the attacker reuses on both sides.
		pk := randomPublicKey()

		producerTx := functions.CreateTransaction(
			0,
			common2.RegisterProducer,
			0,
			&payload.ProducerInfo{
				OwnerKey:      pk,
				NodePublicKey: randomPublicKey(),
				NickName:      randomNickname(),
			},
			[]*common2.Attribute{},
			[]*common2.Input{},
			[]*common2.Output{},
			0,
			[]*program.Program{},
		)

		claimTx := functions.CreateTransaction(
			0,
			common2.CRCouncilMemberClaimNode,
			0,
			&payload.CRCouncilMemberClaimNode{
				NodePublicKey:         pk,
				CRCouncilCommitteeDID: *randomProgramHash(),
			},
			[]*common2.Attribute{},
			[]*common2.Input{},
			[]*common2.Output{},
			0,
			[]*program.Program{},
		)

		// true == the manager must report these as conflicting.
		txs := []interfaces.Transaction{producerTx, claimTx}
		verifyTxListWithConflictManager(txs, db, true, t)
	})
}

// TestNX10bDistinctKeysStillAdmitted is the negative control. Without it the test above
// would pass under a change that made EVERY producer/claim pair conflict, which would be a
// liveness regression rather than a fix.
func TestNX10bDistinctKeysStillAdmitted(t *testing.T) {
	conflictTestProc(func(db *UtxoCacheDB) {
		producerTx := functions.CreateTransaction(
			0,
			common2.RegisterProducer,
			0,
			&payload.ProducerInfo{
				OwnerKey:      randomPublicKey(),
				NodePublicKey: randomPublicKey(),
				NickName:      randomNickname(),
			},
			[]*common2.Attribute{},
			[]*common2.Input{},
			[]*common2.Output{},
			0,
			[]*program.Program{},
		)

		claimTx := functions.CreateTransaction(
			0,
			common2.CRCouncilMemberClaimNode,
			0,
			&payload.CRCouncilMemberClaimNode{
				NodePublicKey:         randomPublicKey(),
				CRCouncilCommitteeDID: *randomProgramHash(),
			},
			[]*common2.Attribute{},
			[]*common2.Input{},
			[]*common2.Output{},
			0,
			[]*program.Program{},
		)

		// false == no key is shared, so both must still be admitted.
		txs := []interfaces.Transaction{producerTx, claimTx}
		verifyTxListWithConflictManager(txs, db, false, t)
	})
}
