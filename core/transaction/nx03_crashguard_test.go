// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// NX-03 — fail-on-pristine for the ReturnSideChainDepositCoin zero-input /
// out-of-range-index node kill.
//
// The proof drives the PRODUCTION entry point, not the function that was edited:
// txn.ContextCheck(parameters) is DefaultChecker.ContextCheck
// (core/transaction/transactionchecker.go:164), the exact frame above
// SpecialContextCheck in the live crash stack captured on an isolated node:
//
//	panic: runtime error: index out of range [0] with length 0
//	  ...SpecialContextCheck     returnsidechaindepositcointransaction.go:133
//	  ...DefaultChecker.ContextCheck        transactionchecker.go:164
//	  ...BlockChain.CheckTransactionContext blockchain/txvalidator.go:83
//	  ...TxPool.appendToTxPool              mempool/txpool.go:137
//	  ...netsync.(*SyncManager).handleTxMsg elanet/netsync/manager.go:366
//	  created by ...SyncManager.Start       elanet/netsync/manager.go:1093
//
// The last two frames are why this is fatal rather than merely annoying: the
// netsync blockHandler goroutine is started bare and nothing on that stack
// recovers, so the panic terminates the process. (The JSON-RPC leg survives only
// because net/http recovers, which is why this is a P2P-reachable kill and not
// an RPC-reachable one.)
//
// Both tests use the REAL chain store built by txValidatorSpecialTxTestSuite,
// and the zero-input target is the REAL genesis RegisterAsset transaction whose
// hash IS the compiled-in constant core.ELAAssetID — the same object an attacker
// names on mainnet, with no chain lookup required.
package transaction

import (
	"math"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// nx03Attempt runs a full production ContextCheck and reports whether it
// panicked instead of returning.
func nx03Attempt(txn interfaces.Transaction,
	parameters *TransactionParameters) (panicked interface{}, err error) {
	defer func() {
		panicked = recover()
	}()

	_, contextErr := txn.ContextCheck(parameters)
	if contextErr != nil {
		err = contextErr
	}
	return
}

// nx03BuildAttackTx assembles the attacker's transaction: a real unspent
// outpoint as input (ownership is NOT required — checkTransactionSignature runs
// AFTER the panic), and an OTReturnSideChainDepositCoin output whose payload
// names `depositHash`.
func (s *txValidatorSpecialTxTestSuite) nx03BuildAttackTx(
	fixture arbiterCrossChainUTXOFixture, depositHash common.Uint256,
	chainParams *config.Configuration) interfaces.Transaction {

	witness := &program.Program{Code: s.crossChainArbiterScript(
		s.arbitrators.MajorityCount, len(s.arbitrators.GetCrossChainArbiters()))}
	nonce := common2.NewAttribute(common2.Nonce, []byte("nx03"))

	txn := functions.CreateTransaction(
		common2.TxVersion09,
		common2.ReturnSideChainDepositCoin,
		payload.ReturnSideChainDepositCoinVersion,
		&payload.ReturnSideChainDepositCoin{},
		[]*common2.Attribute{&nonce},
		[]*common2.Input{fixture.depositInput},
		[]*common2.Output{{
			AssetID:     core.ELAAssetID,
			Value:       fixture.reserveAmount - chainParams.ReturnDepositCoinFee,
			ProgramHash: fixture.payerProgramHash,
			Type:        common2.OTReturnSideChainDepositCoin,
			Payload: &outputpayload.ReturnSideChainDeposit{
				Version:                outputpayload.ReturnSideChainDepositVersion,
				GenesisBlockAddress:    fixture.bankAddress,
				DepositTransactionHash: depositHash,
			},
		}},
		0,
		[]*program.Program{witness},
	)
	return CreateTransactionByType(txn, s.Chain)
}

// TestNX03ZeroInputDepositTxDoesNotKillTheNode is the fail-on-pristine
// assertion. Removing the `len(tx.Inputs()) == 0` guard turns this into
// `panic: runtime error: index out of range [0] with length 0`, which in
// production is process death on the netsync goroutine.
func (s *txValidatorSpecialTxTestSuite) TestNX03ZeroInputDepositTxDoesNotKillTheNode() {
	// Precondition, asserted rather than assumed: the compiled-in asset id
	// resolves, through the always-enabled tx index, to a ZERO-INPUT transaction
	// on every node. This is what makes the attack need no chain lookup at all.
	genesisAsset, _, err := s.Chain.GetDB().GetTransaction(core.ELAAssetID)
	s.Require().NoError(err, "core.ELAAssetID must resolve in the tx index")
	s.Require().Equal(0, len(genesisAsset.Inputs()),
		"the genesis RegisterAsset transaction must have zero inputs")

	fixture := s.createArbiterCrossChainUTXOFixture()
	blockHeight := fixture.transactionHeight + 1
	chainParams := *s.Chain.GetParams()
	chainParams.CrossChainUTXOFreezeHeight = 0
	chainParams.CrossChainUTXORestrictionHeight = blockHeight
	chainParams.ReturnCrossChainCoinStartHeight = 0
	chainParams.DPoSConfiguration.DPOSNodeCrossChainHeight = math.MaxUint32
	chainParams.CRConfiguration.CRAgreementCount = uint32(s.arbitrators.MajorityCount)

	originalCRCArbiters := s.arbitrators.CRCArbitrators
	s.arbitrators.CRCArbitrators = s.arbitrators.CurrentArbitrators
	defer func() {
		s.arbitrators.CRCArbitrators = originalCRCArbiters
	}()

	txn := s.nx03BuildAttackTx(fixture, core.ELAAssetID, &chainParams)
	parameters := &TransactionParameters{
		Transaction: txn,
		BlockHeight: blockHeight,
		Config:      &chainParams,
		BlockChain:  s.Chain,
	}
	txn.SetParameters(parameters)
	s.signCrossChainProgram(txn, txn.Programs()[0])

	cleanup := s.prepareArbiterCrossChainContext(&chainParams)
	defer cleanup()

	panicked, err := nx03Attempt(txn, parameters)
	s.Require().Nil(panicked,
		"NX-03 REGRESSION: an unauthenticated ReturnSideChainDepositCoin naming the "+
			"zero-input genesis RegisterAsset transaction PANICKED the production "+
			"ContextCheck path")
	s.Require().Error(err,
		"NX-03: a deposit tx with no inputs must be REJECTED, not accepted")
	s.T().Logf("NX-03 ok: rejected with: %v", err)
}

// NOT TESTED, AND DELIBERATELY SO — the second deref on the same line pair,
// refTx.Outputs()[tx.Inputs()[0].Previous.Index], is guarded in the fix but I
// could NOT establish that it is reachable, and I am not going to ship a test
// that pretends otherwise.
//
// To fire it, the STORED transaction the attacker names must itself carry an
// input whose Previous.Index is out of range for the transaction it references.
// No such transaction can be in the store: (a) CheckBlockContext resolves every
// input through GetTxReference before a block is ever saved, so the block is
// rejected first; and (b) even bypassing validation, persistence itself panics
// earlier. I tried exactly that — SaveBlock on a hand-built block containing a
// transaction with Previous{TxID: <1-output tx>, Index: 7} — and got:
//
//	test panicked: runtime error: index out of range [7] with length 1
//	  indexers.(*UtxoIndex).ConnectBlock  blockchain/indexers/utxoindex.go:203
//	  indexers.(*Manager).ConnectBlock    blockchain/indexers/manager.go:451
//	  (*ChainStoreFFLDB).SaveBlock        blockchain/chainstoreffldb.go:184
//
// So the index guard is DEFENCE IN DEPTH against a vector I have no evidence is
// live, not a proven kill like the zero-input one. It is retained because it is
// free and cannot change any acceptance decision (an out-of-range index panics
// today, so no retained transaction has one), but it is reported as such rather
// than as a second proven fix.
