// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// SUBMITAUX — coverage for the PRODUCTION submitauxblock path, the only route
// that produces mainnet blocks.
//
// WHAT WAS ACTUALLY MISSING (measured on 21098e0, not assumed).
// The tree was NOT bare: blockchain/b2_submitauxblock_gate_test.go already
// exercises the F-041/F-090 canonical-AuxPow gate at and above
// StrictMoneyRangeHeight. But it REPRODUCES the wire path in the test body
// (deserialize an AuxPow, assign it to a header, call CheckBlockSanity) rather
// than calling the shipped functions. A census of every *_test.go in the tree
// found that `SubmitAuxBlock`, `CreateAuxBlock` and `AddDposBlock` appeared
// ONLY inside comments — zero call sites. pow.Service.SubmitAuxBlock,
// pow.Service.CreateAuxBlock and mempool.BlockPool.AddDposBlock could each have
// been deleted outright and the whole suite stayed green. The half that ACCEPTS
// a mined block — auxBlockPool lookup, AddDposBlock routing, ProcessBlock,
// maybeAcceptBlock, connect — had no coverage at any height, and the strict
// money-range and coinbase rules had none through this path at all, because a
// header-only block dies at "does not contain any transactions" long before
// them.
//
// WHAT THESE TESTS DO. They stand up a real BlockChain on a real ChainStore, a
// real TxPool and BlockPool, and a real pow.Service, then drive the shipped
// entry points:
//
//	pow.Service.CreateAuxBlock   (the createauxblock half)
//	  -> pow.Service.SubmitAuxBlock  (the submitauxblock half)
//	    -> mempool.BlockPool.AddDposBlock
//	      -> blockchain.BlockChain.ProcessBlock
//	        -> CheckBlockSanity / maybeAcceptBlock / CheckBlockContext / connect
//
// servers.SubmitAuxBlock is the only leg NOT driven here: it is RPC parameter
// unmarshalling plus a service-level permission check over Pow.SubmitAuxBlock,
// and it reaches the consensus rules exclusively through the function this file
// does call. The hex round-trip it performs on the AuxPow is reproduced in
// relauxProof so the submitted proof is a wire-form proof, not an in-memory one.
//
// HEIGHTS — two complementary shapes, deliberately:
//
//   - TestRelauxSubmitAuxBlockAtMainnetGateHeight uses the LITERAL mainnet gate,
//     config.MainNetStrictMoneyRangeHeight (2,260,451), with the default params
//     untouched. A unit-context chain cannot be 2.26M blocks tall, so the block
//     cannot connect; what is proven there is the gate BOUNDARY on the real
//     number — a rejected submission stops AT the gate, an accepted one reaches
//     maybeAcceptBlock ("wrong block height!", which sits strictly after
//     CheckBlockSanity in processBlock).
//
//   - Every other test relocates the gate onto a height a real chain can hold
//     (the technique blockchain/strict_money_gate_test.go gateChain already
//     uses) so the block genuinely CONNECTS and the accept is a real accept:
//     the chain tip advances onto the crafted block. That is the only way to
//     reach CheckBlockContext and the gated coinbase rules through this path.
//
// The below-gate arm of each money test is the one that matters most: it shows
// the pristine node ACCEPTING the crafted coinbase, which is the incident.
package pow

import (
	"strings"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/auxpow"
	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	transaction2 "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/mempool"
	"github.com/elastos/Elastos.ELA/utils/test"
)

// relauxNonCanonicalErr is the F-041/F-090 gate rejection.
const relauxNonCanonicalErr = "non-canonical (malleable) AuxPow encoding"

// relauxPastSanityErr is raised by maybeAcceptBlock, which runs strictly AFTER
// CheckBlockSanity in processBlock. Seeing it proves a submission cleared the
// AuxPow gate and the proof of work.
const relauxPastSanityErr = "wrong block height!"

// relauxGate is the height the relocated gate is armed at, and the height of the
// block every test submits, so the crafted block sits exactly AT the gate.
//
// It is 2, not 1, and that matters: connectBlockBracketed calls CheckBlockContext
// with node.Parent, which is nil for the first block above genesis, and
// CheckBlockContext returns nil immediately when its prevNode is nil ("the
// genesis block is valid by definition"). At height 1 the whole context leg —
// checkTxsContext, and with it checkCoinbaseTransactionContext and every gated
// coinbase rule — is therefore SKIPPED. relauxNode consequently mines one clean
// block before handing the harness over, so the block under test has a real
// parent node and the context rules actually run.
const relauxGate uint32 = 2

// relauxStartTip is the tip relauxNode leaves behind: the parent of the block
// every test submits.
const relauxStartTip uint32 = relauxGate - 1

// relauxGateOff puts the gate far above the block under test, which is the
// pristine (pre-hard-fork) behaviour retained history must keep replaying under.
const relauxGateOff uint32 = 100

type relauxHarness struct {
	svc    *Service
	chain  *blockchain.BlockChain
	params *config.Configuration
	payTo  string
}

// relauxNode builds a complete node — real store, real chain, real mempools,
// real pow service — with StrictMoneyRangeHeight armed at gate, and with
// CheckRewardHeight set to 0 so that coinbase-context rejections are actually
// returned (see relauxNodeWith and TestRelauxCoinbaseContextErrorSwallowed).
func relauxNode(t *testing.T, gate uint32) *relauxHarness {
	t.Helper()
	return relauxNodeWith(t, gate, 0)
}

// relauxNodeWith is relauxNode with CheckRewardHeight made explicit.
//
// WHY THAT PARAMETER IS EXPOSED. checkTxsContext ends with:
//
//	err := b.checkCoinbaseTransactionContext(...)
//	if err != nil {
//	    if block.Height < b.chainParams.CheckRewardHeight {
//	        if err = block.Serialize(buf); err != nil { return err }   // REASSIGNS err
//	    } else {
//	        if e := block.Serialize(buf); e != nil { return e }        // uses e
//	    }
//	    ...logging...
//	}
//	return err
//
// Below CheckRewardHeight the rejection is OVERWRITTEN by the (successful, hence
// nil) Serialize and the block is accepted anyway. CheckRewardHeight defaults to
// 436,812 on mainnet, so a harness chain a few blocks tall lands in the
// swallowing branch and NO coinbase-context rule can ever be observed to fire.
// Setting it to 0 selects the correct branch. CheckRewardHeight has exactly one
// use in the whole tree — that comparison — so nothing else moves.
//
// Mainnet is not exposed at gate 1: StrictMoneyRangeHeight (2,260,451) is far
// above CheckRewardHeight (436,812), so at the restart tip the else-branch runs
// and rejections propagate. TestRelauxCoinbaseContextErrorSwallowed pins the
// defect rather than leaving it as a comment.
func relauxNodeWith(t *testing.T, gate, checkRewardHeight uint32) *relauxHarness {
	t.Helper()

	functions.GetTransactionByTxType = transaction2.GetTransaction
	functions.GetTransactionByBytes = transaction2.GetTransactionByBytes
	functions.CreateTransaction = transaction2.CreateTransaction
	functions.GetTransactionParameters = transaction2.GetTransactionparameters
	log.NewDefault(test.NodeLogPath, 0, 0, 0)

	params := config.GetDefaultParams()
	params.GenesisBlock = core.GenesisBlock(*params.FoundationProgramHash)
	params.StrictMoneyRangeHeight = gate
	params.CheckRewardHeight = checkRewardHeight

	ckp := checkpoint.NewManager(params)
	store, err := blockchain.NewChainStore(t.TempDir(), params)
	if err != nil {
		t.Fatalf("NewChainStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	st := state.NewState(params, nil, nil, nil, func() bool { return false },
		nil, nil, nil, nil, nil, nil, nil)

	chain, err := blockchain.New(store, params, st, nil, ckp)
	if err != nil {
		t.Fatalf("blockchain.New: %v", err)
	}
	if err := chain.Init(nil); err != nil {
		t.Fatalf("chain.Init: %v", err)
	}

	arbStrs := []string{
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
		"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
		"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
		"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
	}
	arbs := make([]state.ArbiterMember, 0, len(arbStrs))
	for _, v := range arbStrs {
		a, _ := common.HexStringToBytes(v)
		ar, _ := state.NewOriginArbiter(a)
		arbs = append(arbs, ar)
	}
	mock := &state.ArbitratorsMock{CurrentArbitrators: arbs}

	prev := blockchain.DefaultLedger
	blockchain.DefaultLedger = &blockchain.Ledger{
		Arbitrators: mock,
		Blockchain:  chain,
		Store:       store,
	}
	t.Cleanup(func() { blockchain.DefaultLedger = prev })

	blkPool := mempool.NewBlockPool(params)
	blkPool.Chain = chain
	blkPool.Store = store
	blkPool.IsCurrent = func() bool { return true }

	payTo, err := params.FoundationProgramHash.ToAddress()
	if err != nil {
		t.Fatalf("ToAddress: %v", err)
	}

	svc := NewService(&Config{
		PayToAddr:      payTo,
		MinerInfo:      "relaux",
		Chain:          chain,
		ChainParams:    params,
		TxMemPool:      mempool.NewTxPool(params, ckp),
		BlkMemPool:     blkPool,
		BroadcastBlock: func(block *types.Block) {},
		Arbitrators:    mock,
	})

	h := &relauxHarness{svc: svc, chain: chain, params: params, payTo: payTo}

	// Mine and connect one clean block so the block under test has a real parent
	// node and CheckBlockContext does not short-circuit. This also exercises the
	// accept path once more, below the relocated gate.
	// The loop is BOUNDED on purpose. If submitauxblock stops connecting blocks —
	// which is exactly what deleting its production dispatch does — an unbounded
	// loop would hang until the go test timeout and report a useless failure.
	// Bounded, it fails immediately and names the cause.
	for i := 0; i < int(relauxStartTip)+2 && h.chain.GetHeight() < relauxStartTip; i++ {
		blk, err := h.svc.CreateAuxBlock(h.payTo)
		if err != nil {
			t.Fatalf("CreateAuxBlock while advancing to tip %d: %v",
				relauxStartTip, err)
		}
		if err := relauxSubmit(t, h, blk, relauxCanonical); err != nil {
			t.Fatalf("SubmitAuxBlock while advancing to tip %d: %s",
				relauxStartTip, relauxDeep(err))
		}
	}
	if got := h.chain.GetHeight(); got != relauxStartTip {
		t.Fatalf("harness must start at tip %d, got %d — submitauxblock accepted "+
			"the block but it did not CONNECT, so the production dispatch into "+
			"the block pool is not being reached", relauxStartTip, got)
	}

	return h
}

type relauxEnc int

const (
	relauxCanonical relauxEnc = iota
	// relauxDisplayOrder is the byte-reversed parent hash produced by pool
	// software that serialised it as displayed. 431,903 retained blocks carry
	// it, the last at height 2,090,418.
	relauxDisplayOrder
	// relauxZeroParent is the shape the node's OWN SolveBlock produced.
	// 177,337 retained blocks carry it, the last at height 180,217.
	relauxZeroParent
	// relauxBadMerkleIndex malleates the high bits GetMerkleRoot never reads.
	// Zero retained blocks carry it; AuxPow.Check passes it regardless.
	relauxBadMerkleIndex
)

// relauxProof builds the merge-mining proof a pool would submit for blk in the
// chosen encoding, and round-trips it through the hex wire form exactly as
// servers.SubmitAuxBlock does before handing it to Pow.SubmitAuxBlock.
func relauxProof(t *testing.T, blk *types.Block, enc relauxEnc) *auxpow.AuxPow {
	t.Helper()
	identity := blk.Hash()
	ap := auxpow.GenerateAuxPow(identity)

	target := blockchain.CompactToBig(blk.Header.Bits)
	solved := false
	for i := uint32(0); i < 1<<26; i++ {
		ap.ParBlockHeader.Nonce = i
		h := ap.ParBlockHeader.Hash()
		if blockchain.HashToBig(&h).Cmp(target) <= 0 {
			solved = true
			break
		}
	}
	if !solved {
		t.Fatal("could not solve the parent header")
	}

	parent := ap.ParBlockHeader.Hash()
	switch enc {
	case relauxCanonical:
		ap.ParentHash = parent
	case relauxDisplayOrder:
		rev, err := common.Uint256FromBytes(common.BytesReverse(parent.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		ap.ParentHash = *rev
	case relauxZeroParent:
		ap.ParentHash = common.Uint256{}
	case relauxBadMerkleIndex:
		ap.ParentHash = parent
		ap.ParMerkleIndex = 1 << 20
	}

	if !ap.Check(&identity, auxpow.AuxPowChainID) {
		t.Fatal("every encoding here must be a VALID merged-mining proof; the " +
			"canonical-encoding gate is the only thing that separates them")
	}
	return ap
}

// relauxSubmit pools blk the way CreateAuxBlock does and drives the production
// submitauxblock entry point over it.
func relauxSubmit(t *testing.T, h *relauxHarness, blk *types.Block, enc relauxEnc) error {
	t.Helper()
	h.svc.auxBlockPool.AppendBlock(blk)
	hash := blk.Hash()
	return h.svc.SubmitAuxBlock(&hash, relauxProof(t, blk, enc))
}

// relauxRebuildCoinbase replaces the block's coinbase with one carrying the
// given output values and lock time, reusing the original program hashes, and
// restamps the merkle root. A FRESH transaction is built rather than the
// existing one mutated because BaseTransaction.Hash() caches its result.
func relauxRebuildCoinbase(t *testing.T, blk *types.Block,
	values []common.Fixed64, lockTime uint32) {
	t.Helper()
	old := blk.Transactions[0]
	srcOuts := old.Outputs()
	if values == nil {
		for _, o := range srcOuts {
			values = append(values, o.Value)
		}
	}
	outs := make([]*common2.Output, 0, len(values))
	for i, v := range values {
		src := srcOuts[i%len(srcOuts)]
		outs = append(outs, &common2.Output{
			AssetID:     src.AssetID,
			Value:       v,
			ProgramHash: src.ProgramHash,
			Type:        src.Type,
			Payload:     src.Payload,
		})
	}
	blk.Transactions[0] = functions.CreateTransaction(
		old.Version(), old.TxType(), old.PayloadVersion(), old.Payload(),
		old.Attributes(), old.Inputs(), outs, lockTime, old.Programs())

	ids := make([]common.Uint256, 0, len(blk.Transactions))
	for _, tx := range blk.Transactions {
		ids = append(ids, tx.Hash())
	}
	root, err := crypto.ComputeRoot(ids)
	if err != nil {
		t.Fatalf("ComputeRoot: %v", err)
	}
	blk.Header.MerkleRoot = root
}

// relauxDeep renders the full inner-error chain of an elaerr wrapper, so an
// assertion can name the rule that actually fired rather than the outermost
// wrapper text.
func relauxDeep(err error) string {
	if err == nil {
		return "<nil>"
	}
	out := err.Error()
	for {
		w, ok := err.(interface{ InnerError() error })
		if !ok || w.InnerError() == nil {
			return out
		}
		err = w.InnerError()
		out += " || " + err.Error()
	}
}

// relauxMined runs the real createauxblock half and returns the pooled block.
func relauxMined(t *testing.T, h *relauxHarness) *types.Block {
	t.Helper()
	blk, err := h.svc.CreateAuxBlock(h.payTo)
	if err != nil {
		t.Fatalf("CreateAuxBlock: %v", err)
	}
	if blk.Height != relauxGate {
		t.Fatalf("expected the first mined block at height %d, got %d",
			relauxGate, blk.Height)
	}
	return blk
}

// TestRelauxSubmitAuxBlockAcceptsAtGate is the POSITIVE CONTROL for every
// rejection test in this file. With the gate ARMED at the mined block's own
// height, a well-formed merge-mining submission must be ACCEPTED and must
// actually CONNECT — the chain tip advances. If this test ever fails to advance
// the tip, the rejection tests below prove nothing, because everything would be
// rejected for unrelated reasons.
func TestRelauxSubmitAuxBlockAcceptsAtGate(t *testing.T) {
	h := relauxNode(t, relauxGate)

	if got := h.chain.GetHeight(); got != relauxStartTip {
		t.Fatalf("expected the harness at tip %d, got %d", relauxStartTip, got)
	}
	if h.chain.StrictMoneyActive(relauxStartTip) {
		t.Fatalf("the gate must be INACTIVE at the parent height %d", relauxStartTip)
	}
	if !h.chain.StrictMoneyActive(relauxGate) {
		t.Fatalf("the gate must be ARMED at height %d or this file is vacuous",
			relauxGate)
	}

	blk := relauxMined(t, h)
	if err := relauxSubmit(t, h, blk, relauxCanonical); err != nil {
		t.Fatalf("a well-formed submission at the gate must be ACCEPTED, got: %s",
			relauxDeep(err))
	}
	if got := h.chain.GetHeight(); got != relauxGate {
		t.Fatalf("the accepted block must CONNECT: expected tip %d, got %d",
			relauxGate, got)
	}
	if !h.chain.BlockExists(&[]common.Uint256{blk.Hash()}[0]) {
		t.Fatal("the accepted block must be in the chain")
	}
}

// TestRelauxSubmitAuxBlockAuxPowEncodingGate drives F-041/F-090 through the
// production submitauxblock path: at the gate every non-canonical encoding is
// refused, below it every one is still accepted so retained history replays.
func TestRelauxSubmitAuxBlockAuxPowEncodingGate(t *testing.T) {
	encs := []struct {
		name string
		enc  relauxEnc
		// normalised is true when SubmitAuxBlock repairs the encoding before validation,
		// so the submission CONNECTS at the gate instead of being rejected.
		//
		// F-041 submission side: ParentHash is read by neither AuxPow.Check() nor
		// CheckProofOfWork(), so deriving it from ParBlockHeader cannot invalidate a valid
		// proof of work. Pools were never required to send it canonically and nothing
		// enforced it, so rejecting instead of repairing would have stopped a pool's blocks
		// from the first block of the restart -- and the restart necessarily begins in PoW,
		// which makes that pool the only thing able to move the chain.
		//
		// ParMerkleIndex is NOT repaired and must stay rejected: AuxPow.Check() consumes it
		// through GetMerkleRoot(ParCoinbaseTx.Hash(), ParCoinBaseMerkle, ParMerkleIndex), so
		// forcing it to 0 could silently break a genuine merkle proof. Repairing only the
		// field that no verifier reads is the whole distinction.
		normalised bool
	}{
		{"display-order ParentHash", relauxDisplayOrder, true},
		{"zero ParentHash", relauxZeroParent, true},
		{"malleated ParMerkleIndex", relauxBadMerkleIndex, false},
	}

	for _, e := range encs {
		e := e
		t.Run(e.name+"/at gate", func(t *testing.T) {
			h := relauxNode(t, relauxGate)
			err := relauxSubmit(t, h, relauxMined(t, h), e.enc)

			if e.normalised {
				if err != nil {
					t.Fatalf("%s must be NORMALISED by SubmitAuxBlock and CONNECT at the "+
						"gate, got: %s", e.name, relauxDeep(err))
				}
				if got := h.chain.GetHeight(); got != relauxGate {
					t.Fatalf("a normalised submission must connect: expected tip %d, got %d",
						relauxGate, got)
				}
				return
			}

			if err == nil {
				t.Fatalf("%s must be REJECTED at the gate; the block connected "+
					"instead (tip %d)", e.name, h.chain.GetHeight())
			}
			if !strings.Contains(relauxDeep(err), relauxNonCanonicalErr) {
				t.Fatalf("%s must be rejected BY THE GATE, got: %s",
					e.name, relauxDeep(err))
			}
			if got := h.chain.GetHeight(); got != relauxStartTip {
				t.Fatalf("a rejected submission must not move the tip from %d, got %d", relauxStartTip, got)
			}
		})

		t.Run(e.name+"/below gate", func(t *testing.T) {
			h := relauxNode(t, relauxGateOff)
			if h.chain.StrictMoneyActive(relauxGate) {
				t.Fatal("this arm requires the gate DISARMED at the block height")
			}
			if err := relauxSubmit(t, h, relauxMined(t, h), e.enc); err != nil {
				t.Fatalf("REPLAY BREAK: %s must still be accepted below the gate, "+
					"got: %s", e.name, relauxDeep(err))
			}
			if got := h.chain.GetHeight(); got != relauxGate {
				t.Fatalf("below the gate the block must still connect, tip %d", got)
			}
		})
	}
}

// relauxWrapOutputs returns coinbase output values that sum, in wrapping signed
// 64-bit arithmetic, to exactly reward — the tuning that made block 2260451's
// crafted coinbase look ordinary. n outputs of unit, plus a remainder.
func relauxWrapOutputs(n int, unit, reward common.Fixed64) []common.Fixed64 {
	vals := make([]common.Fixed64, 0, n+1)
	var sum common.Fixed64
	for i := 0; i < n; i++ {
		vals = append(vals, unit)
		sum += unit // deliberately wraps
	}
	return append(vals, reward-sum)
}

// TestRelauxSubmitAuxBlockMoneyRangePerOutput is the block-2260451 shape driven
// through the production submitauxblock path: three coinbase outputs, each far
// outside the money range, whose wrapping sum lands exactly on the correct block
// reward so every downstream reward comparison is satisfied.
//
// The below-gate arm is the incident: the pristine rule set ACCEPTS it.
func TestRelauxSubmitAuxBlockMoneyRangePerOutput(t *testing.T) {
	const crafted = common.Fixed64(9000000000000000000)

	t.Run("at gate", func(t *testing.T) {
		h := relauxNode(t, relauxGate)
		blk := relauxMined(t, h)
		vals := relauxWrapOutputs(2, crafted, h.params.GetBlockReward(relauxGate))
		relauxRebuildCoinbase(t, blk, vals, blk.Height)

		err := relauxSubmit(t, h, blk, relauxCanonical)
		if err == nil {
			t.Fatalf("a coinbase with outputs of %d sela must be REJECTED at the "+
				"gate; it connected instead (tip %d)", crafted, h.chain.GetHeight())
		}
		if !strings.Contains(relauxDeep(err), "transaction output amount") ||
			!strings.Contains(relauxDeep(err), common.ErrMoneyRange.Error()) {
			t.Fatalf("must be rejected by the per-output money-range bound, got: %s",
				relauxDeep(err))
		}
	})

	t.Run("below gate reproduces the incident", func(t *testing.T) {
		h := relauxNode(t, relauxGateOff)
		blk := relauxMined(t, h)
		reward := h.params.GetBlockReward(relauxGate)
		vals := relauxWrapOutputs(2, crafted, reward)

		var sum common.Fixed64
		for _, v := range vals {
			sum += v
		}
		if sum != reward {
			t.Fatalf("the crafted outputs must wrap to exactly the block reward "+
				"%d, got %d", reward, sum)
		}
		relauxRebuildCoinbase(t, blk, vals, blk.Height)

		if err := relauxSubmit(t, h, blk, relauxCanonical); err != nil {
			t.Fatalf("below the gate the pristine rules accepted this shape on "+
				"mainnet; if it is refused here the test no longer reproduces the "+
				"incident: %s", relauxDeep(err))
		}
		if got := h.chain.GetHeight(); got != relauxGate {
			t.Fatalf("the crafted block must connect below the gate, tip %d", got)
		}
	})
}

// TestRelauxSubmitAuxBlockMoneyRangeAggregate isolates the AGGREGATE leg of the
// money-range rule, which the fix comment calls out as mattering independently:
// every individual output is INSIDE the bound, only the running sum wraps. The
// per-output check cannot catch this one.
func TestRelauxSubmitAuxBlockMoneyRangeAggregate(t *testing.T) {
	// 184 outputs at the inclusive per-output ceiling overshoot 2^64, so the
	// remainder brings the wrapped total back onto the reward.
	const n = 184

	build := func(t *testing.T, h *relauxHarness) []common.Fixed64 {
		t.Helper()
		vals := relauxWrapOutputs(n, common.MaxELAMoney,
			h.params.GetBlockReward(relauxGate))
		for i, v := range vals {
			if !common.MoneyRange(v) {
				t.Fatalf("output %d = %d is individually out of range; this test "+
					"must isolate the AGGREGATE leg", i, v)
			}
		}
		return vals
	}

	t.Run("at gate", func(t *testing.T) {
		h := relauxNode(t, relauxGate)
		blk := relauxMined(t, h)
		relauxRebuildCoinbase(t, blk, build(t, h), blk.Height)

		err := relauxSubmit(t, h, blk, relauxCanonical)
		if err == nil {
			t.Fatalf("an output sum that wraps signed 64-bit must be REJECTED at "+
				"the gate; it connected instead (tip %d)", h.chain.GetHeight())
		}
		if !strings.Contains(relauxDeep(err), "transaction output total") {
			t.Fatalf("must be rejected by the AGGREGATE money-range bound, got: %s",
				relauxDeep(err))
		}
	})

	t.Run("below gate reproduces the incident", func(t *testing.T) {
		h := relauxNode(t, relauxGateOff)
		blk := relauxMined(t, h)
		relauxRebuildCoinbase(t, blk, build(t, h), blk.Height)

		if err := relauxSubmit(t, h, blk, relauxCanonical); err != nil {
			t.Fatalf("below the gate the wrapping aggregate was accepted; if it is "+
				"refused here the test no longer reproduces the incident: %s",
				relauxDeep(err))
		}
		if got := h.chain.GetHeight(); got != relauxGate {
			t.Fatalf("the crafted block must connect below the gate, tip %d", got)
		}
	})
}

// TestRelauxSubmitAuxBlockCoinbaseLockTimePin drives the FV-19 coinbase rule —
// a gate-1 coinbase check that lives in CheckBlockContext, i.e. past
// CheckBlockSanity — through the production submitauxblock path. Reaching it at
// all is the point: it is only evaluated for a block that is genuinely
// connecting, which is precisely what the previous coverage could not produce.
func TestRelauxSubmitAuxBlockCoinbaseLockTimePin(t *testing.T) {
	t.Run("at gate", func(t *testing.T) {
		h := relauxNode(t, relauxGate)
		blk := relauxMined(t, h)
		relauxRebuildCoinbase(t, blk, nil, 0) // LockTime 0 == mature immediately

		err := relauxSubmit(t, h, blk, relauxCanonical)
		if err == nil {
			t.Fatalf("a coinbase whose LockTime is not its own block height must "+
				"be REJECTED at the gate; it connected instead (tip %d)",
				h.chain.GetHeight())
		}
		if !strings.Contains(relauxDeep(err), "coinbase locktime must equal block height") {
			t.Fatalf("must be rejected by the coinbase LockTime pin, got: %s",
				relauxDeep(err))
		}
	})

	t.Run("below gate", func(t *testing.T) {
		h := relauxNode(t, relauxGateOff)
		blk := relauxMined(t, h)
		relauxRebuildCoinbase(t, blk, nil, 0)

		if err := relauxSubmit(t, h, blk, relauxCanonical); err != nil {
			t.Fatalf("REPLAY BREAK: the LockTime pin must not bind below the gate, "+
				"got: %s", relauxDeep(err))
		}
		if got := h.chain.GetHeight(); got != relauxGate {
			t.Fatalf("below the gate the block must still connect, tip %d", got)
		}
	})
}

// TestRelauxSubmitAuxBlockCoinbaseRewardRule proves the coinbase reward-share
// rule is reached and enforced on this path. NOTE it is UNGATED — it binds at
// every height, so both arms reject. That is asserted rather than glossed: a
// miner cannot pay itself more than the schedule allows through submitauxblock
// at any height, gate or no gate.
func TestRelauxSubmitAuxBlockCoinbaseRewardRule(t *testing.T) {
	for _, gate := range []uint32{relauxGate, relauxGateOff} {
		gate := gate
		name := "at gate"
		if gate != relauxGate {
			name = "below gate (rule is ungated)"
		}
		t.Run(name, func(t *testing.T) {
			h := relauxNode(t, gate)
			blk := relauxMined(t, h)

			outs := blk.Transactions[0].Outputs()
			vals := make([]common.Fixed64, 0, len(outs))
			for _, o := range outs {
				vals = append(vals, o.Value)
			}
			vals[1] += 100000000 // one extra ELA to the miner
			relauxRebuildCoinbase(t, blk, vals, blk.Height)

			err := relauxSubmit(t, h, blk, relauxCanonical)
			if err == nil {
				t.Fatalf("a coinbase paying the miner more than the schedule must "+
					"be REJECTED; it connected instead (tip %d)", h.chain.GetHeight())
			}
			if got := h.chain.GetHeight(); got != relauxStartTip {
				t.Fatalf("a rejected submission must not move the tip from %d, got %d", relauxStartTip, got)
			}
		})
	}
}

// TestRelauxCoinbaseContextErrorSwallowed pins a defect this coverage exposed:
// below CheckRewardHeight, checkTxsContext DISCARDS every
// checkCoinbaseTransactionContext rejection, because the error variable is
// reassigned by a block.Serialize whose success then makes the function return
// nil. The two arms below differ ONLY in CheckRewardHeight and reach opposite
// verdicts on a byte-identical submission.
//
// SCOPE — mainnet at gate 1 is NOT exposed: StrictMoneyRangeHeight (2,260,451)
// sits far above the mainnet CheckRewardHeight (436,812), so the correct branch
// runs at the restart tip and the gated coinbase rules do bind. The exposure is
// for heights below CheckRewardHeight — historical replay, and any network
// configured with a high value (regnet 100, testnet 280,000). No supply effect
// is claimed: retained history is valid by construction, so nothing was
// wrongly accepted in practice. This test is a guard, not a fix; the swallowing
// branch is left exactly as shipped.
func TestRelauxCoinbaseContextErrorSwallowed(t *testing.T) {
	craft := func(t *testing.T, h *relauxHarness) *types.Block {
		t.Helper()
		blk := relauxMined(t, h)
		relauxRebuildCoinbase(t, blk, nil, 0) // violates the gated LockTime pin
		return blk
	}

	t.Run("swallowed below CheckRewardHeight", func(t *testing.T) {
		// CheckRewardHeight above the block height selects the reassigning branch.
		h := relauxNodeWith(t, relauxGate, relauxGate+1)
		err := relauxSubmit(t, h, craft(t, h), relauxCanonical)
		if err != nil {
			t.Skipf("the swallowing branch no longer discards the rejection (%s); "+
				"if checkTxsContext was fixed, delete this test", relauxDeep(err))
		}
		if got := h.chain.GetHeight(); got != relauxGate {
			t.Fatalf("expected the invalid block to connect anyway, tip %d", got)
		}
		t.Log("DEFECT CONFIRMED: a coinbase violating the gated LockTime pin was " +
			"ACCEPTED because checkTxsContext overwrote the rejection with the " +
			"result of block.Serialize")
	})

	t.Run("returned at and above CheckRewardHeight", func(t *testing.T) {
		h := relauxNodeWith(t, relauxGate, 0)
		err := relauxSubmit(t, h, craft(t, h), relauxCanonical)
		if err == nil {
			t.Fatalf("with CheckRewardHeight below the block the rejection must "+
				"propagate; the block connected instead (tip %d)", h.chain.GetHeight())
		}
		if !strings.Contains(relauxDeep(err), "coinbase locktime must equal block height") {
			t.Fatalf("expected the coinbase LockTime pin, got: %s", relauxDeep(err))
		}
	})
}

// relauxBlockAt assembles a miner submission for an arbitrary height the way
// GenerateBlock does. It exists so the LITERAL mainnet gate height can be
// reached without a 2.26M-block chain.
func relauxBlockAt(t *testing.T, h *relauxHarness, height uint32) *types.Block {
	t.Helper()
	cb, err := h.svc.CreateCoinbaseTx(h.payTo, height)
	if err != nil {
		t.Fatalf("CreateCoinbaseTx: %v", err)
	}
	blk := &types.Block{
		Header: common2.Header{
			Version:   0,
			Previous:  h.params.GenesisBlock.Hash(),
			Timestamp: uint32(time.Now().Unix()),
			Bits:      h.params.PowConfiguration.PowLimitBits,
			Height:    height,
			Nonce:     0,
		},
		Transactions: []interfaces.Transaction{cb},
	}
	ids := []common.Uint256{cb.Hash()}
	root, err := crypto.ComputeRoot(ids)
	if err != nil {
		t.Fatalf("ComputeRoot: %v", err)
	}
	blk.Header.MerkleRoot = root
	return blk
}

// TestRelauxSubmitAuxBlockAtMainnetGateHeight pins the gate BOUNDARY on the
// LITERAL mainnet number, config.MainNetStrictMoneyRangeHeight, with the default
// params untouched — no relocated gate anywhere in this test.
//
// The route is the POW-consensus branch of AddDposBlock, which hands the block
// straight to Chain.ProcessBlock; that is a real production route (it is what
// RevertToPOW puts the chain on) and it is the branch that does not depend on
// the pool's tip-relative retention window, so a block 2.26M heights above a
// unit-context tip can still reach CheckBlockSanity.
//
// The block cannot CONNECT here — nothing can build a 2.26M-block chain in a
// unit test — so acceptance is expressed as "reached maybeAcceptBlock", which
// sits strictly after CheckBlockSanity in processBlock. No end-to-end claim is
// made at this height; the connecting proof is the relocated-gate tests above.
func TestRelauxSubmitAuxBlockAtMainnetGateHeight(t *testing.T) {
	gate := config.MainNetStrictMoneyRangeHeight

	newNode := func(t *testing.T) *relauxHarness {
		t.Helper()
		h := relauxNode(t, gate)
		if h.params.StrictMoneyRangeHeight != config.MainNetStrictMoneyRangeHeight {
			t.Fatalf("this test must run on the real mainnet gate, got %d",
				h.params.StrictMoneyRangeHeight)
		}
		h.chain.GetState().ConsensusAlgorithm = state.POW
		return h
	}

	// A canonical submission clears the gate at and above it: the restart stays
	// minable by real merge miners.
	for _, height := range []uint32{gate, gate + 1} {
		height := height
		t.Run("canonical clears the gate", func(t *testing.T) {
			h := newNode(t)
			err := relauxSubmit(t, h, relauxBlockAt(t, h, height), relauxCanonical)
			got := relauxDeep(err)
			if strings.Contains(got, relauxNonCanonicalErr) {
				t.Fatalf("height %d: a canonical submission was refused by the "+
					"gate — the restart would be unminable: %s", height, got)
			}
			if !strings.Contains(got, relauxPastSanityErr) {
				t.Fatalf("height %d: expected the submission to reach "+
					"maybeAcceptBlock, got: %s", height, got)
			}
		})
	}

	// At and above the gate, a non-canonical encoding is either REPAIRED by SubmitAuxBlock
	// or refused. Which of the two depends on whether a verifier reads the field.
	//
	// ParentHash is read by neither AuxPow.Check() nor CheckProofOfWork(), so deriving it
	// from ParBlockHeader cannot invalidate a valid proof of work. Repairing it is what
	// keeps the restart minable by a pool whose stratum software was never required to send
	// the field canonically -- and since the restart necessarily begins in PoW, that pool is
	// the only thing that can move the chain.
	//
	// ParMerkleIndex IS read, through
	// GetMerkleRoot(ParCoinbaseTx.Hash(), ParCoinBaseMerkle, ParMerkleIndex), so forcing it
	// would risk silently breaking a genuine merkle proof. It stays refused.
	for _, e := range []struct {
		name       string
		enc        relauxEnc
		normalised bool
	}{
		{"display-order ParentHash", relauxDisplayOrder, true},
		{"zero ParentHash", relauxZeroParent, true},
		{"malleated ParMerkleIndex", relauxBadMerkleIndex, false},
	} {
		e := e
		label := " refused at the gate"
		if e.normalised {
			label = " normalised and cleared at the gate"
		}
		t.Run(e.name+label, func(t *testing.T) {
			h := newNode(t)
			err := relauxSubmit(t, h, relauxBlockAt(t, h, gate), e.enc)
			got := relauxDeep(err)

			if e.normalised {
				if strings.Contains(got, relauxNonCanonicalErr) {
					t.Fatalf("%s must be REPAIRED by SubmitAuxBlock and clear the gate at "+
						"height %d; it was refused instead: %s", e.name, gate, got)
				}
				if !strings.Contains(got, relauxPastSanityErr) {
					t.Fatalf("%s: expected the repaired submission to reach "+
						"maybeAcceptBlock, got: %s", e.name, got)
				}
				return
			}

			if !strings.Contains(got, relauxNonCanonicalErr) {
				t.Fatalf("%s must be refused at height %d, got: %s",
					e.name, gate, got)
			}
		})

		// One height below the real gate the same encoding must still pass, or
		// retained mainnet history stops replaying.
		t.Run(e.name+" still accepted one height below", func(t *testing.T) {
			if e.enc == relauxBadMerkleIndex {
				t.Skip("no retained block carries a malleated ParMerkleIndex; " +
					"only the two encodings mainnet actually carried are " +
					"replay-critical")
			}
			h := newNode(t)
			err := relauxSubmit(t, h, relauxBlockAt(t, h, gate-1), e.enc)
			got := relauxDeep(err)
			if strings.Contains(got, relauxNonCanonicalErr) {
				t.Fatalf("REPLAY BREAK: %s must still pass at height %d, got: %s",
					e.name, gate-1, got)
			}
			if !strings.Contains(got, relauxPastSanityErr) {
				t.Fatalf("height %d: expected the submission to reach "+
					"maybeAcceptBlock, got: %s", gate-1, got)
			}
		})
	}
}
