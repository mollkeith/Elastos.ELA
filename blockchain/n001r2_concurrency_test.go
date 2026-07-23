// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package blockchain

import (
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	program2 "github.com/elastos/Elastos.ELA/core/contract/program"
	types2 "github.com/elastos/Elastos.ELA/core/types"
	common3 "github.com/elastos/Elastos.ELA/core/types/common"
	functions2 "github.com/elastos/Elastos.ELA/core/types/functions"
	interfaces2 "github.com/elastos/Elastos.ELA/core/types/interfaces"
	outputpayload2 "github.com/elastos/Elastos.ELA/core/types/outputpayload"
	payload2 "github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	state2 "github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// r2BestHeight backs the bestHeight closure of the Arbiters under test.
var r2BestHeight uint32

// r2ArbiterKeys are the producer/arbiter public keys the harness drives.
var r2ArbiterKeys = []string{
	"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
	"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
	"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
	"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
	"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
}

// r2RegisterProducerTx / r2VoteProducerTx build the two real transactions the
// harness needs to give the Arbiters four active, voted producers, so the
// emergency ForceChange it drives runs the REAL rotation (UpdateNextArbitrators ->
// ChangeCurrentArbitrators -> History.Commit) rather than bailing out early on
// ErrInsufficientProducer.
func r2RegisterProducerTx(ownerPublicKey, nodePublicKey []byte,
	nickName string) interfaces2.Transaction {
	pk, _ := crypto.DecodePoint(ownerPublicKey)
	depositCont, _ := contract.CreateDepositContractByPubKey(pk)
	return functions2.CreateTransaction(
		0,
		common3.RegisterProducer,
		0,
		&payload2.ProducerInfo{
			OwnerKey:      ownerPublicKey,
			NodePublicKey: nodePublicKey,
			NickName:      nickName,
		},
		[]*common3.Attribute{},
		[]*common3.Input{},
		[]*common3.Output{
			{
				ProgramHash: *depositCont.ToProgramHash(),
				Value:       common.Fixed64(5000 * 1e8),
			},
		},
		0,
		[]*program2.Program{},
	)
}

func r2VoteProducerTx(amount common.Fixed64,
	candidateVotes []outputpayload2.CandidateVotes) interfaces2.Transaction {
	return functions2.CreateTransaction(
		common3.TxVersion09,
		common3.TransferAsset,
		0,
		&payload2.TransferAsset{},
		[]*common3.Attribute{},
		[]*common3.Input{},
		[]*common3.Output{
			{
				AssetID:     common.Uint256{},
				Value:       amount,
				OutputLock:  0,
				ProgramHash: common.Uint168{},
				Type:        common3.OTVote,
				Payload: &outputpayload2.VoteOutput{
					Version: outputpayload2.VoteProducerAndCRVersion,
					Contents: []outputpayload2.VoteContent{{
						VoteType:       outputpayload2.Delegate,
						CandidateVotes: candidateVotes,
					}},
				},
			},
		},
		0,
		[]*program2.Program{},
	)
}

// r2Chain builds a real Arbiters wired to a real checkpoint.Manager (which
// NewArbitrators registers the dpos CheckPoint into), drives it to a tip with four
// active voted producers, and returns everything the boundary methods need.
func r2Chain(t *testing.T) (*state2.Arbiters, *checkpoint.Manager,
	*config.Configuration, [][]byte, uint32) {

	// core/transaction imports blockchain, so an INTERNAL blockchain test cannot
	// import it to wire the transaction factory. The external blockchain_test files
	// in this same test binary (e.g. h_crashguard_test.go) do that in their init(),
	// which runs before any test body.
	require.NotNil(t, functions2.CreateTransaction,
		"transaction factory must be wired by the package test binary init")

	keys := make([][]byte, 0, len(r2ArbiterKeys))
	for _, v := range r2ArbiterKeys {
		k, err := common.HexStringToBytes(v)
		require.NoError(t, err)
		keys = append(keys, k)
	}

	// A PRIVATE parameter set: other tests in this package mutate the shared
	// config.DefaultParams, and the rotation rules this harness walks are
	// parameter-sensitive. Isolate so the result does not depend on test order.
	params := config.GetDefaultParams()
	ckp := checkpoint.NewManager(params)
	// No checkpoint files: this harness only exercises the in-memory brackets.
	ckp.SetNeedSave(false)
	params.DPoSConfiguration.CRCArbiters = []string{
		"03e435ccd6073813917c2d841a0815d21301ec3286bc1412bb5b099178c68a10b6",
		"038a1829b4b2bee784a99bebabbfecfec53f33dadeeeff21b460f8b4fc7c2ca771",
	}

	abt, err := state2.NewArbitrators(params, nil, nil,
		nil, nil, nil,
		nil, nil, nil, ckp)
	require.NoError(t, err)
	abt.RegisterFunction(func() uint32 { return r2BestHeight },
		func() *common.Uint256 { return &common.Uint256{} },
		func(h uint32) (*types2.Block, error) {
			return &types2.Block{Header: common3.Header{Height: h}}, nil
		}, nil)
	abt.State = state2.NewState(params, nil, nil, nil,
		func() bool { return false },
		nil, nil, nil,
		nil, nil, nil, nil)

	height := abt.ChainParams.VoteStartHeight
	r2BestHeight = height
	abt.ProcessBlock(&types2.Block{
		Header: common3.Header{Height: height},
		Transactions: []interfaces2.Transaction{
			r2RegisterProducerTx(keys[0], keys[0], "p1"),
			r2RegisterProducerTx(keys[1], keys[1], "p2"),
			r2RegisterProducerTx(keys[2], keys[2], "p3"),
			r2RegisterProducerTx(keys[3], keys[3], "p4"),
		},
	}, nil)

	for i := 0; i < 5; i++ {
		height++
		r2BestHeight = height
		abt.ProcessBlock(&types2.Block{
			Header: common3.Header{Height: height}}, nil)
	}
	require.Equal(t, 4, len(abt.ActivityProducers))

	height++
	r2BestHeight = height
	abt.ProcessBlock(&types2.Block{
		Header: common3.Header{Height: height},
		Transactions: []interfaces2.Transaction{
			r2VoteProducerTx(10, []outputpayload2.CandidateVotes{
				{Candidate: keys[0], Votes: 5}})}}, nil)

	return abt, ckp, params, keys, height
}

// TestN001R2CheckpointBracketSerialization is the fail-on-pristine proof for the R2
// residual of #4/N-001.
//
// N-001 shipped specialTxMtx at the connectBlock bracket, the four DPoS-gossip
// brackets and the reorg-detach rollback -- but NOT at the checkpoint replay/save
// boundaries. Those boundaries (BlockChain.replayCheckpointBlock, which the
// InitCheckpoint replay loop runs, and BlockChain.saveBlockCheckpoints, which the
// reorg attach loop and processBlock run) reach
// checkpoint.Manager.OnBlockSaved -> dpos/state CheckPoint.OnBlockSaved ->
// Arbiters.ProcessBlock, which mutates exactly the state a concurrent gossip
// emergency bracket mutates -- under a DIFFERENT mutex. Concretely,
// Arbiters.ProcessBlock reads a.DutyIndex with NO lock at all
// (a.State.ProcessBlock(block, sponsor, a.DutyIndex)) while the gossip bracket's
// forceChange -> ChangeCurrentArbitrators writes a.DutyIndex under a.mtx, and
// State.ProcessBlock writes the producer maps under s.mtx while forceChange reads
// them under a.mtx only.
//
// This test drives goroutine group A through the PRODUCTION boundary methods and
// goroutine group B through the shipped gossip bracket shape, concurrently, on one
// shared Arbiters.
//
//	FAIL-ON-PRISTINE: with the two LockSpecialTx/UnlockSpecialTx boundaries in
//	replayCheckpointBlock and saveBlockCheckpoints removed, `go test -race` reports
//	`WARNING: DATA RACE` on Arbiters.DutyIndex (read in Arbiters.ProcessBlock, write
//	in ChangeCurrentArbitrators) and the run FAILS. With them present the run is
//	clean, repeatedly.
//
// Every group-B bracket is net-zero (force-change then undo), so the emergency
// bookkeeping must be back at its baseline at the end -- a torn interleave would
// leave a force-change or a processed-payload marker behind.
func TestN001R2CheckpointBracketSerialization(t *testing.T) {
	abt, ckp, params, keys, tip := r2Chain(t)

	// b.state is only read for ConsensusAlgorithm / RevertToPOWBlockHeight at the
	// OnBlockSaved call; give it its own State so the harness measures only the
	// Arbiters brackets.
	chainState := state2.NewState(params, nil, nil, nil,
		func() bool { return false },
		nil, nil, nil,
		nil, nil, nil, nil)
	b := &BlockChain{CkpManager: ckp, state: chainState, chainParams: params}

	savedLedger := DefaultLedger
	DefaultLedger = &Ledger{Blockchain: b, Arbitrators: abt}
	defer func() { DefaultLedger = savedLedger }()

	const groups = 4
	const iterations = 60

	var errMtx sync.Mutex
	var replayErrs []error
	var wg sync.WaitGroup

	// Group A: the checkpoint replay / save boundaries (the code under test).
	wg.Add(groups)
	for g := 0; g < groups; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				blk := &types2.Block{Header: common3.Header{Height: tip}}
				if i%2 == 0 {
					b.saveBlockCheckpoints(&types2.DposBlock{Block: blk})
					continue
				}
				if err := b.replayCheckpointBlock(
					&types2.DposBlock{Block: blk}); err != nil {
					errMtx.Lock()
					replayErrs = append(replayErrs, err)
					errMtx.Unlock()
				}
			}
		}(g)
	}

	// Group B: the shipped DPoS-gossip bracket shape (blockchain.ProcessInactiveArbiter
	// / dpos manager / arbitrator), kept net-zero with the reject-path undo so the
	// harness is repeatable. A distinct sponsor per goroutine keeps payload hashes
	// distinct so AddInactivePayload does not dedup the bracket away.
	wg.Add(groups)
	for g := 0; g < groups; g++ {
		go func(id int) {
			defer wg.Done()
			p := &payload2.InactiveArbitrators{
				Sponsor:     keys[id%len(keys)],
				Arbitrators: [][]byte{keys[(id+1)%len(keys)]},
				BlockHeight: tip + 1,
			}
			for i := 0; i < iterations; i++ {
				abt.LockSpecialTx()
				_ = abt.ProcessSpecialTxPayload(p, tip)
				abt.UndoPendingSpecialTx()
				abt.UnlockSpecialTx()
			}
		}(g)
	}

	wg.Wait()

	// No deadlock (we got here), no -race report, no panic.
	errMtx.Lock()
	assert.Empty(t, replayErrs, "replay boundary must not fail")
	errMtx.Unlock()

	after := abt.Snapshot()
	assert.False(t, after.ForceChanged,
		"net-zero gossip brackets must leave no force-change behind")
	assert.Equal(t, 0, len(after.InactiveTxs),
		"no processed-payload marker leaked out of an interleaved bracket")
}
