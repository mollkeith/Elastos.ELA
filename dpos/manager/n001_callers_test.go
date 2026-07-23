// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package manager

import (
	crand "crypto/rand"
	"os"
	"testing"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	transaction "github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/outputpayload"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	dposlog "github.com/elastos/Elastos.ELA/dpos/log"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// N-001 fail-on-pristine harness (package manager, white-box).
//
// These tests drive the REAL DPoS-gossip callers of ProcessSpecialTxPayload
// (dposmanager.go OnBlockReceived / OnInactiveArbitratorsAccepted and
// proposaldispatcher.go tryEnterEmergencyState). The fix under test adds an
// unconditional CommitPendingSpecialTx() at each site so the emergency
// ForceChange those callers apply is PERMANENT (pre-e376150 semantics) and can
// no longer be silently reversed by a later Arbiters.RollbackTo. The only
// difference between the fixed tree and the pristine (33e12f8) tree is inside
// the caller bodies, so the SAME test source compiles on both and:
//
//   fixed:    caller commits the savepoint  -> ForceChange SURVIVES RollbackTo(tip)
//   pristine: caller leaks the savepoint    -> ForceChange DESTROYED by RollbackTo(tip)
//
// The Arbiters harness mirrors the proven test/unit/f093 one (a real Arbiters
// wired with a getBlockByHeight closure so the real force-change path runs).
// ---------------------------------------------------------------------------

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
	config.DefaultParams = *config.GetDefaultParams()
	// The gossip callers log via dpos/log; production initialises it. Level 5
	// (LevelOff) keeps the logger non-nil while suppressing all output.
	dposlog.Init(os.TempDir(), 5, 20, 20)
}

// n001BestHeight backs the bestHeight closure of the Arbiters under test.
var n001BestHeight uint32

// n001AbtList holds the producer/arbiter node keys used by the harness.
var n001AbtList [][]byte

func n001RandomUint168() *common.Uint168 {
	randBytes := make([]byte, 21)
	crand.Read(randBytes)
	result, _ := common.Uint168FromBytes(randBytes)
	return result
}

func n001RegisterProducerTx(ownerPublicKey, nodePublicKey []byte,
	nickName string) interfaces.Transaction {
	pk, _ := crypto.DecodePoint(ownerPublicKey)
	depositCont, _ := contract.CreateDepositContractByPubKey(pk)
	return functions.CreateTransaction(
		0, common2.RegisterProducer, 0,
		&payload.ProducerInfo{
			OwnerKey:      ownerPublicKey,
			NodePublicKey: nodePublicKey,
			NickName:      nickName,
		},
		[]*common2.Attribute{}, []*common2.Input{},
		[]*common2.Output{{
			ProgramHash: *depositCont.ToProgramHash(),
			Value:       common.Fixed64(5000 * 1e8),
		}},
		0, []*program.Program{},
	)
}

func n001VoteProducerTx(amount common.Fixed64,
	candidateVotes []outputpayload.CandidateVotes) interfaces.Transaction {
	return functions.CreateTransaction(
		common2.TxVersion09, common2.TransferAsset, 0,
		&payload.TransferAsset{},
		[]*common2.Attribute{}, []*common2.Input{},
		[]*common2.Output{{
			AssetID:     common.Uint256{},
			Value:       amount,
			OutputLock:  0,
			ProgramHash: *n001RandomUint168(),
			Type:        common2.OTVote,
			Payload: &outputpayload.VoteOutput{
				Version: outputpayload.VoteProducerAndCRVersion,
				Contents: []outputpayload.VoteContent{{
					VoteType:       outputpayload.Delegate,
					CandidateVotes: candidateVotes,
				}},
			},
		}},
		0, []*program.Program{},
	)
}

// n001InactiveTx wraps an InactiveArbitrators payload in a real transaction, as
// the gossip callers see it on the wire.
func n001InactiveTx(p *payload.InactiveArbitrators) interfaces.Transaction {
	return functions.CreateTransaction(
		0, common2.InactiveArbitrators, 0, p,
		[]*common2.Attribute{}, []*common2.Input{}, []*common2.Output{},
		0, []*program.Program{},
	)
}

// n001BuildArbiters builds a real Arbiters driven up to a tip that has four
// active, voted producers, so ProcessSpecialTxPayload runs the real emergency
// ForceChange (SnapshotByHeight -> UpdateNextArbitrators -> ChangeCurrent ->
// History.Commit). Returns the Arbiters and the tip height.
func n001BuildArbiters(t *testing.T) (*state.Arbiters, uint32) {
	arbitratorsStr := []string{
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
		"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
		"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
		"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
	}
	n001AbtList = make([][]byte, 0)
	for _, v := range arbitratorsStr {
		a, _ := common.HexStringToBytes(v)
		n001AbtList = append(n001AbtList, a)
	}
	params := config.GetDefaultParams()
	ckpManager := checkpoint.NewManager(params)
	params.DPoSConfiguration.CRCArbiters = []string{
		"03e435ccd6073813917c2d841a0815d21301ec3286bc1412bb5b099178c68a10b6",
		"038a1829b4b2bee784a99bebabbfecfec53f33dadeeeff21b460f8b4fc7c2ca771",
	}
	abt, _ := state.NewArbitrators(params, nil, nil,
		nil, nil, nil, nil, nil, nil, ckpManager)
	abt.RegisterFunction(func() uint32 { return n001BestHeight },
		func() *common.Uint256 { return &common.Uint256{} },
		func(h uint32) (*types.Block, error) {
			return &types.Block{Header: common2.Header{Height: h}}, nil
		}, nil)
	abt.State = state.NewState(params, nil, nil, nil,
		func() bool { return false },
		nil, nil, nil, nil, nil, nil, nil)

	height := params.VoteStartHeight
	n001BestHeight = height
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height},
		Transactions: []interfaces.Transaction{
			n001RegisterProducerTx(n001AbtList[0], n001AbtList[0], "p1"),
			n001RegisterProducerTx(n001AbtList[1], n001AbtList[1], "p2"),
			n001RegisterProducerTx(n001AbtList[2], n001AbtList[2], "p3"),
			n001RegisterProducerTx(n001AbtList[3], n001AbtList[3], "p4"),
		},
	}, nil)
	for i := 0; i < 5; i++ {
		height++
		n001BestHeight = height
		abt.ProcessBlock(&types.Block{
			Header: common2.Header{Height: height}}, nil)
	}
	require.Equal(t, 4, len(abt.ActivityProducers))

	height++
	n001BestHeight = height
	abt.ProcessBlock(&types.Block{
		Header: common2.Header{Height: height},
		Transactions: []interfaces.Transaction{
			n001VoteProducerTx(10, []outputpayload.CandidateVotes{
				{Candidate: n001AbtList[0], Votes: 5}})}}, nil)

	require.NotEmpty(t, abt.GetArbitrators())
	return abt, height
}

// n001SetLedger installs a minimal DefaultLedger whose Blockchain.GetHeight()
// returns tip (getHeight = len(Nodes)-1), so the callers force-change at tip.
func n001SetLedger(tip uint32, arb state.Arbitrators) func() {
	orig := blockchain.DefaultLedger
	bc := &blockchain.BlockChain{Nodes: make([]*blockchain.BlockNode, tip+1)}
	blockchain.DefaultLedger = &blockchain.Ledger{Blockchain: bc, Arbitrators: arb}
	return func() { blockchain.DefaultLedger = orig }
}

// n001Server is a minimal elanet.Server whose only wired method is IsCurrent.
// The embedded (nil) interface supplies the rest; none is called on the path
// under test.
type n001Server struct{ elanet.Server }

func (n001Server) IsCurrent() bool { return false }

// n001CurrentArbiterKey returns a node key that is a current on-duty arbiter, so
// the callers' isCurrentArbiter()/IsArbitrator() guard passes.
func n001CurrentArbiterKey(abt *state.Arbiters) []byte {
	for _, a := range abt.GetArbitrators() {
		if a.IsNormal {
			return a.NodePublicKey
		}
	}
	return nil
}

func n001Payload(tip uint32) *payload.InactiveArbitrators {
	return &payload.InactiveArbitrators{
		Sponsor:     n001AbtList[0],
		Arbitrators: [][]byte{n001AbtList[1]},
		BlockHeight: tip + 1,
	}
}

// n001AssertSurvivesRollback runs the shared discriminator: after the caller has
// applied the emergency ForceChange, a later reorg rolls the Arbiters back to
// tip. History.RollbackTo is strictly-greater-than, so the force-change group
// (committed AT tip) is only reachable through the special-tx savepoint. If the
// caller COMMITTED it (fix), the savepoint is gone and the change survives; if
// the caller LEAKED it (pristine), RollbackTo's undoPendingSpecialTx reverses it.
func n001AssertSurvivesRollback(t *testing.T, abt *state.Arbiters, tip uint32) {
	forced := abt.Snapshot()
	require.True(t, forced.ForceChanged, "sanity: the real gossip ForceChange ran")
	require.Equal(t, 1, len(forced.InactiveTxs), "sanity: the payload marker was added")

	require.NoError(t, abt.RollbackTo(tip))
	after := abt.Snapshot()

	assert.True(t, after.ForceChanged,
		"N-001: a committed gossip ForceChange must survive a later RollbackTo")
	assert.Equal(t, len(forced.CurrentArbitrators), len(after.CurrentArbitrators),
		"N-001: the rotated arbiter set must survive the rollback")
	assert.Equal(t, 1, len(after.InactiveTxs),
		"N-001: the processed-payload marker must survive the rollback")
}

// TestN001Caller4_OnInactiveArbitratorsAccepted drives dposmanager.go:658.
func TestN001Caller4_OnInactiveArbitratorsAccepted(t *testing.T) {
	abt, tip := n001BuildArbiters(t)
	defer n001SetLedger(tip, abt)()

	d := &DPOSManager{
		publicKey:      n001CurrentArbiterKey(abt),
		arbitrators:    abt,
		illegalMonitor: &IllegalBehaviorMonitor{},
		blockCache:     &ConsensusBlockCache{},
		dispatcher:     &ProposalDispatcher{eventAnalyzer: &eventAnalyzer{}},
	}
	d.dispatcher.inactiveCountDown.Reset(0)
	d.blockCache.Reset(nil)
	require.False(t, abt.Snapshot().ForceChanged)

	d.OnInactiveArbitratorsAccepted(n001Payload(tip))
	n001AssertSurvivesRollback(t, abt, tip)
}

// TestN001Caller3_OnBlockReceived drives dposmanager.go:590 (the in-block
// InactiveArbitrators loop).
func TestN001Caller3_OnBlockReceived(t *testing.T) {
	abt, tip := n001BuildArbiters(t)
	defer n001SetLedger(tip, abt)()

	d := &DPOSManager{
		publicKey:      n001CurrentArbiterKey(abt),
		arbitrators:    abt,
		server:         n001Server{},
		illegalMonitor: &IllegalBehaviorMonitor{},
		blockCache:     &ConsensusBlockCache{},
		dispatcher:     &ProposalDispatcher{eventAnalyzer: &eventAnalyzer{}},
	}
	d.dispatcher.inactiveCountDown.Reset(0)
	d.blockCache.Reset(nil)
	require.False(t, abt.Snapshot().ForceChanged)

	block := &types.Block{
		Header:       common2.Header{Height: tip},
		Transactions: []interfaces.Transaction{n001InactiveTx(n001Payload(tip))},
	}
	d.OnBlockReceived(block, false)
	n001AssertSurvivesRollback(t, abt, tip)
}

// TestN001Caller2_TryEnterEmergencyState drives proposaldispatcher.go:779.
func TestN001Caller2_TryEnterEmergencyState(t *testing.T) {
	abt, tip := n001BuildArbiters(t)
	defer n001SetLedger(tip, abt)()

	mgr := &DPOSManager{
		publicKey:      n001CurrentArbiterKey(abt),
		arbitrators:    abt,
		illegalMonitor: &IllegalBehaviorMonitor{},
		blockCache:     &ConsensusBlockCache{},
		// txPool stays nil: AppendToTxPool is nil-receiver guarded.
	}
	mgr.blockCache.Reset(nil)
	disp := &ProposalDispatcher{
		cfg: ProposalDispatcherConfig{
			Manager:             mgr,
			EventAnalyzerConfig: EventAnalyzerConfig{Arbitrators: abt},
		},
		illegalMonitor: &IllegalBehaviorMonitor{},
		eventAnalyzer:  &eventAnalyzer{},
	}
	disp.inactiveCountDown.Reset(0)
	disp.currentInactiveArbitratorTx = n001InactiveTx(n001Payload(tip))
	mgr.dispatcher = disp
	require.False(t, abt.Snapshot().ForceChanged)

	// signCount well above minSignCount (a fraction of the CRC arbiter count + 1).
	require.True(t, disp.tryEnterEmergencyState(len(abt.GetCRCArbiters())*2+10))
	n001AssertSurvivesRollback(t, abt, tip)
}
