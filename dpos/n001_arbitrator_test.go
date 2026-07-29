// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

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
	"github.com/elastos/Elastos.ELA/dpos/manager"
	"github.com/elastos/Elastos.ELA/dpos/state"
	"github.com/elastos/Elastos.ELA/elanet"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// N-001 fail-on-pristine for the fourth caller: dpos/arbitrator.go:180
// (Arbitrator.OnInactiveArbitratorsTxReceived). Same discriminator as the
// dpos/manager sites: the fix adds an unconditional CommitPendingSpecialTx()
// after ProcessSpecialTxPayload, so the emergency ForceChange survives a later
// RollbackTo(tip) on the fixed tree and is destroyed on the pristine (33e12f8)
// tree.
//
// To REACH the ProcessSpecialTxPayload call the caller requires the node to be a
// non-arbiter emergency candidate. Producing a natural candidate pool needs a
// far-future DPoS era / dozens of producers, so a thin wrapper overrides only
// GetCandidates() (the plumbing guard) and delegates every other call --
// including ProcessSpecialTxPayload / CommitPendingSpecialTx / RollbackTo -- to
// the REAL Arbiters, so the code under test is unchanged.
// ---------------------------------------------------------------------------

func init() {
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters
	config.DefaultParams = *config.GetDefaultParams()
	dposlog.Init(os.TempDir(), 5, 20, 20)
}

var n001BestHeight uint32
var n001AbtList [][]byte
var n001Params *config.Configuration

func n001RandomUint168() *common.Uint168 {
	b := make([]byte, 21)
	crand.Read(b)
	r, _ := common.Uint168FromBytes(b)
	return r
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
	n001Params = params
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
	return abt, height
}

func n001SetLedger(tip uint32, arb state.Arbitrators) func() {
	orig := blockchain.DefaultLedger
	bc := &blockchain.BlockChain{Nodes: make([]*blockchain.BlockNode, tip+1)}
	blockchain.DefaultLedger = &blockchain.Ledger{Blockchain: bc, Arbitrators: arb}
	return func() { blockchain.DefaultLedger = orig }
}

func n001Payload(tip uint32) *payload.InactiveArbitrators {
	return &payload.InactiveArbitrators{
		Sponsor:     n001AbtList[0],
		Arbitrators: [][]byte{n001AbtList[1]},
		BlockHeight: tip + 1,
	}
}

// n001ArbWrap delegates every Arbitrators method to the embedded real Arbiters
// except GetCandidates, which it forces so the emergency-candidate guard passes.
type n001ArbWrap struct {
	state.Arbitrators
	cands [][]byte
}

func (w *n001ArbWrap) GetCandidates() [][]byte { return w.cands }

// n001Server is a minimal elanet.Server whose only wired method is IsCurrent.
type n001Server struct{ elanet.Server }

func (n001Server) IsCurrent() bool { return false }

// TestN001Caller1_OnInactiveArbitratorsTxReceived drives dpos/arbitrator.go:180.
func TestN001Caller1_OnInactiveArbitratorsTxReceived(t *testing.T) {
	abt, tip := n001BuildArbiters(t)
	defer n001SetLedger(tip, abt)()

	// n001AbtList[4] was never registered as a producer, so it is not a current
	// arbiter -- the caller's non-arbiter guard passes -- and we force it into the
	// candidate list so it is treated as an emergency candidate.
	candKey := n001AbtList[4]
	require.False(t, abt.IsArbitrator(candKey))
	require.GreaterOrEqual(t, abt.GetArbitersCount()/3, 1,
		"sanity: at least one emergency-candidate slot")
	wrap := &n001ArbWrap{Arbitrators: abt, cands: [][]byte{candKey}}

	mgr := manager.NewManager(manager.DPOSManagerConfig{
		PublicKey:   candKey,
		Arbitrators: wrap,
		ChainParams: n001Params,
	})
	a := &Arbitrator{
		cfg:         Config{Arbitrators: wrap, Server: n001Server{}},
		dposManager: mgr,
	}
	require.False(t, abt.Snapshot().ForceChanged)

	a.OnInactiveArbitratorsTxReceived(n001Payload(tip))

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
