// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Reorg revert-symmetry harness, CR committee edition. Same contract as
// revsym_arbiters_test.go: drive the REAL Committee.ProcessBlock / RollbackTo and
// compare the COMPLETE derived state -- every candidate, every DepositInfo, every
// DepositOutputs VALUE, the proposal manager and the history bookkeeping.
//
// The shipped comparator here (committeeKeyFrameEqual -> keyframeEqual /
// stateKeyframeEqual / proposalKeyFrameEqual) has the same blind spots as its DPoS
// counterpart, which is why F-065's CR half shipped without a rollback test that
// could see it.
package unit

import (
	"fmt"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/types"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/cr/state"
	"github.com/elastos/Elastos.ELA/test/revsym"
)

const (
	revsymCRPub  = "02f981e4dae4983a5d284d01609ad735e3242c5672bb2c7bb0018cc36f9ab0c4a5"
	revsymCRPriv = "15e0947580575a9b6729570bed6360a890f84a07dc837922fe92275feec837d4"
)

// runCommitteeReorg applies the segment through the real ProcessBlock, undoes it
// with the real RollbackTo, and requires the complete state to be restored exactly.
func runCommitteeReorg(t *testing.T, name string, c *state.Committee,
	base uint32, seg []revsymStep) {
	t.Helper()
	opt := revsymOptions()
	before := revsym.Dump(c, opt)
	for _, s := range seg {
		c.ProcessBlock(&types.Block{
			Header:       common2.Header{Height: s.height},
			Transactions: s.txs,
		}, nil)
	}
	if revsym.Diff(before, revsym.Dump(c, opt), 1) == "" {
		t.Fatalf("%s: the segment changed NOTHING -- the case reaches no closure", name)
	}
	if err := c.RollbackTo(base); err != nil {
		t.Fatalf("%s: RollbackTo(%d): %v", name, base, err)
	}
	if d := revsym.Diff(before, revsym.Dump(c, opt), 25); d != "" {
		t.Errorf("%s: REORG REVERT ASYMMETRY -- complete committee state after undo "+
			"!= state before the segment:\n%s", name, d)
	}
}

func newRevsymCommittee() (*state.Committee, uint32) {
	ckp := checkpoint.NewManager(config.GetDefaultParams())
	c := state.NewCommittee(&config.DefaultParams, ckp)
	h := config.DefaultParams.CRConfiguration.CRVotingStartHeight
	// Establish the fork point: a committed parent block.
	c.ProcessBlock(&types.Block{Header: common2.Header{Height: h}}, nil)
	return c, h
}

// TestRevsym_Committee_RegisterCR reaches cr/state registerCR, whose revert used to
// delete every added DepositOutputs key unconditionally (F-065, CR half).
func TestRevsym_Committee_RegisterCR(t *testing.T) {
	c, h := newRevsymCommittee()
	runCommitteeReorg(t, "register-cr", c, h, []revsymStep{{h + 1,
		[]interfaces.Transaction{
			getRegisterCRTx(revsymCRPub, revsymCRPriv, "revsym nick 1"),
		}}})
}

// TestRevsym_Committee_DepositTopUp reaches cr/state processDeposit -- the direct
// map write F-065 History-wrapped -- by paying more ELA into an existing CR's
// deposit address.
func TestRevsym_Committee_DepositTopUp(t *testing.T) {
	c, h := newRevsymCommittee()
	h++
	c.ProcessBlock(&types.Block{
		Header: common2.Header{Height: h},
		Transactions: []interfaces.Transaction{
			getRegisterCRTx(revsymCRPub, revsymCRPriv, "revsym nick 2"),
		}}, nil)

	pub, err := common.HexStringToBytes(revsymCRPub)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	depositHash, err := contract.PublicKeyToDepositProgramHash(pub)
	if err != nil {
		t.Fatalf("deposit hash: %v", err)
	}

	for i, value := range []common.Fixed64{1 * 1e8, 4000 * 1e8} {
		h++
		c.ProcessBlock(&types.Block{Header: common2.Header{Height: h}}, nil)
		runCommitteeReorg(t, fmt.Sprintf("cr-deposit-topup-%d", i), c, h,
			[]revsymStep{{h + 1, []interfaces.Transaction{
				getTransferAssetTx(revsymCRPub, value, *depositHash),
			}}})
		h++
	}
}
