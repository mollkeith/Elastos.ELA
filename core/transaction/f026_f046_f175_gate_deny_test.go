// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// gdGate is the mainnet StrictMoneyRangeHeight (recovery / coordinated-upgrade gate).
// The gate-deny batch (F-026 producer/cancel Schnorr mirror, F-046 UpdateCR version
// discipline, F-175 CRCProposalWithdraw default-deny) activates its new rejections at
// and above this height; below it, retained history replays byte-identically.
const gdGate = uint32(2260451)

var gdBelow = []uint32{0, gdGate - 100, gdGate - 1}
var gdAbove = []uint32{gdGate, gdGate + 1, gdGate + 144}

// ------------------------------------------------------------------ F-026

// gdUpdateProducer builds an UpdateProducer at height h with payload version ver.
// ProducerSchnorrStartHeight is pinned to MaxUint32 (mainnet dormant value); the
// pre-existing DPoSV2 / MultiCode gates are zeroed so they never mask the Schnorr gate.
func gdUpdateProducer(ver byte, h uint32) *UpdateProducerTransaction {
	c := &config.Configuration{StrictMoneyRangeHeight: gdGate}
	c.DPoSV2StartHeight = 0
	c.SupportMultiCodeHeight = 0
	c.ProducerSchnorrStartHeight = math.MaxUint32
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.UpdateProducer, ver,
		&payload.ProducerInfo{}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: c})
	return txn.(*UpdateProducerTransaction)
}

func gdCancelProducer(ver byte, h uint32) *CancelProducerTransaction {
	c := &config.Configuration{StrictMoneyRangeHeight: gdGate}
	c.SupportMultiCodeHeight = 0
	c.ProducerSchnorrStartHeight = math.MaxUint32
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.CancelProducer, ver,
		&payload.ProcessProducer{OwnerKey: []byte{0x02, 0x03}}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: c})
	return txn.(*CancelProducerTransaction)
}

// TestF026ProducerSchnorrGateMirror — RegisterProducer rejects the Schnorr producer
// version below ProducerSchnorrStartHeight (dormant on mainnet), but UpdateProducer and
// CancelProducer did not, leaking the dormant Schnorr re-key / cancel path via the
// update/cancel routes. FIX-PROOF (fails on pristine): the Schnorr version must be
// REJECTED at/above the gate while ProducerSchnorrStartHeight is unreached. Run -count=20.
func TestF026ProducerSchnorrGateMirror(t *testing.T) {
	// FIX-PROOF: Schnorr UpdateProducer (0x02) rejected at/above the gate.
	for _, h := range gdAbove {
		if err := gdUpdateProducer(payload.ProducerInfoSchnorrVersion, h).HeightVersionCheck(); err == nil {
			t.Fatalf("F-026: Schnorr UpdateProducer at height %d must be REJECTED at/above gate (dormant ProducerSchnorrStartHeight)", h)
		}
	}
	// FIX-PROOF: Schnorr CancelProducer (0x01) rejected at/above the gate.
	for _, h := range gdAbove {
		if err := gdCancelProducer(payload.ProcessProducerSchnorrVersion, h).HeightVersionCheck(); err == nil {
			t.Fatalf("F-026: Schnorr CancelProducer at height %d must be REJECTED at/above gate", h)
		}
	}
	// REPLAY-SAFETY: below the gate the Schnorr version still passes HeightVersionCheck
	// (byte-identical to the pre-fix pipeline).
	for _, h := range gdBelow {
		if err := gdUpdateProducer(payload.ProducerInfoSchnorrVersion, h).HeightVersionCheck(); err != nil {
			t.Fatalf("F-026: below-gate replay broken — Schnorr UpdateProducer at %d must pass, got %v", h, err)
		}
		if err := gdCancelProducer(payload.ProcessProducerSchnorrVersion, h).HeightVersionCheck(); err != nil {
			t.Fatalf("F-026: below-gate replay broken — Schnorr CancelProducer at %d must pass, got %v", h, err)
		}
	}
	// FEATURE-ACTIVATION: once ProducerSchnorrStartHeight is reached, the Schnorr version
	// is accepted at/above the gate (the mirror is a true activation, not a blanket ban).
	up := gdUpdateProducer(payload.ProducerInfoSchnorrVersion, gdGate+10)
	up.parameters.Config.ProducerSchnorrStartHeight = gdGate
	if err := up.HeightVersionCheck(); err != nil {
		t.Fatalf("F-026: Schnorr UpdateProducer at/after ProducerSchnorrStartHeight must pass, got %v", err)
	}
	cp := gdCancelProducer(payload.ProcessProducerSchnorrVersion, gdGate+10)
	cp.parameters.Config.ProducerSchnorrStartHeight = gdGate
	if err := cp.HeightVersionCheck(); err != nil {
		t.Fatalf("F-026: Schnorr CancelProducer at/after ProducerSchnorrStartHeight must pass, got %v", err)
	}
	// RELATED-TX: non-Schnorr producer versions are unaffected at every height.
	for _, h := range append(append([]uint32{}, gdBelow...), gdAbove...) {
		if err := gdUpdateProducer(payload.ProducerInfoVersion, h).HeightVersionCheck(); err != nil {
			t.Fatalf("F-026: base UpdateProducer version at %d must pass, got %v", h, err)
		}
		if err := gdCancelProducer(payload.ProcessProducerVersion, h).HeightVersionCheck(); err != nil {
			t.Fatalf("F-026: base CancelProducer version at %d must pass, got %v", h, err)
		}
	}
}

// ------------------------------------------------------------------ F-046

func gdUpdateCR(ver byte, h uint32) *UpdateCRTransaction {
	c := &config.Configuration{StrictMoneyRangeHeight: gdGate}
	c.CRSchnorrStartHeight = math.MaxUint32
	c.DPoSConfiguration.NFTStartHeight = 0
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.UpdateCR, ver,
		&payload.CRInfo{}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: c})
	return txn.(*UpdateCRTransaction)
}

// TestF046UpdateCRVersionGate — UpdateCR had NO HeightVersionCheck (DefaultChecker
// no-op), so unknown/dormant payload versions bypassed the version discipline
// RegisterCR enforces. FIX-PROOF (fails on pristine): unknown versions and the dormant
// Schnorr version must be REJECTED at/above the gate. Run -count=20.
func TestF046UpdateCRVersionGate(t *testing.T) {
	unknownVers := []byte{0x04, 0x05, 0x7f, 0xff}

	// FIX-PROOF: unknown versions rejected at/above the gate (default-deny).
	for _, v := range unknownVers {
		for _, h := range gdAbove {
			if err := gdUpdateCR(v, h).HeightVersionCheck(); err == nil {
				t.Fatalf("F-046: unknown UpdateCR version 0x%x at height %d must be REJECTED at/above gate", v, h)
			}
		}
	}
	// FIX-PROOF: dormant Schnorr version rejected at/above the gate (CRSchnorrStartHeight).
	for _, h := range gdAbove {
		if err := gdUpdateCR(payload.CRInfoSchnorrVersion, h).HeightVersionCheck(); err == nil {
			t.Fatalf("F-046: Schnorr UpdateCR at height %d must be REJECTED at/above gate (dormant CRSchnorrStartHeight)", h)
		}
	}
	// REPLAY-SAFETY: below the gate every version (known, Schnorr, and unknown) passes,
	// byte-identical to the pre-fix DefaultChecker no-op.
	replayVers := append([]byte{payload.CRInfoVersion, payload.CRInfoDIDVersion,
		payload.CRInfoSchnorrVersion, payload.CRInfoMultiSignVersion}, unknownVers...)
	for _, v := range replayVers {
		for _, h := range gdBelow {
			if err := gdUpdateCR(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-046: below-gate replay broken — version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
	// RELATED-TX: base / DID / Multi versions still pass at/above the gate (not banned).
	for _, v := range []byte{payload.CRInfoVersion, payload.CRInfoDIDVersion, payload.CRInfoMultiSignVersion} {
		for _, h := range gdAbove {
			if err := gdUpdateCR(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-046: known UpdateCR version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
}

// ------------------------------------------------------------------ F-175

func gdWithdraw(ver byte, h uint32) *CRCProposalWithdrawTransaction {
	c := &config.Configuration{StrictMoneyRangeHeight: gdGate}
	c.CRConfiguration.CRCommitteeStartHeight = 0
	c.CRConfiguration.CRCProposalWithdrawPayloadV1Height = 0
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.CRCProposalWithdraw, ver,
		&payload.CRCProposalWithdraw{}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: c})
	return txn.(*CRCProposalWithdrawTransaction)
}

// TestF175WithdrawUnknownVersion — CRCProposalWithdraw.HeightVersionCheck had no default
// case, so a v>=2 payload skipped BOTH the v0 recipient/CR-expenses-source binding and
// the v1 recipient/amount binding, reaching only the owner-signature check. FIX-PROOF
// (fails on pristine): unknown versions must be REJECTED at/above the gate. Run -count=20.
func TestF175WithdrawUnknownVersion(t *testing.T) {
	unknownVers := []byte{0x02, 0x03, 0x7f, 0xff}

	// FIX-PROOF: unknown versions rejected at/above the gate (default-deny).
	for _, v := range unknownVers {
		for _, h := range gdAbove {
			if err := gdWithdraw(v, h).HeightVersionCheck(); err == nil {
				t.Fatalf("F-175: unknown CRCProposalWithdraw version 0x%x at height %d must be REJECTED at/above gate", v, h)
			}
		}
	}
	// REPLAY-SAFETY: below the gate the same unknown versions pass HeightVersionCheck,
	// byte-identical to the pre-fix pipeline (no default case).
	for _, v := range unknownVers {
		for _, h := range gdBelow {
			if err := gdWithdraw(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-175: below-gate replay broken — unknown version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
	// RELATED-TX: the defined v1 (Version01) withdraw is unaffected at every height.
	for _, h := range append(append([]uint32{}, gdBelow...), gdAbove...) {
		if err := gdWithdraw(payload.CRCProposalWithdrawVersion01, h).HeightVersionCheck(); err != nil {
			t.Fatalf("F-175: defined CRCProposalWithdraw v1 at %d must pass, got %v", h, err)
		}
	}
}
