// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

// b3Gate is the mainnet StrictMoneyRangeHeight (recovery gate). The unknown-version
// default-deny (F-039 / F-069) is active at/above it; below it the legacy behavior
// (no default-deny) is preserved byte-identically for replay-safety.
const b3Gate = uint32(2260451)

// b3Cfg builds a config with the gate set, and SupportMultiCodeHeight/DPoSV2StartHeight
// zeroed so the pre-existing height gates never interfere with the version check under
// test (isolates the new default-deny).
func b3Cfg() *config.Configuration {
	c := &config.Configuration{StrictMoneyRangeHeight: b3Gate}
	c.SupportMultiCodeHeight = 0
	c.DPoSV2StartHeight = 0
	return c
}

func buildCancel(ver byte, h uint32) *CancelProducerTransaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.CancelProducer, ver,
		&payload.ProcessProducer{OwnerKey: []byte{0x02, 0x03}}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: b3Cfg()})
	return txn.(*CancelProducerTransaction)
}

func buildUpdate(ver byte, h uint32) *UpdateProducerTransaction {
	txn := functions.CreateTransaction(
		common2.TxVersion09, common2.UpdateProducer, ver,
		&payload.ProducerInfo{}, []*common2.Attribute{},
		[]*common2.Input{}, []*common2.Output{}, 0,
		[]*program.Program{{Code: []byte{0x01}}})
	txn.SetParameters(&TransactionParameters{Transaction: txn, BlockHeight: h, Config: b3Cfg()})
	return txn.(*UpdateProducerTransaction)
}

// TestF039CancelUnknownPayloadVersion — CancelProducer unknown-version default-deny.
// HeightVersionCheck runs (SanityCheck + ContextCheck) BEFORE SpecialContextCheck, so
// rejecting the unknown version here blocks the unauthenticated checkProcessProducer
// fall-through (v>=3 with no owner proof) before it can cancel an arbitrary producer.
// Run -count=20 for the fix-proof.
func TestF039CancelUnknownPayloadVersion(t *testing.T) {
	// ProcessProducer defined versions: 0 (ECDSA), 1 (Schnorr), 2 (MultiCode).
	knownVers := []byte{0x00, 0x01, 0x02}
	unknownVers := []byte{0x03, 0x04, 0x05, 0x7f, 0xff}
	belowHeights := []uint32{0, b3Gate - 100, b3Gate - 1}
	aboveHeights := []uint32{b3Gate, b3Gate + 1, b3Gate + 144}

	// FIX-PROOF: every unknown version is rejected at/above the gate.
	for _, v := range unknownVers {
		for _, h := range aboveHeights {
			if err := buildCancel(v, h).HeightVersionCheck(); err == nil {
				t.Fatalf("F-039: unknown CancelProducer version 0x%x at height %d must be REJECTED at/above gate", v, h)
			}
		}
	}
	// REPLAY-SAFETY / exploit surface: the same unknown versions are ACCEPTED below the
	// gate (byte-identical to the pre-fix pipeline — the auth hole that the fix closes
	// only at/above the coordinated-upgrade gate).
	for _, v := range unknownVers {
		for _, h := range belowHeights {
			if err := buildCancel(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-039: below-gate replay broken — unknown version 0x%x at %d must pass HeightVersionCheck, got %v", v, h, err)
			}
		}
	}
	// RELATED-TX: defined versions pass at every height (no legitimate cancel rejected).
	for _, v := range knownVers {
		for _, h := range append(append([]uint32{}, belowHeights...), aboveHeights...) {
			if err := buildCancel(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-039: defined CancelProducer version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
}

// TestF069UpdateUnknownPayloadVersion — UpdateProducer unknown-version default-deny
// (identity takeover via NodePublicKey re-key on the v>=4 fall-through). Run -count=20.
func TestF069UpdateUnknownPayloadVersion(t *testing.T) {
	// ProducerInfo defined versions: 0, 1 (DposV2), 2 (Schnorr), 3 (MultiCode).
	knownVers := []byte{0x00, 0x01, 0x02, 0x03}
	unknownVers := []byte{0x04, 0x05, 0x10, 0x7f, 0xff}
	belowHeights := []uint32{0, b3Gate - 100, b3Gate - 1}
	aboveHeights := []uint32{b3Gate, b3Gate + 1, b3Gate + 144}

	for _, v := range unknownVers {
		for _, h := range aboveHeights {
			if err := buildUpdate(v, h).HeightVersionCheck(); err == nil {
				t.Fatalf("F-069: unknown UpdateProducer version 0x%x at height %d must be REJECTED at/above gate", v, h)
			}
		}
	}
	for _, v := range unknownVers {
		for _, h := range belowHeights {
			if err := buildUpdate(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-069: below-gate replay broken — unknown version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
	for _, v := range knownVers {
		for _, h := range append(append([]uint32{}, belowHeights...), aboveHeights...) {
			if err := buildUpdate(v, h).HeightVersionCheck(); err != nil {
				t.Fatalf("F-069: defined UpdateProducer version 0x%x at %d must pass, got %v", v, h, err)
			}
		}
	}
}
