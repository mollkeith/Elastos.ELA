// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/core/transaction"
	"github.com/elastos/Elastos.ELA/core/types/functions"

	"github.com/stretchr/testify/assert"
)

// TestF043RefuseMainnetWithGatesOff proves F-043 part 2: a binary that keeps the MAINNET
// foundation identity (e.g. via a mislabelled ActiveNet, which the no-default params switch
// leaves on mainnet) but whose incident gates resolved to Disabled must refuse to start,
// while a correctly-armed mainnet and any non-mainnet foundation start normally.
//
// Fail-on-pristine: neutralize the panic condition in enforceMainnetIncidentGatesArmed and
// the "gates off -> panic" assertion stops panicking, so this test depends on the fix.
func TestF043RefuseMainnetWithGatesOff(t *testing.T) {
	// armed mainnet: real foundation + coordinated gate values -> must start.
	armed := config.GetDefaultParams()
	armed.StrictMoneyRangeHeight = config.MainNetStrictMoneyRangeHeight
	armed.CrossChainUTXOFreezeHeight = config.MainNetCrossChainUTXOFreezeHeight
	armed.ForcedRollbackTrigger = config.MainNetForcedRollbackTrigger
	assert.True(t, config.IsMainNetFoundationProgramHash(armed.FoundationProgramHash),
		"precondition: GetDefaultParams is the mainnet foundation identity")
	assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(armed) },
		"a correctly-armed mainnet must start")

	// mainnet identity but strict-money gate DISABLED -> must refuse to start.
	off := config.GetDefaultParams()
	off.CrossChainUTXOFreezeHeight = config.MainNetCrossChainUTXOFreezeHeight
	off.ForcedRollbackTrigger = config.MainNetForcedRollbackTrigger
	off.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
	assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(off) },
		"mainnet identity with the strict-money gate disabled must refuse to start")

	// mainnet identity but forced-rollback trigger cleared -> must refuse to start.
	noTrigger := config.GetDefaultParams()
	noTrigger.StrictMoneyRangeHeight = config.MainNetStrictMoneyRangeHeight
	noTrigger.CrossChainUTXOFreezeHeight = config.MainNetCrossChainUTXOFreezeHeight
	noTrigger.ForcedRollbackTrigger = ""
	assert.Panics(t, func() { enforceMainnetIncidentGatesArmed(noTrigger) },
		"mainnet identity with the forced-rollback trigger cleared must refuse to start")

	// NON-mainnet foundation with gates disabled -> must start (private/forked net).
	private := config.GetDefaultParams()
	private.FoundationProgramHash = &common.Uint168{} // not the mainnet identity
	private.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
	private.ForcedRollbackTrigger = ""
	assert.False(t, config.IsMainNetFoundationProgramHash(private.FoundationProgramHash))
	assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(private) },
		"a private/forked net (different foundation) with gates off must start")
}

// TestF043PostSterilizeCustomFoundationNotRefused is the regression test for the ordering
// fix: enforceMainnetIncidentGatesArmed must run AFTER Sterilize, so a private/forked net
// that sets a custom (non-mainnet) FoundationAddress is respected. Before the fix the guard
// ran before Sterilize recomputed FoundationProgramHash and saw the inherited mainnet
// default hash -> a legitimate private net with gates off was falsely refused.
func TestF043PostSterilizeCustomFoundationNotRefused(t *testing.T) {
	// Sterilize computes GenesisBlock via the functions.* tx hooks; initialize them as
	// SetupConfig does so the real Sterilize path runs.
	functions.GetTransactionByTxType = transaction.GetTransaction
	functions.GetTransactionByBytes = transaction.GetTransactionByBytes
	functions.CreateTransaction = transaction.CreateTransaction
	functions.GetTransactionParameters = transaction.GetTransactionparameters

	p := config.GetDefaultParams()                                // mainnet default identity
	p.FoundationAddress = "8ZNizBf4KhhPjeJRGpox6rPcHE5Np6tFx3"    // custom (testnet) foundation
	// BEFORE Sterilize the inherited hash is STILL the mainnet default -- running the
	// guard here (the pre-fix ordering) would see mainnet identity and falsely refuse.
	assert.True(t, config.IsMainNetFoundationProgramHash(p.FoundationProgramHash),
		"pre-Sterilize the hash is the inherited mainnet default (the bug trigger)")
	p = p.Sterilize()                                            // recomputes FoundationProgramHash
	p.StrictMoneyRangeHeight = config.DisabledStrictMoneyRangeHeight
	p.ForcedRollbackTrigger = ""

	assert.False(t, config.IsMainNetFoundationProgramHash(p.FoundationProgramHash),
		"after Sterilize the identity must be the custom foundation, not mainnet")
	assert.NotPanics(t, func() { enforceMainnetIncidentGatesArmed(p) },
		"a private/forked net (custom FoundationAddress) with gates off must start")
}
