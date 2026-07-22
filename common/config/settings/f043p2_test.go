// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"

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
