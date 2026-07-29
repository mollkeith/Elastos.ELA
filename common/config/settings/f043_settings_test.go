// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package settings

import (
	"testing"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/stretchr/testify/assert"
)

// TestF043ActiveNetWhitespaceKeepsMainnetGates proves the F-043 label
// normalization. A whitespace-padded mainnet label previously missed the
// `case "", "mainnet", "main"` arm and fell through to `default:`, which DISABLES
// the CrossChain-UTXO freeze/restriction, strict-money-range and forced-rollback
// controls -- while the params switch (no default arm) kept full MAINNET params.
// That combination is a node syncing mainnet with every incident gate off.
//
// Fail-on-pristine: pre-fix these labels yield DisabledCrossChainUTXORestrictionHeight.
func TestF043ActiveNetWhitespaceKeepsMainnetGates(t *testing.T) {
	for _, label := range []string{"MainNet ", " mainnet", "  MAINNET  ", "main "} {
		t.Run(label, func(t *testing.T) {
			configuration := config.GetDefaultParams()
			configuration.ActiveNet = label
			configuration.CrossChainUTXOFreezeHeight = 0
			configuration.CrossChainUTXORestrictionHeight = 0

			enforceCrossChainUTXORestrictionHeights(configuration)

			assert.Equal(t, config.MainNetCrossChainUTXOFreezeHeight,
				configuration.CrossChainUTXOFreezeHeight,
				"whitespace-padded mainnet label must keep the coordinated freeze height")
			assert.Equal(t, config.MainNetCrossChainUTXORestrictionHeight,
				configuration.CrossChainUTXORestrictionHeight,
				"whitespace-padded mainnet label must keep the coordinated restriction height")
		})
	}
}

// TestF043PrivateNetStillDisabled is the anti-regression for the INTENTIONAL
// private/forked-net contract (also asserted by the existing suite): a genuinely
// unknown label must still disable the incident gates. The F-043 change only
// trims whitespace and warns -- it must not turn unknown labels fatal.
func TestF043PrivateNetStillDisabled(t *testing.T) {
	configuration := config.GetDefaultParams()
	configuration.ActiveNet = "private-net"
	configuration.CrossChainUTXOFreezeHeight = 0
	configuration.CrossChainUTXORestrictionHeight = 0

	enforceCrossChainUTXORestrictionHeights(configuration)

	assert.Equal(t, config.DisabledCrossChainUTXORestrictionHeight,
		configuration.CrossChainUTXOFreezeHeight)
	assert.Equal(t, config.DisabledCrossChainUTXORestrictionHeight,
		configuration.CrossChainUTXORestrictionHeight)
}
