// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"

	"github.com/stretchr/testify/assert"
)

// historicalFixtureKeys are the values that used to be compiled into
// cmd/script/api/arbitrators.go as the arbitratorsPrivateKeys package var.
// They are repeated here — in a _test.go file, which is never linked into a
// shipped binary — so that the F-159 move to an external fixture file can be
// proven to be value-for-value identical.
var historicalFixtureKeys = []string{
	"e372ca1032257bb4be1ac99c4861ec542fd55c25c37f5f58ba8b177850b3fdeb",
	"e6deed7e23406e2dce7b01e85bcb33872a47b6200ca983fcf0540dff284923b0",
	"4441968d02a5df4dbc08ca11da2acc86c980e5fe9ff250450a80fd7421d2b0f1",
	"0b14a04e203301809feccc61dbf4e745203a3263d29a4b4091aaa138ba5fb26d",
	"0c11ebca60af2a09ac13dd84fd29c03b99cd086a08a69a9e5b87255fd9cf2eee",
	"ad44a6d5a5d1f7cafa2fa82c719108e9814ff5c71078e1cafa9f734343a2f806",
}

// TestF159FixtureKeysUnchanged is the no-behaviour-change proof for F-159: the
// externalised fixture file must hand the white-box harness exactly the keys it
// used to get from the compiled-in package var, and each one must still be the
// private key of the matching entry in arbitratorsPublicKeys.
func TestF159FixtureKeysUnchanged(t *testing.T) {
	root := f159RepoRoot(t)
	assert.NoError(t, os.Setenv(arbiterKeysEnv,
		filepath.Join(root, defaultArbiterKeysPath)))
	defer os.Unsetenv(arbiterKeysEnv)

	assert.Equal(t, len(historicalFixtureKeys), len(arbitratorsPublicKeys))

	for i, want := range historicalFixtureKeys {
		got, err := arbitratorPrivateKey(i)
		assert.NoError(t, err)
		assert.Equal(t, want, got, "fixture key %d must be unchanged", i)

		priv, err := common.HexStringToBytes(got)
		assert.NoError(t, err)
		acc, err := account.NewAccountWithPrivateKey(priv)
		assert.NoError(t, err)
		pub, err := acc.PublicKey.EncodePoint(true)
		assert.NoError(t, err)
		assert.Equal(t, arbitratorsPublicKeys[i], common.BytesToHexString(pub),
			"fixture key %d must still match arbitratorsPublicKeys[%d]", i, i)
	}

	// Out-of-range indices are rejected rather than panicking.
	_, err := arbitratorPrivateKey(len(historicalFixtureKeys))
	assert.Error(t, err)
	_, err = arbitratorPrivateKey(-1)
	assert.Error(t, err)
}

func f159RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	assert.NoError(t, err)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root")
	return ""
}
