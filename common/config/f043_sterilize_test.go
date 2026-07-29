// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestF043SterilizeMalformedFoundationAddress proves the F-043 prerequisite fix:
// a malformed FoundationAddress must fail with a CLEAR, field-naming message at the
// parse site, not a nil-pointer dereference in core.GenesisBlock(*FoundationProgramHash)
// ~40 lines later. (The valid-address path is unchanged: the fix only swaps the
// discarded `_` for a captured err that is nil on success, so the success branch is
// byte-identical; a full-Sterilize happy-path test is omitted because core.GenesisBlock
// needs the functions.* tx hooks, which the config package cannot import without a cycle.)
//
// Fail-on-pristine: pre-fix the discarded error left FoundationProgramHash == nil and
// Sterilize panicked with "invalid memory address or nil pointer dereference".
func TestF043SterilizeMalformedFoundationAddress(t *testing.T) {
	p := &Configuration{FoundationAddress: "not-a-valid-ela-address"}

	defer func() {
		r := recover()
		assert.NotNil(t, r, "Sterilize must fail on a malformed FoundationAddress")
		msg := ""
		if r != nil {
			msg = strings.ToLower(toStr(r))
		}
		assert.Contains(t, msg, "foundationaddress",
			"the failure must name the offending field, not be an opaque nil deref")
		assert.NotContains(t, msg, "nil pointer",
			"must NOT be the old obscure nil-pointer dereference")
	}()

	p.Sterilize()
}

func toStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}
