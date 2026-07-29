// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package api

import (
	"testing"

	"github.com/elastos/Elastos.ELA/core/types/payload"

	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

// TestF160IllegalTypeGlobalsAreDistinct proves F-160.
//
// RegisterIllegalBlocksType built the "illegal_blocks" metatable but published
// it under the global name "illegal_votes" — the only duplicate SetGlobal in the
// repo. Because api.go registers votes first and blocks second, the blocks
// metatable clobbered the votes one, so lua scripts got:
//
//	illegal_votes.new()  -> a *payload.DPOSIllegalBlocks (wrong userdata type)
//	illegal_blocks.new() -> index of a nil global (constructor unreachable)
//
// Pre-fix the illegal_blocks lookup below raises "attempt to index a non-table
// object(nil)" and the test fails.
func TestF160IllegalTypeGlobalsAreDistinct(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	RegisterIllegalVotesType(L)
	RegisterIllegalBlocksType(L)

	votesMT := L.GetGlobal(luaIllegalVotesTypeName)
	blocksMT := L.GetGlobal(luaIllegalBlocksTypeName)
	assert.NotEqual(t, lua.LNil, votesMT, "global illegal_votes must be registered")
	assert.NotEqual(t, lua.LNil, blocksMT, "global illegal_blocks must be registered")
	assert.NotEqual(t, votesMT, blocksMT,
		"F-160: the two constructors must not share one global name")

	assert.NoError(t, L.DoString(`v = illegal_votes.new()`),
		"illegal_votes.new() must be reachable")
	assert.NoError(t, L.DoString(`b = illegal_blocks.new(0, 1)`),
		"F-160: illegal_blocks.new() must be reachable")

	v, ok := L.GetGlobal("v").(*lua.LUserData)
	if !assert.True(t, ok, "illegal_votes.new() must return userdata") {
		return
	}
	_, ok = v.Value.(*payload.DPOSIllegalVotes)
	assert.True(t, ok, "F-160: illegal_votes.new() must build DPOSIllegalVotes, got %T", v.Value)

	b, ok := L.GetGlobal("b").(*lua.LUserData)
	if !assert.True(t, ok, "F-160: illegal_blocks.new() must return userdata") {
		return
	}
	blocks, ok := b.Value.(*payload.DPOSIllegalBlocks)
	if !assert.True(t, ok, "F-160: illegal_blocks.new() must build DPOSIllegalBlocks, got %T", b.Value) {
		return
	}
	assert.Equal(t, uint32(1), blocks.BlockHeight)
}
