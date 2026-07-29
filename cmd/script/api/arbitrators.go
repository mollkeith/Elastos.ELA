// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package api

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/dpos/state"

	"github.com/yuin/gopher-lua"
)

const (
	luaArbitratorsTypeName = "arbitrators"
	MajorityCount          = 4
)

var (
	arbitratorsPublicKeys = []string{
		"023a133480176214f88848c6eaa684a54b316849df2b8570b57f3a917f19bbc77a",
		"030a26f8b4ab0ea219eb461d1e454ce5f0bd0d289a6a64ffc0743dab7bd5be0be9",
		"0288e79636e41edce04d4fa95d8f62fed73a76164f8631ccc42f5425f960e4a0c7",
		"03e281f89d85b3a7de177c240c4961cb5b1f2106f09daa42d15874a38bbeae85dd",
		"0393e823c2087ed30871cbea9fa5121fa932550821e9f3b17acef0e581971efab0",
		"0382c9e7f11c01d3bde067d006dc2e7b2378499b543a790454d5603e338911ca29",
	}
	// NOTE (F-159): the matching private keys are deliberately NOT compiled
	// in. They live in an external fixture file and are read at run time by
	// arbitratorPrivateKey() in fixturekeys.go, so no signing key material
	// ships inside the distributed ela-cli binary.
)

func RegisterArbitratorsType(L *lua.LState) {
	mt := L.NewTypeMetatable(luaArbitratorsTypeName)
	L.SetGlobal("arbitrators", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newArbitrators))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), arbitratorsMethods))
}

// Constructor
func newArbitrators(L *lua.LState) int {
	arbiters := make([]state.ArbiterMember, 0)
	for _, arbiter := range arbitratorsPublicKeys {
		arbiterByte, _ := common.HexStringToBytes(arbiter)
		ar, _ := state.NewOriginArbiter(arbiterByte)
		arbiters = append(arbiters, ar)
	}

	a := state.NewArbitratorsMock(arbiters, 0, MajorityCount)

	ud := L.NewUserData()
	ud.Value = a
	L.SetMetatable(ud, L.GetTypeMetatable(luaArbitratorsTypeName))
	L.Push(ud)

	return 1
}

// Checks whether the first lua argument is a *LUserData with *Attribute and returns this *Attribute.
func checkArbitrators(L *lua.LState, idx int) *state.ArbitratorsMock {
	ud := L.CheckUserData(idx)
	if v, ok := ud.Value.(*state.ArbitratorsMock); ok {
		return v
	}
	L.ArgError(1, "arbitrators expected")
	return nil
}

var arbitratorsMethods = map[string]lua.LGFunction{
	"get_duty_index": arbitratorsGetDutyIndex,
	"set_duty_index": arbitratorsSetDutyIndex,
}

func arbitratorsGetDutyIndex(L *lua.LState) int {
	a := checkArbitrators(L, 1)
	L.Push(lua.LNumber(a.GetDutyChangeCount()))

	return 1
}

func arbitratorsSetDutyIndex(L *lua.LState) int {
	a := checkArbitrators(L, 1)
	index := L.ToInt(2)
	a.SetDutyChangeCount(index)

	return 0
}
