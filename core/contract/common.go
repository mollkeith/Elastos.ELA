// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package contract

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/vm"
)

type ContractType byte

const (
	Signature ContractType = iota
	MultiSig
	Custom
	Schnorr
)

func IsStandard(code []byte) bool {
	if len(code) != 35 {
		return false
	}
	if code[0] != 33 || code[34] != byte(vm.CHECKSIG) {
		return false
	}
	return true
}

func IsSchnorr(code []byte) bool {
	if len(code) != 35 {
		return false
	}
	if int(code[0]) != vm.PUSH1 {
		return false
	}
	if int(code[1])+2 != len(code) {
		return false
	}
	return true
}

func IsMultiSig(code []byte) bool {
	var m int16 = 0
	var n int16 = 0
	i := 0

	if len(code) < 37 {
		return false
	}
	if code[i] > byte(vm.PUSH16) {
		return false
	}
	if code[i] < byte(vm.PUSH1) && code[i] != 1 && code[i] != 2 {
		return false
	}

	switch code[i] {
	case 1:
		i++
		m = int16(code[i])
		i++
		break
	case 2:
		i++
		m = common.BytesToInt16(code[i:])
		i += 2
		break
	default:
		m = int16(code[i]) - 80
		i++
		break
	}

	if m < 1 || m > 1024 {
		return false
	}

	for code[i] == 33 {
		i += 34
		if len(code) <= i {
			return false
		}
		n++
	}
	if n < m || n > 1024 {
		return false
	}

	switch code[i] {
	case 1:
		i++
		// F-203: bounds-check the variable-advance read before indexing.
		if i >= len(code) {
			return false
		}
		if n != int16(code[i]) {
			return false
		}
		i++
		break
	case 2:
		i++
		// F-203: the case-2 selector reads TWO bytes via BytesToInt16(code[i:]).
		if i+2 > len(code) {
			return false
		}
		if n != common.BytesToInt16(code[i:]) {
			return false
		}
		i += 2
		break
	default:
		if n != (int16(code[i]) - 80) {
			return false
		}
		i++
		break
	}

	// F-203: the parser's variable advances (m/n selectors + 34-byte pubkey stride) can
	// push i to len(code); the only prior guard was a `len(code) < 37` ENTRY check, so
	// this final read sliced OOB -> pre-auth remote panic (reachable via RunPrograms /
	// ReturnDeposit before any signature check). Bound it. Ungated crash-harden: a
	// well-formed multisig code ends exactly at i (the len(code) != i check below), so
	// this never fires on a legitimate program.
	if i >= len(code) {
		return false
	}
	if code[i] != byte(vm.CHECKMULTISIG) {
		return false
	}
	i++
	if len(code) != i {
		return false
	}

	return true
}

func GetCodeType(code []byte) ContractType {
	if IsStandard(code) {
		return Signature
	}
	if IsMultiSig(code) {
		return MultiSig
	}
	if IsSchnorr(code) {
		return Schnorr
	}
	return Custom
}

func GetPrefixType(programHash common.Uint168) PrefixType {
	prefixType := PrefixType(programHash[0])
	return PrefixType(prefixType)
}
