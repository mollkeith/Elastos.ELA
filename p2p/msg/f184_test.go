// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"bytes"
	"testing"

	common2 "github.com/elastos/Elastos.ELA/core/types/common"
)

// TestF184FilterLoadRejectsTruncatedTxTypes is the fail-on-pristine test for
// F-184. The mid-list ReadElement error was swallowed with `return nil`, so a
// peer that declared N transaction types and then truncated the list got a
// silently shortened filter installed instead of a decode failure.
func TestF184FilterLoadRejectsTruncatedTxTypes(t *testing.T) {
	original := &FilterLoad{
		Filter:    []byte{0xff, 0xff, 0xff, 0xff},
		HashFuncs: 3,
		Tweak:     7,
		Flags:     1,
		TxTypes: []common2.TxType{
			common2.TransferAsset,
			common2.CoinBase,
			common2.RegisterProducer,
		},
	}

	var buf bytes.Buffer
	if err := original.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()

	// Drop the last two tx-type bytes; the declared count still says three.
	truncated := encoded[:len(encoded)-2]

	var got FilterLoad
	if err := got.Deserialize(bytes.NewReader(truncated)); err == nil {
		t.Fatalf("F-184: filterload declaring 3 tx types with only 1 on the "+
			"wire decoded successfully, installing a silently truncated "+
			"filter with %d tx types", len(got.TxTypes))
	}
}

// TestF184FilterLoadBackCompatUnchanged pins the two behaviours that must NOT
// move: a well formed filterload still decodes, and a filterload that omits the
// TxTypes field entirely is still accepted (the deliberate io.EOF back-compat
// for older SPV peers).
func TestF184FilterLoadBackCompatUnchanged(t *testing.T) {
	original := &FilterLoad{
		Filter:    []byte{0x0f, 0xf0},
		HashFuncs: 2,
		Tweak:     11,
		Flags:     0,
		TxTypes:   []common2.TxType{common2.TransferAsset},
	}

	var buf bytes.Buffer
	if err := original.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	encoded := buf.Bytes()

	var got FilterLoad
	if err := got.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("well formed filterload must still decode: %v", err)
	}
	if len(got.TxTypes) != 1 || got.TxTypes[0] != common2.TransferAsset {
		t.Fatalf("round trip lost tx types: %v", got.TxTypes)
	}

	// Older peers stop after Flags and send no TxTypes count at all.
	noTxTypes := encoded[:len(encoded)-2]

	var legacy FilterLoad
	if err := legacy.Deserialize(bytes.NewReader(noTxTypes)); err != nil {
		t.Fatalf("a filterload without the TxTypes field must still be "+
			"accepted (back-compat), got %v", err)
	}
	if len(legacy.TxTypes) != 0 {
		t.Fatalf("expected no tx types, got %v", legacy.TxTypes)
	}
}
