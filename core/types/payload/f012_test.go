// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// TestF012SidechainIllegalDataRejectsHugeSignLen — F-012 site 3: SidechainIllegalData
// allocated `make([][]byte, signLen)` from a wire varint before any budget check ->
// remote OOM / `makeslice: len out of range`. Mirrors the shipped confirm.go /
// inactivearbitrators.go decode-DoS guards: reject signLen > MaxSidechainIllegalSigns.
func TestF012SidechainIllegalDataRejectsHugeSignLen(t *testing.T) {
	var buf bytes.Buffer
	s := &SidechainIllegalData{}
	if err := s.SerializeUnsigned(&buf, SidechainIllegalDataVersion); err != nil {
		t.Skipf("serialize unavailable: %v", err)
	}
	common.WriteVarUint(&buf, uint64(1)<<40) // huge -> pre-fix `makeslice: len out of range` panic

	var got SidechainIllegalData
	if err := got.Deserialize(bytes.NewReader(buf.Bytes()), SidechainIllegalDataVersion); err == nil {
		t.Fatal("F-012: expected rejection of signLen > MaxSidechainIllegalSigns (pre-fix: unbounded make())")
	}
}

// TestF012BlockEvidenceRejectsHugeSigners — F-012 sibling: BlockEvidence.DeserializeOthers
// allocated `make([][]byte, 0, len)` from a wire varint before any budget check ->
// `makeslice: cap out of range`, reachable pre-auth via IllegalBlockEvidence relay.
func TestF012BlockEvidenceRejectsHugeSigners(t *testing.T) {
	var buf bytes.Buffer
	b := &BlockEvidence{}
	if err := b.SerializeUnsigned(&buf); err != nil {
		t.Skipf("serialize unavailable: %v", err)
	}
	// DeserializeOthers reads the signers-count varint first (before the make).
	common.WriteVarUint(&buf, uint64(1)<<40) // huge -> pre-fix `makeslice: cap out of range` panic

	var got BlockEvidence
	if err := got.Deserialize(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("F-012: expected rejection of signers count > MaxDPoSIllegalSigners (pre-fix: unbounded make())")
	}
}
