// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"strings"
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
	err := got.Deserialize(bytes.NewReader(buf.Bytes()), SidechainIllegalDataVersion)
	if err == nil {
		t.Fatal("F-012: expected rejection of signLen > MaxSidechainIllegalSigns (pre-fix: unbounded make())")
	}
	// FV-25: this probe IS correctly positioned (SerializeUnsigned writes every field
	// through GenesisBlockAddress), but it only asserted "some error". Pin the guard.
	if !strings.Contains(err.Error(), "sidechain illegal signLen exceeds maximum") {
		t.Fatalf("F-012: rejected for the WRONG reason: %v", err)
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
	// FV-25: SerializeUnsigned writes ONLY the Header. DeserializeOthers reads the
	// BlockConfirm varbytes FIRST and the signers count SECOND, so the huge varint
	// used to stand here landed on the BlockConfirm LENGTH and was rejected by
	// ReadVarBytes' pact.MaxBlockHeaderSize cap -- the F-012 guard was never reached
	// and deleting it would not have failed this test. Write an empty BlockConfirm so
	// the probe lands where the guard actually is.
	if err := common.WriteVarBytes(&buf, nil); err != nil {
		t.Fatalf("write empty BlockConfirm: %v", err)
	}
	common.WriteVarUint(&buf, uint64(1)<<40) // huge -> pre-fix `makeslice: cap out of range` panic

	var got BlockEvidence
	err := got.Deserialize(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("F-012: expected rejection of signers count > MaxDPoSIllegalSigners (pre-fix: unbounded make())")
	}
	// FV-25: and it must be rejected BY THE GUARD, not by an unrelated size cap the
	// probe happened to trip on the way in. This assertion is what makes the test
	// discriminate: delete the guard at dposillegalblocks.go and the error becomes a
	// makeslice panic instead of this message.
	if !strings.Contains(err.Error(), "dpos illegal signers length exceeds maximum") {
		t.Fatalf("F-012: rejected for the WRONG reason -- the probe never reached the "+
			"signers-count guard: %v", err)
	}
}
