// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package payload

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// TestConfirmDeserializeRejectsHugeSignCount ensures a crafted confirm with an
// enormous signCount is rejected before the upfront slice allocation, rather than
// crashing/OOMing the node.
func TestConfirmDeserializeRejectsHugeSignCount(t *testing.T) {
	var buf bytes.Buffer
	// minimal valid Proposal prefix is not needed: Proposal.Deserialize will fail
	// first on an empty reader, so feed a byte stream that reaches signCount by
	// serializing a real (empty) proposal then a huge count.
	p := &Confirm{}
	// Serialize a zero-value proposal to get past Proposal.Deserialize.
	if err := p.Proposal.Serialize(&buf); err != nil {
		t.Skipf("proposal serialize unavailable: %v", err)
	}
	huge := make([]byte, 8)
	binary.LittleEndian.PutUint64(huge, uint64(MaxDPOSProposalVotes)+1)
	buf.Write(huge)

	var got Confirm
	if err := got.Deserialize(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("expected rejection of signCount > MaxDPOSProposalVotes")
	}
}

// TestInactiveArbitratorsRejectsHugeCount guards the same decode-DoS class.
func TestInactiveArbitratorsRejectsHugeCount(t *testing.T) {
	var buf bytes.Buffer
	ia := &InactiveArbitrators{}
	if err := ia.SerializeUnsigned(&buf, 0); err != nil {
		t.Skipf("serialize unavailable: %v", err)
	}
	common.WriteVarUint(&buf, uint64(MaxInactiveArbitrators)+1)

	var got InactiveArbitrators
	if err := got.Deserialize(bytes.NewReader(buf.Bytes()), 0); err == nil {
		t.Fatal("expected rejection of count > MaxInactiveArbitrators")
	}
}
