// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"

	"github.com/stretchr/testify/assert"
)

// TestF142WithdrawableMapRoundTrip proves F-142 (the CR twin of F-165): the CR
// ProposalKeyFrame.deserializeWithdrawableTransactionsMap read each entry off the wire
// but never inserted it, so every CR checkpoint round-trip / restart returned an EMPTY map
// — wiping the CRC RealWithdraw pending queue. Drives the REAL serialize -> deserialize
// round-trip; pre-fix the deserialized map is empty, post-fix it matches the source.
func TestF142WithdrawableMapRoundTrip(t *testing.T) {
	kf := &ProposalKeyFrame{}
	src := map[common.Uint256]common2.OutputInfo{
		{4}: {Recipient: common.Uint168{0x44}, Amount: 400},
		{5}: {Recipient: common.Uint168{0x55}, Amount: 500},
	}

	var buf bytes.Buffer
	assert.NoError(t, kf.serializeWithdrawableTransactionsMap(src, &buf))
	got, err := kf.deserializeWithdrawableTransactionsMap(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)

	assert.Equal(t, len(src), len(got),
		"F-142: all CR withdrawable entries must survive the checkpoint round-trip (pre-fix this was 0)")
	for h, info := range src {
		g, ok := got[h]
		assert.True(t, ok, "entry %v must be restored", h)
		assert.Equal(t, info.Amount, g.Amount)
		assert.Equal(t, info.Recipient, g.Recipient)
	}
}
