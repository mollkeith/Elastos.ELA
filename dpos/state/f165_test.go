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

// TestF165WithdrawableMapRoundTrip proves F-165: the DPoS
// deserializeWithdrawableTransactionsMap read each entry off the wire but never inserted
// it into the map, so every checkpoint round-trip / restart returned an EMPTY map —
// wiping the pending DposV2ClaimRewardRealWithdraw + VotesRealWithdraw queues. This drives
// the REAL serialize -> deserialize round-trip and asserts the entries survive. Pre-fix
// the deserialized map is empty; post-fix it matches the source.
func TestF165WithdrawableMapRoundTrip(t *testing.T) {
	kf := &StateKeyFrame{}
	src := map[common.Uint256]common2.OutputInfo{
		{1}: {Recipient: common.Uint168{0x11}, Amount: 100},
		{2}: {Recipient: common.Uint168{0x22}, Amount: 200},
		{3}: {Recipient: common.Uint168{0x33}, Amount: 300},
	}

	var buf bytes.Buffer
	assert.NoError(t, kf.serializeWithdrawableTransactionsMap(src, &buf))
	got, err := kf.deserializeWithdrawableTransactionsMap(bytes.NewReader(buf.Bytes()))
	assert.NoError(t, err)

	assert.Equal(t, len(src), len(got),
		"F-165: all withdrawable entries must survive the checkpoint round-trip (pre-fix this was 0)")
	for h, info := range src {
		g, ok := got[h]
		assert.True(t, ok, "entry %v must be restored", h)
		assert.Equal(t, info.Amount, g.Amount)
		assert.Equal(t, info.Recipient, g.Recipient)
	}
}
