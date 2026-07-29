// Copyright (c) 2017-2021 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"errors"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/stretchr/testify/require"
)

// budgetWriter accepts a fixed number of bytes and then fails every further
// write, the way a full disk or a dying file handle does.
type budgetWriter struct {
	remaining int
	written   int
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errors.New("no space left on device")
	}
	w.remaining -= len(p)
	w.written += len(p)
	return len(p), nil
}

// TestF143Twin_ProgramHashVotesSerializeReportsWriteErrors is the DPoS-side twin of
// the cr/state F-143 defect: byte-for-byte the same function, with the same two
// discarded write errors, on the DPoS checkpoint's serialize path.
func TestF143Twin_ProgramHashVotesSerializeReportsWriteErrors(t *testing.T) {
	vmap := map[common.Uint168][]payload.VotesWithLockTime{
		{0x12, 0x34}: {{Candidate: []byte{0x01, 0x02}, Votes: 100, LockTime: 7}},
	}

	kf := &StateKeyFrame{}
	w := &budgetWriter{remaining: 1 + common.UINT168SIZE}
	err := kf.SerializeProgramHashVotesInfoMap(vmap, w)

	require.Error(t, err,
		"a short write inside the votes map must be reported, not swallowed")
	require.Equal(t, 1+common.UINT168SIZE, w.written,
		"serialization must stop at the first failed write")

	ok := &budgetWriter{remaining: 4096}
	require.NoError(t, kf.SerializeProgramHashVotesInfoMap(vmap, ok))
	require.Greater(t, ok.written, 1+common.UINT168SIZE)
}
