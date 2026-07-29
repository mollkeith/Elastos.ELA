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

// TestF143_ProgramHashVotesSerializeReportsWriteErrors: the length prefix of each
// entry's vote slice, and every vote in it, had their write errors discarded while
// every neighbouring write in this file checks its own. A failing writer therefore
// produced a TRUNCATED keyframe and a nil error, and the checkpoint save reported
// that it had serialized cleanly.
//
// The budget is sized to cover the map count (1 byte) plus the Uint168 key
// (21 bytes) and to run out exactly on the vote-count prefix that was unchecked.
func TestF143_ProgramHashVotesSerializeReportsWriteErrors(t *testing.T) {
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

	// A writer with room for everything must still succeed unchanged.
	ok := &budgetWriter{remaining: 4096}
	require.NoError(t, kf.SerializeProgramHashVotesInfoMap(vmap, ok))
	require.Greater(t, ok.written, 1+common.UINT168SIZE)
}

// TestF145_KeyFrameSnapshotCarriesNextTermAndClaimedKeys: KeyFrame.Snapshot left
// out NextMembers, ClaimedDPoSKeys and NextClaimedDPoSKeys even though all three
// are KeyFrame state that the disk Serialize path writes, so a snapshot silently
// dropped the next-term committee and the claimed DPoS node keys.
func TestF145_KeyFrameSnapshotCarriesNextTermAndClaimedKeys(t *testing.T) {
	kf := NewKeyFrame()

	next := common.Uint168{0xaa, 0xbb}
	kf.NextMembers[next] = &CRMember{MemberState: MemberElected}
	kf.ClaimedDPoSKeys["claimed-now"] = struct{}{}
	kf.NextClaimedDPoSKeys["claimed-next"] = struct{}{}

	snapshot := kf.Snapshot()

	require.Len(t, snapshot.NextMembers, 1,
		"snapshot must carry the next-term committee")
	require.Contains(t, snapshot.NextMembers, next)
	require.Contains(t, snapshot.ClaimedDPoSKeys, "claimed-now",
		"snapshot must carry the claimed DPoS node keys")
	require.Contains(t, snapshot.NextClaimedDPoSKeys, "claimed-next",
		"snapshot must carry the next-term claimed DPoS node keys")

	// and it has to be a copy, not the live map
	delete(kf.NextMembers, next)
	delete(kf.ClaimedDPoSKeys, "claimed-now")
	delete(kf.NextClaimedDPoSKeys, "claimed-next")
	require.Len(t, snapshot.NextMembers, 1)
	require.Len(t, snapshot.ClaimedDPoSKeys, 1)
	require.Len(t, snapshot.NextClaimedDPoSKeys, 1)
}
