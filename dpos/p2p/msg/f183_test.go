// Copyright (c) 2017-2020 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

var errStatusWriterFull = errors.New("writer refused the write")

type statusBudgetWriter struct {
	budget int
	buf    bytes.Buffer
}

func (w *statusBudgetWriter) Write(p []byte) (int, error) {
	if len(p) > w.budget {
		n, _ := w.buf.Write(p[:w.budget])
		w.budget = 0
		return n, errStatusWriterFull
	}
	n, err := w.buf.Write(p)
	w.budget -= n
	return n, err
}

// TestF183ConsensusStatusDeserializeRejectsTruncatedStatus is the
// fail-on-pristine test for the read half of F-183. The first ReadVarUint
// error was swallowed with `return nil`, so a status message truncated right
// after the view start time decoded as a fully successful, completely empty
// consensus status - which DPoS view recovery then treated as a real answer
// from the peer.
func TestF183ConsensusStatusDeserializeRejectsTruncatedStatus(t *testing.T) {
	var buf bytes.Buffer
	if err := common.WriteUint32(&buf, 3); err != nil {
		t.Fatal(err)
	}
	if err := common.WriteUint32(&buf, 9); err != nil {
		t.Fatal(err)
	}
	if err := common.WriteUint64(&buf,
		uint64(time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}
	// Message stops here: no accept-vote count follows.

	var status ConsensusStatus
	if err := status.Deserialize(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatalf("F-183: a status truncated after the view start time "+
			"decoded successfully into an empty status "+
			"(ViewOffset=%d, %d accept votes, %d pending proposals)",
			status.ViewOffset, len(status.AcceptVotes),
			len(status.PendingProposals))
	}
}

// TestF183ConsensusStatusSerializeReportsCountWriteError is the
// fail-on-pristine test for the write half of F-183: the accept-vote count
// write error was swallowed with `return nil`, so Serialize reported success
// after emitting a status truncated at the accept-vote list.
func TestF183ConsensusStatusSerializeReportsCountWriteError(t *testing.T) {
	status := &ConsensusStatus{
		ConsensusStatus: 1,
		ViewOffset:      2,
		ViewStartTime:   time.Unix(0, 12345),
		AcceptVotes:     []payload.DPOSProposalVote{},
	}

	// uint32 + uint32 + uint64 = 16 bytes fit; the accept-vote count does not.
	w := &statusBudgetWriter{budget: 16}
	err := status.Serialize(w)
	if err == nil {
		t.Fatal("F-183: Serialize reported success after the accept-vote " +
			"count write failed, emitting a truncated status message")
	}
	if !errors.Is(err, errStatusWriterFull) {
		t.Fatalf("expected the writer error to propagate, got %v", err)
	}
}

// TestF183ConsensusStatusRoundTripUnchanged pins that well formed status
// messages are unaffected by the fix.
func TestF183ConsensusStatusRoundTripUnchanged(t *testing.T) {
	status := &ConsensusStatus{
		ConsensusStatus:  4,
		ViewOffset:       5,
		ViewStartTime:    time.Unix(0, 67890),
		AcceptVotes:      []payload.DPOSProposalVote{},
		RejectedVotes:    []payload.DPOSProposalVote{},
		PendingProposals: []payload.DPOSProposal{},
		PendingVotes:     []payload.DPOSProposalVote{},
	}

	var buf bytes.Buffer
	if err := status.Serialize(&buf); err != nil {
		t.Fatalf("serialize failed: %v", err)
	}

	var got ConsensusStatus
	if err := got.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if got.ConsensusStatus != status.ConsensusStatus ||
		got.ViewOffset != status.ViewOffset {
		t.Fatal("round trip lost status fields")
	}
}
