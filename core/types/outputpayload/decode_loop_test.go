package outputpayload

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
)

// TestVoteContentDeserializeStopsOnTruncatedBody is the regression for the swallowed
// Deserialize error. Previously `if cv.Deserialize(r,version); err != nil` discarded
// the return and re-tested a stale nil err, so a huge candidatesCount with a truncated
// body appended a zero value every iteration until the node exhausted memory.
// It must now return an error promptly instead of looping.
func TestVoteContentDeserializeStopsOnTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(Delegate))                 // voteType
	common.WriteVarUint(&buf, 1000000)            // huge candidatesCount, body truncated
	// no candidate bodies follow

	var vc VoteContent
	done := make(chan error, 1)
	go func() { done <- vc.Deserialize(bytes.NewReader(buf.Bytes()), VoteProducerAndCRVersion) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error on truncated body, got nil (loop swallowed it)")
		}
		if len(vc.CandidateVotes) > 16 {
			t.Fatalf("appended %d zero-value entries before erroring", len(vc.CandidateVotes))
		}
	default:
		// returned synchronously above in practice; if it blocked, the select's
		// default would race — read it blocking instead.
		if err := <-done; err == nil {
			t.Fatal("expected error, got nil")
		}
	}
}

// TestVoteContentRejectsHugeCandidateCount covers the decode-DoS count cap.
func TestVoteContentRejectsHugeCandidateCount(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(byte(Delegate))
	common.WriteVarUint(&buf, uint64(MaxVoteCandidatesPerContent)+1)

	var vc VoteContent
	if err := vc.Deserialize(bytes.NewReader(buf.Bytes()), VoteProducerAndCRVersion); err == nil {
		t.Fatal("expected rejection of candidatesCount > MaxVoteCandidatesPerContent")
	}
}
