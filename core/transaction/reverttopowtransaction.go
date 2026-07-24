// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package transaction

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type RevertToPOWTransaction struct {
	BaseTransaction
}

func (t *RevertToPOWTransaction) CheckTransactionInput() error {
	if len(t.Inputs()) != 0 {
		return errors.New("no cost transactions must has no input")
	}
	return nil
}

func (t *RevertToPOWTransaction) CheckTransactionOutput() error {

	if len(t.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}
	if len(t.Outputs()) != 0 {
		return errors.New("no cost transactions should have no output")
	}

	return nil
}

func (t *RevertToPOWTransaction) CheckAttributeProgram() error {
	if len(t.Programs()) != 0 || len(t.Attributes()) != 0 {
		return errors.New("zero cost tx should have no attributes and programs")
	}
	return nil
}

func (t *RevertToPOWTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.RevertToPOW:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *RevertToPOWTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *RevertToPOWTransaction) HeightVersionCheck() error {
	if t.parameters.BlockHeight < t.parameters.Config.DPoSConfiguration.RevertToPOWStartHeight {
		return errors.New(fmt.Sprintf("not support %s transaction "+
			"before RevertToPOWStartHeight", t.TxType().Name()))
	}

	return nil
}

func (t *RevertToPOWTransaction) SpecialContextCheck() (result elaerr.ELAError, end bool) {
	p, ok := t.Payload().(*payload.RevertToPOW)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}

	if p.WorkingHeight != t.parameters.BlockHeight {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid start POW block height")), true
	}

	switch p.Type {
	case payload.NoBlock:
		lastBlockTime := t.lastBlockTime()

		var noBlockTime int64
		if t.parameters.BlockHeight < t.parameters.Config.DPoSConfiguration.ChangeViewV1Height {
			noBlockTime = t.parameters.Config.DPoSConfiguration.RevertToPOWNoBlockTime
		} else {
			noBlockTime = t.parameters.Config.DPoSConfiguration.RevertToPOWNoBlockTimeV1
		}

		if t.parameters.TimeStamp == 0 {
			// is not in block, check by local time.
			localTime := t.MedianAdjustedTime().Unix()
			if localTime-lastBlockTime < noBlockTime {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
			}
		} else {
			// is in block, check by the time of existed block.
			//
			// FV-22 (gate 1, StrictMoneyRangeHeight): F-057 additionally required the
			// VALIDATING NODE'S OWN peer-adjusted clock to confirm the interval, to stop
			// a producer future-dating one header by RevertToPOWNoBlockTimeV1 (which
			// equals MaxTimeOffsetSeconds) and forcing DPoS->POW with zero elapsed time.
			// That leg is WITHDRAWN here: MedianAdjustedTime is TimeSource.AdjustedTime,
			// i.e. local wall clock plus a median offset over up to 199 peer samples, so
			// two honest nodes with identical chain state and different peer sets can
			// reach opposite ACCEPT/REJECT verdicts on the same block. A node-local,
			// peer-set-dependent quantity must not decide block acceptance.
			//
			// The replacement proposed in review -- header.Timestamp minus
			// CalcPastMedianTime(parent) -- was NOT taken, and the reason is measured,
			// not asserted. CalcPastMedianTime returns the median of the parent and its
			// 10 ancestors, so it sits BELOW the parent's own timestamp on any normally
			// spaced chain. Over the retained mainnet copy that holds without exception:
			// for ALL 30 RevertToPOW blocks in history the median lies below the parent
			// (by 76s to 17,131s), and in a 2,241-height control sample spread over the
			// whole chain it is below in 2,241 of 2,241 with a mean gap of 601.5s.
			// Substituting it would therefore have made the at/above-gate leg STRICTLY
			// MORE PERMISSIVE -- by ~600s of forgeable slack -- than the pre-gate leg it
			// replaces: it would have removed F-057's protection and weakened upstream's
			// as well. (For reference the 29 NoBlock reverts clear the parent-bound
			// threshold with margins of +12s upward, so the deterministic rule kept below
			// still admits every genuine historical rescue.)
			//
			// What remains is the deterministic, ancestry-only condition below. The
			// residual it leaves open is stated plainly rather than papered over: a
			// producer able to mine a block can still claim a stall by future-dating its
			// header, exactly as upstream allows. Closing that deterministically requires
			// the demanded gap to exceed what a producer can forge (i.e.
			// noBlockTime + MaxTimeOffsetSeconds), which doubles the emergency failsafe's
			// latency from 2h to 4h -- a consensus-policy decision, not a defect fix, and
			// therefore left to the owner rather than taken here.
			if int64(t.parameters.TimeStamp)-lastBlockTime < noBlockTime {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
			}
		}
	case payload.NoProducers:
		if !t.parameters.BlockChain.GetState().NoProducers {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("current producers is enough")), true
		}
	case payload.NoClaimDPOSNode:
		if !t.parameters.BlockChain.GetState().NoClaimDPOSNode {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("current CR member claimed DPoS node")), true
		}
	default:
		// F-098: an unknown RevertToPOW Type previously fell through to accept,
		// forcing DPoS->POW with NONE of the stall/flag preconditions. Reject
		// unknown types at/above the gate. createRevertToPOWTransaction only ever
		// emits Type 0/1/2, so no historical block carries Type>=3 -> replay-safe.
		if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid RevertToPOW type")), true
		}
	}
	return nil, true
}

// lastBlockTime returns the timestamp the no-block interval is measured from.
//
// FV-22 (UNGATED): this is the timestamp of the PARENT of the block under validation
// whenever the caller supplied it -- every production path does (the block path from
// the real parent, the mempool and mining paths from BestChain, which is the parent
// of the block those transactions are destined for). Reading BestChain.Timestamp
// directly, as this function used to, evaluated the rule against the validating
// node's current tip: for a block arriving on a competing branch that timestamp
// belongs to an unrelated chain, so two nodes with different tips could reach
// opposite verdicts on the same block. The BestChain fallback is retained only for
// callers that construct parameters without a parent, and preserves the previous
// behaviour exactly for them.
func (t *RevertToPOWTransaction) lastBlockTime() int64 {
	if ts, ok := t.parameters.PrevBlockTimestamp(); ok {
		return int64(ts)
	}
	return int64(t.parameters.BlockChain.BestChain.Timestamp)
}

func (t *RevertToPOWTransaction) MedianAdjustedTime() time.Time {
	newTimestamp := t.parameters.BlockChain.TimeSource.AdjustedTime()
	minTimestamp := t.parameters.BlockChain.MedianTimePast.Add(time.Second)

	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	return newTimestamp
}
