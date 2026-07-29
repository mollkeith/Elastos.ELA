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

	"github.com/elastos/Elastos.ELA/blockchain"
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
			//
			// This leg deliberately keeps the node's own clock and is deliberately not
			// gated. TimeStamp==0 means no block carries this transaction yet: the
			// mempool-admission and mining paths. That is a local relay/inclusion policy
			// decision, not a block-acceptance decision, so a node-local, peer-set-dependent
			// quantity is legitimate here: two nodes disagreeing about whether to hold a
			// transaction in their own pool costs a relay, not a chain split. The moment the
			// transaction is put in a block the in-block branch below decides, and that branch
			// consults no clock at all. Do not unify the two legs.
			localTime := t.MedianAdjustedTime().Unix()
			if localTime-lastBlockTime < noBlockTime {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
			}
		} else {
			// is in block, check by the time of existed block.
			//
			// At and above gate 1 (StrictMoneyRangeHeight) the demanded gap is
			// noBlockTime + MaxTimeOffsetSeconds. Below the gate the legacy comparison
			// is kept verbatim so retained history replays byte-identically.
			//
			// What it closes. A block's own header timestamp is written by its
			// producer, and CheckBlockSanity only bounds it at
			// AdjustedTime + MaxTimeOffsetSeconds. Since RevertToPOWNoBlockTimeV1
			// (7200s) equals MaxTimeOffsetSeconds (7200s), a producer could future-date
			// one header by exactly the stall window and satisfy the legacy comparison
			// with zero real elapsed time, forcing DPoS->POW at will. Requiring
			// noBlockTime + MaxTimeOffsetSeconds makes the most a producer can forge
			// (MaxTimeOffsetSeconds) insufficient on its own: whatever it post-dates,
			// at least noBlockTime of real time must have passed since the parent.
			// The rule is deterministic and ancestry-only, header timestamp minus
			// parent timestamp, both consensus data, so it consults no wall clock,
			// no peer set and nothing else node-local.
			//
			// What it costs, measured rather than asserted. An honest producer dates its
			// header at about now, so the emergency failsafe now needs about 4h of stall
			// instead of about 2h (V1 era: 7200 -> 14400s; the pre-V1 43200 -> 50400s pairing
			// exists only below ChangeViewV1Height=1911200, which is far below the gate, so 4h
			// is the only threshold that can ever be live). Over the retained mainnet copy
			// (2,260,597 stored block records, CRC-clean, every parent hash verified) there are
			// 30 RevertToPOW transactions in history, 29 NoBlock and 1 NoProducers, all at
			// heights 1184559..2129088, i.e. all below gate 1 (2260451), so not one retained
			// block changes verdict. Of the 29 NoBlock rescues, 28 would have missed this
			// threshold and had to wait longer, between 1h53m27s and 1h59m48s more (mean
			// 7,081.9s), and 1 (height 1405191, gap 85,240s) would still have passed. That is
			// the price of the rule, and it is the number the restart runbook carries.
			//
			// What was tried and rejected, so nobody re-proposes it:
			//
			//   - Requiring the validating node's own peer-adjusted clock
			//     (MedianAdjustedTime = TimeSource.AdjustedTime, i.e. local wall clock plus a
			//     median offset over up to 199 peer samples) to confirm the interval.
			//     Withdrawn and never to return: two honest nodes with identical chain state
			//     and different peer sets reach opposite accept/reject verdicts on the same
			//     block. A node-local, peer-set-dependent quantity must not decide block
			//     acceptance.
			//
			//   - header.Timestamp minus CalcPastMedianTime(parent). CalcPastMedianTime
			//     returns the median of the parent and its 10 ancestors, so it sits below the
			//     parent's own timestamp on any normally spaced chain. Over the retained
			//     mainnet copy that holds without exception: for all 30 RevertToPOW blocks in
			//     history the median lies below the parent (by 76s to 17,131s), and in a
			//     2,241-height control sample spread over the whole chain it is below in 2,241
			//     of 2,241 with a mean gap of 601.5s. Substituting it would have made this leg
			//     strictly more permissive, by about 600s of forgeable slack, than the legacy
			//     rule it replaces: it would have removed this protection and weakened
			//     upstream's. Do not resurrect it.
			//
			// This sits on gate 1 and introduces no new height constant: a third gate is never
			// permitted, so the choice had to be made before the restart.
			if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
				if int64(t.parameters.TimeStamp)-lastBlockTime <
					noBlockTime+blockchain.MaxTimeOffsetSeconds {
					return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
				}
			} else {
				if int64(t.parameters.TimeStamp)-lastBlockTime < noBlockTime {
					return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
				}
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
		// An unknown RevertToPOW Type falls through to accept, forcing DPoS->POW with
		// none of the stall/flag preconditions. Reject unknown types at/above the gate.
		// createRevertToPOWTransaction only ever emits Type 0/1/2, so no historical block
		// carries Type>=3 and replay is unaffected.
		if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
			return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid RevertToPOW type")), true
		}
	}
	return nil, true
}

// lastBlockTime returns the timestamp the no-block interval is measured from.
//
// Ungated. This is the timestamp of the parent of the block under validation
// whenever the caller supplied it, and every production path does (the block path
// from the real parent, the mempool and mining paths from BestChain, which is the
// parent of the block those transactions are destined for). Reading
// BestChain.Timestamp directly evaluates the rule against the validating node's
// current tip: for a block arriving on a competing branch that timestamp belongs to
// an unrelated chain, so two nodes with different tips could reach opposite
// verdicts on the same block. The BestChain fallback is retained only for callers
// that construct parameters without a parent, and preserves that behaviour exactly
// for them.
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
