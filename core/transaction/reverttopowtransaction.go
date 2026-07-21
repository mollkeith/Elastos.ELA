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
		lastBlockTime := int64(t.parameters.BlockChain.BestChain.Timestamp)

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
			if int64(t.parameters.TimeStamp)-lastBlockTime < noBlockTime {
				return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid block time")), true
			}
			// F-057: the block header timestamp is producer-controlled, and because
			// RevertToPOWNoBlockTimeV1 == MaxTimeOffsetSeconds, a healthy-chain block
			// future-dated to tip+noBlockTime satisfies the check above with ZERO real
			// elapsed time -> forces DPoS->POW with no genuine arbiter stall. At/above
			// the recovery gate, also require the node's OWN adjusted clock to confirm
			// the no-block interval actually elapsed (the same guard the mempool path
			// above already uses), so the forged header timestamp cannot be fed into the
			// decision. A genuine >=noBlockTime stall still passes with no added delay
			// (now - old tip >= noBlockTime, fires at exactly the threshold) and
			// historical replay passes trivially (now >> ancient tip). Below the gate the
			// original block-timestamp-only check is preserved for replay-safety of
			// pre-gate history.
			if t.parameters.BlockHeight >= t.parameters.Config.StrictMoneyRangeHeight {
				localTime := t.MedianAdjustedTime().Unix()
				if localTime-lastBlockTime < noBlockTime {
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

func (t *RevertToPOWTransaction) MedianAdjustedTime() time.Time {
	newTimestamp := t.parameters.BlockChain.TimeSource.AdjustedTime()
	minTimestamp := t.parameters.BlockChain.MedianTimePast.Add(time.Second)

	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	return newTimestamp
}
