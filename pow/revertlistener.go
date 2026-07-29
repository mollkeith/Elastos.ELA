// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pow

import (
	"time"

	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/functions"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

const CheckRevertToPOWInterval = time.Minute

func (pow *Service) ListenForRevert() {
	go func() {
		// Reported once, not once a minute. See the duplicate branch below.
		revertToPOWPooled := false
		for {
			time.Sleep(CheckRevertToPOWInterval)
			currentHeight := pow.chain.BestChain.Height
			if currentHeight < pow.chainParams.DPoSConfiguration.RevertToPOWStartHeight {
				continue
			}
			if pow.arbiters.IsInPOWMode() {
				continue
			}
			lastBlockTimestamp := int64(pow.arbiters.GetLastBlockTimestamp())
			localTimestamp := pow.chain.TimeSource.AdjustedTime().Unix()
			var noBlockTime int64
			if currentHeight < pow.chainParams.DPoSConfiguration.ChangeViewV1Height {
				noBlockTime = pow.chainParams.DPoSConfiguration.RevertToPOWNoBlockTime
			} else {
				noBlockTime = pow.chainParams.DPoSConfiguration.RevertToPOWNoBlockTimeV1
			}

			log.Debug("ListenForRevert lastBlockTimestamp:", lastBlockTimestamp,
				"localTimestamp:", localTimestamp, "RevertToPOWNoBlockTime:", noBlockTime)
			if localTimestamp-lastBlockTimestamp < noBlockTime {
				continue
			}

			revertToPOWPayload := payload.RevertToPOW{
				Type:          payload.NoBlock,
				WorkingHeight: pow.chain.BestChain.Height + 1,
			}
			tx := functions.CreateTransaction(
				common2.TxVersion09,
				common2.RevertToPOW,
				payload.RevertToPOWVersion,
				&revertToPOWPayload,
				[]*common2.Attribute{},
				[]*common2.Input{},
				[]*common2.Output{},
				0,
				[]*program.Program{},
			)

			err := pow.txMemPool.AppendToTxPoolWithoutEvent(tx)
			if err != nil {
				// The ticker re-offers the same transaction every round for as
				// long as the chain has produced no block, so once the first
				// offer succeeds every later one is refused as a duplicate.
				// That is the steady state, not a fault. MEASURED on a
				// five-node rehearsal at the real restart height: one accept
				// followed by an "already exist" refusal every 60 seconds
				// indefinitely, logged at ERR. Restart day is exactly when an
				// operator can least afford a recurring red line that means
				// nothing, so the duplicate is reported once at info and any
				// other failure keeps its ERR.
				if err.Code() == elaerr.ErrTxDuplicate {
					if !revertToPOWPooled {
						revertToPOWPooled = true
						log.Info("revertToPOW transaction is already in the " +
							"transaction pool; further offers are duplicates " +
							"and will not be reported again")
					}
				} else {
					log.Error("failed to append revertToPOW transaction to " +
						"transaction pool, err:" + err.Error())
				}
			}
		}
	}()
}
