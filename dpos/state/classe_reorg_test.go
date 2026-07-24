// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Class-E reorg revert-symmetry, ELECTED-producer edition. These tests drive the
// REAL forward production functions to Append the exact source revert closures, then
// call the REAL History.RollbackTo -- the identical closure execution a live chain
// reorg performs via CkpManager.OnRollbackTo -> Arbiters.RollbackTo / State.RollbackTo
// -> History.RollbackTo. The four fixes (F-064, F-215, F-180, F-109) differ from the
// pristine parent (80378ab) ONLY in a revert-closure body, so the SAME test source
// PASSES on the fixed tree and FAILS on pristine. Each test:
//   - reaches the closure through the real function (path-reached proof asserted),
//   - varies reorg depth (1/2/5/deep),
//   - repeats many times for determinism.
package state

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	pg "github.com/elastos/Elastos.ELA/core/contract/program"
	common2 "github.com/elastos/Elastos.ELA/core/types/common"
	"github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/utils"

	"github.com/stretchr/testify/assert"
)

const classEReps = 8

// classEDepths are the reorg depths (# of detached blocks across the discriminating
// block) exercised by every Class-E scenario.
var classEDepths = []uint32{1, 2, 5, 60}

// -----------------------------------------------------------------------------
// F-064 (Critical): updateInactiveCountV2 forward zeroes inactiveCountV2 on crossing
// the >=3 threshold and sets the producer Inactive; the pristine revert guard re-read
// the (now zeroed) count as ">= 3" -> always false -> revertSettingInactiveProducer
// never ran -> producer STUCK Inactive after a reorg across the threshold. Fixed drives
// the undo off a captured `fired` flag.
// -----------------------------------------------------------------------------
func TestClassE_F064_InactiveThresholdRollbackRestoresActive(t *testing.T) {
	for _, depth := range classEDepths {
		for rep := 0; rep < classEReps; rep++ {
			s := &State{
				StateKeyFrame: &StateKeyFrame{
					ActivityProducers: map[string]*Producer{},
					InactiveProducers: map[string]*Producer{},
				},
				History:     utils.NewHistory(maxHistoryCapacity),
				ChainParams: &config.Configuration{},
			}
			const key = "pE064"
			const H = uint32(1000)
			p := &Producer{state: Active, inactiveCountV2: 2} // one increment from the threshold
			s.ActivityProducers[key] = p

			// FORWARD via the real production function: cross the threshold at H.
			s.updateInactiveCountV2(true, false, false, p, H, key)
			s.History.Commit(H)

			// Path-reached proof: the threshold actually fired.
			assert.Equal(t, Inactive, p.state, "path reached: crossing must set Inactive")
			assert.Equal(t, uint32(0), p.inactiveCountV2, "path reached: count zeroed on firing")
			if _, ok := s.InactiveProducers[key]; !ok {
				t.Fatalf("path reached: producer must be in InactiveProducers after firing")
			}
			if _, ok := s.ActivityProducers[key]; ok {
				t.Fatalf("path reached: producer must have left ActivityProducers after firing")
			}

			// Commit depth-1 further (empty) blocks so the reorg detaches `depth` blocks.
			for h := H + 1; h < H+depth; h++ {
				s.History.Commit(h)
			}

			// REORG across the threshold-cross block.
			assert.NoError(t, s.History.RollbackTo(H-1))

			// DISCRIMINATOR: fixed restores Active; pristine leaves it stuck Inactive.
			assert.Equalf(t, Active, p.state,
				"F-064 depth=%d rep=%d: rollback MUST restore Active (pristine: stuck Inactive)", depth, rep)
			assert.Equalf(t, uint32(2), p.inactiveCountV2,
				"F-064 depth=%d rep=%d: inactiveCountV2 restored to pre-block value", depth, rep)
			if _, ok := s.ActivityProducers[key]; !ok {
				t.Fatalf("F-064 depth=%d rep=%d: producer must be restored to ActivityProducers", depth, rep)
			}
			if _, ok := s.InactiveProducers[key]; ok {
				t.Fatalf("F-064 depth=%d rep=%d: producer must be removed from InactiveProducers", depth, rep)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// F-215: returnDeposit's returnAction undo hard-set producer.state = Canceled; a
// non-Canceled producer (Active/Inactive/Pending) that returned deposit was therefore
// wrongly Canceled after a reorg. Fixed restores the captured oriState.
// -----------------------------------------------------------------------------

// fakeReturnTx embeds the (nil) Transaction interface and overrides ONLY the three
// methods returnDeposit calls: Inputs(), Outputs(), Programs().
type fakeReturnTx struct {
	interfaces.Transaction
	inputs   []*common2.Input
	programs []*pg.Program
}

func (t *fakeReturnTx) Inputs() []*common2.Input   { return t.inputs }
func (t *fakeReturnTx) Outputs() []*common2.Output { return nil }
func (t *fakeReturnTx) Programs() []*pg.Program    { return t.programs }

func TestClassE_F215_ReturnDepositRollbackRestoresOriState(t *testing.T) {
	// Only non-Canceled prior states: the forward is a no-op on state for these, so the
	// ONLY thing that touches state is the revert closure -> a clean discriminator.
	for _, oriState := range []ProducerState{Active, Inactive, Pending} {
		for _, depth := range classEDepths {
			for rep := 0; rep < classEReps; rep++ {
				s := &State{
					StateKeyFrame: &StateKeyFrame{
						ActivityProducers: map[string]*Producer{},
						InactiveProducers: map[string]*Producer{},
						PendingProducers:  map[string]*Producer{},
						CanceledProducers: map[string]*Producer{},
						IllegalProducers:  map[string]*Producer{},
						DepositOutputs:    map[string]common.Fixed64{},
					},
					History:     utils.NewHistory(maxHistoryCapacity),
					ChainParams: &config.Configuration{},
				}

				// 34-byte owner key: != crypto.NegativeBigLength(33) so
				// GetOwnerKeyDepositProgramHash takes the non-validating ToProgramHash
				// branch; code length 36 (<37) so contract.IsMultiSig is false and
				// ownerKey == code[1:len-1].
				ownerKey := make([]byte, 34)
				ownerKey[0] = 0x21
				for i := 1; i < 34; i++ {
					ownerKey[i] = byte(0x40 + i)
				}
				key := hex.EncodeToString(ownerKey)
				code := append([]byte{0x22}, ownerKey...)
				code = append(code, 0xAC)

				p := &Producer{state: oriState, totalAmount: 5000}
				p.info.OwnerKey = ownerKey
				s.ActivityProducers[key] = p

				// One deposit input worth 1500 -> inputValue observable in the forward.
				var txid common.Uint256
				copy(txid[:], []byte{0x11, 0x22, 0x33, byte(rep)})
				op := common2.NewOutPoint(txid, 0)
				in := &common2.Input{Previous: *op}
				s.DepositOutputs[in.ReferKey()] = 1500

				tx := &fakeReturnTx{
					inputs:   []*common2.Input{in},
					programs: []*pg.Program{{Code: code}},
				}

				const H = uint32(2000)
				// FORWARD via the real function.
				s.returnDeposit(tx, H)
				s.History.Commit(H)

				// Path-reached proof: the forward ran (totalAmount -= inputValue) and did
				// NOT change a non-Canceled producer's state.
				assert.Equalf(t, common.Fixed64(3500), p.totalAmount,
					"path reached: returnDeposit forward ran (oriState=%v)", oriState)
				assert.Equalf(t, oriState, p.state,
					"forward leaves a non-Canceled producer's state unchanged (oriState=%v)", oriState)

				for h := H + 1; h < H+depth; h++ {
					s.History.Commit(h)
				}

				// REORG.
				assert.NoError(t, s.History.RollbackTo(H-1))

				// DISCRIMINATOR: fixed restores oriState; pristine hard-sets Canceled.
				assert.Equalf(t, oriState, p.state,
					"F-215 oriState=%v depth=%d rep=%d: rollback MUST restore oriState (pristine wrongly sets Canceled)",
					oriState, depth, rep)
				assert.Equalf(t, common.Fixed64(5000), p.totalAmount,
					"F-215 oriState=%v depth=%d rep=%d: totalAmount restored", oriState, depth, rep)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// F-180: DPoSV2ActiveHeight activation rollback restored `oriHeight`(=height) instead
// of the pre-activation math.MaxUint32 the guard proved. A reorg across the DPoSV2
// activation therefore PINS DPoSV2ActiveHeight to a wrong (activated) height on
// pristine -- and because the forward guard is `== math.MaxUint32`, the winning branch
// then NEVER re-activates, so the divergence is permanent. Fixed restores MaxUint32.
// -----------------------------------------------------------------------------

// f180Params builds the mainnet-mirror config (MemberCount=12, NormalArbitratorsCount=24)
// and steers UpdateNextArbitrators to reach the activation Append and then RETURN cleanly:
//   - CRClaimDPOSNodeStartHeight = MaxUint32   -> skip the top NeedNextTurnDPOSInfo Append
//   - ChangeCommitteeNewCRHeight = 0           -> resetNextArbiterByCRC takes the voted-
//     producer branch, where len(votedProducers=0) < len(CRCArbiters=big) returns an error
//     immediately AFTER the activation Append (so only the activation closure is cached).
func f180Params() *config.Configuration {
	c := &config.Configuration{}
	c.CRConfiguration.MemberCount = 12
	c.CRConfiguration.CRClaimDPOSNodeStartHeight = math.MaxUint32
	c.CRConfiguration.ChangeCommitteeNewCRHeight = 0
	c.DPoSConfiguration.NormalArbitratorsCount = 24
	// large CRCArbiters list -> forces "votedProducers less than CRCArbiters" error.
	big := make([]string, 100)
	for i := range big {
		big[i] = fmt.Sprintf("crc%02d", i)
	}
	c.DPoSConfiguration.CRCArbiters = big
	return c
}

// newF180Arbiters returns an Arbiters that is pre-activation (DPoSV2ActiveHeight==MaxUint32)
// but has 36 DPoSV2-effected producers so isDposV2Active() is true (36 >= 24*3/2). Note:
// ActivityProducers stays EMPTY so GetDposV2ActiveProducers() returns nil -> the clean
// resetNextArbiterByCRC error above.
func newF180Arbiters() *Arbiters {
	skf := NewStateKeyFrame()
	for i := 0; i < 36; i++ {
		skf.DposV2EffectedProducers[fmt.Sprintf("e%02d", i)] = &Producer{state: Active}
	}
	skf.DPoSV2ActiveHeight = math.MaxUint32
	params := f180Params()
	st := &State{
		StateKeyFrame: skf,
		History:       utils.NewHistory(maxHistoryCapacity),
		ChainParams:   params,
	}
	return &Arbiters{
		State:       st,
		degradation: &degradation{},
		ChainParams: params,
		History:     utils.NewHistory(maxHistoryCapacity),
		CRCommittee: nil,
	}
}

// runActivation drives the REAL UpdateNextArbitrators activation Append at height h and
// commits it. The recover() guards against any downstream machinery after the activation
// Append; the Append itself is registered before resetNextArbiterByCRC returns/errors.
func runActivation(a *Arbiters, h uint32) {
	func() {
		defer func() { _ = recover() }()
		_ = a.UpdateNextArbitrators(h, h)
	}()
	a.History.Commit(h)
}

func TestClassE_F180_ReorgAcrossActivationRestoresMaxUint32(t *testing.T) {
	for _, depth := range classEDepths {
		for rep := 0; rep < classEReps; rep++ {
			a := newF180Arbiters()
			const trigger = uint32(500)

			assert.Equal(t, uint32(math.MaxUint32), a.DPoSV2ActiveHeight, "pre: not activated")
			assert.True(t, a.isDposV2Active(), "pre: 36 effected producers => isDposV2Active")

			// FORWARD: real activation Append at `trigger`.
			runActivation(a, trigger)

			// Path-reached proof: activation forward fired.
			want := trigger + uint32(a.ChainParams.CRConfiguration.MemberCount) +
				uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount)
			assert.Equalf(t, want, a.DPoSV2ActiveHeight,
				"path reached: activation forward set DPoSV2ActiveHeight=height+36 (depth=%d rep=%d)", depth, rep)

			// Depth: commit further empty blocks above the activation trigger.
			for h := trigger + 1; h < trigger+depth; h++ {
				a.History.Commit(h)
			}

			// REORG across activation.
			assert.NoError(t, a.History.RollbackTo(trigger-1))

			// DISCRIMINATOR 1: fixed restores MaxUint32; pristine pins to `trigger`.
			assert.Equalf(t, uint32(math.MaxUint32), a.DPoSV2ActiveHeight,
				"F-180 depth=%d rep=%d: reorg across activation MUST restore MaxUint32 (pristine pins to trigger=%d)",
				depth, rep, trigger)

			// DISCRIMINATOR 2 (permanent divergence): on the winning branch the fixed node
			// RE-ACTIVATES (guard MaxUint32 is true again); pristine's guard fails forever.
			h2 := trigger + depth + 10
			runActivation(a, h2)
			want2 := h2 + uint32(a.ChainParams.CRConfiguration.MemberCount) +
				uint32(a.ChainParams.DPoSConfiguration.NormalArbitratorsCount)
			assert.Equalf(t, want2, a.DPoSV2ActiveHeight,
				"F-180 depth=%d rep=%d: fixed re-activates on the new branch to h2+36 (pristine stuck at trigger, never re-activates)",
				depth, rep)
		}
	}
}

// -----------------------------------------------------------------------------
// F-109: Arbiters.RollbackTo never pruned height-keyed Snapshots/SnapshotKeysDesc above
// the rollback target. SnapshotByHeight APPENDS (not replaces), so a reorg left stale
// arbiter snapshots >target that corrupt later snapshot lookups. Fixed prunes them.
// -----------------------------------------------------------------------------
func newF109Arbiters() *Arbiters {
	return &Arbiters{
		State: &State{
			StateKeyFrame: NewStateKeyFrame(),
			History:       utils.NewHistory(maxHistoryCapacity),
			ChainParams:   &config.Configuration{},
		},
		degradation:      &degradation{},
		History:          utils.NewHistory(maxHistoryCapacity),
		Snapshots:        map[uint32][]*CheckPoint{},
		SnapshotKeysDesc: []uint32{},
	}
}

func TestClassE_F109_RollbackPrunesStaleSnapshots(t *testing.T) {
	// `above` == how many stale snapshots sit ABOVE the rollback target (== reorg depth
	// in snapshot terms). Vary it 1/2/5/deep.
	for _, above := range []int{1, 2, 5, 12} {
		for rep := 0; rep < classEReps; rep++ {
			a := newF109Arbiters()
			const target = uint32(1000)

			// Seed snapshots the way SnapshotByHeight would: keys sorted descending, each
			// mapping to a non-nil []*CheckPoint. Three at/below target, `above` above it.
			seed := []uint32{target, target - 1, target - 2, target - 3}
			for i := 1; i <= above; i++ {
				seed = append(seed, target+uint32(i))
			}
			for _, h := range seed {
				a.SnapshotKeysDesc = append(a.SnapshotKeysDesc, h)
				a.Snapshots[h] = []*CheckPoint{{}}
			}
			sort.Slice(a.SnapshotKeysDesc, func(i, j int) bool {
				return a.SnapshotKeysDesc[i] > a.SnapshotKeysDesc[j]
			})
			assert.Equal(t, len(seed), len(a.SnapshotKeysDesc), "path reached: snapshots seeded")

			// REORG via the REAL Arbiters.RollbackTo.
			assert.NoError(t, a.RollbackTo(target))

			// DISCRIMINATOR: every snapshot ABOVE target must be gone (map + key list);
			// pristine keeps them (stale).
			for i := 1; i <= above; i++ {
				h := target + uint32(i)
				if _, ok := a.Snapshots[h]; ok {
					t.Fatalf("F-109 above=%d rep=%d: Snapshots[%d] (>target) MUST be pruned (pristine keeps it)", above, rep, h)
				}
			}
			for _, k := range a.SnapshotKeysDesc {
				assert.LessOrEqualf(t, k, target,
					"F-109 above=%d rep=%d: no SnapshotKeysDesc entry may exceed target after rollback (found %d)", above, rep, k)
			}
			assert.Equalf(t, 4, len(a.SnapshotKeysDesc),
				"F-109 above=%d rep=%d: exactly the 4 at/below-target keys survive", above, rep)
			// at/below-target snapshots retained.
			for _, h := range []uint32{target, target - 1, target - 2, target - 3} {
				if _, ok := a.Snapshots[h]; !ok {
					t.Fatalf("F-109 above=%d rep=%d: snapshot at/below target (%d) must be retained", above, rep, h)
				}
			}
		}
	}
}
