// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package state

import (
	"bytes"
	"errors"
	"io"
	"math"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/checkpoint"
	"github.com/elastos/Elastos.ELA/core/types"
)

const (
	// CheckpointKey defines key of DPoS checkpoint.
	CheckpointKey = "cp_dpos"

	// checkpointExtension defines checkpoint file extension of DPoS checkpoint.
	checkpointExtension = ".dcp"

	// CheckPointInterval defines interval height between two neighbor check
	// points.
	CheckPointInterval = uint32(720)

	// checkpointEffectiveHeight defines the minimal height Arbiters obj
	// should scan to recover effective state.
	checkpointEffectiveHeight = uint32(720)
)

// CheckPoint defines all variables need record in database
// degradationTag marks the start of the trailing degradation block appended to
// a DPoS state checkpoint (F-096). Legacy checkpoints end before it.
var degradationTag = [4]byte{'D', 'E', 'G', 'R'}

type CheckPoint struct {
	StateKeyFrame
	Height                      uint32
	DutyIndex                   int
	LastArbitrators             []ArbiterMember
	CurrentArbitrators          []ArbiterMember
	NextArbitrators             []ArbiterMember
	NextCandidates              []ArbiterMember
	CurrentCandidates           []ArbiterMember
	CurrentReward               RewardData
	NextReward                  RewardData
	LastDPoSRewards             map[string]map[string]common.Fixed64
	CurrentCRCArbitersMap       map[common.Uint168]ArbiterMember
	CurrentOnDutyCRCArbitersMap map[common.Uint168]ArbiterMember
	NextCRCArbitersMap          map[common.Uint168]ArbiterMember
	NextCRCArbiters             []ArbiterMember

	CRCChangedHeight           uint32
	AccumulativeReward         common.Fixed64
	FinalRoundChange           common.Fixed64
	ClearingHeight             uint32
	ArbitersRoundReward        map[common.Uint168]common.Fixed64
	IllegalBlocksPayloadHashes map[common.Uint256]interface{}

	ForceChanged bool

	// F-096: degradation state persisted so a cold restart does not lose the
	// DSInactive / DSUnderstaffed mode + processed-inactive-tx set and re-run
	// PreProcessSpecialTx, re-triggering a spurious ForceChange. Written as a
	// trailing back-compat "DEGR" block (legacy checkpoints lacking it default
	// to DSNormal on restore).
	DegradationState  byte
	UnderstaffedSince uint32
	InactivateHeight  uint32
	InactiveTxs       map[common.Uint256]interface{}

	arbitrators *Arbiters
}

func (c *CheckPoint) SaveStartHeight() uint32 {
	// same to CR
	return c.arbitrators.ChainParams.CRConfiguration.CRVotingStartHeight
}

func (c *CheckPoint) StartHeight() uint32 {
	return uint32(math.Min(float64(c.arbitrators.ChainParams.VoteStartHeight),
		float64(c.arbitrators.ChainParams.CRCOnlyDPOSHeight-
			c.arbitrators.ChainParams.DPoSConfiguration.PreConnectOffset)))
}

func (c *CheckPoint) OnBlockSaved(block *types.DposBlock) {
	if block.Height <= c.GetHeight() {
		return
	}
	c.arbitrators.ProcessBlock(block.Block, block.Confirm)
}

func (c *CheckPoint) OnRollbackSeekTo(height uint32) {
	c.arbitrators.RollbackSeekTo(height)
}

// newBaselineArbiters builds the genesis-fresh Arbiters that BOTH checkpoint rebuild
// sites -- OnReset and the deep OnRollbackTo branch -- reconstruct the checkpoint
// from. Both need the SAME fully constructed baseline: initFromArbitrators
// dereferences ar.State.StateKeyFrame and (since F-096) ar.degradation, and ALIASES
// ar.illegalBlocksPayloadHashes / ar.LastDPoSRewards into the CheckPoint, from where
// recoverFromCheckPoints plants them on the LIVE Arbiters -- while a hand-built
// &Arbiters{} leaves every one of those nil. Building the baseline in exactly one
// place, over a constructor (initArbitrators) that establishes the WHOLE class
// invariant, is what keeps a rebuild equal to a genesis-fresh NewArbitrators.
//
// It takes the live Arbiters because three of the NewArbitrators literal's fields are
// genesis-time INPUTS rather than functions of chainParams: the CR committee, the
// checkpoint manager, and the operator-supplied block-confirm sponsor overrides (read
// once from DPoSConfiguration.SponsorsFilePath at construction). Carrying them across
// from the live object reproduces the genesis values exactly, with no file I/O and --
// decisively -- no new error path inside a reorg-recovery reset.
//
// The one deliberate divergence is *State: only its StateKeyFrame is rebuilt, not the
// closures NewState installs. That is REQUIRED, not an oversight -- NewState calls
// events.Subscribe(state.handleEvents), so constructing one per reset would leak a
// subscription to a dead State on every deep reorg. It is also inert:
// initFromArbitrators reads exactly *ar.State.StateKeyFrame off this object, and
// recoverFromCheckPoints re-points the LIVE State's StateKeyFrame without ever
// replacing the live State itself, so the live closures survive untouched.
//
// UNGATED: it produces the genesis defaults the pristine rebuild always intended, so
// nothing consensus-visible changes -- the paths simply stop crashing.
func newBaselineArbiters(live *Arbiters) (*Arbiters, error) {
	ar := &Arbiters{
		// Genesis-time inputs, not derivable from chainParams.
		CRCommittee:                  live.CRCommittee,
		CkpManager:                   live.CkpManager,
		BlockConfirmProposalSponsors: live.BlockConfirmProposalSponsors,
	}
	ar.State = &State{
		StateKeyFrame: NewStateKeyFrame(),
	}
	// initArbitrators fills the whole rest of the genesis baseline: arbiters, CRC
	// maps, rewards, degradation, illegalBlocksPayloadHashes, LastDPoSRewards,
	// Snapshots, SnapshotKeysDesc, nextCandidates, History and ChainParams.
	if err := ar.initArbitrators(live.ChainParams); err != nil {
		return nil, err
	}
	return ar, nil
}

func (c *CheckPoint) OnReset() error {
	log.Info("dpos state OnReset")
	ar, err := newBaselineArbiters(c.arbitrators)
	if err != nil {
		return err
	}
	c.initFromArbitrators(ar)
	c.arbitrators.RecoverFromCheckPoints(c)
	return nil
}

func (c *CheckPoint) OnRollbackTo(height uint32) error {
	if height < c.StartHeight() {
		ar, err := newBaselineArbiters(c.arbitrators)
		if err != nil {
			return err
		}
		c.initFromArbitrators(ar)
		c.arbitrators.RecoverFromCheckPoints(c)
		return nil
	}
	return c.arbitrators.RollbackTo(height)
}

func (c *CheckPoint) Key() string {
	return CheckpointKey
}

func (c *CheckPoint) OnInit() {
	c.arbitrators.RecoverFromCheckPoints(c)
}

func (c *CheckPoint) Snapshot() checkpoint.ICheckPoint {
	// init check point
	c.initFromArbitrators(c.arbitrators)

	buf := new(bytes.Buffer)
	if err := c.Serialize(buf); err != nil {
		c.LogError(err)
		return nil
	}
	result := &CheckPoint{}
	if err := result.Deserialize(buf); err != nil {
		c.LogError(err)
		return nil
	}
	return result
}

func (c *CheckPoint) GetHeight() uint32 {
	return c.Height
}

func (c *CheckPoint) SetHeight(height uint32) {
	c.Height = height
}

func (c *CheckPoint) SavePeriod() uint32 {
	return CheckPointInterval
}

func (c *CheckPoint) EffectivePeriod() uint32 {
	return checkpointEffectiveHeight
}

func (c *CheckPoint) DataExtension() string {
	return checkpointExtension
}

func (c *CheckPoint) Priority() checkpoint.Priority {
	return checkpoint.Medium
}

func (c *CheckPoint) Generator() func(buf []byte) checkpoint.ICheckPoint {
	return func(buf []byte) checkpoint.ICheckPoint {
		stream := new(bytes.Buffer)
		stream.Write(buf)

		result := &CheckPoint{}
		if err := result.Deserialize(stream); err != nil {
			c.LogError(err)
			return nil
		}
		return result
	}
}

func (c *CheckPoint) LogError(err error) {
	log.Warn("[CheckPoint] error: ", err.Error())
}

// Serialize write data to writer
func (c *CheckPoint) Serialize(w io.Writer) (err error) {
	if err = common.WriteUint32(w, c.Height); err != nil {
		return
	}

	if err = common.WriteUint32(w, uint32(c.DutyIndex)); err != nil {
		return
	}

	if err = c.writeArbiters(w, c.LastArbitrators); err != nil {
		return
	}

	if err = c.writeArbiters(w, c.CurrentArbitrators); err != nil {
		return
	}

	if err = c.writeArbiters(w, c.CurrentCandidates); err != nil {
		return
	}

	if err = c.writeArbiters(w, c.NextArbitrators); err != nil {
		return
	}

	if err = c.writeArbiters(w, c.NextCandidates); err != nil {
		return
	}

	if err = c.CurrentReward.Serialize(w); err != nil {
		return
	}

	if err = c.NextReward.Serialize(w); err != nil {
		return
	}

	if err = c.serializeDPoSRewardsMap(w, c.LastDPoSRewards); err != nil {
		return
	}

	if err = c.serializeCRCArbitersMap(w, c.CurrentCRCArbitersMap); err != nil {
		return
	}
	if err = c.serializeCRCArbitersMap(w, c.CurrentOnDutyCRCArbitersMap); err != nil {
		return
	}

	if err = c.serializeCRCArbitersMap(w, c.NextCRCArbitersMap); err != nil {
		return
	}
	if err = c.writeArbiters(w, c.NextCRCArbiters); err != nil {
		return
	}

	if err = common.WriteUint32(w, c.CRCChangedHeight); err != nil {
		return
	}

	if err = c.AccumulativeReward.Serialize(w); err != nil {
		return
	}

	if err = c.FinalRoundChange.Serialize(w); err != nil {
		return
	}

	if err = common.WriteUint32(w, c.ClearingHeight); err != nil {
		return
	}

	if err = c.serializeRoundRewardMap(w, c.ArbitersRoundReward); err != nil {
		return
	}

	if err = c.serializeIllegalPayloadHashesMap(w, c.IllegalBlocksPayloadHashes); err != nil {
		return
	}

	if err = common.WriteElements(w, c.ForceChanged); err != nil {
		return
	}
	if err = c.StateKeyFrame.Serialize(w); err != nil {
		return
	}
	// F-096: trailing back-compat degradation block.
	return c.serializeDegradation(w)
}

// serializeDegradation writes the trailing degradation block: a 4-byte "DEGR"
// tag, the degradation state byte, understaffedSince, inactivateHeight and the
// processed-inactive-tx hash set. The tag lets a legacy checkpoint (which ends
// right after StateKeyFrame) be detected on read.
func (c *CheckPoint) serializeDegradation(w io.Writer) (err error) {
	if _, err = w.Write(degradationTag[:]); err != nil {
		return
	}
	if err = common.WriteElements(w, c.DegradationState,
		c.UnderstaffedSince, c.InactivateHeight); err != nil {
		return
	}
	return c.serializeIllegalPayloadHashesMap(w, c.InactiveTxs)
}

// deserializeDegradation reads the optional trailing degradation block. A clean
// EOF where the tag is expected means a legacy checkpoint written before F-096,
// so the degradation state defaults to DSNormal instead of erroring.
func (c *CheckPoint) deserializeDegradation(r io.Reader) (err error) {
	var tag [4]byte
	if _, err = io.ReadFull(r, tag[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			c.DegradationState = byte(DSNormal)
			c.InactiveTxs = make(map[common.Uint256]interface{})
			return nil
		}
		return err
	}
	if tag != degradationTag {
		return errors.New("invalid degradation checkpoint tag")
	}
	if err = common.ReadElements(r, &c.DegradationState,
		&c.UnderstaffedSince, &c.InactivateHeight); err != nil {
		return
	}
	c.InactiveTxs, err = c.deserializeIllegalPayloadHashes(r)
	return
}

// copyInactiveTxs returns a copy of the processed-inactive-tx hash set so the
// checkpoint does not alias the live degradation map.
func copyInactiveTxs(src map[common.Uint256]interface{}) map[common.Uint256]interface{} {
	dst := make(map[common.Uint256]interface{}, len(src))
	for k := range src {
		dst[k] = nil
	}
	return dst
}

func (c *CheckPoint) serializeCRCArbitersMap(w io.Writer,
	rmap map[common.Uint168]ArbiterMember) (err error) {
	if err = common.WriteVarUint(w, uint64(len(rmap))); err != nil {
		return
	}
	for k, v := range rmap {
		if err = k.Serialize(w); err != nil {
			return
		}

		if err = common.WriteUint8(w, uint8(v.GetType())); err != nil {
			return
		}

		if err = v.Serialize(w); err != nil {
			return
		}
	}
	return
}

func (c *CheckPoint) serializeDPoSRewardsMap(w io.Writer,
	rmap map[string]map[string]common.Fixed64) (err error) {
	if err = common.WriteVarUint(w, uint64(len(rmap))); err != nil {
		return
	}
	for k, v := range rmap {
		if err = common.WriteVarString(w, k); err != nil {
			return
		}
		if err = common.WriteVarUint(w, uint64(len(v))); err != nil {
			return
		}
		for k2, v2 := range v {
			if err = common.WriteVarString(w, k2); err != nil {
				return
			}
			if err = v2.Serialize(w); err != nil {
				return
			}
		}
	}
	return
}

func (c *CheckPoint) serializeRoundRewardMap(w io.Writer,
	rmap map[common.Uint168]common.Fixed64) (err error) {
	if err = common.WriteVarUint(w, uint64(len(rmap))); err != nil {
		return
	}
	for k, v := range rmap {
		if err = k.Serialize(w); err != nil {
			return
		}

		if err = v.Serialize(w); err != nil {
			return
		}
	}
	return
}

func (c *CheckPoint) serializeIllegalPayloadHashesMap(w io.Writer,
	rmap map[common.Uint256]interface{}) (err error) {
	if err = common.WriteVarUint(w, uint64(len(rmap))); err != nil {
		return
	}
	for k, _ := range rmap {
		if err = k.Serialize(w); err != nil {
			return
		}
	}
	return
}

// Deserialize read data to reader
func (c *CheckPoint) Deserialize(r io.Reader) (err error) {
	if c.Height, err = common.ReadUint32(r); err != nil {
		return
	}

	var dutyIndex uint32
	if dutyIndex, err = common.ReadUint32(r); err != nil {
		return
	}
	c.DutyIndex = int(dutyIndex)

	if c.LastArbitrators, err = c.readArbiters(r); err != nil {
		return
	}

	if c.CurrentArbitrators, err = c.readArbiters(r); err != nil {
		return
	}

	if c.CurrentCandidates, err = c.readArbiters(r); err != nil {
		return
	}

	if c.NextArbitrators, err = c.readArbiters(r); err != nil {
		return
	}

	if c.NextCandidates, err = c.readArbiters(r); err != nil {
		return
	}

	if err = c.CurrentReward.Deserialize(r); err != nil {
		return
	}

	if err = c.NextReward.Deserialize(r); err != nil {
		return
	}

	if c.LastDPoSRewards, err = c.deserializeDPoSRewardsMap(r); err != nil {
		return
	}

	if c.CurrentCRCArbitersMap, err = c.deserializeCRCArbitersMap(r); err != nil {
		return
	}
	if c.CurrentOnDutyCRCArbitersMap, err = c.deserializeCRCArbitersMap(r); err != nil {
		return
	}
	if c.NextCRCArbitersMap, err = c.deserializeCRCArbitersMap(r); err != nil {
		return
	}
	if c.NextCRCArbiters, err = c.readArbiters(r); err != nil {
		return
	}

	if c.CRCChangedHeight, err = common.ReadUint32(r); err != nil {
		return
	}

	if err = c.AccumulativeReward.Deserialize(r); err != nil {
		return
	}

	if err = c.FinalRoundChange.Deserialize(r); err != nil {
		return
	}

	if c.ClearingHeight, err = common.ReadUint32(r); err != nil {
		return
	}

	if c.ArbitersRoundReward, err = c.deserializeRoundRewardMap(r); err != nil {
		return
	}

	c.IllegalBlocksPayloadHashes, err = c.deserializeIllegalPayloadHashes(r)
	if err != nil {
		return
	}
	if err = common.ReadElement(r, &c.ForceChanged); err != nil {
		return
	}
	if err = c.StateKeyFrame.Deserialize(r); err != nil {
		return
	}
	// F-096: optional trailing degradation block (absent in legacy checkpoints).
	return c.deserializeDegradation(r)
}

func (c *CheckPoint) deserializeCRCArbitersMap(r io.Reader) (
	rmap map[common.Uint168]ArbiterMember, err error) {

	var count uint64
	if count, err = common.ReadVarUint(r, 0); err != nil {
		return
	}
	rmap = make(map[common.Uint168]ArbiterMember)
	for i := uint64(0); i < count; i++ {
		var k common.Uint168
		if err = k.Deserialize(r); err != nil {
			return
		}

		var arbiterType uint8
		if arbiterType, err = common.ReadUint8(r); err != nil {
			return
		}
		var am ArbiterMember
		switch ArbiterType(arbiterType) {
		case Origin:
			am = &originArbiter{}
		case DPoS:
			am = &dposArbiter{}
		case CROrigin:
			am = &dposArbiter{}
		case CRC:
			am = &crcArbiter{}
		default:
			err = errors.New("invalid arbiter type")
			return
		}
		if err = am.Deserialize(r); err != nil {
			return
		}

		rmap[k] = am
	}
	return
}

func (c *CheckPoint) deserializeIllegalPayloadHashes(
	r io.Reader) (hmap map[common.Uint256]interface{}, err error) {
	var count uint64
	if count, err = common.ReadVarUint(r, 0); err != nil {
		return
	}
	hmap = make(map[common.Uint256]interface{})
	for i := uint64(0); i < count; i++ {
		var k common.Uint256
		if err = k.Deserialize(r); err != nil {
			return
		}
		hmap[k] = nil
	}
	return
}

func (c *CheckPoint) deserializeDPoSRewardsMap(
	r io.Reader) (rmap map[string]map[string]common.Fixed64, err error) {
	var count uint64
	if count, err = common.ReadVarUint(r, 0); err != nil {
		return
	}
	rmap = make(map[string]map[string]common.Fixed64)
	for i := uint64(0); i < count; i++ {
		var k string
		if k, err = common.ReadVarString(r); err != nil {
			return
		}

		var count2 uint64
		if count2, err = common.ReadVarUint(r, 0); err != nil {
			return
		}
		rmap2 := make(map[string]common.Fixed64)
		for i := uint64(0); i < count2; i++ {
			var k2 string
			if k2, err = common.ReadVarString(r); err != nil {
				return
			}
			reward := common.Fixed64(0)
			if err = reward.Deserialize(r); err != nil {
				return
			}
			rmap2[k2] = reward
		}

		rmap[k] = rmap2
	}
	return
}

func (c *CheckPoint) deserializeRoundRewardMap(
	r io.Reader) (rmap map[common.Uint168]common.Fixed64, err error) {
	var count uint64
	if count, err = common.ReadVarUint(r, 0); err != nil {
		return
	}
	rmap = make(map[common.Uint168]common.Fixed64)
	for i := uint64(0); i < count; i++ {
		var k common.Uint168
		if err = k.Deserialize(r); err != nil {
			return
		}
		reward := common.Fixed64(0)
		if err = reward.Deserialize(r); err != nil {
			return
		}
		rmap[k] = reward
	}
	return
}

func (c *CheckPoint) writeArbiters(w io.Writer,
	arbiters []ArbiterMember) error {
	if err := common.WriteVarUint(w, uint64(len(arbiters))); err != nil {
		return err
	}

	for _, ar := range arbiters {
		if err := SerializeArbiterMember(ar, w); err != nil {
			return err
		}
	}
	return nil
}

func (c *CheckPoint) readArbiters(r io.Reader) ([]ArbiterMember, error) {
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}

	arbiters := make([]ArbiterMember, 0, count)
	for i := uint64(0); i < count; i++ {
		arbiter, err := ArbiterMemberFromReader(r)
		if err != nil {
			return nil, err
		}
		arbiters = append(arbiters, arbiter)
	}
	return arbiters, nil
}

// initFromArbitrators copies an Arbiters into this CheckPoint. Its callers are
// Snapshot() and NewCheckpoint() over the LIVE Arbiters, and the two rebuild sites
// over a newBaselineArbiters() baseline -- all of which are fully constructed.
//
// The nil guards below are therefore BELT AND BRACES, not the fix: the fix is that
// initArbitrators now establishes the whole genesis baseline, so no caller can reach
// here with these nil. They exist so a FUTURE hand-built &Arbiters{} caller that
// skips newBaselineArbiters cannot silently re-open this defect class -- neither the
// nil DEREFERENCES (ar.State.StateKeyFrame, ar.degradation) nor the nil MAPS that
// recoverFromCheckPoints would plant on the live Arbiters for ProcessSpecialTxPayload
// to index-write. Each guard emits exactly the documented genesis/legacy default, so
// taking one produces the same CheckPoint a complete baseline would. On every path
// that exists today they are provably not taken, so nothing observable changes.
func (c *CheckPoint) initFromArbitrators(ar *Arbiters) {
	c.CurrentCandidates = ar.CurrentCandidates
	c.NextArbitrators = ar.nextArbitrators
	c.NextCandidates = ar.nextCandidates
	c.CurrentReward = ar.CurrentReward
	c.NextReward = ar.NextReward
	c.LastDPoSRewards = ar.LastDPoSRewards
	if c.LastDPoSRewards == nil {
		c.LastDPoSRewards = make(map[string]map[string]common.Fixed64)
	}
	c.LastArbitrators = ar.LastArbitrators
	c.CurrentArbitrators = ar.CurrentArbitrators
	// Legacy default: the empty genesis key frame NewArbitrators starts from.
	if ar.State != nil && ar.State.StateKeyFrame != nil {
		c.StateKeyFrame = *ar.State.StateKeyFrame
	} else {
		c.StateKeyFrame = *NewStateKeyFrame()
	}
	c.DutyIndex = ar.DutyIndex
	c.AccumulativeReward = ar.accumulativeReward
	c.FinalRoundChange = ar.finalRoundChange
	c.ClearingHeight = ar.clearingHeight
	// arbitersRoundReward is genuinely nil on a genesis-fresh Arbiters (explicitly so
	// in the NewArbitrators literal) and is only ever wholesale-reassigned, never
	// index-written, so it is deliberately NOT defaulted here: defaulting it would
	// make a rebuild differ from genesis.
	c.ArbitersRoundReward = ar.arbitersRoundReward
	c.IllegalBlocksPayloadHashes = ar.illegalBlocksPayloadHashes
	if c.IllegalBlocksPayloadHashes == nil {
		c.IllegalBlocksPayloadHashes = make(map[common.Uint256]interface{})
	}
	c.CRCChangedHeight = ar.crcChangedHeight
	c.CurrentCRCArbitersMap = ar.CurrentCRCArbitersMap
	c.NextCRCArbitersMap = ar.nextCRCArbitersMap
	c.NextCRCArbiters = ar.nextCRCArbiters
	c.ForceChanged = ar.forceChanged
	// F-096: capture degradation state so it survives serialize/restore. The legacy
	// default for a nil degradation is the one a pre-F-096 checkpoint restores as:
	// DSNormal, no understaffedSince / inactivateHeight, empty processed set.
	if ar.degradation != nil {
		c.DegradationState = byte(ar.degradation.state)
		c.UnderstaffedSince = ar.degradation.understaffedSince
		c.InactivateHeight = ar.degradation.inactivateHeight
		c.InactiveTxs = copyInactiveTxs(ar.degradation.inactiveTxs)
	} else {
		c.DegradationState = byte(DSNormal)
		c.UnderstaffedSince = 0
		c.InactivateHeight = 0
		c.InactiveTxs = copyInactiveTxs(nil)
	}

}

func NewCheckpoint(ar *Arbiters) *CheckPoint {
	cp := &CheckPoint{
		arbitrators: ar,
	}
	cp.initFromArbitrators(ar)
	return cp
}
