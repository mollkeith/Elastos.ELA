// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package checkpoint

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/common/log"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/utils"
)

// todo remove this
const (
	txpoolCheckpointKey = "cp_txPool"
	dposCheckpointKey   = "cp_dpos"
	crCheckpointKey     = "cp_cr"

	MaxCheckPointFilesCount int = 36
)

type Priority byte
type RollBackStatus byte

const (
	DefaultCheckpoint = "default"

	VeryHigh   Priority = 0x00
	High       Priority = 0x01
	MediumHigh Priority = 0x02
	Medium     Priority = 0x03
	MediumLow  Priority = 0x04
	Low        Priority = 0x05
	VeryLow    Priority = 0x06
)

// BlockListener defines events during block lifetime.
type BlockListener interface {
	// OnBlockSaved is an event fired after block saved to chain db,
	// which means block has been settled in block chain.
	OnBlockSaved(block *types.DposBlock)

	// OnRollbackTo is an event fired during the block chain rollback,
	// since we only tolerance 6 blocks rollback so out max rollback support
	// can be 6 blocks by default.
	OnRollbackTo(height uint32) error

	// OnRollbackSeekTo is an event fired during the block chain rollback,
	// only rollback history without do commit.
	OnRollbackSeekTo(height uint32)
}

// ICheckPoint is a interface defines operators that all memory state should
// implement to restore and get when needed.
type ICheckPoint interface {
	common.Serializable
	BlockListener

	// Key is the unique id in manager to identity checkpoints.
	Key() string

	// Snapshot take a snapshot of current state, this should be a deep copy
	// because we are in a async environment.
	Snapshot() ICheckPoint

	// GetHeight returns current height of checkpoint by which determines how to
	// choose between multi-history checkpoints.
	GetHeight() uint32

	// SetHeight set current height of checkpoint by which determines how to
	// choose between multi-history checkpoints.
	SetHeight(uint32)

	// SavePeriod defines how long should we save the checkpoint.
	SavePeriod() uint32

	// SaveStartHeight returns the height to create checkpoints file.
	SaveStartHeight() uint32

	// EffectivePeriod defines the legal height a checkpoint can take
	// effect.
	EffectivePeriod() uint32

	// DataExtension defines extension of checkpoint related data files.
	DataExtension() string

	// Generator returns a generator to create a checkpoint by a data buffer.
	Generator() func(buf []byte) ICheckPoint

	// LogError will output the specify error with custom log format.
	LogError(err error)

	// Priority defines the priority by which we decide the order when
	// process block and rollback block.
	Priority() Priority

	// OnInit fired after manager successfully loaded default checkpoint.
	OnInit()

	// GetHeight returns initial height checkpoint should start with.
	StartHeight() uint32

	//reset
	OnReset() error
}

// Manager holds checkpoints save automatically.
type Manager struct {
	checkpoints map[string]ICheckPoint
	channels    map[string]*fileChannels
	cfg         *config.Configuration
	mtx         sync.RWMutex
}

// OnBlockSaved is an event fired after block saved to chain db,
// which means block has been settled in block chain.
func (m *Manager) OnBlockSaved(block *types.DposBlock,
	filter func(point ICheckPoint) bool, isPow bool, revertToPowHeight uint32, init bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.onBlockSaved(block, filter, true, isPow, revertToPowHeight, init)
}

// OnRollbackTo is an event fired during the block chain rollback, since we
// only tolerance 6 blocks rollback so out max rollback support can be 6 blocks
// by default.
func (m *Manager) OnRollbackTo(height uint32, isPow bool) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	//if isPow {
	//	err := m.RestoreTo(int(height))
	//	if err != nil {
	//		log.Errorf("Error rollback to height %d , %s ", height, err.Error())
	//		return err
	//	}
	//} else {
	sortedPoints := m.getOrderedCheckpoints()
	for _, v := range sortedPoints {
		if err := v.OnRollbackTo(height); err != nil {
			log.Errorf("manager rollback failed,", err)
			return err
		}
	}
	//}
	return nil
}

// Register will register a checkpoint with key in checkpoint as the unique id.
func (m *Manager) Register(checkpoint ICheckPoint) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.checkpoints[checkpoint.Key()] = checkpoint
	m.channels[checkpoint.Key()] = NewFileChannels(m.cfg)
}

// Unregister will unregister a checkpoint with key in checkpoint as the
// unique id.
func (m *Manager) Unregister(key string) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.channels[key]; !ok {
		return
	}

	delete(m.checkpoints, key)
	m.channels[key].Exit()
	delete(m.channels, key)
}

// GetCheckpoint get a checkpoint by key and height. If height is lower than
// last height of checkpoints and EnableHistory in Config struct is true
// should return supported checkpoints, otherwise will return nil instead.
func (m *Manager) GetCheckpoint(key string, height uint32) (
	checkpoint ICheckPoint, found bool) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	checkpoint, found = m.checkpoints[key]
	if height >= checkpoint.GetHeight() {
		return
	}

	if !found {
		return
	}

	if m.cfg.CheckPointConfiguration.EnableHistory {
		return m.findHistoryCheckpoint(checkpoint, height)
	} else {
		return nil, false
	}
}

func (m *Manager) OnReset() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	sortedPoints := m.getOrderedCheckpoints()
	for i, v := range sortedPoints {
		err := v.OnReset()
		if err != nil {
			log.Error(" Reset ", err, " i", i)
		}
	}
	return nil
}

// Restore will load all data of each checkpoints file and store in
// corresponding meta-data.
func (m *Manager) Restore() (err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	var failures []string
	sortedPoints := m.getOrderedCheckpoints()
	for _, v := range sortedPoints {
		// fixme: Skip 'dpos' and 'cr' checkpoint temporary
		//if v.Key() == "dpos" || v.Key() == "cr" {
		//	continue
		//}
		// F-123: a failed load must not be erased by a later successful one. As
		// shipped the failure went into the NAMED return and the next iteration's
		// success overwrote it with nil, so a manager that restored only some of its
		// checkpoints reported success. Keep loading the remaining checkpoints -- a
		// missing default file is normal on a fresh node and the others must still
		// come up -- but report every failure to the caller.
		if e := m.loadDefaultCheckpoint(v); e != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", v.Key(), e.Error()))
			continue
		}
		v.OnInit()
	}
	if len(failures) != 0 {
		return errors.New("checkpoint restore incomplete -> " +
			strings.Join(failures, "; "))
	}
	return nil
}

// RestoreTo will load all data of specific height in each checkpoints file and store in
// corresponding meta-data.
func (m *Manager) RestoreTo(height int) (err error) {
	sortedPoints := m.getOrderedCheckpoints()
	for _, v := range sortedPoints {
		if err = m.loadSpecificHeightCheckpoint(v, height); err != nil {
			return
		}
		v.OnInit()
		v.OnRollbackSeekTo(uint32(height))
	}
	return
}

func (m *Manager) Reset(filter func(point ICheckPoint) bool) {
	for _, v := range m.checkpoints {
		if filter != nil && !filter(v) {
			continue
		}
		m.channels[v.Key()].Reset(v, nil)
	}
}

// SafeHeight returns the minimum height of all checkpoints from which we can
// rescan block chain data.
func (m *Manager) SafeHeight() uint32 {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	height := uint32(math.MaxUint32)
	for _, v := range m.checkpoints {
		if v.Key() == "cp_txPool" {
			continue
		}
		var recordHeight uint32
		if v.GetHeight() >= v.EffectivePeriod() {
			recordHeight = v.GetHeight() - v.EffectivePeriod()
		} else {
			recordHeight = 0
		}
		safeHeight := uint32(math.Max(float64(recordHeight),
			float64(v.StartHeight())))
		if safeHeight < height {
			height = safeHeight
		}
	}
	return height
}

// MaxHeight returns the highest embedded checkpoint height across the consensus
// checkpoints (skipping cp_txPool). After InitCheckpoint's init replay this equals
// the highest RESTORED snapshot-file height, because init replay advances state but
// skips SetHeight. A forced rollback uses this to verify no restored snapshot sits
// at or above the rewound target -- the case a min-based SafeHeight cannot detect.
func (m *Manager) MaxHeight() uint32 {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	var height uint32
	for _, v := range m.checkpoints {
		if v.Key() == "cp_txPool" {
			continue
		}
		if v.GetHeight() > height {
			height = v.GetHeight()
		}
	}
	return height
}

// Close will clean all related resources.
func (m *Manager) Close() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for _, v := range m.channels {
		v.Exit()
	}
}

// SetDataPath set root path of all checkpoints.
func (m *Manager) SetDataPath(path string) {
	m.cfg.CheckPointConfiguration.DataPath = path
}

// RegisterNeedSave register the need save function.
func (m *Manager) SetNeedSave(needSave bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.cfg.CheckPointConfiguration.NeedSave = needSave
}

func (m *Manager) getOrderedCheckpoints() []ICheckPoint {
	sortedPoints := make([]ICheckPoint, 0, len(m.checkpoints))
	for _, v := range m.checkpoints {
		sortedPoints = append(sortedPoints, v)
	}
	sort.Slice(sortedPoints, func(i, j int) bool {
		return sortedPoints[i].Priority() < sortedPoints[j].Priority()
	})
	return sortedPoints
}

func (m *Manager) onBlockSaved(block *types.DposBlock,
	filter func(point ICheckPoint) bool, async bool, isPow bool, revertToPowHeight uint32, init bool) {

	sortedPoints := m.getOrderedCheckpoints()

	for _, v := range sortedPoints {
		if filter != nil && !filter(v) {
			continue
		}
		if block.Height < v.StartHeight() || block.Height <= v.GetHeight() {
			continue
		}
		v.OnBlockSaved(block)

		if !m.cfg.CheckPointConfiguration.NeedSave || init || block.Height <= v.SaveStartHeight() {
			continue
		}

		originalHeight := v.GetHeight()
		if originalHeight > 0 && v.Key() == txpoolCheckpointKey {
			reply := make(chan bool, 1)
			m.channels[v.Key()].Replace(v, reply, block.Height-1)
			if !async {
				<-reply
			}
		} else if originalHeight > 0 && block.Height ==
			originalHeight+v.EffectivePeriod() {

			reply := make(chan bool, 1)
			m.channels[v.Key()].Replace(v, reply, originalHeight)
			if !async {
				<-reply
			}
		}

		if block.Height >=
			originalHeight+v.SavePeriod() {
			v.SetHeight(block.Height)
			snapshot := v.Snapshot()
			if snapshot == nil {
				log.Error("snapshot is nil, key:", v.Key())
				continue
			}
			reply := make(chan bool, 1)
			m.channels[v.Key()].Save(snapshot, reply)
			if !async {
				<-reply
			}
		}
	}
}

func (m *Manager) findHistoryCheckpoint(current ICheckPoint,
	findHeight uint32) (checkpoint ICheckPoint, found bool) {
	bestHeight := current.GetHeight()
	for bestHeight > findHeight && bestHeight >= current.SavePeriod() {
		bestHeight -= current.SavePeriod()
	}
	// bestHeight still larger than findHeight means findHeight less than
	// current.SavePeriod(), then set to zero directly
	if bestHeight > findHeight {
		bestHeight = 0
	}

	path := getFilePathByHeight(m.cfg.CheckPointConfiguration.DataPath, current, bestHeight)
	return m.constructCheckpoint(current, path)
}

func (m *Manager) loadDefaultCheckpoint(current ICheckPoint) (err error) {
	path := getDefaultPath(m.cfg.CheckPointConfiguration.DataPath, current)
	return m.loadCheckpointFile(current, path)
}

func (m *Manager) loadSpecificHeightCheckpoint(current ICheckPoint, height int) (err error) {
	path := getSpecificHeightPath(m.cfg.CheckPointConfiguration.DataPath, current, height)
	return m.loadCheckpointFile(current, path)
}

// loadCheckpointFile deserializes a checkpoint file into the LIVE checkpoint
// object registered with the manager.
//
// F-121: ICheckPoint.Deserialize writes straight into that live object, so a
// truncated or corrupt file leaves it half-populated -- and, because Height is the
// first field every implementation reads, it leaves the live checkpoint carrying
// the height of a state it does not actually hold. Restore() then skips OnInit(),
// so the consensus state is never recovered, while SafeHeight() keeps reporting
// the height read out of the bad file; InitCheckpoint's replay therefore starts
// ABOVE the blocks that would have rebuilt the state and the node runs at full
// block height with empty CR/DPoS state. Putting the pre-load height back on
// failure returns the checkpoint to the full-replay path, which is the correct
// recovery. Nothing changes on the success path.
func (m *Manager) loadCheckpointFile(current ICheckPoint, path string) (err error) {
	data, err := m.readFileBuffer(path)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	buf.Write(data)

	heightBefore := current.GetHeight()
	if err = current.Deserialize(buf); err != nil {
		current.SetHeight(heightBefore)
		return err
	}
	return nil
}

func (m *Manager) readFileBuffer(path string) (buf []byte, err error) {
	if !utils.FileExisted(path) {
		err = errors.New(fmt.Sprintf("can't find file: %s", path))
		return
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0400)
	if err != nil || file == nil {
		return
	}
	defer file.Close()
	buf, err = ioutil.ReadAll(file)
	return
}

func (m *Manager) constructCheckpoint(proto ICheckPoint, path string) (
	ICheckPoint, bool) {
	data, err := m.readFileBuffer(path)
	if err != nil {
		proto.LogError(err)
		return nil, false
	}
	return proto.Generator()(data), true
}

func getFilePath(root string, checkpoint ICheckPoint) string {
	return getFilePathByHeight(root, checkpoint, checkpoint.GetHeight())
}

func getDefaultPath(root string, checkpoint ICheckPoint) string {
	return filepath.Join(getCheckpointDirectory(root, checkpoint),
		string(os.PathSeparator), getDefaultFileName(checkpoint))
}

func getSpecificHeightPath(root string, checkpoint ICheckPoint, height int) string {
	return filepath.Join(getCheckpointDirectory(root, checkpoint),
		string(os.PathSeparator), getSpecificHeightFileName(checkpoint, height))
}

func getFilePathByHeight(root string, checkpoint ICheckPoint,
	height uint32) string {
	return filepath.Join(getCheckpointDirectory(root, checkpoint),
		string(os.PathSeparator), getFileName(checkpoint, height))
}

func getFileName(checkpoint ICheckPoint, height uint32) string {
	return strconv.FormatUint(uint64(height), 10) +
		checkpoint.DataExtension()
}

func getDefaultFileName(checkpoint ICheckPoint) string {
	return DefaultCheckpoint + checkpoint.DataExtension()
}

func getSpecificHeightFileName(checkpoint ICheckPoint, height int) string {
	return strconv.Itoa(height) + checkpoint.DataExtension()
}

func getCheckpointDirectory(root string,
	checkpoint ICheckPoint) string {
	return filepath.Join(root, checkpoint.Key())
}

func NewManager(cfg *config.Configuration) *Manager {
	return &Manager{
		checkpoints: make(map[string]ICheckPoint),
		channels:    make(map[string]*fileChannels),
		cfg:         cfg,
	}
}
