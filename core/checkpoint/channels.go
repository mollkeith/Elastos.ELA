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
	"os"
	"path/filepath"
	"strings"

	"github.com/elastos/Elastos.ELA/common/config"
	"github.com/elastos/Elastos.ELA/utils"
)

type fileMsg struct {
	checkpoint ICheckPoint
	reply      chan bool
}

type heightFileMsg struct {
	fileMsg
	height uint32
}

type fileChannels struct {
	cfg *config.CheckPointConfiguration

	save          chan fileMsg
	clean         chan fileMsg
	reset         chan fileMsg
	replace       chan heightFileMsg
	remove        chan heightFileMsg
	replaceRemove chan heightFileMsg
	exit          chan struct{}
}

func (c *fileChannels) Save(checkpoint ICheckPoint, reply chan bool) {
	c.save <- fileMsg{checkpoint, reply}
}

func (c *fileChannels) Clean(checkpoint ICheckPoint, reply chan bool) {
	c.clean <- fileMsg{checkpoint, reply}
}

func (c *fileChannels) Replace(checkpoint ICheckPoint, reply chan bool,
	height uint32) {
	c.replace <- heightFileMsg{fileMsg{checkpoint, reply},
		height}
}

func (c *fileChannels) Remove(checkpoint ICheckPoint, reply chan bool,
	height uint32) {
	c.remove <- heightFileMsg{fileMsg{checkpoint, reply},
		height}
}

func (c *fileChannels) ReplaceRemove(checkpoint ICheckPoint, reply chan bool,
	height uint32) {
	c.replaceRemove <- heightFileMsg{fileMsg{checkpoint, reply},
		height}
}

func (c *fileChannels) Reset(checkpoint ICheckPoint, reply chan bool) {
	c.reset <- fileMsg{checkpoint, reply}
}

func (c *fileChannels) Exit() {
	c.exit <- struct{}{}
}

func (c *fileChannels) messageLoop() {
	for {
		var msg fileMsg
		var heightMsg heightFileMsg
		select {
		case msg = <-c.save:
			if err := c.saveCheckpoint(&msg); err != nil {
				msg.checkpoint.LogError(err)
			}
		case msg = <-c.clean:
			if err := c.cleanCheckpoints(&msg, true, false); err != nil {
				msg.checkpoint.LogError(err)
			}
		case msg = <-c.reset:
			if err := c.cleanCheckpoints(&msg, true, true); err != nil {
				msg.checkpoint.LogError(err)
			}
		case heightMsg = <-c.replace:
			if err := c.replaceCheckpoints(&heightMsg); err != nil {
				heightMsg.checkpoint.LogError(err)
			}
		case heightMsg = <-c.remove:
			if err := c.removeCheckpoints(&heightMsg); err != nil {
				heightMsg.checkpoint.LogError(err)
			}
		case heightMsg = <-c.replaceRemove:
			if err := c.replaceAndRemoveCheckpoints(&heightMsg); err != nil {
				heightMsg.checkpoint.LogError(err)
			}
		case <-c.exit:
			return
		}
	}
}

func (c *fileChannels) saveCheckpoint(msg *fileMsg) (err error) {
	// Report what actually happened: a reply of "saved" must not be sent when
	// Serialize or Write failed.
	defer func() { c.replyMsg(msg, err == nil) }()

	dir := getCheckpointDirectory(c.cfg.DataPath, msg.checkpoint)
	if !utils.FileExisted(dir) {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return
		}
	}

	// Serialize before touching the destination. Opening the final path with
	// O_TRUNC first means a Serialize error destroys the checkpoint already on
	// disk and leaves a zero-length file behind.
	buf := new(bytes.Buffer)
	if err = msg.checkpoint.Serialize(buf); err != nil {
		return
	}

	filename := getFilePath(c.cfg.DataPath, msg.checkpoint)
	if err = writeFileAtomic(filename, buf.Bytes()); err != nil {
		return
	}

	if !c.cfg.EnableHistory {
		return c.cleanCheckpoints(msg, false, false)
	}
	return nil
}

// writeFileAtomic writes data to a sibling temp file, flushes it to stable storage
// and renames it over path.
//
// Writing the final path in place with no fsync leaves a short checkpoint file
// that still "exists" after a crash or power cut mid-write, and
// replaceCheckpoints only tests existence before renaming it over
// default.<ext>, which then feeds the restore path on the next start.
// rename(2) inside one directory is atomic, so a reader sees either the
// previous checkpoint or the complete new one, never a torn one. The directory
// entry itself is deliberately not fsynced: losing the rename in a power cut
// leaves the previous good file in place, which is a consistent outcome.
func writeFileAtomic(path string, data []byte) (err error) {
	tmp := path + ".tmp"
	var file *os.File
	if file, err = os.OpenFile(tmp,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err != nil {
		return
	}
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()

	if _, err = file.Write(data); err != nil {
		file.Close()
		return
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return
	}
	if err = file.Close(); err != nil {
		return
	}
	return os.Rename(tmp, path)
}

func (c *fileChannels) cleanCheckpoints(msg *fileMsg,
	needReplay, cleanAll bool) (err error) {
	if needReplay {
		defer func() { c.replyMsg(msg, err == nil) }()
	}

	dir := getCheckpointDirectory(c.cfg.DataPath, msg.checkpoint)
	reserveCurrentName := getFileName(msg.checkpoint, msg.checkpoint.GetHeight())
	reservePrevName := getFileName(msg.checkpoint,
		msg.checkpoint.GetHeight()-msg.checkpoint.SavePeriod())
	defaultName := getDefaultFileName(msg.checkpoint)

	var files []os.FileInfo
	if files, err = ioutil.ReadDir(dir); err != nil {
		return
	}

	for _, f := range files {
		if !cleanAll {
			if f.Name() == reserveCurrentName || f.Name() == reservePrevName ||
				f.Name() == defaultName {
				continue
			}
		}
		if e := os.Remove(filepath.Join(dir, f.Name())); e != nil {
			msg.checkpoint.LogError(e)
		}
	}
	return
}

func (c *fileChannels) replaceCheckpoints(msg *heightFileMsg) (err error) {
	defer func() { c.replyMsg(&msg.fileMsg, err == nil) }()

	defaultFullName := getDefaultPath(c.cfg.DataPath, msg.checkpoint)
	// source file is the previous saved checkpoint
	sourceFullName := getFilePathByHeight(c.cfg.DataPath, msg.checkpoint,
		msg.height)
	if !utils.FileExisted(sourceFullName) {
		return errors.New(fmt.Sprintf("source file %s does not exist",
			sourceFullName))
	}

	if utils.FileExisted(defaultFullName) {
		if err = os.Remove(defaultFullName); err != nil {
			return
		}
	}

	return os.Rename(sourceFullName, defaultFullName)
}

func (c *fileChannels) replaceAndRemoveCheckpoints(msg *heightFileMsg) (err error) {
	defer func() { c.replyMsg(&msg.fileMsg, err == nil) }()

	defaultFullName := getDefaultPath(c.cfg.DataPath, msg.checkpoint)
	// source file is the previous saved checkpoint
	sourceFullName := getFilePathByHeight(c.cfg.DataPath, msg.checkpoint,
		msg.height)
	if !utils.FileExisted(sourceFullName) {
		return errors.New(fmt.Sprintf("source file %s does not exist",
			sourceFullName))
	}

	dir := getCheckpointDirectory(c.cfg.DataPath, msg.checkpoint)
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(dir); err != nil {
		return
	}

	for _, f := range files {
		if strings.Contains(sourceFullName, f.Name()) {
			continue
		}

		if e := os.Remove(filepath.Join(dir, f.Name())); e != nil {
			msg.checkpoint.LogError(e)
		}
	}

	return os.Rename(sourceFullName, defaultFullName)
}

func (c *fileChannels) removeCheckpoints(msg *heightFileMsg) (err error) {
	defer func() { c.replyMsg(&msg.fileMsg, err == nil) }()

	// source file is the previous saved checkpoint
	sourceFullName := getFilePathByHeight(c.cfg.DataPath, msg.checkpoint,
		msg.height)

	if !utils.FileExisted(sourceFullName) {
		return errors.New(fmt.Sprintf("source file %s does not exist",
			sourceFullName))
	}

	return os.Remove(sourceFullName)
}

// replyMsg hands the outcome of a file operation back to the caller waiting on the
// reply channel. The outcome must reflect the operation, not be true unconditionally.
func (c *fileChannels) replyMsg(msg *fileMsg, ok bool) {
	if msg.reply != nil {
		msg.reply <- ok
	}
}

func NewFileChannels(cfg *config.Configuration) *fileChannels {
	channels := &fileChannels{
		cfg:           &cfg.CheckPointConfiguration,
		save:          make(chan fileMsg),
		clean:         make(chan fileMsg),
		reset:         make(chan fileMsg),
		replace:       make(chan heightFileMsg),
		remove:        make(chan heightFileMsg),
		replaceRemove: make(chan heightFileMsg),
		exit:          make(chan struct{}),
	}
	go channels.messageLoop()
	return channels
}
