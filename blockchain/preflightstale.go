// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package blockchain

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// THE STALE-TARBALL TRAP, and an honest answer about it.
//
// Operators fast-sync by unpacking https://node-data.elastos.io/ela/ela-data-latest.tgz
// over <node dir>/data. A tarball built from a PRE-FORK chain puts the removed
// chain back on a node that had already been repaired, and it looks like a
// successful repair.
//
// CAN THE STORE TELL? NO. Measured, not asserted: test/unit/ops2_onceonly_test.go
// builds cell A (a node that has simply not started yet) and cell E (a node whose
// data directory was replaced with a pre-rollback copy AFTER the rollback ran) and
// the two are the same store -- cell E's setup is literally "rebuild the identical
// chain over the same dir". Both are armed, both rewind, both print the same line.
// There is no byte in the block store that differs, because the rollback's only
// durable record IS the absence of the block, and restoring the data directory
// restores the block. Anything claiming to distinguish them from the store alone
// would be inventing a signal.
//
// The good news, and it must not be overstated either: the prediction is the same
// in both cases and it is CORRECT in both. Such a node rewinds to the target and
// then syncs forward on the recovered chain. The cost is wasted time and a false
// belief that something was repaired -- not a node on the wrong chain, PROVIDED the
// binary it starts under is this one. A pre-fork tarball unpacked under an OLD
// binary is the case with no defence here at all, and this tool cannot see the
// binary the operator will actually launch. It reports its own version so the
// operator can compare.
//
// So what CAN be measured is reported, labelled for exactly what it is:
//
//   - the node's own logs, which live in <node dir>/logs and are therefore a
//     SIBLING of the data/ directory a tarball is unpacked over. If they record a
//     completed rewind and the store now holds the removed block again, this data
//     directory was replaced after that rewind. That is real evidence and it is
//     one-directional: its presence is strong, its absence proves nothing (logs
//     rotate, and a rebuilt node has none).
//   - the newest write time in the block store, so the operator can compare it
//     with the coordinated restart. Also one-directional: tar preserves mtimes, so
//     a stale tarball unpacks with stale times, but a live node stopped before the
//     restart looks the same.

// rewindEvidenceLines are the operator lines a completed forced rollback writes.
// They go through log.Operatorf, which writes an unconditional record whatever the
// print level is, so a node that ran one has them unless the file has rotated away.
var rewindEvidenceLines = []string{
	"FORCED ROLLBACK: block store rewound to",
	"FORCED ROLLBACK: ALREADY APPLIED",
	"FORCED ROLLBACK: nothing to roll back on this node",
}

// preflightLogScanFiles bounds how many log files are read, newest first.
const preflightLogScanFiles = 12

// preflightLogScanBytes bounds how much of each file is read.
const preflightLogScanBytes = 32 * 1024 * 1024

// addStaleDataFinding appends the stale-data section of the report.
func (r *PreflightReport) addStaleDataFinding(chain *BlockChain, opts PreflightOptions) {
	if r.Outcome != PreflightWillRewind {
		return
	}
	evidence, checked := scanNodeLogsForCompletedRewind(opts.NodeDir)

	r.Warnings = append(r.Warnings, "THE STORE CANNOT TELL YOU WHETHER THIS IS A "+
		"NODE THAT HAS SIMPLY NOT STARTED YET, OR A NODE WHOSE DATA DIRECTORY WAS "+
		"REPLACED WITH PRE-FORK DATA AFTER THE RESTART. Both hold the removed block, "+
		"both rewind, and the two stores are identical. If you unpacked "+
		"ela-data-latest.tgz (or restored a backup) over this data directory, you "+
		"did not repair anything: you put the abandoned chain back, and this rewind "+
		"is undoing that, not fixing a node.")

	switch {
	case evidence != "":
		r.Warnings = append(r.Warnings, fmt.Sprintf("EVIDENCE THAT THIS DATA "+
			"DIRECTORY WAS REPLACED: this node's own logs (a sibling of data/, so a "+
			"tarball unpacked over data/ leaves them behind) already record a "+
			"completed forced rollback -- %q -- yet the store holds the removed "+
			"block again. Something put it back.", evidence))
	case checked:
		r.Notes = append(r.Notes, "This node's logs carry no record of a completed "+
			"forced rollback. That is what a node which has never started under "+
			"this binary looks like -- and also what a node whose logs have rotated "+
			"away looks like, so it is not proof of anything.")
	default:
		r.Notes = append(r.Notes, "No node log directory was found next to the data "+
			"directory, so the one piece of local evidence about whether this node "+
			"already rolled back could not be read.")
	}

	r.Warnings = append(r.Warnings, fmt.Sprintf("CHECK YOURSELF, because this tool "+
		"cannot: (1) the newest write in this block store is %s -- if that is BEFORE "+
		"the coordinated restart and this node was supposed to be running, the data "+
		"is not this node's own; (2) confirm the binary you are about to start is "+
		"%s, since pre-fork data under a pre-fork binary is the one case nothing "+
		"here defends against.",
		r.Store.NewestWrite.Format("2006-01-02 15:04:05 MST"), r.Version))
}

// scanNodeLogsForCompletedRewind looks for a completed-rewind line in the node's
// own logs. It returns the line found (or "") and whether any log file was read.
//
// It is bounded on purpose: a pre-flight must not turn into a full-text search of
// an unbounded log directory on restart day.
func scanNodeLogsForCompletedRewind(nodeDir string) (string, bool) {
	if nodeDir == "" {
		return "", false
	}
	logDir := filepath.Join(nodeDir, "logs", "node")
	entries, err := os.ReadDir(logDir)
	if err != nil || len(entries) == 0 {
		return "", false
	}
	type namedTime struct {
		path string
		mod  int64
	}
	var files []namedTime
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		files = append(files, namedTime{filepath.Join(logDir, e.Name()),
			info.ModTime().UnixNano()})
	}
	if len(files) == 0 {
		return "", false
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod > files[j].mod })
	if len(files) > preflightLogScanFiles {
		files = files[:preflightLogScanFiles]
	}

	read := false
	for _, f := range files {
		fh, oerr := os.Open(f.path)
		if oerr != nil {
			continue
		}
		read = true
		var n int64
		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			n += int64(len(line)) + 1
			if n > preflightLogScanBytes {
				break
			}
			for _, want := range rewindEvidenceLines {
				if strings.Contains(line, want) {
					fh.Close()
					return strings.TrimSpace(line), true
				}
			}
		}
		fh.Close()
	}
	return "", read
}
