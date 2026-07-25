// Copyright (c) 2026 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package main -- OPS2 item 1, the REFUSAL half.
//
// Every forced-rollback refusal in this binary leaves through printErrorAndExit, and
// printErrorAndExit used log.Error, which common/log drops whenever the configured
// print level is above errorLog.
//
// MEASURED PRISTINE BEHAVIOUR (canonical tree 8e78ce3, this test): at PrintLevel 4 a
// node that REFUSED TO START exited 255 with an empty stderr. Nothing on the console,
// nothing in the log file, exit status 255 and no explanation -- on restart day, on a
// chain holding real value.
//
// This runs the real function in a real subprocess so the assertion is about file
// descriptor 2 and a real process exit status, not about a swapped-out writer.
package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA/common/log"
)

// ops2FatalChildEnv makes the test process act as the node under test instead of as
// the driver.
const ops2FatalChildEnv = "OPS2_FATAL_CHILD"

// ops2SilentLevel drops errors as well as warnings: common/log's fatalLog, i.e.
// PrintLevel 4. It is an ordinary value for an operator who wants a quiet node.
const ops2SilentLevel = 4

// ops2FatalSentinel is the text of the fatal error the child refuses with.
const ops2FatalSentinel = "OPS2-FATAL-forced rollback refused to start this node"

// ops2WarnSentinel is emitted through plain log.Warnf by the child. Its ABSENCE from
// the child's output proves the level really was quiet, so the assertion below is
// about level-independence rather than about a level that never filtered anything.
const ops2WarnSentinel = "OPS2-CONTROL-A-PLAIN-WARNING"

// TestOps2PrintErrorAndExitIsAudibleAtEveryLevel is the item-1 proof for main.go.
//
// FAILS ON PRISTINE: the child's stderr is empty.
func TestOps2PrintErrorAndExitIsAudibleAtEveryLevel(t *testing.T) {
	if os.Getenv(ops2FatalChildEnv) == "1" {
		log.NewDefault(filepath.Join(t.TempDir(), "logs"), ops2SilentLevel, 0, 0)
		log.Warnf(ops2WarnSentinel)
		printErrorAndExit(errors.New(ops2FatalSentinel))
		return
	}

	cmd := exec.Command(os.Args[0],
		"-test.run=^TestOps2PrintErrorAndExitIsAudibleAtEveryLevel$")
	cmd.Env = append(os.Environ(), ops2FatalChildEnv+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("the child did not exit with a failure status: err=%v\nstdout: %s",
			err, stdout.String())
	}
	if code := exitErr.ExitCode(); code != 255 {
		t.Errorf("exit status %d, want 255 (os.Exit(-1))", code)
	}

	if strings.Contains(stdout.String(), ops2WarnSentinel) ||
		strings.Contains(stderr.String(), ops2WarnSentinel) {
		t.Fatalf("control: a plain log.Warnf survived at this level, so the child was "+
			"not a quieted node at all\nstdout: %s\nstderr: %s",
			stdout.String(), stderr.String())
	}

	if !strings.Contains(stderr.String(), ops2FatalSentinel) {
		t.Errorf("a node refused to start and wrote NOTHING to stderr.\n"+
			"stderr was: %q\nstdout was: %q", stderr.String(), stdout.String())
	}
}

// TestOps2MainForcedRollbackLinesUseTheOperatorChannel is a STRUCTURAL assertion over
// main.go, and it is labelled as one.
//
// main.go emits three lines of its own on the forced-rollback path: the ARMED
// announcement, the configured-vs-actual trigger diagnostic and the post-rebuild
// baseline confirmation. Reaching them behaviourally means running startNode, which
// opens stores, binds ports and blocks; the OPS2 suite instead replays that sequence
// against the production blockchain entry points, and so cannot see which channel
// main.go itself used. This closes that gap the only cheap way there is: by reading
// the source.
//
// What it can prove: the call was not reverted to the level-filtered channel. What it
// cannot prove: that the call is reached. The behavioural half of item 1 -- that the
// channel works at any print level, and that printErrorAndExit uses it -- is proven
// above and in common/log.
func TestOps2MainForcedRollbackLinesUseTheOperatorChannel(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)

	for _, want := range []string{
		`log.Operatorf("FORCED ROLLBACK: ARMED`,
		`log.Operatorf("forced rollback trigger check`,
		`log.Operatorf("forced rollback: post-rebuild baseline OK`,
		"log.OperatorError(err)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("main.go no longer emits %q through the operator channel, so this "+
				"line is invisible on a node at PrintLevel 3 or above", want)
		}
	}
	// Nothing on this path may go back to the level-filtered channel.
	for _, forbidden := range []string{
		`log.Warnf("FORCED ROLLBACK`,
		`log.Warnf("forced rollback`,
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("main.go emits %q through the level-filtered channel", forbidden)
		}
	}
}
