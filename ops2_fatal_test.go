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
