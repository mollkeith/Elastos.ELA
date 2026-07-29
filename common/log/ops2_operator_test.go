// Copyright (c) 2026 The Elastos DAO
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

// Package log -- OPS2 item 1, the mechanism.
//
// Operatorf and OperatorError make two promises, and each needs its own assertion or
// half the mechanism can be removed without anything failing:
//
//  1. the line reaches STDERR whatever the configured print level is, and
//  2. the line is RECORDED, also whatever the level is, so a node that rewound its
//     chain has that fact in its log file afterwards.
//
// The tests around them (test/unit/ops2_*.go, the root package's ops2_fatal_test.go)
// prove the production call sites use them. These prove the helpers themselves.
package log

import (
	"bytes"
	"io"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"testing"
)

// ops2Silent is common/log's disableLog: nothing at all survives the level filter.
const ops2Silent = disableLog

// ops2Capture installs a logger at `level` whose sink is a buffer, swaps os.Stderr for
// a pipe, runs fn, and returns (log sink, stderr).
func ops2Capture(t *testing.T, level uint8, fn func()) (string, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	var errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); io.Copy(&errBuf, r) }()

	realErr := os.Stderr
	saved := logger
	sink := new(bytes.Buffer)
	os.Stderr = w
	logger = newTestLogger(sink, level)

	func() {
		defer func() {
			os.Stderr = realErr
			w.Close()
			logger = saved
		}()
		fn()
	}()
	wg.Wait()
	return sink.String(), errBuf.String()
}

// TestOps2OperatorfReachesStderrAtEveryLevel is the level-independence proof.
func TestOps2OperatorfReachesStderrAtEveryLevel(t *testing.T) {
	for level := uint8(0); level <= ops2Silent; level++ {
		sink, stderr := ops2Capture(t, level, func() {
			Warnf("OPS2-PLAIN-WARNING")
			Operatorf("OPS2-OPERATOR-LINE %d", 7)
		})
		if !strings.Contains(stderr, "OPS2-OPERATOR-LINE 7") {
			t.Errorf("level %d: Operatorf did not reach stderr; stderr=%q", level, stderr)
		}
		if !strings.Contains(sink, "OPS2-OPERATOR-LINE 7") {
			t.Errorf("level %d: Operatorf left no record in the log; sink=%q", level, sink)
		}
		// The control: at levels above warnLog a plain warning must be gone, or this
		// test is not measuring level-independence at all.
		if level > warnLog && strings.Contains(sink, "OPS2-PLAIN-WARNING") {
			t.Errorf("level %d: a plain warning survived, so the level is not quiet",
				level)
		}
	}
}

// TestOps2OperatorErrorReachesStderrAtEveryLevel is the same proof for the fatal path
// main.go's printErrorAndExit uses.
func TestOps2OperatorErrorReachesStderrAtEveryLevel(t *testing.T) {
	for level := uint8(0); level <= ops2Silent; level++ {
		sink, stderr := ops2Capture(t, level, func() {
			OperatorError(&ops2Err{"OPS2-OPERATOR-ERROR"})
		})
		if !strings.Contains(stderr, "OPS2-OPERATOR-ERROR") {
			t.Errorf("level %d: OperatorError did not reach stderr; stderr=%q",
				level, stderr)
		}
		if !strings.Contains(sink, "OPS2-OPERATOR-ERROR") {
			t.Errorf("level %d: OperatorError left no record in the log; sink=%q",
				level, sink)
		}
	}
}

// TestOps2OperatorErrorIgnoresNil keeps the fatal path from printing a bare "<nil>".
func TestOps2OperatorErrorIgnoresNil(t *testing.T) {
	sink, stderr := ops2Capture(t, 0, func() { OperatorError(nil) })
	if stderr != "" || sink != "" {
		t.Errorf("OperatorError(nil) wrote something: stderr=%q sink=%q", stderr, sink)
	}
}

// TestOps2OperatorSurvivesAnUninitialisedLogger covers the window before setupLog
// runs. common/log's package logger is nil there and every other helper panics; the
// operator channel must still reach the console instead of taking the node down.
func TestOps2OperatorSurvivesAnUninitialisedLogger(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	var errBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); io.Copy(&errBuf, r) }()

	realErr := os.Stderr
	saved := logger
	os.Stderr = w
	logger = nil
	func() {
		defer func() {
			os.Stderr = realErr
			w.Close()
			logger = saved
			if p := recover(); p != nil {
				t.Errorf("the operator channel panicked with no logger: %v", p)
			}
		}()
		Operatorf("OPS2-NO-LOGGER")
		OperatorError(&ops2Err{"OPS2-NO-LOGGER-ERR"})
	}()
	wg.Wait()

	for _, want := range []string{"OPS2-NO-LOGGER", "OPS2-NO-LOGGER-ERR"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("missing %q on stderr; got %q", want, errBuf.String())
		}
	}
}

// ops2Err is a minimal error so this file needs no extra import.
type ops2Err struct{ s string }

func (e *ops2Err) Error() string { return e.s }

// newTestLogger builds a Logger writing to w. It mirrors NewLogger without the
// rotating file writer, so an assertion reads the record directly instead of racing a
// file sink.
func newTestLogger(w io.Writer, level uint8) *Logger {
	return &Logger{
		level:  level,
		writer: w,
		logger: stdlog.New(w, "", stdlog.Ldate|stdlog.Lmicroseconds),
	}
}
