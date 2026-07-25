// Copyright (c) 2017-2020 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/elalog"
)

const (
	Red    = "1;31"
	Green  = "1;32"
	Yellow = "1;33"
	Pink   = "1;35"
	Cyan   = "1;36"
)

func Color(code, msg string) string {
	return fmt.Sprintf("\033[%sm%s\033[m", code, msg)
}

const (
	debugLog uint8 = iota
	infoLog
	warnLog
	errorLog
	fatalLog
	disableLog
)

var (
	levels = []string{
		debugLog:   Color(Green, "[DBG]"),
		infoLog:    Color(Pink, "[INF]"),
		warnLog:    Color(Yellow, "[WRN]"),
		errorLog:   Color(Red, "[ERR]"),
		fatalLog:   Color(Red, "[FAT]"),
		disableLog: "DISABLED",
	}
	Stdout = os.Stdout
)

const (
	calldepth = 2

	defaultPerLogFileSize int64 = 20 * elalog.MBSize
	defaultLogsFolderSize int64 = 5 * elalog.GBSize
)

var logger *Logger

func levelName(level uint8) string {
	if int(level) >= len(levels) {
		return fmt.Sprintf("LEVEL%d", level)
	}
	return levels[int(level)]
}

type Logger struct {
	level  uint8 // The log print level
	writer io.Writer
	logger *log.Logger
}

func NewLogger(outputPath string, level uint8, maxPerLogSizeMb,
	maxLogsSizeMb int64) *Logger {
	fileWriter := fileWriter(outputPath, maxPerLogSizeMb, maxLogsSizeMb)
	logWriter := io.MultiWriter(os.Stdout, fileWriter)

	return &Logger{
		level:  level,
		writer: logWriter,
		logger: log.New(logWriter, "", log.Ldate|log.Lmicroseconds),
	}
}

func NewFileLogger(outputPath string, level uint8, maxPerLogSizeMb,
	maxLogsSizeMb int64) *Logger {
	fileWriter := fileWriter(outputPath, maxPerLogSizeMb, maxLogsSizeMb)

	return &Logger{
		level:  level,
		writer: fileWriter,
		logger: log.New(fileWriter, "", log.Ldate|log.Lmicroseconds),
	}
}

func fileWriter(outputPath string, maxPerLogSizeMb,
	maxLogsSizeMb int64) io.Writer {
	var perLogFileSize = defaultPerLogFileSize
	var logsFolderSize = defaultLogsFolderSize

	if maxPerLogSizeMb != 0 {
		perLogFileSize = maxPerLogSizeMb * elalog.MBSize
	}
	if maxLogsSizeMb != 0 {
		logsFolderSize = maxLogsSizeMb * elalog.MBSize
	}

	return elalog.NewFileWriter(outputPath, perLogFileSize, logsFolderSize)
}

func NewDefault(path string, level uint8, maxPerLogSizeMb, maxLogsSizeMb int64) *Logger {
	logger = NewLogger(path, level, maxPerLogSizeMb, maxLogsSizeMb)
	return logger
}

// NewDiscardDefault installs a package logger that writes nowhere.
//
// The package-level helpers (Infof, Warnf, ...) dereference `logger` with no nil
// check, so a command that calls into production code which logs MUST install one
// before it does -- ScanForcedRollbackStore's Infof would otherwise panic. Every
// other constructor opens a ROTATING FILE, which is the wrong answer for a
// strictly read-only command: `ela-cli preflight` must not create a logs directory
// as a side effect of predicting a boot, and cmd/purgeresidue's
// log.NewDefault("logs/node", ...) does exactly that under whatever the current
// directory happens to be.
//
// Operator-facing output is unaffected: Operatorf and OperatorError write to
// os.Stderr directly and are already nil-logger safe.
func NewDiscardDefault(level uint8) *Logger {
	logger = &Logger{
		level:  level,
		writer: io.Discard,
		logger: log.New(io.Discard, "", 0),
	}
	return logger
}

func (l *Logger) Writer() io.Writer {
	return l.writer
}

func (l *Logger) Output(level uint8, a ...interface{}) {
	if l.level <= level {
		a = append([]interface{}{levelName(level), "GID", common.Goid() + ","}, a...)
		l.logger.Output(calldepth, fmt.Sprintln(a...))
	}
}

func (l *Logger) Outputf(level uint8, format string, v ...interface{}) {
	if l.level <= level {
		v = append([]interface{}{levelName(level), "GID", common.Goid()}, v...)
		l.logger.Output(calldepth, fmt.Sprintf("%s %s %s, "+format+"\n", v...))
	}
}

// outputfAlways writes a record whatever the configured print level is.
//
// Logger.Outputf drops anything below l.level, which is right for ordinary logging
// and wrong for the one-shot destructive operations Operatorf below serves: a node
// run at PrintLevel 4 would keep no record at all that its chain was rewound. This
// is the only path that bypasses the level, and only those operations use it.
func (l *Logger) outputfAlways(level uint8, format string, v ...interface{}) {
	v = append([]interface{}{levelName(level), "GID", common.Goid()}, v...)
	l.logger.Output(calldepth, fmt.Sprintf("%s %s %s, "+format+"\n", v...))
}

func (l *Logger) Debug(a ...interface{}) {
	if l.level > debugLog {
		return
	}

	pc, file, line, ok := runtime.Caller(calldepth)
	if !ok {
		return
	}

	fn := runtime.FuncForPC(pc)
	a = append([]interface{}{fn.Name(), filepath.Base(file) + ":" + strconv.Itoa(line)}, a...)

	l.Output(debugLog, a...)
}

func (l *Logger) Debugf(format string, a ...interface{}) {
	if l.level > debugLog {
		return
	}

	pc, file, line, ok := runtime.Caller(calldepth)
	if !ok {
		return
	}

	fn := runtime.FuncForPC(pc)
	a = append([]interface{}{fn.Name(), filepath.Base(file), line}, a...)

	l.Outputf(debugLog, "%s %s:%d "+format, a...)
}

func (l *Logger) Info(a ...interface{}) {
	l.Output(infoLog, a...)
}

func (l *Logger) Infof(format string, a ...interface{}) {
	l.Outputf(infoLog, format, a...)
}

func (l *Logger) Warn(a ...interface{}) {
	l.Output(warnLog, a...)
}

func (l *Logger) Warnf(format string, a ...interface{}) {
	l.Outputf(warnLog, format, a...)
}

func (l *Logger) Error(a ...interface{}) {
	if l.level <= errorLog {
		l.Output(errorLog, a...)
	}
}

func (l *Logger) Errorf(format string, a ...interface{}) {
	l.Outputf(errorLog, format, a...)
}

func (l *Logger) Fatal(a ...interface{}) {
	l.Output(fatalLog, a...)
}

func (l *Logger) Fatalf(format string, a ...interface{}) {
	l.Outputf(fatalLog, format, a...)
}

// Level returns the current logging level.
func (l *Logger) Level() elalog.Level {
	return elalog.Level(l.level)
}

// SetLevel changes the logging level to the passed level.
func (l *Logger) SetLevel(level elalog.Level) {
	l.level = uint8(level)
}

func Debug(a ...interface{}) {
	logger.Debug(a...)
}

func Debugf(format string, a ...interface{}) {
	logger.Debugf(format, a...)
}

func Info(a ...interface{}) {
	logger.Info(a...)
}

func Warn(a ...interface{}) {
	logger.Warn(a...)
}

func Error(a ...interface{}) {
	logger.Error(a...)
}

func Fatal(a ...interface{}) {
	logger.Fatal(a...)
}

func Infof(format string, a ...interface{}) {
	logger.Infof(format, a...)
}

func Warnf(format string, a ...interface{}) {
	logger.Warnf(format, a...)
}

func Errorf(format string, a ...interface{}) {
	logger.Errorf(format, a...)
}

func Fatalf(format string, a ...interface{}) {
	logger.Fatalf(format, a...)
}

// Operatorf reports an operator-critical event: it writes to STDERR unconditionally
// and records the line in the log unconditionally.
//
// It exists for the forced rollback, which is a one-shot, irreversible rewind of a
// live chain. Every line describing it went through log.Warnf, and MEASURED on this
// tree a full 719-block rewind on a node at PrintLevel 3 produced zero bytes of
// output and zero log lines: the loudest event in the system was invisible on exactly
// the nodes whose operators had turned the noise down. Stderr is not routed through
// the logger at all, so writing there is level-independent by construction.
//
// It is deliberately NOT a general-purpose "important" logger. Ordinary warnings and
// errors keep their level semantics; the cost of this one is that its lines appear on
// both streams when the level would have printed them anyway, which is the right
// trade only for events an operator must never miss.
func Operatorf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "%s "+format+"\n",
		append([]interface{}{levels[warnLog]}, a...)...)
	if logger != nil {
		logger.outputfAlways(warnLog, format, a...)
	}
}

// OperatorError is Operatorf for a fatal error. main.go's printErrorAndExit used
// log.Error, which the same filter drops at PrintLevel 4 and above -- so a node that
// REFUSED TO START exited 255 with nothing written anywhere, which is the worst
// possible failure mode on restart day.
func OperatorError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", levels[errorLog], err.Error())
	if logger != nil {
		logger.outputfAlways(errorLog, "%s", err.Error())
	}
}

func SetPrintLevel(level uint8) {
	logger.SetLevel(elalog.Level(level))
}
