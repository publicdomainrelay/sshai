package common

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
)

// LogLevel represents a logging level.
type LogLevel int32

const (
	LogLevelTrace LogLevel = iota
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

var globalLogLevel atomic.Int32

func init() {
	globalLogLevel.Store(int32(LogLevelInfo))
}

// SetLogLevel sets the global log level from a string (trace/debug/info/warn/error).
func SetLogLevel(level string) {
	switch strings.ToLower(level) {
	case "trace":
		globalLogLevel.Store(int32(LogLevelTrace))
	case "debug":
		globalLogLevel.Store(int32(LogLevelDebug))
	case "info":
		globalLogLevel.Store(int32(LogLevelInfo))
	case "warn", "warning":
		globalLogLevel.Store(int32(LogLevelWarn))
	case "error":
		globalLogLevel.Store(int32(LogLevelError))
	default:
		log.Printf("unknown log level %q, defaulting to info", level)
		globalLogLevel.Store(int32(LogLevelInfo))
	}
}

// GetLogLevel returns the current global log level.
func GetLogLevel() LogLevel {
	return LogLevel(globalLogLevel.Load())
}

func logf(level LogLevel, prefix, format string, args ...interface{}) {
	if LogLevel(globalLogLevel.Load()) > level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] %s\n", prefix, msg)
}

// Trace logs at trace level (very verbose — every line of action output, every expression evaluation).
func Trace(format string, args ...interface{}) { logf(LogLevelTrace, "TRACE", format, args...) }

// Debug logs at debug level (step setup, script content, action resolution).
func Debug(format string, args ...interface{}) { logf(LogLevelDebug, "DEBUG", format, args...) }

// Info logs at info level (workflow/job/step lifecycle events).
func Info(format string, args ...interface{}) { logf(LogLevelInfo, "INFO", format, args...) }

// Warn logs at warn level.
func Warn(format string, args ...interface{}) { logf(LogLevelWarn, "WARN", format, args...) }

// LogError logs at error level.
func LogError(format string, args ...interface{}) { logf(LogLevelError, "ERROR", format, args...) }
