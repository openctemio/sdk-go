package core

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Logger is the interface for logging in the SDK.
// Implement this interface to use a custom logger (e.g., logrus, zap).
type Logger interface {
	// Debug logs a debug message
	Debug(format string, args ...interface{})

	// Info logs an info message
	Info(format string, args ...interface{})

	// Warn logs a warning message
	Warn(format string, args ...interface{})

	// Error logs an error message
	Error(format string, args ...interface{})
}

// LogLevel represents the logging level.
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelSilent
)

// DefaultLogger is the default logger implementation using standard library.
type DefaultLogger struct {
	level  LogLevel
	prefix string
	logger *log.Logger
}

// NewDefaultLogger creates a new default logger.
func NewDefaultLogger(prefix string, level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level:  level,
		prefix: prefix,
		logger: log.New(os.Stderr, "", log.LstdFlags),
	}
}

// SetOutput sets the output writer.
func (l *DefaultLogger) SetOutput(w io.Writer) {
	l.logger.SetOutput(w)
}

// SetLevel sets the log level.
func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message.
func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.log("DEBUG", format, args...)
	}
}

// Info logs an info message.
func (l *DefaultLogger) Info(format string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.log("INFO", format, args...)
	}
}

// Warn logs a warning message.
func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	if l.level <= LogLevelWarn {
		l.log("WARN", format, args...)
	}
}

// Error logs an error message.
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.log("ERROR", format, args...)
	}
}

func (l *DefaultLogger) log(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if l.prefix != "" {
		l.logger.Printf("[%s] [%s] %s", l.prefix, level, msg)
	} else {
		l.logger.Printf("[%s] %s", level, msg)
	}
}

// NopLogger is a no-op logger that discards all messages.
type NopLogger struct{}

func (l *NopLogger) Debug(format string, args ...interface{}) {}
func (l *NopLogger) Info(format string, args ...interface{})  {}
func (l *NopLogger) Warn(format string, args ...interface{})  {}
func (l *NopLogger) Error(format string, args ...interface{}) {}

// PrintfLogger is a simple logger that uses fmt.Printf.
// This is what the verbose mode was using before.
type PrintfLogger struct {
	prefix string
}

// NewPrintfLogger creates a new printf logger.
func NewPrintfLogger(prefix string) *PrintfLogger {
	return &PrintfLogger{prefix: prefix}
}

func (l *PrintfLogger) Debug(format string, args ...interface{}) {
	l.print(format, args...)
}

func (l *PrintfLogger) Info(format string, args ...interface{}) {
	l.print(format, args...)
}

func (l *PrintfLogger) Warn(format string, args ...interface{}) {
	l.print(format, args...)
}

func (l *PrintfLogger) Error(format string, args ...interface{}) {
	l.print(format, args...)
}

func (l *PrintfLogger) print(format string, args ...interface{}) {
	if l.prefix != "" {
		fmt.Printf("[%s] %s\n", l.prefix, fmt.Sprintf(format, args...))
	} else {
		fmt.Printf("%s\n", fmt.Sprintf(format, args...))
	}
}

// Global default logger - can be replaced by users
var defaultLogger Logger = &NopLogger{}

// SetDefaultLogger sets the global default logger.
func SetDefaultLogger(logger Logger) {
	if logger == nil {
		logger = &NopLogger{}
	}
	defaultLogger = logger
}

// GetDefaultLogger returns the global default logger.
func GetDefaultLogger() Logger {
	return defaultLogger
}

// LoggerFromVerbose creates a logger based on verbose flag.
// If verbose is true, returns a PrintfLogger, otherwise returns NopLogger.
func LoggerFromVerbose(prefix string, verbose bool) Logger {
	if verbose {
		return NewPrintfLogger(prefix)
	}
	return &NopLogger{}
}

// Ensure implementations satisfy the interface
var (
	_ Logger = (*DefaultLogger)(nil)
	_ Logger = (*NopLogger)(nil)
	_ Logger = (*PrintfLogger)(nil)
)
