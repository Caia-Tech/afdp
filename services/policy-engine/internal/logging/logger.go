package logging

import (
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog for structured logging
type Logger struct {
	*slog.Logger
}

// NewLogger creates a new logger
func NewLogger(level string) *Logger {
	// Parse log level
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Create handler
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	
	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{Logger: logger}
}