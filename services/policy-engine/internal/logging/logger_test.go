package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger("debug")
	assert.NotNil(t, logger)
}

func TestLoggerLevels(t *testing.T) {
	testCases := []string{"debug", "info", "warn", "error"}
	
	for _, level := range testCases {
		logger := NewLogger(level)
		assert.NotNil(t, logger, "Logger should not be nil for level: %s", level)
	}
}