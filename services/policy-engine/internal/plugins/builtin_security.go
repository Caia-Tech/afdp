package plugins

import (
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// NewBuiltinSecurityProvider creates a new built-in security provider
func NewBuiltinSecurityProvider(config framework.PluginConfig, logger *logging.Logger) (framework.Plugin, error) {
	return security.NewProvider(config, logger)
}