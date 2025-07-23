package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestMetricsCollector(t *testing.T) {
	t.Run("NewCollector", func(t *testing.T) {
		config := framework.MetricsConfig{
			Enabled:   true,
			Port:      9090,
			Path:      "/metrics",
			Namespace: "test",
		}
		
		collector := NewCollector(config)
		assert.NotNil(t, collector)
	})

	t.Run("DisabledCollector", func(t *testing.T) {
		config := framework.MetricsConfig{
			Enabled: false,
		}
		
		collector := NewCollector(config)
		assert.NotNil(t, collector)
	})
}