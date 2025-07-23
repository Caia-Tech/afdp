package metrics

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Collector collects metrics for the framework
type Collector struct {
	// Framework metrics
	frameworkUptime       prometheus.Gauge
	pluginCount          prometheus.Gauge
	evaluationTotal      prometheus.Counter
	evaluationDuration   prometheus.Histogram
	cacheHits            prometheus.Counter
	cacheMisses          prometheus.Counter
	
	// Plugin metrics
	pluginLoads          *prometheus.CounterVec
	pluginUnloads        *prometheus.CounterVec
	pluginHealth         *prometheus.GaugeVec
	pluginRequestCount   *prometheus.CounterVec
	pluginRequestLatency *prometheus.HistogramVec
	
	// API metrics
	httpRequestTotal     *prometheus.CounterVec
	httpRequestDuration  *prometheus.HistogramVec
	
	startTime time.Time
	mu        sync.RWMutex
}

// NewCollector creates a new metrics collector
func NewCollector(config framework.MetricsConfig) *Collector {
	namespace := config.Namespace
	if namespace == "" {
		namespace = "afdp"
	}

	collector := &Collector{
		frameworkUptime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "framework",
			Name:      "uptime_seconds",
			Help:      "Framework uptime in seconds",
		}),
		
		pluginCount: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "framework",
			Name:      "plugin_count",
			Help:      "Number of loaded plugins",
		}),
		
		evaluationTotal: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "policy",
			Name:      "evaluations_total",
			Help:      "Total number of policy evaluations",
		}),
		
		evaluationDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "policy",
			Name:      "evaluation_duration_seconds",
			Help:      "Policy evaluation duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}),
		
		cacheHits: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "cache",
			Name:      "hits_total",
			Help:      "Total number of cache hits",
		}),
		
		cacheMisses: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "cache",
			Name:      "misses_total",
			Help:      "Total number of cache misses",
		}),
		
		pluginLoads: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "plugin",
			Name:      "loads_total",
			Help:      "Total number of plugin loads",
		}, []string{"type", "name"}),
		
		pluginUnloads: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "plugin",
			Name:      "unloads_total",
			Help:      "Total number of plugin unloads",
		}, []string{"type", "name"}),
		
		pluginHealth: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "plugin",
			Name:      "health",
			Help:      "Plugin health status (1=healthy, 0=unhealthy)",
		}, []string{"type", "name"}),
		
		pluginRequestCount: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "plugin",
			Name:      "requests_total",
			Help:      "Total number of plugin requests",
		}, []string{"type", "name", "method"}),
		
		pluginRequestLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "plugin",
			Name:      "request_duration_seconds",
			Help:      "Plugin request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"type", "name", "method"}),
		
		httpRequestTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		}, []string{"method", "endpoint", "status"}),
		
		httpRequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "endpoint"}),
		
		startTime: time.Now(),
	}

	return collector
}

// Start starts the metrics collector
func (c *Collector) Start() {
	// Start uptime updater
	go c.updateUptime()
}

// Stop stops the metrics collector
func (c *Collector) Stop() {
	// Nothing to stop for now
}

// RecordEvaluation records a policy evaluation
func (c *Collector) RecordEvaluation(duration time.Duration) {
	c.evaluationTotal.Inc()
	c.evaluationDuration.Observe(duration.Seconds())
}

// RecordBatchEvaluation records a batch policy evaluation
func (c *Collector) RecordBatchEvaluation(duration time.Duration, count int) {
	c.evaluationTotal.Add(float64(count))
	c.evaluationDuration.Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit
func (c *Collector) RecordCacheHit() {
	c.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (c *Collector) RecordCacheMiss() {
	c.cacheMisses.Inc()
}

// RecordPluginLoad records a plugin load
func (c *Collector) RecordPluginLoad(pluginType, pluginName string) {
	c.pluginLoads.WithLabelValues(pluginType, pluginName).Inc()
	c.updatePluginCount(1)
}

// RecordPluginUnload records a plugin unload
func (c *Collector) RecordPluginUnload(pluginType, pluginName string) {
	c.pluginUnloads.WithLabelValues(pluginType, pluginName).Inc()
	c.updatePluginCount(-1)
}

// RecordPluginHealth records plugin health status
func (c *Collector) RecordPluginHealth(pluginType, pluginName, status string) {
	value := 0.0
	if status == "healthy" {
		value = 1.0
	}
	c.pluginHealth.WithLabelValues(pluginType, pluginName).Set(value)
}

// RecordPluginRequest records a plugin request
func (c *Collector) RecordPluginRequest(pluginType, pluginName, method string, duration time.Duration) {
	c.pluginRequestCount.WithLabelValues(pluginType, pluginName, method).Inc()
	c.pluginRequestLatency.WithLabelValues(pluginType, pluginName, method).Observe(duration.Seconds())
}

// RecordHTTPRequest records an HTTP request
func (c *Collector) RecordHTTPRequest(method, endpoint string, status int, duration time.Duration) {
	statusStr := fmt.Sprintf("%d", status)
	c.httpRequestTotal.WithLabelValues(method, endpoint, statusStr).Inc()
	c.httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// updateUptime updates the framework uptime metric
func (c *Collector) updateUptime() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		uptime := time.Since(c.startTime).Seconds()
		c.frameworkUptime.Set(uptime)
	}
}

// updatePluginCount updates the plugin count
func (c *Collector) updatePluginCount(delta int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Get current value and update
	// In a real implementation, would track actual count
	c.pluginCount.Add(float64(delta))
}