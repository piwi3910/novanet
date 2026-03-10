package agent

import (
	"github.com/azrtydxb/novanet/internal/agentmetrics"
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics for the agent.
var (
	MetricEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "endpoints_total",
		Help:      "Number of pod endpoints managed by the agent.",
	})
	MetricPolicies = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "policies_total",
		Help:      "Number of compiled policy rules.",
	})
	MetricTunnels = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "tunnels_total",
		Help:      "Number of overlay tunnels.",
	})
	MetricIdentities = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "identities_total",
		Help:      "Number of distinct identities.",
	})
	MetricCNIAddLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet",
		Subsystem: "cni",
		Name:      "add_duration_seconds",
		Help:      "Latency of CNI ADD operations.",
		Buckets:   prometheus.DefBuckets,
	})
	MetricCNIDelLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet",
		Subsystem: "cni",
		Name:      "del_duration_seconds",
		Help:      "Latency of CNI DEL operations.",
		Buckets:   prometheus.DefBuckets,
	})
	MetricRemoteEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "remote_endpoints_total",
		Help:      "Number of remote pod endpoints synced for cross-node identity resolution.",
	})
)

// RegisterMetrics registers all Prometheus metrics for the agent.
func RegisterMetrics() {
	prometheus.MustRegister(
		MetricEndpoints,
		MetricPolicies,
		MetricTunnels,
		MetricIdentities,
		MetricCNIAddLatency,
		MetricCNIDelLatency,
		MetricRemoteEndpoints,
	)
	// Register shared dataplane metrics (flow counters, TCP latency histogram, etc.).
	agentmetrics.Register()
}
