// Package agentmetrics defines and registers Prometheus metrics for NovaNet.
// It follows the same explicit-registration pattern as routingmetrics.
package agentmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// FlowTotal counts observed network flows by source identity, destination
	// identity, and verdict.
	FlowTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet",
		Name:      "flow_total",
		Help:      "Total observed network flows.",
	}, []string{"src_identity", "dst_identity", "verdict"})

	// DropsTotal counts dropped packets by reason.
	DropsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet",
		Name:      "drops_total",
		Help:      "Total dropped packets by reason.",
	}, []string{"reason"})

	// PolicyVerdictTotal counts policy evaluation results by action.
	PolicyVerdictTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet",
		Name:      "policy_verdict_total",
		Help:      "Total policy verdict evaluations by action.",
	}, []string{"action"})

	// TCPConnectionTotal counts TCP connection events by flag type
	// (SYN, FIN, RST) for connection lifecycle observability.
	TCPConnectionTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet",
		Subsystem: "dataplane",
		Name:      "tcp_connection_total",
		Help:      "Total TCP connection events by flag type.",
	}, []string{"flag"})

	// TCPLatencySeconds observes estimated TCP round-trip latency derived from
	// flow events. Buckets span datacenter-range latencies (10µs to 100ms).
	TCPLatencySeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet",
		Subsystem: "dataplane",
		Name:      "tcp_latency_seconds",
		Help:      "Estimated TCP round-trip latency from flow events.",
		Buckets: []float64{
			0.00001,  // 10µs
			0.000025, // 25µs
			0.00005,  // 50µs
			0.0001,   // 100µs
			0.00025,  // 250µs
			0.0005,   // 500µs
			0.001,    // 1ms
			0.0025,   // 2.5ms
			0.005,    // 5ms
			0.01,     // 10ms
			0.025,    // 25ms
			0.05,     // 50ms
			0.1,      // 100ms
		},
	})
)

// Register registers all NovaNet metrics with the default Prometheus registerer.
func Register() {
	prometheus.MustRegister(
		FlowTotal,
		DropsTotal,
		PolicyVerdictTotal,
		TCPConnectionTotal,
		TCPLatencySeconds,
	)
}
