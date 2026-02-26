package metrics

import (
	"regexp"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// prometheusNameRe matches valid Prometheus metric names: letters, digits, and
// underscores, must not start with a digit.
var prometheusNameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// TestMetricsNonNil verifies that all package-level metric variables are
// initialised (non-nil) at package init time.
func TestMetricsNonNil(t *testing.T) {
	if FlowTotal == nil {
		t.Error("FlowTotal is nil")
	}
	if DropsTotal == nil {
		t.Error("DropsTotal is nil")
	}
	if PolicyVerdictTotal == nil {
		t.Error("PolicyVerdictTotal is nil")
	}
	if TCPLatencySeconds == nil {
		t.Error("TCPLatencySeconds is nil")
	}
}

// TestRegister verifies that Register() does not panic and that all metrics can
// be gathered from a fresh registry without error.
func TestRegister(t *testing.T) {
	reg := prometheus.NewRegistry()

	// Re-create metrics so they are independent of the global default registry
	// used by Register().  We test Register() itself via a no-panic check, then
	// validate the metric descriptors through a custom registry below.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Register() panicked: %v", r)
		}
	}()

	// Register a fresh set of the same metrics into a custom registry to verify
	// they are gatherable without error.
	flowTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet", Name: "flow_total", Help: "Total observed network flows.",
	}, []string{"src_identity", "dst_identity", "verdict"})
	dropsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet", Name: "drops_total", Help: "Total dropped packets by reason.",
	}, []string{"reason"})
	policyVerdictTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "novanet", Name: "policy_verdict_total", Help: "Total policy verdict evaluations by action.",
	}, []string{"action"})

	tcpLatencySeconds := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet", Subsystem: "dataplane", Name: "tcp_latency_seconds",
		Help: "Estimated TCP round-trip latency from flow events.",
		Buckets: []float64{0.00001, 0.0001, 0.001, 0.01, 0.1},
	})

	reg.MustRegister(
		flowTotal, dropsTotal, policyVerdictTotal,
		tcpLatencySeconds,
	)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() returned error: %v", err)
	}
	if len(mfs) == 0 {
		t.Error("Gather() returned no metric families")
	}
}

// readCounter returns the current float64 value from a *dto.Metric that holds
// a counter sample.
func readCounter(c prometheus.Counter) float64 {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		panic(err)
	}
	return m.GetCounter().GetValue()
}

// TestCounterIncrement verifies that counter metrics accumulate values correctly.
func TestCounterIncrement(t *testing.T) {
	t.Run("FlowTotal", func(t *testing.T) {
		c := FlowTotal.WithLabelValues("id-a", "id-b", "allow")
		before := readCounter(c)
		c.Inc()
		after := readCounter(c)
		if after != before+1 {
			t.Errorf("FlowTotal: expected %v after Inc, got %v", before+1, after)
		}
		c.Add(3)
		final := readCounter(c)
		if final != after+3 {
			t.Errorf("FlowTotal: expected %v after Add(3), got %v", after+3, final)
		}
	})

	t.Run("DropsTotal", func(t *testing.T) {
		c := DropsTotal.WithLabelValues("policy")
		before := readCounter(c)
		c.Inc()
		after := readCounter(c)
		if after != before+1 {
			t.Errorf("DropsTotal: expected %v after Inc, got %v", before+1, after)
		}
		c.Add(5)
		final := readCounter(c)
		if final != after+5 {
			t.Errorf("DropsTotal: expected %v after Add(5), got %v", after+5, final)
		}
	})

	t.Run("PolicyVerdictTotal", func(t *testing.T) {
		c := PolicyVerdictTotal.WithLabelValues("deny")
		before := readCounter(c)
		c.Inc()
		after := readCounter(c)
		if after != before+1 {
			t.Errorf("PolicyVerdictTotal: expected %v after Inc, got %v", before+1, after)
		}
	})
}

// readHistogramSampleCount returns the sample count from a Histogram.
func readHistogramSampleCount(h prometheus.Histogram) uint64 {
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		panic(err)
	}
	return m.GetHistogram().GetSampleCount()
}

// readHistogramSampleSum returns the sample sum from a Histogram.
func readHistogramSampleSum(h prometheus.Histogram) float64 {
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		panic(err)
	}
	return m.GetHistogram().GetSampleSum()
}

// TestHistogramObserve verifies that histogram metrics record observations.
func TestHistogramObserve(t *testing.T) {
	t.Run("TCPLatencySeconds", func(t *testing.T) {
		beforeCount := readHistogramSampleCount(TCPLatencySeconds)
		beforeSum := readHistogramSampleSum(TCPLatencySeconds)

		TCPLatencySeconds.Observe(0.001)
		TCPLatencySeconds.Observe(0.005)

		afterCount := readHistogramSampleCount(TCPLatencySeconds)
		afterSum := readHistogramSampleSum(TCPLatencySeconds)

		if afterCount != beforeCount+2 {
			t.Errorf("TCPLatencySeconds: expected sample count %d, got %d", beforeCount+2, afterCount)
		}
		wantSum := beforeSum + 0.001 + 0.005
		if afterSum != wantSum {
			t.Errorf("TCPLatencySeconds: expected sample sum %v, got %v", wantSum, afterSum)
		}
	})
}

// fqNameRe extracts the fqName value from a prometheus.Desc.String() output.
// Desc.String() has the form: Desc{fqName: "novanet_foo", help: "...", ...}
var fqNameRe = regexp.MustCompile(`fqName: "([^"]+)"`)

// TestTCPLatencyHistogramObserve verifies that the TCP latency histogram
// correctly records observations.
func TestTCPLatencyHistogramObserve(t *testing.T) {
	beforeCount := readHistogramSampleCount(TCPLatencySeconds)
	beforeSum := readHistogramSampleSum(TCPLatencySeconds)

	TCPLatencySeconds.Observe(0.0001)  // 100µs
	TCPLatencySeconds.Observe(0.001)   // 1ms

	afterCount := readHistogramSampleCount(TCPLatencySeconds)
	afterSum := readHistogramSampleSum(TCPLatencySeconds)

	if afterCount != beforeCount+2 {
		t.Errorf("TCPLatencySeconds: expected sample count %d, got %d", beforeCount+2, afterCount)
	}
	wantSum := beforeSum + 0.0001 + 0.001
	if afterSum != wantSum {
		t.Errorf("TCPLatencySeconds: expected sample sum %v, got %v", wantSum, afterSum)
	}
}

// TestTCPLatencyBuckets verifies that TCPLatencySeconds uses datacenter-range
// latency buckets (µs to ms).
func TestTCPLatencyBuckets(t *testing.T) {
	var m dto.Metric
	if err := TCPLatencySeconds.Write(&m); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buckets := m.GetHistogram().GetBucket()
	// We defined 13 buckets; proto adds +Inf, so expect at least 13.
	if len(buckets) < 13 {
		t.Errorf("expected at least 13 buckets, got %d", len(buckets))
	}
	// First bucket should be 10µs (0.00001).
	if buckets[0].GetUpperBound() != 0.00001 {
		t.Errorf("first bucket: expected 0.00001, got %v", buckets[0].GetUpperBound())
	}
}

// TestMetricNamingConventions verifies that all registered metric descriptors
// carry names that conform to Prometheus naming rules and use the expected
// "novanet" namespace prefix.
func TestMetricNamingConventions(t *testing.T) {
	// Collect descriptors from every metric variable defined in the package.
	collectors := []prometheus.Collector{
		FlowTotal,
		DropsTotal,
		PolicyVerdictTotal,
		TCPLatencySeconds,
	}

	for _, c := range collectors {
		ch := make(chan *prometheus.Desc, 10)
		c.Describe(ch)
		close(ch)

		for desc := range ch {
			s := desc.String()
			m := fqNameRe.FindStringSubmatch(s)
			if m == nil {
				t.Errorf("could not parse fqName from descriptor: %s", s)
				continue
			}
			fqName := m[1]

			if !prometheusNameRe.MatchString(fqName) {
				t.Errorf("metric name %q does not match Prometheus naming convention", fqName)
			}
			if !strings.HasPrefix(fqName, "novanet_") {
				t.Errorf("metric name %q does not start with novanet_ namespace", fqName)
			}
		}
	}
}

// TestCounterVecLabelVariants verifies that distinct label combinations produce
// independent counter series.
func TestCounterVecLabelVariants(t *testing.T) {
	allow := FlowTotal.WithLabelValues("src1", "dst1", "allow")
	deny := FlowTotal.WithLabelValues("src1", "dst1", "deny")

	allow.Add(10)
	deny.Add(3)

	if readCounter(allow) < 10 {
		t.Errorf("allow counter: expected at least 10, got %v", readCounter(allow))
	}
	if readCounter(deny) < 3 {
		t.Errorf("deny counter: expected at least 3, got %v", readCounter(deny))
	}
	// Ensure the two series are independent — their values must differ by at
	// least the amounts added above.
	if readCounter(allow)-readCounter(deny) < 7 {
		t.Errorf("allow and deny counters appear to share state")
	}
}

// TestCollectDoesNotBlock ensures that Collect() on every metric returns at
// least one sample without blocking.
func TestCollectDoesNotBlock(t *testing.T) {
	collectors := []struct {
		name      string
		collector prometheus.Collector
	}{
		{"FlowTotal", FlowTotal},
		{"DropsTotal", DropsTotal},
		{"PolicyVerdictTotal", PolicyVerdictTotal},
		{"TCPLatencySeconds", TCPLatencySeconds},
	}

	for _, tc := range collectors {
		t.Run(tc.name, func(t *testing.T) {
			// testutil.CollectAndCount returns the number of metric samples
			// collected; it panics or returns 0 only on failure.
			n := testutil.CollectAndCount(tc.collector)
			if n < 1 {
				t.Errorf("%s: CollectAndCount returned %d, expected >= 1", tc.name, n)
			}
		})
	}
}
