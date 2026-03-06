package service

import "testing"

func TestMaglevTableSize(t *testing.T) {
	backends := []string{"10.42.0.1:8080", "10.42.0.2:8080", "10.42.0.3:8080"}
	table := GenerateMaglevTable(backends, 65537)
	if len(table) != 65537 {
		t.Fatalf("expected 65537 entries, got %d", len(table))
	}
}

func TestMaglevDistribution(t *testing.T) {
	backends := []string{"10.42.0.1:8080", "10.42.0.2:8080", "10.42.0.3:8080"}
	table := GenerateMaglevTable(backends, 65537)

	counts := make(map[uint32]int)
	for _, idx := range table {
		counts[idx]++
	}

	expected := 65537 / 3
	for idx, count := range counts {
		ratio := float64(count) / float64(expected)
		if ratio < 0.90 || ratio > 1.10 {
			t.Errorf("backend %d: got %d entries (expected ~%d, ratio %.2f)", idx, count, expected, ratio)
		}
	}
}

func TestMaglevConsistency(t *testing.T) {
	backends3 := []string{"a:80", "b:80", "c:80"}
	backends4 := []string{"a:80", "b:80", "c:80", "d:80"}

	table3 := GenerateMaglevTable(backends3, 65537)
	table4 := GenerateMaglevTable(backends4, 65537)

	stable := 0
	for i := range table3 {
		if table3[i] < 3 && table3[i] == table4[i] {
			stable++
		}
	}
	ratio := float64(stable) / float64(65537)
	if ratio < 0.60 {
		t.Errorf("only %.1f%% entries stable after adding backend", ratio*100)
	}
}

func TestMaglevEmptyBackends(t *testing.T) {
	table := GenerateMaglevTable(nil, 100)
	if len(table) != 100 {
		t.Fatalf("expected 100 entries, got %d", len(table))
	}
	for i, v := range table {
		if v != 0 {
			t.Fatalf("entry %d: expected 0, got %d", i, v)
		}
	}
}

func TestMaglevSingleBackend(t *testing.T) {
	table := GenerateMaglevTable([]string{"10.42.0.1:80"}, 100)
	for i, v := range table {
		if v != 0 {
			t.Fatalf("entry %d: expected 0 (only backend), got %d", i, v)
		}
	}
}
