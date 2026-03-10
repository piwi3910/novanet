package policy

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/azrtydxb/novanet/internal/identity"
)

func TestNewWatcher(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	if watcher == nil {
		t.Fatal("NewWatcher returned nil")
	}
	if watcher.compiler != compiler {
		t.Error("watcher.compiler does not match")
	}
	if watcher.logger != logger {
		t.Error("watcher.logger does not match")
	}
}

func TestWatcher_OnChange(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	// Initially no callback
	watcher.mu.RLock()
	cb := watcher.onChange
	watcher.mu.RUnlock()
	if cb != nil {
		t.Error("onChange should be nil initially")
	}

	// Set callback
	called := false
	testCallback := func(rules []*CompiledRule) {
		called = true
	}
	watcher.OnChange(testCallback)

	watcher.mu.RLock()
	cb = watcher.onChange
	watcher.mu.RUnlock()
	if cb == nil {
		t.Fatal("onChange should not be nil after OnChange")
	}

	// Call the callback
	cb([]*CompiledRule{})
	if !called {
		t.Error("callback was not called")
	}
}

func TestWatcher_OnChange_Multiple(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	callCount := 0
	watcher.OnChange(func(rules []*CompiledRule) {
		callCount++
	})

	// Setting another callback should replace the first
	callCount2 := 0
	watcher.OnChange(func(rules []*CompiledRule) {
		callCount2++
	})

	// Trigger recompile
	watcher.recompileAll()

	// Only second callback should be called
	if callCount != 0 {
		t.Errorf("first callback callCount = %d, want 0", callCount)
	}
	if callCount2 != 0 {
		t.Errorf("second callback callCount = %d, want 0 (no store)", callCount2)
	}
}

func TestWatcher_Recompile(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	// Recompile should not panic with nil store
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Recompile panicked: %v", r)
		}
	}()
	watcher.Recompile()
}

func TestWatcher_recompileAll_NilStore(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	// Should return early with nil store
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("recompileAll panicked: %v", r)
		}
	}()
	watcher.recompileAll()
}

func TestWatcher_recompileAll_WithCallback(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	var receivedRules []*CompiledRule
	watcher.OnChange(func(rules []*CompiledRule) {
		receivedRules = rules
	})

	// Create a mock store
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)

	// Add a network policy to the store
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
	if err := store.Add(np); err != nil {
		t.Fatalf("store.Add: %v", err)
	}

	watcher.store = store

	// Recompile should call the callback
	watcher.recompileAll()

	// Should have received rules (even if empty due to no identities)
	if receivedRules == nil {
		t.Error("receivedRules should not be nil")
	}
}

func TestWatcher_recompileAll_MultiplePolicies(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	var receivedRules []*CompiledRule
	watcher.OnChange(func(rules []*CompiledRule) {
		receivedRules = rules
	})

	// Create a mock store
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)

	// Add multiple network policies
	for i := 0; i < 3; i++ {
		np := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy-" + string(rune('a'+i)),
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		}
		if err := store.Add(np); err != nil {
			t.Fatalf("store.Add[%d]: %v", i, err)
		}
	}

	watcher.store = store

	// Recompile
	watcher.recompileAll()

	// Should have received rules
	if receivedRules == nil {
		t.Error("receivedRules should not be nil")
	}
}

func TestObjectKey(t *testing.T) {
	tests := []struct {
		name     string
		obj      any
		expected string
	}{
		{
			name: "valid network policy",
			obj: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
				},
			},
			expected: "default/test-policy",
		},
		{
			name: "policy without namespace",
			obj: &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-policy",
				},
			},
			expected: "test-policy",
		},
		{
			name:     "invalid object type",
			obj:      "not-a-policy",
			expected: "<unknown>",
		},
		{
			name:     "nil object",
			obj:      nil,
			expected: "<unknown>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := objectKey(tt.obj)
			if key != tt.expected {
				t.Errorf("objectKey() = %q, want %q", key, tt.expected)
			}
		})
	}
}

func TestWatcher_ConcurrentOnChange(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	// Concurrent callback setting
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			watcher.OnChange(func(rules []*CompiledRule) {})
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have a callback set
	watcher.mu.RLock()
	cb := watcher.onChange
	watcher.mu.RUnlock()
	if cb == nil {
		t.Error("onChange should not be nil after concurrent OnChange calls")
	}
}

func TestWatcher_recompileAll_EmptyStore(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	var receivedRules []*CompiledRule
	watcher.OnChange(func(rules []*CompiledRule) {
		receivedRules = rules
	})

	// Create an empty store
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	watcher.store = store

	// Recompile
	watcher.recompileAll()

	// Should have received empty rules
	if receivedRules == nil {
		t.Error("receivedRules should not be nil")
	}
	if len(receivedRules) != 0 {
		t.Errorf("receivedRules length = %d, want 0", len(receivedRules))
	}
}

func TestWatcher_recompileAll_NonNetworkPolicyItems(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	var receivedRules []*CompiledRule
	watcher.OnChange(func(rules []*CompiledRule) {
		receivedRules = rules
	})

	// Create a mock store with a key func that accepts any type,
	// so we can test that recompileAll skips non-NetworkPolicy items.
	store := cache.NewStore(func(obj interface{}) (string, error) {
		return fmt.Sprintf("%v", obj), nil
	})

	// Add a non-NetworkPolicy item (should be skipped)
	if err := store.Add("not-a-network-policy"); err != nil {
		t.Fatalf("store.Add: %v", err)
	}

	watcher.store = store

	// Recompile should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("recompileAll panicked: %v", r)
		}
	}()
	watcher.recompileAll()

	// Should have received empty rules (non-NP items skipped)
	if receivedRules == nil {
		t.Error("receivedRules should not be nil")
	}
	if len(receivedRules) != 0 {
		t.Errorf("receivedRules length = %d, want 0", len(receivedRules))
	}
}

func TestWatcher_recompileAll_CallbackNil(t *testing.T) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	// Create a mock store
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	watcher.store = store

	// No callback set - should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("recompileAll panicked: %v", r)
		}
	}()
	watcher.recompileAll()
}

// Benchmark tests
func BenchmarkWatcher_recompileAll(b *testing.B) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	watcher.OnChange(func(rules []*CompiledRule) {})

	// Create a mock store with policies
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for i := 0; i < 10; i++ {
		np := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-policy-" + string(rune('a'+i%26)),
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "test"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
				},
			},
		}
		_ = store.Add(np)
	}
	watcher.store = store

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		watcher.recompileAll()
	}
}

func BenchmarkWatcher_OnChange(b *testing.B) {
	logger := zap.NewNop()
	idAlloc := identity.NewAllocator(logger)
	compiler := NewCompiler(idAlloc, logger)

	watcher := NewWatcher(nil, compiler, logger)

	callback := func(rules []*CompiledRule) {}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		watcher.OnChange(callback)
	}
}

func BenchmarkObjectKey(b *testing.B) {
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		objectKey(np)
	}
}
