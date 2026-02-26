package policy

import (
	"context"
	"sync"

	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// ChangeCallback is called with the full set of compiled rules whenever
// any NetworkPolicy is added, updated, or deleted.
type ChangeCallback func(rules []*CompiledRule)

// Watcher watches Kubernetes NetworkPolicy resources using a SharedIndexInformer.
// On any change, it recompiles ALL policies and invokes the OnChange callback.
type Watcher struct {
	mu sync.RWMutex

	clientset kubernetes.Interface
	compiler  *Compiler
	logger    *zap.Logger

	onChange ChangeCallback
	store    cache.Store
}

// NewWatcher creates a new NetworkPolicy watcher.
func NewWatcher(clientset kubernetes.Interface, compiler *Compiler, logger *zap.Logger) *Watcher {
	return &Watcher{
		clientset: clientset,
		compiler:  compiler,
		logger:    logger,
	}
}

// OnChange sets the callback invoked when policies change.
func (w *Watcher) OnChange(cb ChangeCallback) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onChange = cb
}

// Start begins watching NetworkPolicy resources. It blocks until the context
// is canceled or an error occurs.
func (w *Watcher) Start(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(w.clientset, 0)
	informer := factory.Networking().V1().NetworkPolicies().Informer()

	w.store = informer.GetStore()

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			w.logger.Debug("NetworkPolicy added",
				zap.String("key", objectKey(obj)),
			)
			w.recompileAll()
		},
		UpdateFunc: func(oldObj, newObj any) {
			w.logger.Debug("NetworkPolicy updated",
				zap.String("key", objectKey(newObj)),
			)
			w.recompileAll()
		},
		DeleteFunc: func(obj any) {
			w.logger.Debug("NetworkPolicy deleted",
				zap.String("key", objectKey(obj)),
			)
			w.recompileAll()
		},
	}

	informer.AddEventHandler(handler)

	w.logger.Info("starting NetworkPolicy watcher")

	// Run the informer. This blocks until ctx is done.
	informer.Run(ctx.Done())

	return nil
}

// Recompile triggers a full recompilation of all policies and invokes
// the OnChange callback. Call this when identity allocations change
// (e.g., after AddPod) so that policy rules use actual pod identities.
func (w *Watcher) Recompile() {
	w.recompileAll()
}

// recompileAll fetches all policies from the store, compiles them, and
// invokes the OnChange callback.
func (w *Watcher) recompileAll() {
	if w.store == nil {
		return
	}

	items := w.store.List()
	policies := make([]*networkingv1.NetworkPolicy, 0, len(items))
	for _, item := range items {
		np, ok := item.(*networkingv1.NetworkPolicy)
		if ok {
			policies = append(policies, np)
		}
	}

	rules := w.compiler.CompileAll(policies)

	w.logger.Debug("recompiled all policies",
		zap.Int("policy_count", len(policies)),
		zap.Int("rule_count", len(rules)),
	)

	w.mu.RLock()
	cb := w.onChange
	w.mu.RUnlock()

	if cb != nil {
		cb(rules)
	}
}

// objectKey returns a string identifying the object for logging.
func objectKey(obj any) string {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return "<unknown>"
	}
	return key
}
