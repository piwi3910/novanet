// Package k8s provides Kubernetes watchers for Nodes, Pods, Namespaces,
// and NetworkPolicies using client-go informers.
package k8s

import (
	"context"
	"errors"
	"fmt"

	"github.com/azrtydxb/novanet/internal/constants"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// ErrInformerSyncFailed indicates that an informer cache failed to sync.
var ErrInformerSyncFailed = errors.New("failed to sync informer")

// Watchers manages informers for Kubernetes resources relevant to NovaNet.
type Watchers struct {
	clientset kubernetes.Interface
	nodeName  string
	logger    *zap.Logger
	factory   informers.SharedInformerFactory

	// Node callbacks.
	OnNodeAdd    func(*corev1.Node)
	OnNodeUpdate func(oldNode, newNode *corev1.Node)
	OnNodeDelete func(*corev1.Node)

	// Pod callbacks (filtered to local node).
	OnPodAdd    func(*corev1.Pod)
	OnPodUpdate func(oldPod, newPod *corev1.Pod)
	OnPodDelete func(*corev1.Pod)

	// Remote pod callbacks (non-local pods, for cross-node identity resolution).
	OnRemotePodAdd    func(*corev1.Pod)
	OnRemotePodUpdate func(oldPod, newPod *corev1.Pod)
	OnRemotePodDelete func(*corev1.Pod)

	// Namespace callbacks.
	OnNamespaceAdd    func(*corev1.Namespace)
	OnNamespaceUpdate func(oldNS, newNS *corev1.Namespace)
	OnNamespaceDelete func(*corev1.Namespace)

	// NetworkPolicy callbacks.
	OnNetworkPolicyAdd    func(*networkingv1.NetworkPolicy)
	OnNetworkPolicyUpdate func(oldNP, newNP *networkingv1.NetworkPolicy)
	OnNetworkPolicyDelete func(*networkingv1.NetworkPolicy)

	informers []cache.SharedIndexInformer
}

// NewWatchers creates a new Watchers instance for the given Kubernetes
// clientset. The nodeName is used to filter pod events to only the local node.
func NewWatchers(clientset kubernetes.Interface, nodeName string, logger *zap.Logger) *Watchers {
	factory := informers.NewSharedInformerFactory(clientset, constants.DefaultResyncPeriod)

	return &Watchers{
		clientset: clientset,
		nodeName:  nodeName,
		logger:    logger,
		factory:   factory,
	}
}

// addEventHandler is a generic helper that registers event handlers for any
// informer, eliminating the duplicated handler blocks. The extractObj function
// extracts the typed object from a raw interface{}, handling tombstones.
func addEventHandler[T any](
	informer cache.SharedIndexInformer,
	extract func(obj any) (T, bool),
	onAdd func(T),
	onUpdate func(old, cur T),
	onDelete func(T),
) {
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if onAdd == nil {
				return
			}
			if t, ok := extract(obj); ok {
				onAdd(t)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if onUpdate == nil {
				return
			}
			oldT, ok1 := extract(oldObj)
			newT, ok2 := extract(newObj)
			if ok1 && ok2 {
				onUpdate(oldT, newT)
			}
		},
		DeleteFunc: func(obj any) {
			if onDelete == nil {
				return
			}
			t, ok := extract(obj)
			if !ok {
				tombstone, tsOK := obj.(cache.DeletedFinalStateUnknown)
				if tsOK {
					t, ok = extract(tombstone.Obj)
				}
			}
			if ok {
				onDelete(t)
			}
		},
	})
}

// extractNode extracts a *corev1.Node from a raw object.
func extractNode(obj any) (*corev1.Node, bool) {
	n, ok := obj.(*corev1.Node)
	return n, ok
}

// extractNamespace extracts a *corev1.Namespace from a raw object.
func extractNamespace(obj any) (*corev1.Namespace, bool) {
	ns, ok := obj.(*corev1.Namespace)
	return ns, ok
}

// extractNetworkPolicy extracts a *networkingv1.NetworkPolicy from a raw object.
func extractNetworkPolicy(obj any) (*networkingv1.NetworkPolicy, bool) {
	np, ok := obj.(*networkingv1.NetworkPolicy)
	return np, ok
}

// Start starts all informers and registers event handlers.
func (w *Watchers) Start(ctx context.Context) error {
	// Node informer.
	nodeInformer := w.factory.Core().V1().Nodes().Informer()
	addEventHandler(nodeInformer, extractNode, w.OnNodeAdd, w.OnNodeUpdate, w.OnNodeDelete)
	w.informers = append(w.informers, nodeInformer)

	// Pod informer (with local/remote split).
	podInformer := w.factory.Core().V1().Pods().Informer()
	w.registerPodHandlers(podInformer)
	w.informers = append(w.informers, podInformer)

	// Namespace informer.
	nsInformer := w.factory.Core().V1().Namespaces().Informer()
	addEventHandler(nsInformer, extractNamespace, w.OnNamespaceAdd, w.OnNamespaceUpdate, w.OnNamespaceDelete)
	w.informers = append(w.informers, nsInformer)

	// NetworkPolicy informer.
	npInformer := w.factory.Networking().V1().NetworkPolicies().Informer()
	addEventHandler(npInformer, extractNetworkPolicy, w.OnNetworkPolicyAdd, w.OnNetworkPolicyUpdate, w.OnNetworkPolicyDelete)
	w.informers = append(w.informers, npInformer)

	// Start the factory (which starts all registered informers).
	w.factory.Start(ctx.Done())

	w.logger.Info("started all Kubernetes watchers",
		zap.String("node_name", w.nodeName),
	)

	return nil
}

// registerPodHandlers sets up pod event handlers with local/remote filtering.
// Pods are split into local and remote callbacks based on the node name.
func (w *Watchers) registerPodHandlers(podInformer cache.SharedIndexInformer) {
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			if w.isLocalPod(pod) {
				if w.OnPodAdd != nil {
					w.OnPodAdd(pod)
				}
			} else {
				if w.OnRemotePodAdd != nil {
					w.OnRemotePodAdd(pod)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			oldPod, ok1 := oldObj.(*corev1.Pod)
			newPod, ok2 := newObj.(*corev1.Pod)
			if !ok1 || !ok2 {
				return
			}
			if w.isLocalPod(newPod) {
				if w.OnPodUpdate != nil {
					w.OnPodUpdate(oldPod, newPod)
				}
			} else {
				if w.OnRemotePodUpdate != nil {
					w.OnRemotePodUpdate(oldPod, newPod)
				}
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, tsOK := obj.(cache.DeletedFinalStateUnknown)
				if tsOK {
					pod, ok = tombstone.Obj.(*corev1.Pod)
				}
			}
			if !ok || pod == nil {
				return
			}
			if w.isLocalPod(pod) {
				if w.OnPodDelete != nil {
					w.OnPodDelete(pod)
				}
			} else {
				if w.OnRemotePodDelete != nil {
					w.OnRemotePodDelete(pod)
				}
			}
		},
	})
}

// WaitForSync waits for all informer caches to sync.
func (w *Watchers) WaitForSync(ctx context.Context) error {
	synced := w.factory.WaitForCacheSync(ctx.Done())

	for informerType, ok := range synced {
		if !ok {
			return fmt.Errorf("%w: %v", ErrInformerSyncFailed, informerType)
		}
	}

	w.logger.Info("all informer caches synced")
	return nil
}

// isLocalPod returns true if the pod is scheduled on the local node.
func (w *Watchers) isLocalPod(pod *corev1.Pod) bool {
	return pod.Spec.NodeName == w.nodeName
}
