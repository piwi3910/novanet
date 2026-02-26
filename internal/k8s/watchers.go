// Package k8s provides Kubernetes watchers for Nodes, Pods, Namespaces,
// and NetworkPolicies using client-go informers.
package k8s

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Watchers manages informers for Kubernetes resources relevant to NovaNet.
type Watchers struct {
	clientset kubernetes.Interface
	nodeName  string
	logger    *zap.Logger
	factory   informers.SharedInformerFactory

	// Node callbacks.
	OnNodeAdd    func(*corev1.Node)
	OnNodeUpdate func(old, new *corev1.Node)
	OnNodeDelete func(*corev1.Node)

	// Pod callbacks (filtered to local node).
	OnPodAdd    func(*corev1.Pod)
	OnPodUpdate func(old, new *corev1.Pod)
	OnPodDelete func(*corev1.Pod)

	// Remote pod callbacks (non-local pods, for cross-node identity resolution).
	OnRemotePodAdd    func(*corev1.Pod)
	OnRemotePodUpdate func(old, new *corev1.Pod)
	OnRemotePodDelete func(*corev1.Pod)

	// Namespace callbacks.
	OnNamespaceAdd    func(*corev1.Namespace)
	OnNamespaceUpdate func(old, new *corev1.Namespace)
	OnNamespaceDelete func(*corev1.Namespace)

	// NetworkPolicy callbacks.
	OnNetworkPolicyAdd    func(*networkingv1.NetworkPolicy)
	OnNetworkPolicyUpdate func(old, new *networkingv1.NetworkPolicy)
	OnNetworkPolicyDelete func(*networkingv1.NetworkPolicy)

	informers []cache.SharedIndexInformer
}

// NewWatchers creates a new Watchers instance for the given Kubernetes
// clientset. The nodeName is used to filter pod events to only the local node.
func NewWatchers(clientset kubernetes.Interface, nodeName string, logger *zap.Logger) *Watchers {
	factory := informers.NewSharedInformerFactory(clientset, 30*time.Second)

	return &Watchers{
		clientset: clientset,
		nodeName:  nodeName,
		logger:    logger,
		factory:   factory,
	}
}

// Start starts all informers and registers event handlers.
func (w *Watchers) Start(ctx context.Context) error {
	// Node informer.
	nodeInformer := w.factory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if w.OnNodeAdd != nil {
				if node, ok := obj.(*corev1.Node); ok {
					w.OnNodeAdd(node)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if w.OnNodeUpdate != nil {
				oldNode, ok1 := oldObj.(*corev1.Node)
				newNode, ok2 := newObj.(*corev1.Node)
				if ok1 && ok2 {
					w.OnNodeUpdate(oldNode, newNode)
				}
			}
		},
		DeleteFunc: func(obj any) {
			if w.OnNodeDelete != nil {
				node, ok := obj.(*corev1.Node)
				if !ok {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if ok {
						node, ok = tombstone.Obj.(*corev1.Node)
					}
				}
				if ok && node != nil {
					w.OnNodeDelete(node)
				}
			}
		},
	})
	w.informers = append(w.informers, nodeInformer)

	// Pod informer.
	podInformer := w.factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
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
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
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
	w.informers = append(w.informers, podInformer)

	// Namespace informer.
	nsInformer := w.factory.Core().V1().Namespaces().Informer()
	nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if w.OnNamespaceAdd != nil {
				if ns, ok := obj.(*corev1.Namespace); ok {
					w.OnNamespaceAdd(ns)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if w.OnNamespaceUpdate != nil {
				oldNS, ok1 := oldObj.(*corev1.Namespace)
				newNS, ok2 := newObj.(*corev1.Namespace)
				if ok1 && ok2 {
					w.OnNamespaceUpdate(oldNS, newNS)
				}
			}
		},
		DeleteFunc: func(obj any) {
			if w.OnNamespaceDelete != nil {
				ns, ok := obj.(*corev1.Namespace)
				if !ok {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if ok {
						ns, ok = tombstone.Obj.(*corev1.Namespace)
					}
				}
				if ok && ns != nil {
					w.OnNamespaceDelete(ns)
				}
			}
		},
	})
	w.informers = append(w.informers, nsInformer)

	// NetworkPolicy informer.
	npInformer := w.factory.Networking().V1().NetworkPolicies().Informer()
	npInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if w.OnNetworkPolicyAdd != nil {
				if np, ok := obj.(*networkingv1.NetworkPolicy); ok {
					w.OnNetworkPolicyAdd(np)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if w.OnNetworkPolicyUpdate != nil {
				oldNP, ok1 := oldObj.(*networkingv1.NetworkPolicy)
				newNP, ok2 := newObj.(*networkingv1.NetworkPolicy)
				if ok1 && ok2 {
					w.OnNetworkPolicyUpdate(oldNP, newNP)
				}
			}
		},
		DeleteFunc: func(obj any) {
			if w.OnNetworkPolicyDelete != nil {
				np, ok := obj.(*networkingv1.NetworkPolicy)
				if !ok {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if ok {
						np, ok = tombstone.Obj.(*networkingv1.NetworkPolicy)
					}
				}
				if ok && np != nil {
					w.OnNetworkPolicyDelete(np)
				}
			}
		},
	})
	w.informers = append(w.informers, npInformer)

	// Start the factory (which starts all registered informers).
	w.factory.Start(ctx.Done())

	w.logger.Info("started all Kubernetes watchers",
		zap.String("node_name", w.nodeName),
	)

	return nil
}

// WaitForSync waits for all informer caches to sync.
func (w *Watchers) WaitForSync(ctx context.Context) error {
	synced := w.factory.WaitForCacheSync(ctx.Done())

	for informerType, ok := range synced {
		if !ok {
			return fmt.Errorf("failed to sync informer for %v", informerType)
		}
	}

	w.logger.Info("all informer caches synced")
	return nil
}

// isLocalPod returns true if the pod is scheduled on the local node.
func (w *Watchers) isLocalPod(pod *corev1.Pod) bool {
	return pod.Spec.NodeName == w.nodeName
}
