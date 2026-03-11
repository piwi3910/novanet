// Package remotesync watches all cluster pods via an informer and pushes
// remote (non-local) pod endpoints to the eBPF dataplane, enabling
// cross-node identity resolution for policy enforcement.
package remotesync

import (
	"context"
	"net"
	"sync"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/identity"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// StartRemoteEndpointSync watches all cluster pods via an informer and pushes
// remote (non-local) pod endpoints to the eBPF dataplane.
func StartRemoteEndpointSync(ctx context.Context, logger *zap.Logger, k8sClient kubernetes.Interface,
	dpClient pb.DataplaneControlClient, selfNode string, remoteEndpointsGauge prometheus.Gauge) {

	factory := informers.NewSharedInformerFactory(k8sClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods().Informer()

	var remoteCount int64
	var mu sync.Mutex

	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Spec.NodeName == selfNode || pod.Status.PodIP == "" {
				return
			}
			if upsertRemoteEndpoint(ctx, logger, dpClient, pod) {
				mu.Lock()
				remoteCount++
				remoteEndpointsGauge.Set(float64(remoteCount))
				mu.Unlock()
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok || pod.Spec.NodeName == selfNode {
				return
			}
			if pod.Status.PodIP == "" {
				return
			}
			upsertRemoteEndpoint(ctx, logger, dpClient, pod)
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					pod, _ = tombstone.Obj.(*corev1.Pod)
				}
			}
			if pod == nil || pod.Spec.NodeName == selfNode || pod.Status.PodIP == "" {
				return
			}
			if deleteRemoteEndpoint(ctx, logger, dpClient, pod) {
				mu.Lock()
				remoteCount--
				if remoteCount < 0 {
					remoteCount = 0
				}
				remoteEndpointsGauge.Set(float64(remoteCount))
				mu.Unlock()
			}
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	logger.Info("remote endpoint sync started — cross-node identity resolution enabled")
	<-ctx.Done()
}

func upsertRemoteEndpoint(ctx context.Context, logger *zap.Logger,
	dpClient pb.DataplaneControlClient, pod *corev1.Pod) bool {

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return false
	}

	hostIP := net.ParseIP(pod.Status.HostIP)
	if hostIP == nil {
		return false
	}

	labels := make(map[string]string)
	for k, v := range pod.Labels {
		labels[k] = v
	}
	labels["novanet.io/namespace"] = pod.Namespace
	identityID := identity.HashLabels(labels)

	req := &pb.UpsertEndpointRequest{
		Ip:         podIP.String(),
		Ifindex:    0,
		Mac:        []byte{0, 0, 0, 0, 0, 0},
		IdentityId: uint32(identityID), //nolint:gosec // truncated to uint32 for proto wire format
		PodName:    pod.Name,
		Namespace:  pod.Namespace,
		NodeIp:     hostIP.String(),
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := dpClient.UpsertEndpoint(callCtx, req); err != nil {
		logger.Debug("failed to sync remote endpoint",
			zap.String("pod", pod.Namespace+"/"+pod.Name),
			zap.String("pod_ip", pod.Status.PodIP),
			zap.Error(err))
		return false
	}

	logger.Debug("synced remote endpoint",
		zap.String("pod", pod.Namespace+"/"+pod.Name),
		zap.String("pod_ip", pod.Status.PodIP),
		zap.Uint64("identity_id", identityID),
	)
	return true
}

func deleteRemoteEndpoint(ctx context.Context, logger *zap.Logger,
	dpClient pb.DataplaneControlClient, pod *corev1.Pod) bool {

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return false
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := dpClient.DeleteEndpoint(callCtx, &pb.DeleteEndpointRequest{
		Ip: podIP.String(),
	}); err != nil {
		logger.Debug("failed to remove remote endpoint",
			zap.String("pod", pod.Namespace+"/"+pod.Name),
			zap.String("pod_ip", pod.Status.PodIP),
			zap.Error(err))
		return false
	}

	logger.Debug("removed remote endpoint",
		zap.String("pod", pod.Namespace+"/"+pod.Name),
		zap.String("pod_ip", pod.Status.PodIP),
	)
	return true
}
