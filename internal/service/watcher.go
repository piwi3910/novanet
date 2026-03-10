package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	pb "github.com/azrtydxb/novanet/api/v1"
)

const (
	// DefaultRPCTimeout is the default timeout for dataplane RPC calls.
	DefaultRPCTimeout = 30 * time.Second

	// MaglevTableSize is the size of each Maglev lookup table.
	MaglevTableSize = 65537

	// Scope constants matching eBPF SVC_SCOPE_*.
	scopeClusterIP    uint32 = 0
	scopeNodePort     uint32 = 1
	scopeExternalIP   uint32 = 2
	scopeLoadBalancer uint32 = 3

	// Algorithm constants matching eBPF LB_ALG_*.
	algRandom     uint32 = 0
	algRoundRobin uint32 = 1
	algMaglev     uint32 = 2
)

var errCacheSyncFailed = errors.New("failed to sync service/endpointslice informer caches")

// DataplaneServiceClient is the subset of the dataplane gRPC client
// needed by the service watcher.
type DataplaneServiceClient interface {
	UpsertService(ctx context.Context, in *pb.UpsertServiceRequest) (*pb.UpsertServiceResponse, error)
	DeleteService(ctx context.Context, in *pb.DeleteServiceRequest) (*pb.DeleteServiceResponse, error)
	UpsertBackends(ctx context.Context, in *pb.UpsertBackendsRequest) (*pb.UpsertBackendsResponse, error)
	UpsertMaglevTable(ctx context.Context, in *pb.UpsertMaglevTableRequest) (*pb.UpsertMaglevTableResponse, error)
}

// serviceState tracks the dataplane state for a single Kubernetes Service.
type serviceState struct {
	backendOffset uint32
	backendCount  uint32
	algorithm     uint32
	maglevOffset  uint32 // only if algorithm == maglev
	scopes        []uint32
	clusterIPs    []string // all ClusterIPs (dual-stack: one IPv4 + one IPv6)
}

// Watcher watches Kubernetes Services and EndpointSlices, translating
// them into dataplane gRPC calls for the L4 load balancer.
type Watcher struct {
	mu sync.Mutex

	clientset  kubernetes.Interface
	dpClient   DataplaneServiceClient
	allocator  *SlotAllocator
	defaultAlg string
	dsrEnabled bool
	rpcTimeout time.Duration
	logger     *zap.Logger

	// maglevAllocator tracks Maglev table slots (each service needs MaglevTableSize entries).
	maglevAllocator *SlotAllocator

	// services tracks current state per service key (namespace/name).
	services map[string]*serviceState

	// svcStore and epsStore hold the informer caches.
	svcStore cache.Store
	epsStore cache.Store
}

// WatcherOption configures the service Watcher.
type WatcherOption func(*Watcher)

// WithDSR enables Direct Server Return on all services.
func WithDSR(enabled bool) WatcherOption {
	return func(w *Watcher) {
		w.dsrEnabled = enabled
	}
}

// WithRPCTimeout sets the timeout for dataplane RPC calls.
func WithRPCTimeout(d time.Duration) WatcherOption {
	return func(w *Watcher) {
		w.rpcTimeout = d
	}
}

// NewWatcher creates a new Service/EndpointSlice watcher.
func NewWatcher(
	clientset kubernetes.Interface,
	dpClient DataplaneServiceClient,
	allocator *SlotAllocator,
	defaultAlg string,
	logger *zap.Logger,
	opts ...WatcherOption,
) *Watcher {
	w := &Watcher{
		clientset:       clientset,
		dpClient:        dpClient,
		allocator:       allocator,
		defaultAlg:      defaultAlg,
		rpcTimeout:      DefaultRPCTimeout,
		logger:          logger,
		maglevAllocator: NewSlotAllocator(1048576), // MAX_MAGLEV
		services:        make(map[string]*serviceState),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Start begins watching Service and EndpointSlice resources.
// It runs informers in the background and returns immediately.
func (w *Watcher) Start(ctx context.Context) error {
	factory := informers.NewSharedInformerFactory(w.clientset, 0)

	svcInformer := factory.Core().V1().Services().Informer()
	epsInformer := factory.Discovery().V1().EndpointSlices().Informer()

	w.svcStore = svcInformer.GetStore()
	w.epsStore = epsInformer.GetStore()

	svcHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onServiceChange(obj) },
		UpdateFunc: func(_, obj any) { w.onServiceChange(obj) },
		DeleteFunc: func(obj any) { w.onServiceDelete(obj) },
	}

	epsHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onEndpointSliceChange(obj) },
		UpdateFunc: func(_, obj any) { w.onEndpointSliceChange(obj) },
		DeleteFunc: func(obj any) { w.onEndpointSliceChange(obj) },
	}

	_, _ = svcInformer.AddEventHandler(svcHandler)
	_, _ = epsInformer.AddEventHandler(epsHandler)

	w.logger.Info("starting L4 LB service watcher")

	go svcInformer.Run(ctx.Done())
	go epsInformer.Run(ctx.Done())

	// Wait for caches to sync.
	if !cache.WaitForCacheSync(ctx.Done(), svcInformer.HasSynced, epsInformer.HasSynced) {
		return errCacheSyncFailed
	}

	w.logger.Info("L4 LB service watcher caches synced")
	return nil
}

func (w *Watcher) onServiceChange(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return
	}
	w.reconcileService(svc)
}

func (w *Watcher) onServiceDelete(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		svc, ok = tombstone.Obj.(*corev1.Service)
		if !ok {
			return
		}
	}
	w.deleteService(svc)
}

func (w *Watcher) onEndpointSliceChange(obj any) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		eps, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		if !ok {
			return
		}
	}

	// Find the owning service.
	svcName, ok := eps.Labels[discoveryv1.LabelServiceName]
	if !ok {
		return
	}

	// Look up the service from our store.
	key := eps.Namespace + "/" + svcName
	obj2, exists, err := w.svcStore.GetByKey(key)
	if err != nil || !exists {
		return
	}
	svc, ok := obj2.(*corev1.Service)
	if !ok {
		return
	}

	w.reconcileService(svc)
}

// serviceClusterIPs returns the list of ClusterIPs for a service,
// supporting dual-stack. Falls back to the singular ClusterIP field
// if ClusterIPs is not populated.
func serviceClusterIPs(svc *corev1.Service) []string {
	if len(svc.Spec.ClusterIPs) > 0 {
		// Filter out empty strings and "None".
		var ips []string
		for _, ip := range svc.Spec.ClusterIPs {
			if ip != "" && ip != "None" {
				ips = append(ips, ip)
			}
		}
		return ips
	}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		return []string{svc.Spec.ClusterIP}
	}
	return nil
}

// freeOldState releases dataplane resources for a previously-reconciled service.
func (w *Watcher) freeOldState(ctx context.Context, svc *corev1.Service, old *serviceState) {
	if old.backendCount > 0 {
		w.allocator.Free(old.backendOffset, old.backendCount)
	}
	if old.algorithm == algMaglev && old.maglevOffset > 0 {
		w.maglevAllocator.Free(old.maglevOffset, MaglevTableSize)
	}
	// Delete old service map entries for every tracked ClusterIP.
	for _, scope := range old.scopes {
		for _, port := range svc.Spec.Ports {
			proto := protocolToNumber(port.Protocol)
			for _, clusterIP := range old.clusterIPs {
				ip := w.serviceIPForScope(clusterIP, scope, "")
				_, _ = w.dpClient.DeleteService(ctx, &pb.DeleteServiceRequest{
					Ip:       ip,
					Port:     w.servicePortForScope(port, scope),
					Protocol: proto,
					Scope:    scope,
				})
			}
		}
	}
}

// pushBackends sends backend entries to the dataplane for all ports.
func (w *Watcher) pushBackends(ctx context.Context, key string, offset uint32, backends []backendInfo, ports []corev1.ServicePort) {
	pbBackends := make([]*pb.BackendEntry, 0, len(backends)*len(ports))
	for portIdx, port := range ports {
		for i, be := range backends {
			targetPort := resolveTargetPort(port, be)
			idx := offset + intToU32(portIdx*len(backends)+i)
			pbBackends = append(pbBackends, &pb.BackendEntry{
				Index:  idx,
				Ip:     be.ip,
				Port:   targetPort,
				NodeIp: be.nodeIP,
			})
		}
	}

	if len(pbBackends) > 0 {
		_, err := w.dpClient.UpsertBackends(ctx, &pb.UpsertBackendsRequest{
			Backends: pbBackends,
		})
		if err != nil {
			w.logger.Error("failed to upsert backends", zap.String("service", key), zap.Error(err))
		}
	}
}

// upsertServiceEntries creates or updates dataplane service map entries for all scopes, ports, and ClusterIPs.
func (w *Watcher) upsertServiceEntries(ctx context.Context, key string, svc *corev1.Service, clusterIPs []string, offset uint32, backends []backendInfo, alg, maglevOff uint32, scopes []uint32) {
	for portIdx, port := range svc.Spec.Ports {
		proto := protocolToNumber(port.Protocol)
		portBackendOffset := offset + intToU32(portIdx*len(backends))
		portBackendCount := intToU32(len(backends))

		for _, scope := range scopes {
			// For ClusterIP scope, create one entry per ClusterIP (dual-stack).
			for _, clusterIP := range clusterIPs {
				ip := w.serviceIPForScope(clusterIP, scope, "")
				req := &pb.UpsertServiceRequest{
					Ip:              ip,
					Port:            w.servicePortForScope(port, scope),
					Protocol:        proto,
					Scope:           scope,
					BackendCount:    portBackendCount,
					BackendOffset:   portBackendOffset,
					Algorithm:       alg,
					Flags:           w.computeFlags(svc),
					AffinityTimeout: w.computeAffinityTimeout(svc),
					MaglevOffset:    maglevOff,
				}
				_, err := w.dpClient.UpsertService(ctx, req)
				if err != nil {
					w.logger.Error("failed to upsert service",
						zap.String("service", key),
						zap.String("clusterIP", clusterIP),
						zap.Uint32("scope", scope),
						zap.Error(err),
					)
				}
			}
		}

		// For ExternalIP scope, create one entry per external IP.
		for _, extIP := range svc.Spec.ExternalIPs {
			req := &pb.UpsertServiceRequest{
				Ip:              extIP,
				Port:            portToU32(port.Port),
				Protocol:        proto,
				Scope:           scopeExternalIP,
				BackendCount:    portBackendCount,
				BackendOffset:   portBackendOffset,
				Algorithm:       alg,
				Flags:           w.computeFlags(svc),
				AffinityTimeout: w.computeAffinityTimeout(svc),
				MaglevOffset:    maglevOff,
			}
			_, err := w.dpClient.UpsertService(ctx, req)
			if err != nil {
				w.logger.Error("failed to upsert external IP service",
					zap.String("service", key),
					zap.String("externalIP", extIP),
					zap.Error(err),
				)
			}
		}

		// For LoadBalancer, create one entry per ingress IP.
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				if ingress.IP == "" {
					continue
				}
				req := &pb.UpsertServiceRequest{
					Ip:              ingress.IP,
					Port:            portToU32(port.Port),
					Protocol:        proto,
					Scope:           scopeLoadBalancer,
					BackendCount:    portBackendCount,
					BackendOffset:   portBackendOffset,
					Algorithm:       alg,
					Flags:           w.computeFlags(svc),
					AffinityTimeout: w.computeAffinityTimeout(svc),
					MaglevOffset:    maglevOff,
				}
				_, err := w.dpClient.UpsertService(ctx, req)
				if err != nil {
					w.logger.Error("failed to upsert LB ingress service",
						zap.String("service", key),
						zap.String("ingressIP", ingress.IP),
						zap.Error(err),
					)
				}
			}
		}
	}
}

func (w *Watcher) reconcileService(svc *corev1.Service) {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := svc.Namespace + "/" + svc.Name
	ctx, cancel := context.WithTimeout(context.Background(), w.rpcTimeout)
	defer cancel()

	// Get all ClusterIPs (dual-stack aware).
	clusterIPs := serviceClusterIPs(svc)

	// Skip headless services (no ClusterIPs).
	if len(clusterIPs) == 0 {
		// If we had state, clean it up.
		if _, exists := w.services[key]; exists {
			w.deleteServiceLocked(svc)
		}
		return
	}

	// Collect all ready backend endpoints from EndpointSlices.
	backends := w.collectBackends(svc)

	w.logger.Debug("reconciling service",
		zap.String("service", key),
		zap.Int("backends", len(backends)),
		zap.Int("ports", len(svc.Spec.Ports)),
		zap.Strings("clusterIPs", clusterIPs),
	)

	// Determine algorithm.
	alg := w.resolveAlgorithm()

	// Free old state if it exists.
	if old, exists := w.services[key]; exists {
		w.freeOldState(ctx, svc, old)
	}

	if len(backends) == 0 {
		delete(w.services, key)
		return
	}

	// Allocate backend slots.
	// We need total = len(backends) * len(svc.Spec.Ports) slots.
	// Each service port gets its own backend range.
	totalBackends := intToU32(len(backends) * len(svc.Spec.Ports))
	offset, err := w.allocator.Alloc(totalBackends)
	if err != nil {
		w.logger.Error("failed to allocate backend slots",
			zap.String("service", key),
			zap.Uint32("needed", totalBackends),
			zap.Error(err),
		)
		delete(w.services, key)
		return
	}

	// Push backends to dataplane.
	w.pushBackends(ctx, key, offset, backends, svc.Spec.Ports)

	// Handle Maglev tables if needed.
	var maglevOff uint32
	if alg == algMaglev {
		maglevOff, err = w.maglevAllocator.Alloc(MaglevTableSize)
		if err != nil {
			w.logger.Warn("failed to allocate maglev table, falling back to random",
				zap.String("service", key), zap.Error(err))
			alg = algRandom
		} else {
			// Generate and push maglev table (one per service, uses first port's backends).
			backendStrs := make([]string, len(backends))
			for i, be := range backends {
				backendStrs[i] = be.ip + ":" + fmt.Sprintf("%d", resolveTargetPort(svc.Spec.Ports[0], be))
			}
			table := GenerateMaglevTable(backendStrs, MaglevTableSize)
			_, err = w.dpClient.UpsertMaglevTable(ctx, &pb.UpsertMaglevTableRequest{
				Offset:  maglevOff,
				Entries: table,
			})
			if err != nil {
				w.logger.Error("failed to upsert maglev table", zap.String("service", key), zap.Error(err))
			}
		}
	}

	// Determine which scopes to create.
	scopes := w.computeScopes(svc)

	// Upsert service map entries for all ClusterIPs (dual-stack).
	w.upsertServiceEntries(ctx, key, svc, clusterIPs, offset, backends, alg, maglevOff, scopes)

	// Save state.
	w.services[key] = &serviceState{
		backendOffset: offset,
		backendCount:  totalBackends,
		algorithm:     alg,
		maglevOffset:  maglevOff,
		scopes:        scopes,
		clusterIPs:    clusterIPs,
	}

	w.logger.Info("reconciled service",
		zap.String("service", key),
		zap.Int("backends", len(backends)),
		zap.Uint32("offset", offset),
		zap.Strings("clusterIPs", clusterIPs),
	)
}

func (w *Watcher) deleteService(svc *corev1.Service) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deleteServiceLocked(svc)
}

func (w *Watcher) deleteServiceLocked(svc *corev1.Service) {
	key := svc.Namespace + "/" + svc.Name
	ctx, cancel := context.WithTimeout(context.Background(), w.rpcTimeout)
	defer cancel()

	state, exists := w.services[key]
	if !exists {
		return
	}

	// Delete all service map entries for every tracked ClusterIP.
	for _, scope := range state.scopes {
		for _, port := range svc.Spec.Ports {
			proto := protocolToNumber(port.Protocol)
			for _, clusterIP := range state.clusterIPs {
				ip := w.serviceIPForScope(clusterIP, scope, "")
				_, _ = w.dpClient.DeleteService(ctx, &pb.DeleteServiceRequest{
					Ip:       ip,
					Port:     w.servicePortForScope(port, scope),
					Protocol: proto,
					Scope:    scope,
				})
			}
		}

		// Delete ExternalIP entries.
		if scope == scopeExternalIP {
			for _, extIP := range svc.Spec.ExternalIPs {
				for _, port := range svc.Spec.Ports {
					_, _ = w.dpClient.DeleteService(ctx, &pb.DeleteServiceRequest{
						Ip:       extIP,
						Port:     portToU32(port.Port),
						Protocol: protocolToNumber(port.Protocol),
						Scope:    scopeExternalIP,
					})
				}
			}
		}

		// Delete LB ingress entries.
		if scope == scopeLoadBalancer {
			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				if ingress.IP == "" {
					continue
				}
				for _, port := range svc.Spec.Ports {
					_, _ = w.dpClient.DeleteService(ctx, &pb.DeleteServiceRequest{
						Ip:       ingress.IP,
						Port:     portToU32(port.Port),
						Protocol: protocolToNumber(port.Protocol),
						Scope:    scopeLoadBalancer,
					})
				}
			}
		}
	}

	// Free backend slots.
	if state.backendCount > 0 {
		w.allocator.Free(state.backendOffset, state.backendCount)
	}
	if state.algorithm == algMaglev && state.maglevOffset > 0 {
		w.maglevAllocator.Free(state.maglevOffset, MaglevTableSize)
	}

	delete(w.services, key)

	w.logger.Info("deleted service", zap.String("service", key))
}

// backendInfo holds information about a single backend endpoint.
type backendInfo struct {
	ip       string
	nodeIP   string
	port     int32 // target port from EndpointSlice (may be 0 if using named port)
	portName string
}

// collectBackends gathers all ready backend endpoints for a service from EndpointSlices.
// EndpointSlice addresses already include both IPv4 and IPv6 addresses for dual-stack pods.
func (w *Watcher) collectBackends(svc *corev1.Service) []backendInfo {
	if w.epsStore == nil {
		return nil
	}

	var backends []backendInfo

	for _, obj := range w.epsStore.List() {
		eps, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok {
			continue
		}
		if eps.Namespace != svc.Namespace {
			continue
		}
		svcName, ok := eps.Labels[discoveryv1.LabelServiceName]
		if !ok || svcName != svc.Name {
			continue
		}

		for _, ep := range eps.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, addr := range ep.Addresses {
				// EndpointSlice addresses may contain hostnames (e.g. node
				// names like "worker-21") instead of IPs.  The dataplane
				// expects valid IP addresses, so skip non-IP entries.
				if net.ParseIP(addr) == nil {
					continue
				}
				be := backendInfo{
					ip: addr,
				}
				// Capture port info from the EndpointSlice ports.
				if len(eps.Ports) > 0 && eps.Ports[0].Port != nil {
					be.port = *eps.Ports[0].Port
					if eps.Ports[0].Name != nil {
						be.portName = *eps.Ports[0].Name
					}
				}
				backends = append(backends, be)
			}
		}
	}

	return backends
}

func (w *Watcher) resolveAlgorithm() uint32 {
	switch strings.ToLower(w.defaultAlg) {
	case "round-robin":
		return algRoundRobin
	case "maglev":
		return algMaglev
	default:
		return algRandom
	}
}

func (w *Watcher) computeScopes(svc *corev1.Service) []uint32 {
	scopes := []uint32{scopeClusterIP}

	switch svc.Spec.Type {
	case corev1.ServiceTypeClusterIP:
		// ClusterIP is the base scope, already included above.
	case corev1.ServiceTypeNodePort:
		scopes = append(scopes, scopeNodePort)
	case corev1.ServiceTypeLoadBalancer:
		scopes = append(scopes, scopeNodePort, scopeLoadBalancer)
	case corev1.ServiceTypeExternalName:
		// ExternalName services resolve via DNS; no extra eBPF scopes needed.
	}

	if len(svc.Spec.ExternalIPs) > 0 {
		scopes = append(scopes, scopeExternalIP)
	}

	return scopes
}

// serviceIPForScope returns the IP string to use in the dataplane service map
// for a given scope and ClusterIP. For NodePort scope, an empty string is
// returned (wildcard). For scopes that use a specific IP (ExternalIP,
// LoadBalancer), specificIP overrides if non-empty.
func (w *Watcher) serviceIPForScope(clusterIP string, scope uint32, specificIP string) string {
	switch scope {
	case scopeClusterIP:
		return clusterIP
	case scopeNodePort:
		return "" // wildcard for NodePort
	case scopeExternalIP:
		if specificIP != "" {
			return specificIP
		}
		return clusterIP
	case scopeLoadBalancer:
		if specificIP != "" {
			return specificIP
		}
		return clusterIP
	default:
		return clusterIP
	}
}

func (w *Watcher) servicePortForScope(port corev1.ServicePort, scope uint32) uint32 {
	if scope == scopeNodePort && port.NodePort > 0 {
		return portToU32(port.NodePort)
	}
	return portToU32(port.Port)
}

func (w *Watcher) computeFlags(svc *corev1.Service) uint32 {
	var flags uint32
	if svc.Spec.SessionAffinity == corev1.ServiceAffinityClientIP {
		flags |= 0x01 // SVC_FLAG_AFFINITY
	}
	if svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		flags |= 0x02 // SVC_FLAG_EXT_LOCAL
	}
	if w.dsrEnabled {
		flags |= 0x04 // SVC_FLAG_DSR
	}
	if svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal {
		flags |= 0x08 // SVC_FLAG_INT_LOCAL
	}
	return flags
}

func (w *Watcher) computeAffinityTimeout(svc *corev1.Service) uint32 {
	if svc.Spec.SessionAffinityConfig != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP != nil &&
		svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds != nil {
		return portToU32(*svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds)
	}
	return 0
}

// ServiceCount returns the number of tracked services.
func (w *Watcher) ServiceCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.services)
}

// --- Helpers ---

// portToU32 safely converts a Kubernetes port (int32) to uint32.
// Kubernetes ports are always 1-65535, so negative values map to 0.
func portToU32(port int32) uint32 {
	if port < 0 {
		return 0
	}
	return uint32(port) //nolint:gosec // bounds-checked above
}

// intToU32 safely converts a non-negative int to uint32.
func intToU32(n int) uint32 {
	if n < 0 {
		return 0
	}
	return uint32(n) //nolint:gosec // bounds-checked above
}

func protocolToNumber(proto corev1.Protocol) uint32 {
	switch proto {
	case corev1.ProtocolTCP:
		return 6
	case corev1.ProtocolUDP:
		return 17
	case corev1.ProtocolSCTP:
		return 132
	default:
		return 6 // default to TCP
	}
}

func resolveTargetPort(port corev1.ServicePort, be backendInfo) uint32 {
	// If the EndpointSlice has port info matching this service port, use it.
	if be.portName != "" && be.portName == port.Name {
		return portToU32(be.port)
	}
	if be.port > 0 && port.Name == "" {
		return portToU32(be.port)
	}
	// Fallback to the service target port number.
	if port.TargetPort.IntValue() > 0 {
		return intToU32(port.TargetPort.IntValue())
	}
	return portToU32(port.Port)
}

// scopeName returns a human-readable name for a scope constant.
func scopeName(scope uint32) string {
	switch scope {
	case scopeClusterIP:
		return "ClusterIP"
	case scopeNodePort:
		return "NodePort"
	case scopeExternalIP:
		return "ExternalIP"
	case scopeLoadBalancer:
		return "LoadBalancer"
	default:
		return fmt.Sprintf("scope-%d", scope)
	}
}

// algName returns a human-readable name for an algorithm constant.
func algName(alg uint32) string {
	switch alg {
	case algRandom:
		return "random"
	case algRoundRobin:
		return "round-robin"
	case algMaglev:
		return "maglev"
	default:
		return fmt.Sprintf("alg-%d", alg)
	}
}

// ListTrackedServices returns ServiceInfo for all tracked services.
func (w *Watcher) ListTrackedServices() []*pb.ServiceInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.svcStore == nil {
		return nil
	}

	var result []*pb.ServiceInfo

	for _, obj := range w.svcStore.List() {
		svc, ok := obj.(*corev1.Service)
		if !ok {
			continue
		}
		key := svc.Namespace + "/" + svc.Name
		state, exists := w.services[key]
		if !exists {
			continue
		}

		backends := w.collectBackends(svc)
		backendStrs := make([]string, len(backends))
		for i, be := range backends {
			backendStrs[i] = fmt.Sprintf("%s:%d", be.ip, be.port)
		}

		// Report one ServiceInfo per ClusterIP (dual-stack) per port per scope.
		for _, clusterIP := range state.clusterIPs {
			for _, port := range svc.Spec.Ports {
				for _, scope := range state.scopes {
					info := &pb.ServiceInfo{
						ClusterIp:    clusterIP,
						Port:         portToU32(port.Port),
						Protocol:     string(port.Protocol),
						Scope:        scopeName(scope),
						BackendCount: intToU32(len(backends)),
						Algorithm:    algName(state.algorithm),
						Backends:     backendStrs,
						Dsr:          w.dsrEnabled,
					}
					result = append(result, info)
				}
			}
		}
	}

	return result
}
