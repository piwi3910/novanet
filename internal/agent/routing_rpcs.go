package agent

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	rtypes "github.com/azrtydxb/novanet/internal/routing/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// saturateU32 clamps a uint64 to uint32 range.
func saturateU32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// GetRoutingPeers returns BGP peer state from FRR and augments with intent owner info.
func (s *Server) GetRoutingPeers(ctx context.Context, _ *pb.GetRoutingPeersRequest) (*pb.GetRoutingPeersResponse, error) {
	if s.RoutingMgr == nil {
		return nil, status.Error(codes.FailedPrecondition, "routing not enabled (overlay mode)")
	}

	frrClient := s.RoutingMgr.FRRClient()
	if frrClient == nil {
		return nil, status.Error(codes.Unavailable, "FRR client not available")
	}

	neighbors, err := frrClient.GetBGPNeighbors(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query BGP neighbors: %v", err)
	}

	bfdPeers, _ := frrClient.GetBFDPeers(ctx) //nolint:errcheck // BFD info is optional
	bfdByAddr := make(map[string]string, len(bfdPeers))
	for _, bp := range bfdPeers {
		bfdByAddr[bp.PeerAddress] = bp.Status
	}

	store := s.RoutingMgr.Store()
	peerIntents := store.GetPeerIntents()
	ownerByAddr := make(map[string]string, len(peerIntents))
	for _, pi := range peerIntents {
		ownerByAddr[pi.NeighborAddress] = pi.Owner
	}

	resp := &pb.GetRoutingPeersResponse{
		Peers: make([]*pb.RoutingPeerInfo, 0, len(neighbors)),
	}

	for _, nbr := range neighbors {
		peer := &pb.RoutingPeerInfo{
			NeighborAddress:  nbr.Address,
			RemoteAs:         nbr.RemoteAS,
			State:            nbr.State,
			Uptime:           nbr.UpTime,
			PrefixesReceived: nbr.PrefixesReceived,
			PrefixesSent:     nbr.PrefixesSent,
			MsgReceived:      saturateU32(nbr.MsgRcvd),
			MsgSent:          saturateU32(nbr.MsgSent),
			BfdStatus:        bfdByAddr[nbr.Address],
			Owner:            ownerByAddr[nbr.Address],
		}
		resp.Peers = append(resp.Peers, peer)
	}

	sort.Slice(resp.Peers, func(i, j int) bool {
		return resp.Peers[i].NeighborAddress < resp.Peers[j].NeighborAddress
	})

	return resp, nil
}

// GetRoutingPrefixes returns prefix advertisement state from the intent store.
func (s *Server) GetRoutingPrefixes(ctx context.Context, _ *pb.GetRoutingPrefixesRequest) (*pb.GetRoutingPrefixesResponse, error) {
	if s.RoutingMgr == nil {
		return nil, status.Error(codes.FailedPrecondition, "routing not enabled (overlay mode)")
	}

	store := s.RoutingMgr.Store()
	prefixIntents := store.GetPrefixIntents()

	resp := &pb.GetRoutingPrefixesResponse{
		Prefixes: make([]*pb.RoutingPrefixInfo, 0, len(prefixIntents)),
	}

	for _, pi := range prefixIntents {
		proto := "bgp"
		if pi.Protocol == rtypes.ProtocolOSPF {
			proto = "ospf"
		}
		resp.Prefixes = append(resp.Prefixes, &pb.RoutingPrefixInfo{
			Prefix:   pi.Prefix,
			Protocol: proto,
			State:    "advertised",
			Owner:    pi.Owner,
		})
	}

	sort.Slice(resp.Prefixes, func(i, j int) bool {
		return resp.Prefixes[i].Prefix < resp.Prefixes[j].Prefix
	})

	return resp, nil
}

// GetRoutingBFDSessions returns BFD session state from FRR augmented with intent info.
func (s *Server) GetRoutingBFDSessions(ctx context.Context, _ *pb.GetRoutingBFDSessionsRequest) (*pb.GetRoutingBFDSessionsResponse, error) {
	if s.RoutingMgr == nil {
		return nil, status.Error(codes.FailedPrecondition, "routing not enabled (overlay mode)")
	}

	frrClient := s.RoutingMgr.FRRClient()
	if frrClient == nil {
		return nil, status.Error(codes.Unavailable, "FRR client not available")
	}

	bfdPeers, err := frrClient.GetBFDPeers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query BFD peers: %v", err)
	}

	store := s.RoutingMgr.Store()
	bfdIntents := store.GetBFDIntents()
	bfdByAddr := make(map[string]*pb.RoutingBFDSessionInfo, len(bfdIntents))
	for _, bi := range bfdIntents {
		bfdByAddr[bi.PeerAddress] = &pb.RoutingBFDSessionInfo{
			MinRxMs:          bi.MinRxMs,
			MinTxMs:          bi.MinTxMs,
			DetectMultiplier: bi.DetectMultiplier,
			InterfaceName:    bi.InterfaceName,
			Owner:            bi.Owner,
		}
	}

	peerIntents := store.GetPeerIntents()
	for _, pi := range peerIntents {
		if pi.BFDEnabled {
			if _, ok := bfdByAddr[pi.NeighborAddress]; !ok {
				bfdByAddr[pi.NeighborAddress] = &pb.RoutingBFDSessionInfo{
					MinRxMs:          pi.BFDMinRxMs,
					MinTxMs:          pi.BFDMinTxMs,
					DetectMultiplier: pi.BFDDetectMultiplier,
					Owner:            pi.Owner,
				}
			}
		}
	}

	resp := &pb.GetRoutingBFDSessionsResponse{
		Sessions: make([]*pb.RoutingBFDSessionInfo, 0, len(bfdPeers)),
	}

	for _, bp := range bfdPeers {
		session := &pb.RoutingBFDSessionInfo{
			PeerAddress: bp.PeerAddress,
			Status:      bp.Status,
			Uptime:      bp.Uptime,
		}
		if info, ok := bfdByAddr[bp.PeerAddress]; ok {
			session.MinRxMs = info.MinRxMs
			session.MinTxMs = info.MinTxMs
			session.DetectMultiplier = info.DetectMultiplier
			session.InterfaceName = info.InterfaceName
			session.Owner = info.Owner
		}
		resp.Sessions = append(resp.Sessions, session)
	}

	sort.Slice(resp.Sessions, func(i, j int) bool {
		return resp.Sessions[i].PeerAddress < resp.Sessions[j].PeerAddress
	})

	return resp, nil
}

// GetRoutingOSPFNeighbors returns OSPF neighbor state from FRR.
func (s *Server) GetRoutingOSPFNeighbors(ctx context.Context, _ *pb.GetRoutingOSPFNeighborsRequest) (*pb.GetRoutingOSPFNeighborsResponse, error) {
	if s.RoutingMgr == nil {
		return nil, status.Error(codes.FailedPrecondition, "routing not enabled (overlay mode)")
	}

	frrClient := s.RoutingMgr.FRRClient()
	if frrClient == nil {
		return nil, status.Error(codes.Unavailable, "FRR client not available")
	}

	neighbors, err := frrClient.GetOSPFNeighbors(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query OSPF neighbors: %v", err)
	}

	store := s.RoutingMgr.Store()
	ospfIntents := store.GetOSPFIntents()
	ownerByIface := make(map[string]string, len(ospfIntents))
	for _, oi := range ospfIntents {
		ownerByIface[oi.InterfaceName] = oi.Owner
	}

	resp := &pb.GetRoutingOSPFNeighborsResponse{
		Neighbors: make([]*pb.RoutingOSPFNeighborInfo, 0, len(neighbors)),
	}

	for _, nbr := range neighbors {
		resp.Neighbors = append(resp.Neighbors, &pb.RoutingOSPFNeighborInfo{
			NeighborId:    nbr.NeighborID,
			Address:       nbr.Address,
			InterfaceName: nbr.Interface,
			State:         nbr.State,
			Owner:         ownerByIface[nbr.Interface],
		})
	}

	return resp, nil
}

// StreamRoutingEvents streams routing events to the client.
func (s *Server) StreamRoutingEvents(req *pb.StreamRoutingEventsRequest, stream pb.AgentControl_StreamRoutingEventsServer) error {
	if s.RoutingMgr == nil {
		return status.Error(codes.FailedPrecondition, "routing not enabled (overlay mode)")
	}

	ch := s.RoutingMgr.SubscribeEvents()
	defer s.RoutingMgr.UnsubscribeEvents(ch)

	typeFilter := make(map[string]bool, len(req.EventTypes))
	for _, t := range req.EventTypes {
		typeFilter[t] = true
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case evt, ok := <-ch:
			if !ok {
				return nil
			}

			if req.OwnerFilter != "" && evt.Owner != req.OwnerFilter {
				continue
			}

			if len(typeFilter) > 0 && !typeFilter[evt.EventType] {
				continue
			}

			if err := stream.Send(&pb.RoutingEvent{
				TimestampNs: time.Now().UnixNano(),
				EventType:   evt.EventType,
				Owner:       evt.Owner,
				Detail:      evt.Detail,
				Metadata:    evt.Metadata,
			}); err != nil {
				return fmt.Errorf("send routing event: %w", err)
			}
		}
	}
}
