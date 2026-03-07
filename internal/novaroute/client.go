// Package novaroute provides a gRPC client for communicating with the
// NovaRoute routing control plane via its Unix domain socket.
package novaroute

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	nrpb "github.com/azrtydxb/NovaRoute/api/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ErrNotConnected is returned when an RPC is attempted before Connect.
var ErrNotConnected = errors.New("not connected to NovaRoute")

// Client wraps a NovaRoute gRPC connection with retry logic and lifecycle management.
type Client struct {
	mu sync.Mutex

	socketPath string
	owner      string
	token      string
	logger     *zap.Logger

	conn   *grpc.ClientConn
	client nrpb.RouteControlClient
}

// NewClient creates a new NovaRoute client.
func NewClient(socketPath, owner, token string, logger *zap.Logger) *Client {
	return &Client{
		socketPath: socketPath,
		owner:      owner,
		token:      token,
		logger:     logger,
	}
}

// Connect dials the NovaRoute Unix socket with retries.
func (c *Client) Connect(ctx context.Context) error {
	const maxRetries = 10
	delay := time.Second

	for attempt := 1; ; attempt++ {
		conn, err := grpc.NewClient(
			"unix://"+c.socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err == nil {
			c.mu.Lock()
			c.conn = conn
			c.client = nrpb.NewRouteControlClient(conn)
			c.mu.Unlock()
			c.logger.Info("connected to NovaRoute", zap.String("socket", c.socketPath))
			return nil
		}

		if attempt >= maxRetries {
			return fmt.Errorf("failed to connect after %d attempts: %w", attempt, err)
		}

		c.logger.Warn("NovaRoute connect failed, retrying",
			zap.Error(err), zap.Int("attempt", attempt))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 10*time.Second {
			delay *= 2
		}
	}
}

// Register registers this agent with NovaRoute.
func (c *Client) Register(ctx context.Context) (*nrpb.RegisterResponse, error) {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()

	if cl == nil {
		return nil, ErrNotConnected
	}

	resp, err := cl.Register(ctx, &nrpb.RegisterRequest{
		Owner:           c.owner,
		Token:           c.token,
		ReassertIntents: true,
	})
	if err != nil {
		return nil, fmt.Errorf("register RPC: %w", err)
	}

	c.logger.Info("registered with NovaRoute",
		zap.String("owner", c.owner),
		zap.Strings("current_prefixes", resp.CurrentPrefixes),
	)
	return resp, nil
}

// ConfigureBGP sets the BGP global configuration (AS number and router ID).
func (c *Client) ConfigureBGP(ctx context.Context, localAS uint32, routerID string) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()

	if cl == nil {
		return ErrNotConnected
	}

	_, err := cl.ConfigureBGP(ctx, &nrpb.ConfigureBGPRequest{
		Owner:    c.owner,
		Token:    c.token,
		LocalAs:  localAS,
		RouterId: routerID,
	})
	if err != nil {
		return fmt.Errorf("configure BGP RPC: %w", err)
	}

	c.logger.Info("configured BGP",
		zap.Uint32("local_as", localAS),
		zap.String("router_id", routerID),
	)
	return nil
}

// BFDOptions holds BFD configuration for a BGP peer.
type BFDOptions struct {
	Enabled          bool
	MinRxMs          uint32
	MinTxMs          uint32
	DetectMultiplier uint32
}

// ApplyPeer adds or updates a BGP peer with optional BFD configuration.
func (c *Client) ApplyPeer(ctx context.Context, neighborAddr string, remoteAS uint32, bfd *BFDOptions) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()

	if cl == nil {
		return ErrNotConnected
	}

	peer := &nrpb.BGPPeer{
		NeighborAddress: neighborAddr,
		RemoteAs:        remoteAS,
		PeerType:        nrpb.PeerType_PEER_TYPE_EXTERNAL,
		AddressFamilies: []nrpb.AddressFamily{nrpb.AddressFamily_ADDRESS_FAMILY_IPV4_UNICAST},
	}
	if bfd != nil && bfd.Enabled {
		peer.BfdEnabled = true
		peer.BfdMinRxMs = bfd.MinRxMs
		peer.BfdMinTxMs = bfd.MinTxMs
		peer.BfdDetectMultiplier = bfd.DetectMultiplier
	}

	_, err := cl.ApplyPeer(ctx, &nrpb.ApplyPeerRequest{
		Owner: c.owner,
		Token: c.token,
		Peer:  peer,
	})
	if err != nil {
		return fmt.Errorf("apply peer %s AS%d: %w", neighborAddr, remoteAS, err)
	}

	c.logger.Info("applied BGP peer",
		zap.String("neighbor", neighborAddr),
		zap.Uint32("remote_as", remoteAS),
		zap.Bool("bfd", bfd != nil && bfd.Enabled),
	)
	return nil
}

// AdvertisePrefix advertises a route prefix via BGP.
func (c *Client) AdvertisePrefix(ctx context.Context, prefix string) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()

	if cl == nil {
		return ErrNotConnected
	}

	_, err := cl.AdvertisePrefix(ctx, &nrpb.AdvertisePrefixRequest{
		Owner:    c.owner,
		Token:    c.token,
		Prefix:   prefix,
		Protocol: nrpb.Protocol_PROTOCOL_BGP,
	})
	if err != nil {
		return fmt.Errorf("advertise prefix %s: %w", prefix, err)
	}

	c.logger.Info("advertised prefix", zap.String("prefix", prefix))
	return nil
}

// WithdrawPrefix withdraws a previously advertised prefix.
func (c *Client) WithdrawPrefix(ctx context.Context, prefix string) error {
	c.mu.Lock()
	cl := c.client
	c.mu.Unlock()

	if cl == nil {
		return ErrNotConnected
	}

	_, err := cl.WithdrawPrefix(ctx, &nrpb.WithdrawPrefixRequest{
		Owner:    c.owner,
		Token:    c.token,
		Prefix:   prefix,
		Protocol: nrpb.Protocol_PROTOCOL_BGP,
	})
	if err != nil {
		return fmt.Errorf("withdraw prefix %s: %w", prefix, err)
	}

	c.logger.Info("withdrew prefix", zap.String("prefix", prefix))
	return nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.client = nil
	c.mu.Unlock()

	if conn == nil {
		return nil
	}
	return conn.Close()
}
