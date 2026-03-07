package main

import (
	"fmt"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// callTimeout is the maximum time to wait for a gRPC call response.
	callTimeout = 10 * time.Second
)

// connectAgent dials the agent gRPC socket and returns a client connection.
func connectAgent() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+agentSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to novanet-agent at %s: %w", agentSocket, err)
	}
	return conn, nil
}

// newAgentClient creates an AgentControl client from a gRPC connection.
func newAgentClient(conn *grpc.ClientConn) pb.AgentControlClient {
	return pb.NewAgentControlClient(conn)
}

// connectDataplane dials the dataplane gRPC socket and returns a client connection.
func connectDataplane() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+dataplaneSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dataplane at %s: %w", dataplaneSocket, err)
	}
	return conn, nil
}
