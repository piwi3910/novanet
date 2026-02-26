package novaroute

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestNewClient(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.socketPath != "/run/novaroute/novaroute.sock" {
		t.Fatalf("expected socket path /run/novaroute/novaroute.sock, got %s", c.socketPath)
	}
	if c.owner != "novanet" {
		t.Fatalf("expected owner novanet, got %s", c.owner)
	}
	if c.token != "test-token" {
		t.Fatalf("expected token test-token, got %s", c.token)
	}
}

func TestRegisterNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	_, err := c.Register(context.Background())
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestConfigureBGPNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	err := c.ConfigureBGP(context.Background(), 65011, "192.168.100.11")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestApplyPeerNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	err := c.ApplyPeer(context.Background(), "192.168.100.12", 65012)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestAdvertisePrefixNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	err := c.AdvertisePrefix(context.Background(), "10.244.1.0/24")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestWithdrawPrefixNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	err := c.WithdrawPrefix(context.Background(), "10.244.1.0/24")
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestCloseNotConnected(t *testing.T) {
	c := NewClient("/run/novaroute/novaroute.sock", "novanet", "test-token", testLogger())

	err := c.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnectCanceled(t *testing.T) {
	c := NewClient("/tmp/nonexistent-novaroute.sock", "novanet", "test-token", testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := c.Connect(ctx)
	if err == nil {
		c.Close()
	}
}

func TestConnectSuccess(t *testing.T) {
	// grpc.NewClient with lazy connection succeeds even for non-existent sockets.
	c := NewClient("/tmp/nonexistent-novaroute.sock", "novanet", "test-token", testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := c.Connect(ctx)
	if err != nil {
		t.Fatalf("unexpected error (grpc.NewClient is lazy): %v", err)
	}
	defer c.Close()

	// Client field should be set.
	c.mu.Lock()
	hasClient := c.client != nil
	c.mu.Unlock()

	if !hasClient {
		t.Fatal("expected client to be set after Connect")
	}
}

func TestCloseAfterConnect(t *testing.T) {
	c := NewClient("/tmp/nonexistent-novaroute.sock", "novanet", "test-token", testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	c.Connect(ctx)

	err := c.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After close, client should be nil.
	c.mu.Lock()
	hasClient := c.client != nil
	c.mu.Unlock()

	if hasClient {
		t.Fatal("expected client to be nil after Close")
	}
}
