package frr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestResolveAFICLI_BGP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ipv4-unicast", "ipv4 unicast"},
		{"ipv4", "ipv4 unicast"},
		{"ipv6-unicast", "ipv6 unicast"},
		{"ipv6", "ipv6 unicast"},
		{"unknown", "unknown"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := resolveAFICLI(tt.input)
			if result != tt.expected {
				t.Errorf("resolveAFICLI(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestErrBGPNotConfigured(t *testing.T) {
	if ErrBGPNotConfigured == nil {
		t.Fatal("ErrBGPNotConfigured is nil")
	}
	if got := ErrBGPNotConfigured.Error(); got != "BGP local AS not configured" {
		t.Errorf("ErrBGPNotConfigured = %q, want %q", got, "BGP local AS not configured")
	}
}

func TestNeighborConfig(t *testing.T) {
	cfg := &NeighborConfig{
		SourceAddress: "192.168.1.1",
		EBGPMultihop:  5,
		Password:      "secret",
		Description:   "Test neighbor",
	}

	if cfg.SourceAddress != "192.168.1.1" {
		t.Errorf("SourceAddress = %q, want %q", cfg.SourceAddress, "192.168.1.1")
	}
	if cfg.EBGPMultihop != 5 {
		t.Errorf("EBGPMultihop = %d, want 5", cfg.EBGPMultihop)
	}
	if cfg.Password != "secret" {
		t.Errorf("Password = %q, want %q", cfg.Password, "secret")
	}
	if cfg.Description != "Test neighbor" {
		t.Errorf("Description = %q, want %q", cfg.Description, "Test neighbor")
	}
}

func TestNeighborConfig_Empty(t *testing.T) {
	cfg := &NeighborConfig{}

	if cfg.SourceAddress != "" {
		t.Errorf("SourceAddress = %q, want empty", cfg.SourceAddress)
	}
	if cfg.EBGPMultihop != 0 {
		t.Errorf("EBGPMultihop = %d, want 0", cfg.EBGPMultihop)
	}
	if cfg.Password != "" {
		t.Errorf("Password = %q, want empty", cfg.Password)
	}
	if cfg.Description != "" {
		t.Errorf("Description = %q, want empty", cfg.Description)
	}
}

func TestBGPGracefulRestartCommands(t *testing.T) {
	commands := bgpGracefulRestartCommands()

	if len(commands) == 0 {
		t.Fatal("bgpGracefulRestartCommands returned empty slice")
	}
	if !strings.Contains(commands[0], "bgp graceful-restart") {
		t.Errorf("commands[0] = %q, want to contain %q", commands[0], "bgp graceful-restart")
	}
	if !strings.Contains(commands[1], "bgp graceful-restart restart-time") {
		t.Errorf("commands[1] = %q, want to contain %q", commands[1], "bgp graceful-restart restart-time")
	}
	if !strings.Contains(commands[2], "bgp graceful-restart stalepath-time") {
		t.Errorf("commands[2] = %q, want to contain %q", commands[2], "bgp graceful-restart stalepath-time")
	}
}

func TestClient_GetLocalAS(t *testing.T) {
	logger := zap.NewNop()
	client := NewClient("/tmp", logger)

	// Initially returns 0
	localAS := client.GetLocalAS()
	if localAS != 0 {
		t.Errorf("GetLocalAS() = %d, want 0", localAS)
	}
}

func TestClient_GetLocalAS_AfterConfig(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP global
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Now GetLocalAS should return the configured AS
	localAS := client.GetLocalAS()
	if localAS != 65001 {
		t.Errorf("GetLocalAS() = %d, want 65001", localAS)
	}
}

func TestClient_AddNeighbor_NoBGPConfig(t *testing.T) {
	logger := zap.NewNop()
	client := NewClient("/tmp", logger)
	ctx := context.Background()

	// Should fail because BGP is not configured
	err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "BGP local AS not configured") {
		t.Errorf("error = %q, want to contain %q", err, "BGP local AS not configured")
	}
}

func TestClient_ConfigureBGPGlobal(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Verify commands were sent
	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "router bgp 65001")
	assertStdinContains(t, stdin, "bgp router-id 10.0.0.1")
}

func TestClient_ConfigureBGPGlobal_InvalidAS(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	// AS 0 should still work (FRR will handle validation)
	err := client.ConfigureBGPGlobal(ctx, 0, "10.0.0.1")
	// The fake vtysh always succeeds, so we just verify it doesn't panic
	if err != nil {
		t.Errorf("ConfigureBGPGlobal: unexpected error: %v", err)
	}
}

func TestClient_ReconfigureBGPGlobal_SameAS(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// First configuration
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Same AS - should just update router-id
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.2"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "router bgp 65001")
	assertStdinContains(t, stdin, "bgp router-id 10.0.0.2")
}

func TestClient_ReconfigureBGPGlobal_DifferentAS(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// First configuration
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Different AS - should remove old and create new
	if err := client.ReconfigureBGPGlobal(ctx, 65001, 65002, "10.0.0.1"); err != nil {
		t.Fatalf("ReconfigureBGPGlobal: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "no router bgp 65001")
	assertStdinContains(t, stdin, "router bgp 65002")
}

func TestClient_AddNeighbor(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Add neighbor
	if err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, nil); err != nil {
		t.Fatalf("AddNeighbor: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "router bgp 65001")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 remote-as 65002")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 timers 10 30")
}

func TestClient_AddNeighbor_WithConfig(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Add neighbor with config
	cfg := &NeighborConfig{
		SourceAddress: "192.168.1.1",
		EBGPMultihop:  5,
		Password:      "secret123",
		Description:   "Test peer",
	}
	if err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, cfg); err != nil {
		t.Fatalf("AddNeighbor: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 update-source 192.168.1.1")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 ebgp-multihop 5")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 password secret123")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 description Test peer")
}

func TestClient_AddNeighbor_NoTimers(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Add neighbor without timers
	if err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 0, 0, nil); err != nil {
		t.Fatalf("AddNeighbor: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	// Timers should not be configured
	if strings.Contains(stdin, "timers") {
		t.Errorf("stdin contains 'timers' but should not: %s", stdin)
	}
}

func TestClient_RemoveNeighbor(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Remove neighbor
	if err := client.RemoveNeighbor(ctx, "192.168.1.2"); err != nil {
		t.Fatalf("RemoveNeighbor: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "router bgp 65001")
	assertStdinContains(t, stdin, "no neighbor 192.168.1.2")
}

func TestClient_ActivateNeighborAFI(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Activate AFI
	if err := client.ActivateNeighborAFI(ctx, "192.168.1.2", "ipv4"); err != nil {
		t.Fatalf("ActivateNeighborAFI: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "address-family ipv4 unicast")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 activate")
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 soft-reconfiguration inbound")
}

func TestClient_ActivateNeighborAFI_IPv6(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Activate IPv6 AFI
	if err := client.ActivateNeighborAFI(ctx, "2001:db8::2", "ipv6-unicast"); err != nil {
		t.Fatalf("ActivateNeighborAFI: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "address-family ipv6 unicast")
}

func TestClient_AdvertiseNetwork(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Advertise network
	if err := client.AdvertiseNetwork(ctx, "10.0.0.0/24", "ipv4"); err != nil {
		t.Fatalf("AdvertiseNetwork: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "address-family ipv4 unicast")
	assertStdinContains(t, stdin, "network 10.0.0.0/24")
}

func TestClient_WithdrawNetwork(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Withdraw network
	if err := client.WithdrawNetwork(ctx, "10.0.0.0/24", "ipv4"); err != nil {
		t.Fatalf("WithdrawNetwork: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "address-family ipv4 unicast")
	assertStdinContains(t, stdin, "no network 10.0.0.0/24")
}

func TestClient_SetNeighborMaxPrefix(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Set max prefix
	if err := client.SetNeighborMaxPrefix(ctx, "192.168.1.2", 1000, false, "ipv4"); err != nil {
		t.Fatalf("SetNeighborMaxPrefix: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 maximum-prefix 1000")
	if strings.Contains(stdin, "warning-only") {
		t.Errorf("stdin contains 'warning-only' but should not")
	}
}

func TestClient_SetNeighborMaxPrefix_WarningOnly(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Set max prefix with warning only
	if err := client.SetNeighborMaxPrefix(ctx, "192.168.1.2", 1000, true, "ipv4"); err != nil {
		t.Fatalf("SetNeighborMaxPrefix: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 maximum-prefix 1000 warning-only")
}

func TestClient_ConfigureRouteMap(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Configure route-map
	setCmds := []string{"set local-preference 200", "set community 65001:100"}
	if err := client.ConfigureRouteMap(ctx, "test-map", setCmds); err != nil {
		t.Fatalf("ConfigureRouteMap: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "no route-map test-map")
	assertStdinContains(t, stdin, "route-map test-map permit 10")
	assertStdinContains(t, stdin, "set local-preference 200")
	assertStdinContains(t, stdin, "set community 65001:100")
	assertStdinContains(t, stdin, "exit")
}

func TestClient_ConfigureRouteMap_Empty(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Configure route-map with no set commands
	if err := client.ConfigureRouteMap(ctx, "empty-map", nil); err != nil {
		t.Fatalf("ConfigureRouteMap: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "no route-map empty-map")
	assertStdinContains(t, stdin, "route-map empty-map permit 10")
}

func TestClient_AdvertiseNetworkWithRouteMap(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Advertise network with route-map
	if err := client.AdvertiseNetworkWithRouteMap(ctx, "10.0.0.0/24", "ipv4", "test-map"); err != nil {
		t.Fatalf("AdvertiseNetworkWithRouteMap: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "address-family ipv4 unicast")
	assertStdinContains(t, stdin, "network 10.0.0.0/24 route-map test-map")
}

func TestClient_RemoveRouteMap(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Remove route-map
	if err := client.RemoveRouteMap(ctx, "test-map"); err != nil {
		t.Fatalf("RemoveRouteMap: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "no route-map test-map")
}

func TestClient_SetNeighborBFD_Enable(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Enable BFD
	if err := client.SetNeighborBFD(ctx, "192.168.1.2", true); err != nil {
		t.Fatalf("SetNeighborBFD: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "neighbor 192.168.1.2 bfd")
}

func TestClient_SetNeighborBFD_Disable(t *testing.T) {
	client, dir := setupFakeVtysh(t)
	ctx := context.Background()

	// Configure BGP first
	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	// Clear recorded stdin
	_ = os.Remove(filepath.Join(dir, "stdin"))

	// Disable BFD
	if err := client.SetNeighborBFD(ctx, "192.168.1.2", false); err != nil {
		t.Fatalf("SetNeighborBFD: %v", err)
	}

	stdin := readRecordedStdin(t, dir)
	assertStdinContains(t, stdin, "no neighbor 192.168.1.2 bfd")
}

// --- VTY command injection prevention tests ---

func TestClient_AddNeighbor_InvalidAddr(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	err := client.AddNeighbor(ctx, "not-an-ip", 65002, "external", 10, 30, nil)
	if err == nil {
		t.Fatal("expected error for non-IP address")
	}
	if !strings.Contains(err.Error(), "invalid IP address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_AddNeighbor_InjectionInDescription(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	cfg := &NeighborConfig{
		Description: "legit\nroute-map EVIL permit 10",
	}
	err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, cfg)
	if err == nil {
		t.Fatal("expected error for newline in description")
	}
	if !strings.Contains(err.Error(), "description") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_AddNeighbor_InjectionInPassword(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	cfg := &NeighborConfig{
		Password: "pass\nneighbor 10.0.0.1 remote-as 666",
	}
	err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, cfg)
	if err == nil {
		t.Fatal("expected error for newline in password")
	}
	if !strings.Contains(err.Error(), "password") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_AddNeighbor_InvalidSourceAddress(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	if err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1"); err != nil {
		t.Fatalf("ConfigureBGPGlobal: %v", err)
	}

	cfg := &NeighborConfig{
		SourceAddress: "not-valid-ip",
	}
	err := client.AddNeighbor(ctx, "192.168.1.2", 65002, "external", 10, 30, cfg)
	if err == nil {
		t.Fatal("expected error for invalid source address")
	}
	if !strings.Contains(err.Error(), "source-address") || !strings.Contains(err.Error(), "invalid IP address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_ConfigureBGPGlobal_InjectionInRouterID(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	err := client.ConfigureBGPGlobal(ctx, 65001, "10.0.0.1\nrouter bgp 666")
	if err == nil {
		t.Fatal("expected error for newline in router-id")
	}
	if !strings.Contains(err.Error(), "router-id") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_AdvertiseNetwork_InjectionInPrefix(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()
	client.localAS = 65001

	err := client.AdvertiseNetwork(ctx, "10.0.0.0/24\nroute-map EVIL permit 10", "ipv4")
	if err == nil {
		t.Fatal("expected error for newline in prefix")
	}
	if !strings.Contains(err.Error(), "prefix") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_WithdrawNetwork_InjectionInPrefix(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()
	client.localAS = 65001

	err := client.WithdrawNetwork(ctx, "10.0.0.0/24\nevil-command", "ipv4")
	if err == nil {
		t.Fatal("expected error for newline in prefix")
	}
	if !strings.Contains(err.Error(), "prefix") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_ConfigureRouteMap_InjectionInName(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	err := client.ConfigureRouteMap(ctx, "my-map\nevil-command", nil)
	if err == nil {
		t.Fatal("expected error for newline in route-map name")
	}
	if !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_ConfigureRouteMap_InjectionInSetCmd(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	setCmds := []string{"set local-preference 200\nevil-command"}
	err := client.ConfigureRouteMap(ctx, "test-map", setCmds)
	if err == nil {
		t.Fatal("expected error for newline in set command")
	}
	if !strings.Contains(err.Error(), "set command 0") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestClient_RemoveRouteMap_InjectionInName(t *testing.T) {
	client, _ := setupFakeVtysh(t)
	ctx := context.Background()

	err := client.RemoveRouteMap(ctx, "my-map\nevil")
	if err == nil {
		t.Fatal("expected error for newline in route-map name")
	}
	if !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "control characters") {
		t.Errorf("unexpected error: %v", err)
	}
}

// Benchmark tests
func BenchmarkResolveAFICLI(b *testing.B) {
	inputs := []string{"ipv4", "ipv6", "ipv4-unicast", "ipv6-unicast"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveAFICLI(inputs[i%len(inputs)])
	}
}
