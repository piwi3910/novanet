// Package testutil provides shared test helpers for the novanet project.
package testutil

import (
	"context"

	"github.com/azrtydxb/novanet/internal/dataplane"
)

// MockDataplane implements dataplane.ClientInterface with no-op methods.
// Embed this in test-specific mocks to only override methods you care about.
type MockDataplane struct{}

// Ensure MockDataplane satisfies the interface at compile time.
var _ dataplane.ClientInterface = (*MockDataplane)(nil)

// Connect implements dataplane.ClientInterface.
func (m *MockDataplane) Connect(_ context.Context) error { return nil }

// UpsertEndpoint implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertEndpoint(_ context.Context, _ *dataplane.Endpoint) error { return nil }

// DeleteEndpoint implements dataplane.ClientInterface.
func (m *MockDataplane) DeleteEndpoint(_ context.Context, _ string) error { return nil }

// UpsertPolicy implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertPolicy(_ context.Context, _ *dataplane.PolicyRule) error { return nil }

// DeletePolicy implements dataplane.ClientInterface.
func (m *MockDataplane) DeletePolicy(_ context.Context, _ *dataplane.PolicyRule) error { return nil }

// SyncPolicies implements dataplane.ClientInterface.
func (m *MockDataplane) SyncPolicies(_ context.Context, _ []*dataplane.PolicyRule) (*dataplane.SyncResult, error) {
	return &dataplane.SyncResult{}, nil
}

// UpsertTunnel implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertTunnel(_ context.Context, _ string, _, _ uint32) error { return nil }

// DeleteTunnel implements dataplane.ClientInterface.
func (m *MockDataplane) DeleteTunnel(_ context.Context, _ string) error { return nil }

// UpdateConfig implements dataplane.ClientInterface.
func (m *MockDataplane) UpdateConfig(_ context.Context, _ map[uint32]uint64) error { return nil }

// AttachProgram implements dataplane.ClientInterface.
func (m *MockDataplane) AttachProgram(_ context.Context, _ string, _ dataplane.AttachType) error {
	return nil
}

// DetachProgram implements dataplane.ClientInterface.
func (m *MockDataplane) DetachProgram(_ context.Context, _ string, _ dataplane.AttachType) error {
	return nil
}

// StreamFlows implements dataplane.ClientInterface.
func (m *MockDataplane) StreamFlows(_ context.Context, _ uint32) (<-chan *dataplane.FlowEvent, error) {
	return nil, nil
}

// GetStatus implements dataplane.ClientInterface.
func (m *MockDataplane) GetStatus(_ context.Context) (*dataplane.Status, error) { return nil, nil }

// UpsertSockmapEndpoint implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertSockmapEndpoint(_ context.Context, _ string, _ uint32) error {
	return nil
}

// DeleteSockmapEndpoint implements dataplane.ClientInterface.
func (m *MockDataplane) DeleteSockmapEndpoint(_ context.Context, _ string, _ uint32) error {
	return nil
}

// GetSockmapStats implements dataplane.ClientInterface.
func (m *MockDataplane) GetSockmapStats(_ context.Context) (*dataplane.SockmapStats, error) {
	return nil, nil
}

// UpsertMeshService implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertMeshService(_ context.Context, _ string, _, _ uint32) error {
	return nil
}

// DeleteMeshService implements dataplane.ClientInterface.
func (m *MockDataplane) DeleteMeshService(_ context.Context, _ string, _ uint32) error {
	return nil
}

// ListMeshServices implements dataplane.ClientInterface.
func (m *MockDataplane) ListMeshServices(_ context.Context) ([]*dataplane.MeshServiceEntry, error) {
	return nil, nil
}

// UpdateRateLimitConfig implements dataplane.ClientInterface.
func (m *MockDataplane) UpdateRateLimitConfig(_ context.Context, _, _ uint32, _ uint64) error {
	return nil
}

// GetRateLimitStats implements dataplane.ClientInterface.
func (m *MockDataplane) GetRateLimitStats(_ context.Context) (*dataplane.RateLimitStats, error) {
	return nil, nil
}

// GetBackendHealthStats implements dataplane.ClientInterface.
func (m *MockDataplane) GetBackendHealthStats(_ context.Context, _ string, _ uint32) ([]*dataplane.BackendHealthInfo, error) {
	return nil, nil
}

// UpsertBackends implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertBackends(_ context.Context, _ []*dataplane.Backend) error {
	return nil
}

// UpsertServiceEntry implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertServiceEntry(_ context.Context, _ *dataplane.ServiceConfig) error {
	return nil
}

// UpsertEgressPolicy implements dataplane.ClientInterface.
func (m *MockDataplane) UpsertEgressPolicy(_ context.Context, _ *dataplane.EgressPolicy) error {
	return nil
}

// DeleteEgressPolicy implements dataplane.ClientInterface.
func (m *MockDataplane) DeleteEgressPolicy(_ context.Context, _ uint32, _ string, _ uint32) error {
	return nil
}

// Close implements dataplane.ClientInterface.
func (m *MockDataplane) Close() error { return nil }
