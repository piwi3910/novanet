package frr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeVTYParam_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"simple string", "hello"},
		{"with spaces", "test peer description"},
		{"with dashes", "my-route-map"},
		{"with dots", "192.168.1.1"},
		{"with slashes", "10.0.0.0/24"},
		{"with colons", "2001:db8::1"},
		{"password with symbols", "s3cr3t!@#$%"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeVTYParam(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.input, result)
		})
	}
}

func TestSanitizeVTYParam_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"newline", "hello\nworld"},
		{"carriage return", "hello\rworld"},
		{"crlf", "hello\r\nworld"},
		{"tab", "hello\tworld"},
		{"null byte", "hello\x00world"},
		{"bell", "hello\x07world"},
		{"escape", "hello\x1bworld"},
		{"newline at start", "\nmalicious config"},
		{"newline at end", "value\n"},
		{"inject route-map", "legitimate\nroute-map EVIL permit 10"},
		{"inject neighbor", "desc\nneighbor 10.0.0.1 remote-as 666"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizeVTYParam(tt.input)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidVTYParam))
		})
	}
}

func TestValidateIPAddress_Valid(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"ipv4", "192.168.1.1"},
		{"ipv4 loopback", "127.0.0.1"},
		{"ipv4 zeros", "0.0.0.0"},
		{"ipv6", "2001:db8::1"},
		{"ipv6 loopback", "::1"},
		{"ipv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{"ipv4-mapped ipv6", "::ffff:192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPAddress(tt.addr)
			assert.NoError(t, err)
		})
	}
}

func TestValidateIPAddress_Invalid(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"empty", ""},
		{"hostname", "example.com"},
		{"cidr notation", "10.0.0.0/24"},
		{"with port", "192.168.1.1:8080"},
		{"garbage", "not-an-ip"},
		{"partial ipv4", "192.168.1"},
		{"overflow octet", "256.1.1.1"},
		{"injection attempt", "192.168.1.1\nrouter bgp 666"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPAddress(tt.addr)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidIPAddress))
		})
	}
}
