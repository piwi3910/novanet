// Package main tests for the NovaNet agent daemon.
package main

import (
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// generateMAC
// ---------------------------------------------------------------------------

func TestGenerateMAC_Length(t *testing.T) {
	ip := net.ParseIP("10.244.1.42")
	mac := generateMAC(ip)

	if len(mac) != 6 {
		t.Errorf("expected 6-byte MAC, got %d bytes", len(mac))
	}
}

// TestGenerateMAC_LocallyAdministered verifies the first byte has the
// locally-administered bit (0x02) set and the multicast bit (0x01) clear.
func TestGenerateMAC_LocallyAdministered(t *testing.T) {
	mac := generateMAC(net.ParseIP("10.244.1.2"))

	if mac[0] != 0x02 {
		t.Errorf("expected first byte 0x02 (locally administered), got 0x%02X", mac[0])
	}
}

// TestGenerateMAC_SecondByte verifies that the second byte is the fixed 0xfe
// prefix used to distinguish novanet MACs.
func TestGenerateMAC_SecondByte(t *testing.T) {
	mac := generateMAC(net.ParseIP("172.16.0.1"))

	if mac[1] != 0xfe {
		t.Errorf("expected second byte 0xfe, got 0x%02X", mac[1])
	}
}

// TestGenerateMAC_IPEmbedded verifies that the last four bytes of the MAC are
// the four octets of the IPv4 address.
func TestGenerateMAC_IPEmbedded(t *testing.T) {
	ip := net.ParseIP("10.244.1.7")
	mac := generateMAC(ip)
	ip4 := ip.To4()

	for i, b := range ip4 {
		if mac[2+i] != b {
			t.Errorf("mac[%d] = 0x%02X, want 0x%02X (from IP %s)", 2+i, mac[2+i], b, ip)
		}
	}
}

// TestGenerateMAC_Deterministic verifies that two calls with the same IP
// produce identical MACs.
func TestGenerateMAC_Deterministic(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	mac1 := generateMAC(ip)
	mac2 := generateMAC(ip)

	if mac1.String() != mac2.String() {
		t.Errorf("expected deterministic MAC, got %s and %s", mac1, mac2)
	}
}

// TestGenerateMAC_Unique verifies that different IPs produce different MACs.
func TestGenerateMAC_Unique(t *testing.T) {
	mac1 := generateMAC(net.ParseIP("10.0.0.1"))
	mac2 := generateMAC(net.ParseIP("10.0.0.2"))

	if mac1.String() == mac2.String() {
		t.Errorf("expected distinct MACs for distinct IPs, got %s for both", mac1)
	}
}

// TestGenerateMAC_NilIPv6 verifies that a nil / non-IPv4 address returns the
// zero fallback MAC without panicking.
func TestGenerateMAC_NilIPv6(t *testing.T) {
	mac := generateMAC(net.ParseIP("::1"))

	if len(mac) != 6 {
		t.Errorf("expected 6-byte fallback MAC, got %d bytes", len(mac))
	}
	// The fallback is all-zeros except the first byte.
	if mac[0] != 0x02 {
		t.Errorf("expected fallback first byte 0x02, got 0x%02X", mac[0])
	}
}

// ---------------------------------------------------------------------------
// buildLogger
// ---------------------------------------------------------------------------

func TestBuildLogger_ValidLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error", "DEBUG", "INFO", "WARN", "ERROR"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			logger, err := buildLogger(level)
			if err != nil {
				t.Fatalf("buildLogger(%q) returned error: %v", level, err)
			}
			if logger == nil {
				t.Fatalf("buildLogger(%q) returned nil logger", level)
			}
			_ = logger.Sync()
		})
	}
}

// TestBuildLogger_UnknownLevel verifies that an unrecognised level string falls
// back to Info (rather than returning an error).
func TestBuildLogger_UnknownLevel(t *testing.T) {
	logger, err := buildLogger("verbose")
	if err != nil {
		t.Fatalf("unexpected error for unknown level: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger for unknown level")
	}
	_ = logger.Sync()
}

// TestBuildLogger_EmptyLevel verifies that an empty string is treated like
// "info" and does not cause an error.
func TestBuildLogger_EmptyLevel(t *testing.T) {
	logger, err := buildLogger("")
	if err != nil {
		t.Fatalf("unexpected error for empty level: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger for empty level")
	}
	_ = logger.Sync()
}

// ---------------------------------------------------------------------------
// Version constant
// ---------------------------------------------------------------------------

// TestVersionConstant ensures the Version constant is populated so an
// accidental blank-out is detected.
func TestVersionConstant(t *testing.T) {
	if Version == "" {
		t.Error("Version constant must not be empty")
	}
}
