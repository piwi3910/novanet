package main

import (
	"net"
	"testing"

	"github.com/azrtydxb/novanet/internal/agent"
)

func TestGenerateMAC_Length(t *testing.T) {
	mac := agent.GenerateMAC(net.ParseIP("10.244.1.42"))
	if len(mac) != 6 {
		t.Errorf("expected 6-byte MAC, got %d bytes", len(mac))
	}
}

func TestGenerateMAC_LocallyAdministered(t *testing.T) {
	mac := agent.GenerateMAC(net.ParseIP("10.244.1.2"))
	if mac[0] != 0x02 {
		t.Errorf("expected first byte 0x02, got 0x%02X", mac[0])
	}
}

func TestGenerateMAC_SecondByte(t *testing.T) {
	mac := agent.GenerateMAC(net.ParseIP("172.16.0.1"))
	if mac[1] != 0xfe {
		t.Errorf("expected second byte 0xfe, got 0x%02X", mac[1])
	}
}

func TestGenerateMAC_IPEmbedded(t *testing.T) {
	ip := net.ParseIP("10.244.1.7")
	mac := agent.GenerateMAC(ip)
	ip4 := ip.To4()
	for i, b := range ip4 {
		if mac[2+i] != b {
			t.Errorf("mac[%d] = 0x%02X, want 0x%02X", 2+i, mac[2+i], b)
		}
	}
}

func TestGenerateMAC_Deterministic(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	mac1 := agent.GenerateMAC(ip)
	mac2 := agent.GenerateMAC(ip)
	if mac1.String() != mac2.String() {
		t.Errorf("expected deterministic MAC, got %s and %s", mac1, mac2)
	}
}

func TestGenerateMAC_Unique(t *testing.T) {
	mac1 := agent.GenerateMAC(net.ParseIP("10.0.0.1"))
	mac2 := agent.GenerateMAC(net.ParseIP("10.0.0.2"))
	if mac1.String() == mac2.String() {
		t.Errorf("expected distinct MACs, got %s for both", mac1)
	}
}

func TestGenerateMAC_NilIPv6(t *testing.T) {
	mac := agent.GenerateMAC(net.ParseIP("::1"))
	if len(mac) != 6 {
		t.Errorf("expected 6-byte MAC, got %d bytes", len(mac))
	}
	if mac[0] != 0x02 {
		t.Errorf("expected first byte 0x02, got 0x%02X", mac[0])
	}
}

func TestBuildLogger_ValidLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "DEBUG", "INFO", "WARN", "ERROR"} {
		t.Run(level, func(t *testing.T) {
			logger, err := agent.BuildLogger(level)
			if err != nil {
				t.Fatalf("BuildLogger(%q) error: %v", level, err)
			}
			if logger == nil {
				t.Fatalf("BuildLogger(%q) returned nil", level)
			}
			_ = logger.Sync()
		})
	}
}

func TestBuildLogger_UnknownLevel(t *testing.T) {
	logger, err := agent.BuildLogger("verbose")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	_ = logger.Sync()
}

func TestBuildLogger_EmptyLevel(t *testing.T) {
	logger, err := agent.BuildLogger("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	_ = logger.Sync()
}

func TestVersionConstant(t *testing.T) {
	if agent.Version == "" {
		t.Error("Version constant must not be empty")
	}
}
