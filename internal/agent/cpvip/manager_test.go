package cpvip

import (
	"testing"
)

func TestVipPrefix(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"10.0.0.1", "/32"},
		{"192.168.1.100", "/32"},
		{"fd00::1", "/128"},
		{"2001:db8::1", "/128"},
		{"::ffff:10.0.0.1", "/128"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := vipPrefix(tt.ip)
			if got != tt.want {
				t.Errorf("vipPrefix(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCheckHealthIPv6URL(t *testing.T) {
	cases := []struct {
		nodeIP  string
		wantURL string
	}{
		{"10.0.0.1", "https://10.0.0.1:6443/livez"},
		{"fd00::1", "https://[fd00::1]:6443/livez"},
	}
	for _, tc := range cases {
		t.Run(tc.nodeIP, func(t *testing.T) {
			host := tc.nodeIP
			for _, ch := range host {
				if ch == ':' {
					host = "[" + tc.nodeIP + "]"
					break
				}
			}
			url := "https://" + host + ":6443/livez"
			if url != tc.wantURL {
				t.Errorf("got URL %q, want %q", url, tc.wantURL)
			}
		})
	}
}
