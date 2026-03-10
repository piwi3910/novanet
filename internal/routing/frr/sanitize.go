package frr

import (
	"errors"
	"fmt"
	"net"
	"unicode"
)

// ErrInvalidVTYParam is returned when a VTY command parameter contains
// control characters that could inject arbitrary FRR configuration.
var ErrInvalidVTYParam = errors.New("invalid VTY parameter: contains control characters")

// ErrInvalidIPAddress is returned when a string is not a valid IP address.
var ErrInvalidIPAddress = errors.New("invalid IP address")

// sanitizeVTYParam validates that a string parameter intended for use in a
// VTY command does not contain newlines, carriage returns, or other control
// characters. These characters would allow injection of arbitrary FRR
// configuration lines.
func sanitizeVTYParam(s string) (string, error) {
	for i, r := range s {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: character U+%04X at byte offset %d", ErrInvalidVTYParam, r, i)
		}
	}
	return s, nil
}

// validateIPAddress checks that addr is a valid IPv4 or IPv6 address.
func validateIPAddress(addr string) error {
	if net.ParseIP(addr) == nil {
		return fmt.Errorf("%w: %q", ErrInvalidIPAddress, addr)
	}
	return nil
}
