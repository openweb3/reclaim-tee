package main

import "testing"

// TestRequireCleartextLoopback pins the fail-closed rule for the unauthenticated
// Hub-facing API: it may be served in the clear only where only this host can
// reach it. A deployment that needs to be reachable authenticates the listener
// with -mtls; one that binds a wildcard address by accident is refused.
func TestRequireCleartextLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:18090", "localhost:18090", "[::1]:18090"} {
		if err := requireCleartextLoopback(addr); err != nil {
			t.Errorf("requireCleartextLoopback(%q) = %v, want nil", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:18090", ":18090", "10.0.0.5:18090", "example.com:18090", "not-an-address"} {
		if err := requireCleartextLoopback(addr); err == nil {
			t.Errorf("requireCleartextLoopback(%q) = nil, want a refusal", addr)
		}
	}
}
