package tee

import (
	"strings"
	"testing"
)

// TestForwardResponseHeadersKeepsOnlyTheAllowlist pins the relay contract: the
// Hub may only ever see headers the receipt will attest. A header outside the
// allowlist — however useful it looks — must not cross the seam, and the
// transport's own map must not be mutated.
func TestForwardResponseHeadersKeepsOnlyTheAllowlist(t *testing.T) {
	src := map[string][]string{
		"Content-Type":      {"text/event-stream"},
		"Retry-After":       {"30"},
		"X-Request-Id":      {"req_123"},
		"Set-Cookie":        {"session=secret"},
		"X-Internal-Secret": {"do-not-leak"},
	}
	got := ForwardResponseHeaders(src)

	if _, ok := got["Set-Cookie"]; ok {
		t.Error("Set-Cookie crossed the seam")
	}
	if _, ok := got["X-Internal-Secret"]; ok {
		t.Error("X-Internal-Secret crossed the seam")
	}
	if len(got["Content-Type"]) != 1 || got["Content-Type"][0] != "text/event-stream" {
		t.Errorf("content-type = %v, want [text/event-stream]", got["Content-Type"])
	}
	if len(got["Retry-After"]) != 1 || got["Retry-After"][0] != "30" {
		t.Errorf("retry-after = %v, want [30]", got["Retry-After"])
	}
	if len(got["X-Request-Id"]) != 1 || got["X-Request-Id"][0] != "req_123" {
		t.Errorf("x-request-id = %v, want [req_123]", got["X-Request-Id"])
	}
	// The transport's map is untouched: forwarding must not mutate its input.
	if len(src) != 5 {
		t.Errorf("source map changed size: %d, want 5", len(src))
	}
}

// TestForwardResponseHeadersMatchesByCaseInsensitiveName pins that the
// allowlist matches header names case-insensitively, as HTTP requires.
func TestForwardResponseHeadersMatchesByCaseInsensitiveName(t *testing.T) {
	got := ForwardResponseHeaders(map[string][]string{
		"CONTENT-TYPE": {"text/event-stream"},
	})
	if len(got["CONTENT-TYPE"]) != 1 {
		t.Error("allowlist did not match an uppercased header name")
	}
}

// TestHashResponseHeadersIsDeterministic pins the two properties the receipt
// binding depends on: the digest is a pure function of the header set (map
// iteration order, key order, and value order across calls must not matter for
// the map itself), and case-normalisation means the same header written two
// ways hashes identically.
func TestHashResponseHeadersIsDeterministic(t *testing.T) {
	a := HashResponseHeaders(map[string][]string{
		"Content-Type": {"text/event-stream"},
		"Retry-After":  {"30"},
	})
	b := HashResponseHeaders(map[string][]string{
		"retry-after":  {"30"},
		"content-type": {"text/event-stream"},
	})
	if a != b {
		t.Fatal("same header set hashed differently across builds")
	}

	// An empty set is a real set: it hashes to something, and it is not the
	// same as a set with one empty-named entry. (The latter cannot occur on
	// the wire, but the digest should still be unambiguous.)
	empty := HashResponseHeaders(nil)
	withValue := HashResponseHeaders(map[string][]string{"retry-after": {""}})
	if empty == withValue {
		t.Fatal("empty and non-empty header sets collide")
	}
}

// TestAllowedResponseHeadersListIsCompleteAndNormalised guards the allowlist
// itself: every entry must be lowercase (the matcher lowercases anyway, but a
// non-normalised entry would be dead weight and a trap), non-empty, and free
// of whitespace that could never match a real header name.
func TestAllowedResponseHeadersListIsCompleteAndNormalised(t *testing.T) {
	for name := range AllowedResponseHeaders {
		if name != strings.ToLower(name) {
			t.Errorf("allowlist entry %q is not lowercase", name)
		}
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
			t.Errorf("allowlist entry %q is not a valid header name", name)
		}
	}
}

// TestForwardResponseHeadersCarriesWhatCodexReads pins that a buyer's Codex
// gets the headers it acts on from a subscription response, and that the
// seller's quota and credit headers on the same response stay behind.
func TestForwardResponseHeadersCarriesWhatCodexReads(t *testing.T) {
	src := map[string][]string{
		"X-Codex-Turn-State":                    {"sticky"},
		"X-Models-Etag":                         {"W/\"e0\""},
		"X-Reasoning-Included":                  {"true"},
		"Openai-Model":                          {"gpt-6.1-sol"},
		"X-Codex-Safety-Buffering-Enabled":      {"true"},
		"X-Codex-Safety-Buffering-Faster-Model": {"gpt-6-luna"},
		"X-Oai-Request-Id":                      {"req_1"},
		"Cf-Ray":                                {"8f-SJC"},
		"X-Codex-Primary-Used-Percent":          {"42"},
		"X-Codex-Credits-Balance":               {"10"},
		"X-Codex-Active-Limit":                  {"codex"},
	}
	got := ForwardResponseHeaders(src)
	for _, kept := range []string{"X-Codex-Turn-State", "X-Models-Etag", "X-Reasoning-Included", "Openai-Model", "X-Codex-Safety-Buffering-Enabled", "X-Codex-Safety-Buffering-Faster-Model", "X-Oai-Request-Id", "Cf-Ray"} {
		if len(got[kept]) != 1 || got[kept][0] != src[kept][0] {
			t.Errorf("%s = %v, want %v", kept, got[kept], src[kept])
		}
	}
	for _, dropped := range []string{"X-Codex-Primary-Used-Percent", "X-Codex-Credits-Balance", "X-Codex-Active-Limit"} {
		if _, ok := got[dropped]; ok {
			t.Errorf("%s describes the seller's account and crossed the seam", dropped)
		}
	}
}
