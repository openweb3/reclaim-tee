package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func validSpec(t *testing.T) Spec {
	t.Helper()
	body := []byte(`{"model":"gpt-4o","input":"hello"}`)
	bodyHash := HashBody(body)

	return Spec{
		Version:          VersionV1,
		JobID:            make([]byte, JobIDLength),
		Provider:         "openai",
		Model:            "gpt-4o",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/responses",
		Query:            "",
		Headers:          map[string]string{"content-type": "application/json"},
		BodyHash:         bodyHash[:],
		Nonce:            make([]byte, 16),
		ExpiresAt:        time.Now().Add(time.Minute).Unix(),
		MaxResponseBytes: 1 << 20,
		Stream:           true,
	}
}

func TestEncodeCanonicalIsDeterministic(t *testing.T) {
	spec := validSpec(t)
	// The spec carries a map, whose Go iteration order is randomised. Encoding
	// repeatedly is what actually exercises the canonical sort.
	first, err := spec.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i := 0; i < 64; i++ {
		next, err := spec.EncodeCanonical()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !equalBytes(first, next) {
			t.Fatalf("encoding is not deterministic:\n%s\n%s", hex.EncodeToString(first), hex.EncodeToString(next))
		}
	}
}

func TestHashChangesWithEveryField(t *testing.T) {
	base := validSpec(t)
	baseHash, err := base.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	mutations := map[string]func(*Spec){
		"version":   func(s *Spec) { s.Version = 2 },
		"jobID":     func(s *Spec) { s.JobID[0] ^= 0xff },
		"provider":  func(s *Spec) { s.Provider = "anthropic" },
		"model":     func(s *Spec) { s.Model = "gpt-4o-mini" },
		"method":    func(s *Spec) { s.Method = "GET" },
		"host":      func(s *Spec) { s.Host = "api.anthropic.com" },
		"path":      func(s *Spec) { s.Path = "/v1/messages" },
		"bodyHash":  func(s *Spec) { s.BodyHash[0] ^= 0xff },
		"expiresAt": func(s *Spec) { s.ExpiresAt++ },
		"limit":     func(s *Spec) { s.MaxResponseBytes++ },
		"stream":    func(s *Spec) { s.Stream = false },
		"header":    func(s *Spec) { s.Headers["content-type"] = "text/plain" },
		"newHeader": func(s *Spec) { s.Headers["x-extra"] = "1" },
	}

	for name, mutate := range mutations {
		mutated := validSpec(t)
		mutate(&mutated)
		got, err := mutated.Hash()
		if err != nil {
			t.Fatalf("%s: hash: %v", name, err)
		}
		if got == baseHash {
			t.Errorf("changing %s did not change the spec hash", name)
		}
	}
}

func TestValidateAcceptsValidSpec(t *testing.T) {
	if err := validSpec(t).Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		mut  func(*Spec)
		want error
	}{
		{"bad version", func(s *Spec) { s.Version = 0 }, ErrUnsupportedVersion},
		{"short job id", func(s *Spec) { s.JobID = s.JobID[:8] }, ErrInvalidJobID},
		{"empty provider", func(s *Spec) { s.Provider = "" }, ErrInvalidProvider},
		{"uppercase provider", func(s *Spec) { s.Provider = "OpenAI" }, ErrInvalidProvider},
		{"provider with slash", func(s *Spec) { s.Provider = "open/ai" }, ErrInvalidProvider},
		{"unsupported method", func(s *Spec) { s.Method = "TRACE" }, ErrInvalidMethod},
		{"head method", func(s *Spec) { s.Method = "HEAD" }, ErrInvalidMethod},
		{"empty host", func(s *Spec) { s.Host = "" }, ErrInvalidHost},
		{"host with path", func(s *Spec) { s.Host = "api.openai.com/v1" }, ErrInvalidHost},
		{"host with scheme", func(s *Spec) { s.Host = "https://api.openai.com" }, ErrInvalidHost},
		{"host with userinfo", func(s *Spec) { s.Host = "user@api.openai.com" }, ErrInvalidHost},
		{"host with bad port", func(s *Spec) { s.Host = "api.openai.com:https" }, ErrInvalidHost},
		{"relative path", func(s *Spec) { s.Path = "v1/responses" }, ErrInvalidPath},
		{"traversal path", func(s *Spec) { s.Path = "/v1/../../admin" }, ErrInvalidPath},
		{"path with space", func(s *Spec) { s.Path = "/v1/a b" }, ErrInvalidPath},
		{"short body hash", func(s *Spec) { s.BodyHash = s.BodyHash[:16] }, ErrInvalidBodyHash},
		{"unbounded model", func(s *Spec) { s.Model = strings.Repeat("m", MaxModelLength+1) }, ErrInvalidModel},
		{"model with control character", func(s *Spec) { s.Model = "gpt\n4o" }, ErrInvalidModel},
		{"short nonce", func(s *Spec) { s.Nonce = s.Nonce[:4] }, ErrInvalidNonce},
		{"empty nonce", func(s *Spec) { s.Nonce = nil }, ErrInvalidNonce},
		{"zero expiry", func(s *Spec) { s.ExpiresAt = 0 }, ErrInvalidExpiry},
		{"zero limit", func(s *Spec) { s.MaxResponseBytes = 0 }, ErrInvalidLimit},
		{
			"injected authorization header",
			func(s *Spec) { s.Headers["Authorization"] = "Bearer stolen" },
			ErrInvalidHeaders,
		},
		{
			"header value with CRLF",
			func(s *Spec) { s.Headers["x-a"] = "a\r\nX-Evil: 1" },
			ErrInvalidHeaders,
		},
		{
			"invalid header name",
			func(s *Spec) { s.Headers["x a"] = "1" },
			ErrInvalidHeaders,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec(t)
			tc.mut(&spec)
			err := spec.ValidateAt(now)
			if !isError(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateAtExpiry(t *testing.T) {
	spec := validSpec(t)
	expiresAt := spec.ExpiresAt

	if err := spec.ValidateAt(time.Unix(expiresAt-1, 0)); err != nil {
		t.Fatalf("spec expired too early: %v", err)
	}
	err := spec.ValidateAt(time.Unix(expiresAt, 0))
	if !isError(err, ErrExpired) {
		t.Fatalf("at expiry: got %v, want %v", err, ErrExpired)
	}
	err = spec.ValidateAt(time.Unix(expiresAt+1, 0))
	if !isError(err, ErrExpired) {
		t.Fatalf("after expiry: got %v, want %v", err, ErrExpired)
	}
}

func TestMatchesBody(t *testing.T) {
	spec := validSpec(t)
	body := []byte(`{"model":"gpt-4o","input":"hello"}`)

	if !spec.MatchesBody(body) {
		t.Fatal("matching body rejected")
	}
	if spec.MatchesBody([]byte(`{"model":"gpt-4o","input":"goodbye"}`)) {
		t.Fatal("different body accepted")
	}

	// A body hash commits to exact bytes, so a job whose real body drifts from
	// the committed hash is rejected before the TEE ever dials the provider.
	mismatched := spec
	otherBodyHash := HashBody([]byte("different"))
	mismatched.BodyHash = otherBodyHash[:]
	if mismatched.MatchesBody(body) {
		t.Fatal("body mismatch not detected")
	}
}

// TestSpecHashIsDomainSeparated guards the other half of the same property:
// a spec digest must not be a bare SHA-256 either, or it could be confused
// with a digest produced for another purpose. This matters more now that the
// spec hash is compared across packages rather than checked against a
// signature.
func TestSpecHashIsDomainSeparated(t *testing.T) {
	encoded, err := validSpec(t).EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	bare := sha256.Sum256(encoded)
	specHash, err := validSpec(t).Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if specHash == bare {
		t.Fatal("spec hash is not domain separated")
	}
}

func TestHashBodyIsDomainSeparated(t *testing.T) {
	// The body digest must not equal a bare SHA-256, or it could be confused
	// with a digest produced for another purpose.
	body := []byte("hello")
	if HashBody(body) == sha256.Sum256(body) {
		t.Fatal("body hash is not domain separated")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isError(err, target error) bool {
	return err != nil && errors.Is(err, target)
}
