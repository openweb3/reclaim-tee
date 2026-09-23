package evidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

func idWith(evidence []byte) platform.Identity {
	return platform.Identity{
		Platform:      "simulated",
		ApplicationID: "app",
		Evidence:      evidence,
		EvidenceHash:  sha256.Sum256(evidence),
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("evidence-bytes"))
	if err := s.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "evidence-bytes" {
		t.Fatalf("Load = %q, want evidence-bytes", got)
	}
}

func TestStorePersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("must-survive-restart"))
	if err := s1.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A fresh store over the same directory must resolve what the first wrote —
	// the restart-surviving property a TEE's epoch history needs.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore #2: %v", err)
	}
	got, err := s2.Load(id)
	if err != nil {
		t.Fatalf("Load after reopen: %v", err)
	}
	if string(got) != "must-survive-restart" {
		t.Fatalf("Load = %q after reopen", got)
	}
	if !s2.Has(id) {
		t.Fatal("Has = false after reopen")
	}
}

func TestStoreMissReturnsErrNoEvidence(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_, err = s.Load(platform.Identity{EvidenceHash: sha256.Sum256([]byte("absent"))})
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Load = %v, want ErrNoEvidence", err)
	}
}

func TestStorePutMismatchedHash(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("a"))
	id.EvidenceHash = sha256.Sum256([]byte("different"))
	if err := s.Put(id); err == nil {
		t.Fatal("Put accepted evidence whose bytes do not hash to its EvidenceHash")
	}
}

func TestStoreIgnoresEmptyEvidence(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Put(platform.Identity{}); err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	if hashes, _ := s.ListHashes(); len(hashes) != 0 {
		t.Fatalf("ListHashes = %v, want empty", hashes)
	}
}

func TestHTTPFetcherRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("serve-me"))
	if err := s.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}

	mux := http.NewServeMux()
	NewHTTPServer(s, mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	f, err := NewHTTPFetcher(server.URL, nil)
	if err != nil {
		t.Fatalf("NewHTTPFetcher: %v", err)
	}
	got, err := f.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != "serve-me" {
		t.Fatalf("Fetch = %q, want serve-me", got)
	}
}

func TestHTTPFetcherMiss(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	mux := http.NewServeMux()
	NewHTTPServer(s, mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	f, _ := NewHTTPFetcher(server.URL, nil)
	_, err = f.Fetch(context.Background(), platform.Identity{EvidenceHash: sha256.Sum256([]byte("absent"))})
	if !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Fetch = %v, want ErrNoEvidence", err)
	}
}

func TestHTTPFetcherRefusesWrongBytes(t *testing.T) {
	// A peer returns bytes that do not hash to the requested evidence hash; the
	// fetcher must refuse them rather than hand an inconsistent blob to the
	// verifier.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evidence/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("wrong-answer"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	id := platform.Identity{EvidenceHash: sha256.Sum256([]byte("expected"))}
	f, _ := NewHTTPFetcher(server.URL, nil)
	if _, err := f.Fetch(context.Background(), id); err == nil {
		t.Fatal("Fetch accepted evidence that does not match the requested hash")
	}
}

// TestHTTPFetcherRetriesARetiredConnection: /v1/evidence is served by the same
// listener as /v1/execute, so a rotation can refuse it on the same connection.
// This fetch happens once per hash-only receipt, on the settlement path, so a
// refusal left to the caller is a verified job thrown away after the provider
// already ran. The retry must ask for a connection of its own: every pooled
// connection to a rotating TEE is one a rotation may have retired.
func TestHTTPFetcherRetriesARetiredConnection(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	id := idWith([]byte("serve-me"))
	if err := s.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var hits int32
	recorder := &attemptRecorder{base: http.DefaultTransport}
	mux := http.NewServeMux()
	NewHTTPServer(s, mux)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			http.Error(w, "connection belongs to a retired attestation epoch; reconnect", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()

	f, err := NewHTTPFetcher(server.URL, &http.Client{Transport: recorder})
	if err != nil {
		t.Fatalf("NewHTTPFetcher: %v", err)
	}
	got, err := f.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("a retired connection reached the verifier as a failure: %v", err)
	}
	if string(got) != "serve-me" {
		t.Fatalf("Fetch = %q, want serve-me", got)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("peer saw %d attempts, want 2 (one refusal, one retry)", n)
	}
	if got := recorder.attempts(); len(got) != 2 || got[0] || !got[1] {
		t.Fatalf("attempts asked for their own connection %v, want [false true]", got)
	}
}

// TestHTTPFetcherSurfacesAPeerThatKeepsRefusing bounds the retry: a peer
// answering 503 forever is down, not rotating, and the caller must be told
// rather than looped on.
func TestHTTPFetcherSurfacesAPeerThatKeepsRefusing(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	id := platform.Identity{EvidenceHash: sha256.Sum256([]byte("expected"))}
	f, _ := NewHTTPFetcher(server.URL, nil)
	if _, err := f.Fetch(context.Background(), id); err == nil {
		t.Fatal("Fetch reported success against a peer that only refused")
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("peer saw %d attempts, want exactly 2", n)
	}
}

// attemptRecorder records, per attempt, whether the client asked for a
// connection of its own rather than one out of its pool. A retry that reused a
// pooled connection would be refused again by the same listener, so this is the
// difference between recovering from a rotation and appearing to.
type attemptRecorder struct {
	base http.RoundTripper

	mu         sync.Mutex
	perAttempt []bool
}

func (r *attemptRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.perAttempt = append(r.perAttempt, req.Close)
	r.mu.Unlock()
	return r.base.RoundTrip(req)
}

func (r *attemptRecorder) attempts() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.perAttempt...)
}

func TestChainFallsThroughToNext(t *testing.T) {
	// First fetcher misses, second resolves: the Chain must try in order.
	missing := &Chain{}
	store, _ := NewStore(t.TempDir())
	id := idWith([]byte("chained"))
	if err := store.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	chain := NewChain(missing, store)
	got, err := chain.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("Chain.Fetch: %v", err)
	}
	if string(got) != "chained" {
		t.Fatalf("Chain.Fetch = %q, want chained", got)
	}
}

func TestChainEmptyMiss(t *testing.T) {
	chain := NewChain()
	if _, err := chain.Fetch(context.Background(), platform.Identity{}); !errors.Is(err, ErrNoEvidence) {
		t.Fatalf("Fetch = %v, want ErrNoEvidence", err)
	}
}
