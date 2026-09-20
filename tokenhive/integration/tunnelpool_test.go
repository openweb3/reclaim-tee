package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These two tests pin the pool's terminal handling at the layer the unit tests
// cannot reach: a resident connection that lives inside a stream on the Hub
// relay, carried over the agent's reverse tunnel. The TEE pools by
// (provider, host) and hands the same stream back on the next job, and neither
// job may attest anything but a complete exchange.

// peerCount records the provider-side connections a job arrived on, keyed by
// peer address: one entry per connection, so reuse is visible as a repeat.
type peerCount struct {
	mu    sync.Mutex
	conns map[string]int
}

func (p *peerCount) note(addr string) {
	p.mu.Lock()
	p.conns[addr]++
	p.mu.Unlock()
}

func (p *peerCount) distinct() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

func (p *peerCount) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.conns {
		n += c
	}
	return n
}

// runStreamingJobs executes n chat completions in sequence on one service and
// requires every one of them to attest a complete exchange.
func runStreamingJobs(t *testing.T, target string, srv *httptest.Server, n int) {
	t.Helper()
	service, cred := e2eStack(t, target, srv)
	for i := 0; i < n; i++ {
		spec, body := localChatCompletion(t, target)
		spec.Credential = cred
		result, err := executeEventually(t, service, &spec, body, func([]byte) error { return nil })
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		if got := result.Receipt.Receipt.Completion; got != proof.CompletionComplete {
			t.Fatalf("job %d completion = %v, want complete (a stream over the tunnel was cut short)", i, got)
		}
	}
}

// TestPooledConnectionSurvivesTheTunnel runs three streaming jobs back to back
// through the Hub relay and the agent's reverse tunnel. The second and third
// must find the first's connection still open in the pool — which is what makes
// the resident-connection design worth anything — and all three must complete.
func TestPooledConnectionSurvivesTheTunnel(t *testing.T) {
	peers := &peerCount{conns: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers.note(r.RemoteAddr)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, event := range e2eEvents {
			_, _ = w.Write(event)
			flusher.Flush()
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	runStreamingJobs(t, target, srv, 3)

	if got := peers.distinct(); got != 1 {
		t.Errorf("provider saw %d connections for 3 jobs, want 1 (the resident connection was not reused)", got)
	}
	if got := peers.total(); got != 3 {
		t.Errorf("provider saw %d requests, want 3", got)
	}
}

// TestPooledConnectionRecoversFromAProviderClose covers the other terminal
// state: the provider answers completely and then closes, leaving the pool
// holding a dead socket. A request that writes zero bytes to it reaches nobody,
// so it must be re-dialed rather than reported as a failure — three jobs, one
// connection each.
func TestPooledConnectionRecoversFromAProviderClose(t *testing.T) {
	peers := &peerCount{conns: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers.note(r.RemoteAddr)
		_, _ = io.ReadAll(r.Body)
		term := "data: [DONE]\n\n"
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(term)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, term)
		w.(http.Flusher).Flush()
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, err := hijacker.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	runStreamingJobs(t, target, srv, 3)

	if got := peers.distinct(); got != 3 {
		t.Errorf("provider saw %d connections for 3 jobs, want 3 (a dead pooled socket was not re-dialed)", got)
	}
}
