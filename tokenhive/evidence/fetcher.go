package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// HTTPStore is the server half of evidence retrieval: it serves the Store's
// contents over HTTP so a verifier on another host can resolve a hash-only
// receipt against evidence the TEE published. It exposes two routes:
//
//	GET /v1/evidence/<hex-hash>   raw evidence bytes for that hash (200) or 404
//	GET /v1/evidence              JSON list of stored hex hashes (for syncing)
//
// A Hub or auditor wires an evidence.HTTPFetcher at this base URL.
type HTTPServer struct {
	Store *Store
}

// NewHTTPServer returns a handler serving the given store.
func NewHTTPServer(store *Store, mux *http.ServeMux) *HTTPServer {
	if mux == nil {
		mux = http.NewServeMux()
	}
	h := &HTTPServer{Store: store}
	mux.HandleFunc("/v1/evidence", h.handleList)
	mux.HandleFunc("/v1/evidence/", h.handleGet)
	return h
}

func (h *HTTPServer) handleList(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/evidence" {
		h.handleGet(w, r)
		return
	}
	hashes, err := h.Store.ListHashes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, hh := range hashes {
		io.WriteString(w, hh)
		io.WriteString(w, "\n")
	}
}

func (h *HTTPServer) handleGet(w http.ResponseWriter, r *http.Request) {
	hexHash := strings.TrimPrefix(r.URL.Path, "/v1/evidence/")
	if hexHash == "" || strings.Contains(hexHash, "/") {
		http.NotFound(w, r)
		return
	}
	raw, err := hex.DecodeString(hexHash)
	if err != nil || len(raw) != sha256.Size {
		http.Error(w, "invalid evidence hash", http.StatusBadRequest)
		return
	}
	var hash [32]byte
	copy(hash[:], raw)
	b, err := h.Store.Load(platform.Identity{EvidenceHash: hash})
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(b)
}

// HTTPFetcher is the client half: it resolves an EvidenceHash by asking a peer
// TEE (or Hub) whose /v1/evidence endpoint the deployment populates. It is an
// attest.Fetcher.
type HTTPFetcher struct {
	baseURL string
	client  *http.Client
}

// NewHTTPFetcher returns a fetcher that resolves evidence from base,
// e.g. "https://tee:18090". client performs the requests: pass the
// deployment's mTLS client (pinning the TEE's RA-TLS certificate and
// presenting the Hub client certificate) when the endpoint is served with
// -mtls, or nil for a default client.
func NewHTTPFetcher(base string, client *http.Client) (*HTTPFetcher, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("evidence: empty fetch base URL")
	}
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPFetcher{baseURL: base, client: client}, nil
}

// Fetch resolves id.EvidenceHash against the peer's /v1/evidence endpoint. The
// caller must still validate the returned bytes through a platform verifier;
// this only guarantees the bytes hash to the value the receipt names.
//
// One 503 is retried, once, on a connection the client's pool cannot supply.
// /v1/evidence is served on the same listener as /v1/execute, so a rotation
// retires connections underneath it too — and this fetch sits on the
// settlement path, once per hash-only receipt, which makes a refusal here a
// verified job thrown away after the provider already ran. Unlike execute's
// refusal this one needs no marker to be retryable: the bytes are a read,
// keyed by their own hash and checked against it below, so there is no
// sequence number, credential or provider exchange a second attempt could
// repeat. A peer that is genuinely unavailable fails both attempts; the retry
// costs one round-trip.
func (f *HTTPFetcher) Fetch(ctx context.Context, id platform.Identity) ([]byte, error) {
	raw, err := f.fetch(ctx, id, false)
	if !errors.Is(err, errRefused) {
		return raw, err
	}
	return f.fetch(ctx, id, true)
}

// errRefused marks the one HTTP answer Fetch retries, so the decision cannot be
// lost inside a wrap.
var errRefused = errors.New("evidence: peer refused the fetch")

// fetch performs one retrieval. freshConnection asks for a connection the pool
// has not handed over, which is what the retry above needs: every pooled
// connection to a rotating TEE is one a rotation may have retired, and the pool
// does not learn that until it tries to use them.
//
// That takes more than req.Close, which on HTTP/1 only decides whether the
// connection may be kept once the response is back — the pool is consulted on
// the way in without looking at it — so the pool is evicted as well. Eviction
// is what makes the retry dial, and so complete a handshake that postdates the
// rotation, on either protocol.
func (f *HTTPFetcher) fetch(ctx context.Context, id platform.Identity, freshConnection bool) ([]byte, error) {
	url := f.baseURL + "/v1/evidence/" + hex.EncodeToString(id.EvidenceHash[:])
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Close = freshConnection
	if freshConnection {
		f.client.CloseIdleConnections()
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("evidence: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoEvidence
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("%w: fetch %s: status %d", errRefused, url, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("evidence: fetch %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", url, err)
	}
	if sum := sha256.Sum256(b); sum != id.EvidenceHash {
		return nil, fmt.Errorf("evidence: %s returned bytes that do not match evidence hash %x",
			url, id.EvidenceHash)
	}
	return b, nil
}
