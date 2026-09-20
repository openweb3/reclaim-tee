package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// These tests exercise the user-facing routes (chat completions, Anthropic
// messages, OpenAI Responses) against a scripted TEE: no network, no real
// credential. They lock the Hub's contract on each route: the body's model
// field drives lowest-price provider selection, upstream bytes are relayed
// verbatim (never double-wrapped in another data: frame), and the OpenAI chat
// route alone appends the [DONE] terminator — the other two formats carry
// their own end markers.

// newServeTestHub builds a Hub whose scripted TEE answers every request with
// the supplied upstream SSE bytes (the fixed frames mockprovider serves).
func newServeTestHub(t *testing.T, upstream []byte) *hub.Hub {
	t.Helper()
	return newServeTestHubStatus(t, upstream, 200, nil)
}

// newServeTestHubStatus is newServeTestHub with control over the upstream
// status and the TEE's Reply error, so a test can exercise the pre-dispatch
// error path (every provider refuses) and the upstream-error passthrough.
func newServeTestHubStatus(t *testing.T, upstream []byte, status int, fail error) *hub.Hub {
	t.Helper()

	// The sim fixtures (seller rate table for openai-sim and cheap-sim, plus
	// the per-provider whitelist policies) are generated into a private temp
	// dir so the test never touches the working tree's .sim. Credentials are
	// deliberately absent: they arrive at runtime through agent registration,
	// which these route tests do not exercise (they use a scripted TEE).
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	if err := shared.EnsureDefaults(); err != nil {
		t.Fatalf("ensure defaults: %v", err)
	}
	rates, err := shared.LoadRates()
	if err != nil {
		t.Fatalf("load rates: %v", err)
	}

	stream := [][]byte{upstream}
	ctype := "text/event-stream"
	if status != 200 {
		ctype = "application/json"
	}
	fake := &hub.ScriptedTEE{Reply: func(call int, spec jobs.Spec) (hub.Result, error) {
		if fail != nil {
			return hub.Result{}, fail
		}
		r := hub.ScriptReceipt(stream, proof.Receipt{
			Provider:      spec.Provider,
			StatusCode:    uint32(status),
			Completion:    proof.CompletionComplete,
			ChunkCount:    1,
			ResponseBytes: uint64(len(upstream)),
			ProviderSeq:   uint64(call),
		})
		return hub.Result{
			Status:  uint32(status),
			Headers: map[string][]string{"content-type": {ctype}},
			Chunks:  stream,
			Receipt: proof.SignedReceipt{Receipt: r},
		}, nil
	}}

	h, err := hub.New(hub.Config{
		TEE:        fake,
		Rates:      rates,
		Store:      hub.NewReceiptStore(t.TempDir()),
		Verify:     func(proof.SignedReceipt) error { return nil },
		Commission: 0,
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	return h
}

// newServeTestHubReply is kept for the pre-dispatch failure test: a TEE whose
// Reply always fails.
func newServeTestHubReply(t *testing.T, upstream []byte, fail error) *hub.Hub {
	t.Helper()
	return newServeTestHubStatus(t, upstream, 200, fail)
}

// postBody hits one user-facing route with a JSON body and returns the raw
// response bytes.
func postBody(t *testing.T, route userRoute, body string) (string, string) {
	t.Helper()
	return serveRequest(t, newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n")), route, body)
}

// serveRequest runs one route against a ready hub.
func serveRequest(t *testing.T, h *hub.Hub, route userRoute, body string) (string, string) {
	t.Helper()

	// Fixture policy hosts point at 127.0.0.1:18080, which is also what the
	// route config passes upstream. cheap-sim (0.30) must win over openai-sim
	// (1.00) for every model, exactly as in harness scenario 15.
	cfg := serveConfig{Host: "127.0.0.1:18080", Query: "", Max: 1 << 20}
	handler := &userHandler{h: h, cfg: cfg, route: route}

	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TokenHive-Key", "tenant-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Body.String(), rec.Header().Get("Content-Type")
}

func TestChatRouteAppendsDoneAndRelaysVerbatim(t *testing.T) {
	body, _ := postBody(t, userRoutes[0], `{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(body, "data: {\"id\":\"chatcmpl-sim1\"}") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if !strings.HasSuffix(body, "\ndata: [DONE]\n\n") {
		t.Fatalf("chat stream must terminate with [DONE], got: %q", body)
	}
	if strings.Contains(body, "data: data:") {
		t.Fatalf("upstream bytes were double-wrapped in another data: frame: %q", body)
	}
}

func TestMessagesRouteRelaysAnthropicBytesVerbatim(t *testing.T) {
	// The upstream (mockprovider) serves Anthropic framing: event: message_start
	// ... event: message_stop. The Hub must not add [DONE] — message_stop is the
	// client's end marker.
	route := userRoutes[1]
	body, _ := postBody(t, route, `{"model":"sim-claude-haiku","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"stream":true}`)
	if !strings.Contains(body, "chatcmpl-sim1") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("Anthropic route must not append [DONE]: %q", body)
	}
}

func TestResponsesRouteRelaysResponsesBytesVerbatim(t *testing.T) {
	// OpenAI Responses framing ends with a response.completed event of its own.
	route := userRoutes[2]
	body, _ := postBody(t, route, `{"model":"sim-mock-0.5b","input":"hi","stream":true}`)
	if !strings.Contains(body, "chatcmpl-sim1") {
		t.Fatalf("upstream bytes missing from response: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Fatalf("Responses route must not append [DONE]: %q", body)
	}
}

func TestUserRoutesServeStreamingContentType(t *testing.T) {
	for _, route := range userRoutes {
		body, ctype := postBody(t, route, `{"model":"sim-mock-0.5b"}`)
		if !strings.Contains(ctype, "text/event-stream") {
			t.Errorf("%s content-type = %q, want text/event-stream", route.Path, ctype)
		}
		if body == "" {
			t.Errorf("%s returned an empty stream", route.Path)
		}
	}
}

// TestUpstreamErrorStatusIsPassedThrough locks the fix this protocol change
// exists for: when the upstream answers 401, the buyer sees a 401 with the
// upstream's error body — not a 200 with an SSE stream. The upstream's own
// body is the complete error, so no [DONE] marker is appended to it.
func TestUpstreamErrorStatusIsPassedThrough(t *testing.T) {
	route := userRoutes[0]
	h := newServeTestHubStatus(t,
		[]byte(`{"error":{"message":"invalid api key"}}`), 401, nil)
	status, body, ctype := serveStatus(t, h, route, `{"model":"sim-mock-0.5b"}`)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	if !strings.Contains(ctype, "application/json") {
		t.Errorf("content-type = %q, want the upstream's application/json", ctype)
	}
	if !strings.Contains(body, `{"error":{"message":"invalid api key"}}`) {
		t.Errorf("upstream error body missing: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Errorf("error body must not be spliced with a stream terminator: %q", body)
	}
	if strings.Contains(body, "event: error") {
		t.Errorf("hub error frame must not be spliced into a non-2xx error body: %q", body)
	}
}

// TestUpstreamErrorStatusAlsoPassesThroughRateLimit covers the 429 shape: the
// upstream's Retry-After hint must reach the buyer alongside the status.
func TestUpstreamErrorStatusAlsoPassesThroughRateLimit(t *testing.T) {
	route := userRoutes[0]
	// A 429 receipt is not billable, so the scheduler would fall back to the
	// next provider; with both providers scripted to 429, the last attempt is
	// returned and its status is what the buyer sees.
	h := newServeTestHubStatus(t,
		[]byte(`{"error":{"message":"rate limit exceeded"}}`), 429, nil)
	status, _, _ := serveStatus(t, h, route, `{"model":"sim-mock-0.5b"}`)
	if status != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", status)
	}
}

// serveStatus runs one route and returns the recorded status, body, and
// content type.
func serveStatus(t *testing.T, h *hub.Hub, route userRoute, body string) (int, string, string) {
	t.Helper()
	cfg := serveConfig{Host: "127.0.0.1:18080", Query: "", Max: 1 << 20}
	handler := &userHandler{h: h, cfg: cfg, route: route}

	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TokenHive-Key", "tenant-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header().Get("Content-Type")
}

// TestPreDispatchFailureIsAJSONError locks the deferred-header behaviour: a
// dispatch that fails before any byte is relayed (here: every provider
// refuses) must return a proper JSON error with a non-2xx status, not an SSE
// error frame smuggled under a 200.
func TestPreDispatchFailureIsAJSONError(t *testing.T) {
	route := userRoutes[0]
	failing := newServeTestHubReply(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n"), errors.New("tee refused"))
	body, ctype := serveRequest(t, failing, route, `{"model":"sim-mock-0.5b"}`)
	if strings.Contains(ctype, "text/event-stream") {
		t.Fatalf("error response used SSE content-type %q; want application/json", ctype)
	}
	if !strings.Contains(body, "error") {
		t.Fatalf("error body is not JSON: %q", body)
	}
}

// TestAllProvidersFailingBeforeAStartIsA502 covers the outcome where every
// provider's exchange failed before producing a response: the TEE attests each
// as a verified failure receipt with no status and no bytes, ExecuteForModel
// returns the last such outcome with no Go error, and nothing was ever
// committed to the user's connection. The handler must surface that as a
// proper failure response — not fall through to an empty implicit 200.
func TestAllProvidersFailingBeforeAStartIsA502(t *testing.T) {
	route := userRoutes[0]
	fake := &hub.ScriptedTEE{Reply: func(call int, spec jobs.Spec) (hub.Result, error) {
		r := hub.ScriptReceipt(nil, proof.Receipt{
			Provider:    spec.Provider,
			Completion:  proof.CompletionFailed,
			ProviderSeq: uint64(call),
		})
		return hub.Result{Receipt: proof.SignedReceipt{Receipt: r}}, nil
	}}
	h, err := hub.New(hub.Config{
		TEE: fake,
		Rates: map[string]hub.RateCard{
			"p1": {PerRequestMicros: 100},
			"p2": {PerRequestMicros: 900},
		},
		Store:  hub.NewReceiptStore(t.TempDir()),
		Verify: func(proof.SignedReceipt) error { return nil },
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	status, body, ctype := serveStatus(t, h, route, `{"model":"m"}`)
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", status)
	}
	if !strings.Contains(ctype, "application/json") {
		t.Errorf("content-type = %q, want application/json", ctype)
	}
	if !strings.Contains(body, "no provider produced a response") {
		t.Errorf("error body missing: %q", body)
	}
}

// TestTruncatedStreamIsNotTerminatedAsASuccess locks the mid-stream drop:
// the upstream answered 200, relayed some content, then died. The receipt
// attests CompletionTruncated and prices at zero, but the buyer must not see a
// clean [DONE] — that marker says the answer arrived whole. The handler has to
// surface the truncation as an error frame and withhold the terminator.
func TestTruncatedStreamIsNotTerminatedAsASuccess(t *testing.T) {
	route := userRoutes[0]
	stream := [][]byte{[]byte("data: {\"partial\":true}\n\n")}
	fake := &hub.ScriptedTEE{Reply: func(call int, spec jobs.Spec) (hub.Result, error) {
		r := hub.ScriptReceipt(stream, proof.Receipt{
			Provider:      spec.Provider,
			StatusCode:    200,
			Completion:    proof.CompletionTruncated,
			ChunkCount:    1,
			ResponseBytes: uint64(len(stream[0])),
			ProviderSeq:   uint64(call),
		})
		return hub.Result{
			Status:  200,
			Headers: map[string][]string{"content-type": {"text/event-stream"}},
			Chunks:  stream,
			Receipt: proof.SignedReceipt{Receipt: r},
		}, nil
	}}
	h, err := hub.New(hub.Config{
		TEE: fake,
		Rates: map[string]hub.RateCard{
			"p1": {PerRequestMicros: 100},
			"p2": {PerRequestMicros: 900},
		},
		Store:  hub.NewReceiptStore(t.TempDir()),
		Verify: func(proof.SignedReceipt) error { return nil },
	})
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	status, body, _ := serveStatus(t, h, route, `{"model":"m"}`)
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200 (the stream was already committed)", status)
	}
	if !strings.Contains(body, "data: {\"partial\":true}") {
		t.Errorf("relayed content missing from the stream: %q", body)
	}
	if !strings.Contains(body, "event: error") {
		t.Errorf("truncation must be reported as an error frame: %q", body)
	}
	if strings.Contains(body, "[DONE]") {
		t.Errorf("a truncated stream must not end with [DONE]: %q", body)
	}
}

// TestAPIErrorStatusDistinguishesSupplyOutage locks the status mapping: a
// market with every agent offline is 503 (the model may exist; the supply is
// what is down), a model nobody serves is 404, and quota exhaustion is 429.
func TestAPIErrorStatusDistinguishesSupplyOutage(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"supply down", fmt.Errorf("%w: model %q", hub.ErrNoProvidersOnline, "m"), http.StatusServiceUnavailable},
		{"unknown model", fmt.Errorf("%w: model %q", hub.ErrNoProviderForModel, "m"), http.StatusNotFound},
		{"quota", fmt.Errorf("%w: tenant %q", hub.ErrQuotaExceeded, "t"), http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiErrorStatus(tc.err); got != tc.want {
				t.Errorf("apiErrorStatus(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestModelsEndpointShape pins the /v1/models wire contract at the serve
// layer: JSON with a "models" array, empty (not null) when this Hub has no
// agent gate and therefore nothing declared. Search and directory semantics
// live in the hub package tests; here we only lock the envelope.
func TestModelsEndpointShape(t *testing.T) {
	h := newServeTestHub(t, []byte("x"))
	handler := modelsHandler(h)

	req := httptest.NewRequest(http.MethodGet, modelsPath, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	ctype := rec.Header().Get("Content-Type")
	if !strings.Contains(ctype, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ctype)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"models":[]}` {
		t.Fatalf("empty directory body = %q, want {\"models\":[]}", body)
	}

	// A query parameter is accepted and still yields an empty (filtered) list.
	req = httptest.NewRequest(http.MethodGet, modelsPath+"?q=deepseek", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if body := strings.TrimSpace(rec.Body.String()); body != `{"models":[]}` {
		t.Fatalf("filtered empty directory body = %q, want {\"models\":[]}", body)
	}
}

// TestUserRouteRequiresATenantKey pins the user-side gate: a request with no
// key is refused rather than silently attributed to one shared anonymous
// tenant, and a configured key map both authenticates a provisioned key and
// rejects an unknown one.
func TestUserRouteRequiresATenantKey(t *testing.T) {
	route := userRoutes[0]
	const body = `{"model":"sim-mock-0.5b"}`

	run := func(resolver tenantResolver, key string) int {
		t.Helper()
		h := newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n"))
		handler := &userHandler{
			h:     h,
			cfg:   serveConfig{Host: "127.0.0.1:18080", Max: 1 << 20, Tenants: resolver},
			route: route,
		}
		req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set(tenantKeyHeader, key)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := run(tenantResolver{}, ""); got != http.StatusUnauthorized {
		t.Errorf("no key in open mode = %d, want 401", got)
	}
	if got := run(tenantResolver{}, "tenant-x"); got != http.StatusOK {
		t.Errorf("open mode with a key = %d, want 200", got)
	}
	keys := tenantResolver{keys: map[string]string{"sk-good": "tenant-real"}}
	if got := run(keys, "sk-wrong"); got != http.StatusUnauthorized {
		t.Errorf("unknown key with a key map = %d, want 401", got)
	}
	if got := run(keys, "sk-good"); got != http.StatusOK {
		t.Errorf("provisioned key = %d, want 200", got)
	}
}

// TestProviderFieldPinsTheSource locks the request-side source selection: a
// route body that names a provider is honored exactly — an unknown source is
// refused (404) rather than silently routed to a substitute, and a serving
// source passes through. This is what lets a buyer ask for a specific AI
// source, not just the cheapest.
func TestProviderFieldPinsTheSource(t *testing.T) {
	h := newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n"))
	route := userRoutes[0]
	cfg := serveConfig{Host: "127.0.0.1:18080", Query: "", Max: 1 << 20}

	// cheap-sim is on the fixture market table and serves sim-mock-0.5b: a
	// pinned dispatch to it succeeds. nobody is not a server: the dispatch is
	// refused before any provider answers, exactly like an unknown model.
	run := func(body string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(tenantKeyHeader, "tenant-test")
		rec := httptest.NewRecorder()
		handler := &userHandler{h: h, cfg: cfg, route: route}
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := run(`{"model":"sim-mock-0.5b","provider":"cheap-sim"}`); got != http.StatusOK {
		t.Fatalf("pinned request to a serving provider = %d, want 200", got)
	}
	if got := run(`{"model":"sim-mock-0.5b","provider":"nobody"}`); got != http.StatusNotFound {
		t.Fatalf("pinned request to an unknown provider = %d, want 404 (must not fall back)", got)
	}
	if got := run(`{"model":"sim-mock-0.5b","provider":"cheap-sim"}`); got != http.StatusOK {
		t.Fatalf("pinned request again = %d, want 200", got)
	}
}

// TestProviderFieldIsOptional pins that a route body without a provider still
// works: the buyer who names only a model gets the cheapest server, exactly as
// before this feature.
func TestProviderFieldIsOptional(t *testing.T) {
	body, _ := postBody(t, userRoutes[0], `{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(body, "chatcmpl-sim1") {
		t.Fatalf("provider-less request did not relay: %q", body)
	}
}

// TestModelsEndpointProviderAndModelFilters pins that /v1/models honors the
// expanded market view through the wire: ?provider= narrows to one source and
// ?model= to one model family. The envelope is the same JSON shape; the row
// semantics live in the hub package's MarketQuotes tests.
func TestModelsEndpointProviderAndModelFilters(t *testing.T) {
	h := newServeTestHub(t, []byte("x"))
	handler := modelsHandler(h)

	run := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, rec.Code)
		}
		return strings.TrimSpace(rec.Body.String())
	}

	// With no provider argument and no agent gate, every filtered view is the
	// empty list — same envelope, non-null.
	for _, path := range []string{
		modelsPath + "?provider=cheap-sim",
		modelsPath + "?model=sim-mock",
		modelsPath + "?provider=cheap-sim&model=sim-mock",
	} {
		if body := run(path); body != `{"models":[]}` {
			t.Fatalf("%s = %q, want {\"models\":[]}", path, body)
		}
	}
}

// TestTenantResolverMapsKeyToTenant pins that a provisioned key resolves to its
// tenant rather than being used verbatim: otherwise a caller could name any
// tenant by presenting any key.
func TestTenantResolverMapsKeyToTenant(t *testing.T) {
	r := tenantResolver{keys: map[string]string{"sk-good": "tenant-real"}}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(tenantKeyHeader, "sk-good")
	if tenant, ok := r.resolve(req); !ok || tenant != "tenant-real" {
		t.Fatalf("resolve = %q,%t, want tenant-real,true", tenant, ok)
	}
}

// TestStalledRequestBodyIsCutOff pins the request read deadline against a real
// server: a client that announces a body with Content-Length and then never
// sends it must not hold the connection (and a goroutine) indefinitely. The
// shipped timeout is 30s — far too long to wait for in a test — so this runs the
// same server configuration with a short one.
func TestStalledRequestBodyIsCutOff(t *testing.T) {
	const stallTimeout = 150 * time.Millisecond
	route := userRoutes[0]

	handler := &userHandler{
		h:     newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n")),
		cfg:   serveConfig{Host: "127.0.0.1:18080", Max: 1 << 20},
		route: route,
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Config = newHubServer("", handler, stallTimeout)
	srv.Start()
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Headers arrive; the body they announce never does.
	if _, err := fmt.Fprintf(conn,
		"POST %s HTTP/1.1\r\nHost: hub.test\r\n%s: tenant-test\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n",
		route.Path, tenantKeyHeader); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(raw), "408") {
		t.Fatalf("response = %q, want a 408 for a stalled body", raw)
	}
}

// TestReadTimeoutDoesNotTruncateAResponseStream pins why the read deadline is
// safe to set server-wide: it bounds reading the request, so a response that
// takes longer to finish than the timeout — every SSE answer does — still
// arrives whole. It is WriteTimeout, deliberately left zero, that would cut such
// a stream.
func TestReadTimeoutDoesNotTruncateAResponseStream(t *testing.T) {
	const readTimeout = 100 * time.Millisecond

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Consume the request as the real routes do, so the deadline the server
		// armed on the body is the one under test.
		_, _ = io.Copy(io.Discard, r.Body)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "first")
		flusher.Flush()
		// Write the second half well after the read timeout has elapsed.
		time.Sleep(3 * readTimeout)
		_, _ = io.WriteString(w, "second")
		flusher.Flush()
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.Config = newHubServer("", handler, readTimeout)
	srv.Start()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if string(body) != "firstsecond" {
		t.Fatalf("streamed body = %q, want both halves: a read timeout must not cut a response", body)
	}
}

// writeDeadlineRecorder is a ResponseWriter that records the write deadlines a
// handler arms, so a test can prove a user response is bounded without waiting
// out a real timeout against a stalled socket.
type writeDeadlineRecorder struct {
	hdr       http.Header
	deadlines []time.Time
	status    int
}

func (w *writeDeadlineRecorder) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}
func (w *writeDeadlineRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (w *writeDeadlineRecorder) WriteHeader(code int)        { w.status = code }
func (w *writeDeadlineRecorder) Flush()                      {}
func (w *writeDeadlineRecorder) SetWriteDeadline(t time.Time) error {
	w.deadlines = append(w.deadlines, t)
	return nil
}

// TestUserRouteBoundsTheWriteBackToTheClient pins that every user response
// carries a write deadline, and that the deadline is cleared on the way out so a
// pooled connection does not inherit a spent one. Without the deadline a client
// that stops reading blocks the handler (and the tenant's in-flight slot) for as
// long as it likes.
func TestUserRouteBoundsTheWriteBackToTheClient(t *testing.T) {
	route := userRoutes[0]
	handler := &userHandler{
		h:     newServeTestHub(t, []byte("data: {\"id\":\"chatcmpl-sim1\"}\n\n")),
		cfg:   serveConfig{Host: "127.0.0.1:18080", Max: 1 << 20},
		route: route,
	}

	req := httptest.NewRequest(http.MethodPost, route.Path, strings.NewReader(`{"model":"sim-mock-0.5b"}`))
	req.Header.Set(tenantKeyHeader, "tenant-test")
	w := &writeDeadlineRecorder{}

	handler.ServeHTTP(w, req)

	if len(w.deadlines) < 2 {
		t.Fatalf("recorded %d write deadlines, want at least one armed and one cleared", len(w.deadlines))
	}
	armed := false
	for _, d := range w.deadlines {
		if !d.IsZero() {
			armed = true
		}
	}
	if !armed {
		t.Fatal("handler never armed a write deadline on the user response")
	}
	if last := w.deadlines[len(w.deadlines)-1]; !last.IsZero() {
		t.Fatalf("final write deadline = %v, want zero (cleared for the next request)", last)
	}
}
