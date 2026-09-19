package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// defaultRequestReadTimeout bounds how long a client may take to send a whole
// request — request line, headers, and body — before the Hub gives up on it.
//
// ReadHeaderTimeout alone does not cover this: it stops a client that stalls in
// the headers, but a client that sends headers promptly and then dribbles (or
// never sends) the body it announced with Content-Length keeps a connection and
// its goroutine for as long as it likes. The 16 MiB body cap bounds how much can
// arrive, not how slowly.
//
// It is safe to set server-wide precisely because it bounds *reading the
// request* and nothing else. The stdlib clears the read deadline once the body
// is consumed (and on hijack, which is how the agent gate and the tee relay take
// the connection), so a response that streams for minutes — every SSE answer —
// is untouched; it is WriteTimeout, deliberately left zero, that would cut such
// a stream. The value is generous because a request body may legitimately be
// large and the client's uplink is not the Hub's to choose; the point is that it
// is finite.
const defaultRequestReadTimeout = 30 * time.Second

// defaultResponseWriteTimeout bounds one write back to a user. Without a write
// deadline a client that completes its request and then stops reading fills the
// socket's send buffer and blocks the handler forever, holding the goroutine,
// the tenant's in-flight slot, and the provider connection behind it. The
// deadline rolls with every write, so a slow but progressing reader is never
// cut; it is cleared when the handler returns so a pooled connection is not left
// carrying a spent deadline into the next request.
const defaultResponseWriteTimeout = 30 * time.Second

// serveConfig is the routing the resident service hands to the scheduler: the
// upstream it asks the TEE to reach.
type serveConfig struct {
	Addr string // where the Hub listens for its users
	Host string // the default AI service host:port (must be admitted by the deployment policy)
	// ProviderHosts overrides Host for the named providers. A deployment serves
	// every model from one host in the simulation, but a real deployment fronts
	// several vendors' endpoints, and one seller's token is only good at its
	// own vendor: HostFor (below) is what every spec-framing site uses, so a
	// provider absent from the map is served at Host and nothing else changes.
	ProviderHosts map[string]string
	Query         string // extra upstream query (fault injection, for the harness)
	Max           uint64 // MaxResponseBytes cap passed to the TEE. For a request it caps the body; for a session it caps the downlink, so the session settles for what it delivered instead of being cut un-reconcilably by the Hub
	Tenants       tenantResolver
	// Policy is the deployment whitelist. The Hub advertises it on /v1/policies
	// and admits every dialing agent against it, so buyers and sellers see
	// exactly the whitelist the enclave enforces (the same bundle bytes on an
	// SNP instance) and a request refused by policy is a fact either could have
	// checked up front. Nil means the whitelist was unavailable at startup:
	// the endpoint says so, and no agent is admitted.
	Policy *policy.Policy
}

// HostFor returns the upstream host:port jobs for provider are framed with:
// the per-provider override when one is configured, otherwise the Hub-wide
// default. A zero ProviderHosts map keeps the old behavior (everything to
// Host), so single-upstream deployments and existing tests need no changes.
func (c serveConfig) HostFor(provider string) string {
	if h, ok := c.ProviderHosts[provider]; ok {
		return h
	}
	return c.Host
}

// tenantKeyHeader is the header a user presents to identify itself. It is the
// Hub's user-facing counterpart to the agent gate's key header: a bearer
// credential, held to the same rule (a mismatch is refused, never defaulted).
const tenantKeyHeader = "X-TokenHive-Key"

// tenantResolver maps a presented user key to the tenant it belongs to, which
// is what quota and attribution key on.
//
// With a key map configured, only a provisioned key admits a request and the
// tenant is the mapped name — the caller cannot choose who it is. Without one
// the Hub runs open: the presented key is the tenant, which is the deliberate
// dev stance (there is no provisioned identity to check against), but the key
// is still required. Silently defaulting an absent key to one shared name would
// make every headerless caller a single tenant — one shared quota bucket and
// one indistinguishable attribution — which is worse than refusing them.
type tenantResolver struct {
	// keys maps a user API key to the tenant it authenticates as. Empty means
	// open mode.
	keys map[string]string
}

// resolve returns the tenant a request belongs to, and whether it may proceed.
func (r tenantResolver) resolve(req *http.Request) (string, bool) {
	key := req.Header.Get(tenantKeyHeader)
	if key == "" {
		return "", false
	}
	if len(r.keys) == 0 {
		return key, true
	}
	tenant, ok := r.keys[key]
	return tenant, ok
}

// userRoute describes one user-facing endpoint the Hub relays. The Hub is a
// byte relay, not a format translator: a request's body travels upstream
// unchanged and the upstream's response bytes come back unchanged. The
// difference between routes is which upstream path they address and whether
// the user-visible stream needs an OpenAI-style [DONE] terminator appended.
type userRoute struct {
	// Path is both the user-facing path and the upstream provider path. The
	// connection-resident data path keys providers by policy, and the policy
	// whitelists exactly this path — so which providers may answer a route is
	// decided by the providers' own signed policies, not by the Hub.
	Path string
	// Done appends "data: [DONE]\n\n" after a successful relay. OpenAI
	// chat-completions streams terminate with this marker; Anthropic streams
	// terminate with their own event: message_stop, and OpenAI Responses
	// streams end with the response.completed event, so those routes leave the
	// upstream's framing alone.
	Done bool
}

// userRoutes is the Hub's user-facing API surface. Every route is a byte
// relay of the same shape — read the body, let the model field drive provider
// selection, forward the bytes upstream, stream the upstream's bytes back —
// and differs only in which provider path it addresses and whether the
// user-visible stream needs an OpenAI chat-style [DONE] appended.
//
// The three formats are served verbatim, not translated:
//   - /v1/chat/completions  (OpenAI Chat Completions)  — terminator: [DONE]
//   - /v1/messages          (Anthropic Messages)       — terminator: message_stop
//   - /v1/responses         (OpenAI Responses)         — terminator: response.completed
//
// All three carry the model name in the JSON body's top-level "model" field,
// which is the only part the Hub reads; the rest of the request travels
// untouched, and the response bytes the user sees are exactly the bytes the
// provider produced.
var userRoutes = []userRoute{
	{Path: "/v1/chat/completions", Done: true},
	{Path: "/v1/messages", Done: false},
	{Path: "/v1/responses", Done: false},
}

// agentGatePath and teeRelayPath are the Hub's reverse-tunnel endpoints: the
// AgentGate a Provider Agent dials to come online, and the TeeRelay the TEE
// dials to carry egress across those tunnels. Mounting them is what turns the
// Hub into the rendezvous point for NAT-trapped contributors.
const (
	agentGatePath     = "/v1/agent"
	teeRelayPath      = "/v1/relay"
	credentialKeyPath = "/v1/credential-key"
	modelsPath        = "/v1/models"
	policiesPath      = "/v1/policies"
)

var relayUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// runServe exposes the Hub as a resident OpenAI-compatible HTTP service. It
// blocks until the server stops.
//
// Unlike the one-shot CLI (which pins a provider), this is the product shape:
// a user submits a request and the Hub decides which provider serves it,
// cheapest first, re-emitting the provider's stream to the user.
func runServe(h *hub.Hub, cfg serveConfig) {
	mux := http.NewServeMux()
	for _, route := range userRoutes {
		mux.Handle(route.Path, &userHandler{h: h, cfg: cfg, route: route})
	}
	mux.Handle(sessionPath, &sessionHandler{h: h, cfg: cfg})
	mux.Handle(agentGatePath, h.AgentGate(relayUpgrader))
	mux.Handle(teeRelayPath, h.TeeRelay(relayUpgrader))
	mux.HandleFunc(credentialKeyPath, h.CredentialKeyHandler)
	mux.HandleFunc(modelsPath, modelsHandler(h))
	mux.HandleFunc(policiesPath, policiesHandler(cfg.Policy))
	log.Printf("hub user-facing API listening on http://%s%v (sessions at %s, models at %s, policies at %s)",
		cfg.Addr, routePaths(), sessionPath, modelsPath, policiesPath)
	log.Printf("hub reverse-tunnel endpoints: agent gate %s, tee relay %s, credential key %s",
		agentGatePath, teeRelayPath, credentialKeyPath)
	srv := newHubServer(cfg.Addr, mux, defaultRequestReadTimeout)
	log.Fatal(srv.ListenAndServe())
}

// newHubServer builds the Hub's HTTP server. It is split out so a test can run
// the real configuration with its own read timeout — a test cannot wait out the
// shipped 30s to observe the bound.
//
// WriteTimeout stays zero on purpose: an SSE response has no bounded size or
// duration, and a write deadline would cut a live stream mid-body. ReadTimeout
// is set because it bounds only the read side of a request, which the stdlib
// ends before the handler runs (see defaultRequestReadTimeout).
func newHubServer(addr string, handler http.Handler, readTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		IdleTimeout:       120 * time.Second,
	}
}

func routePaths() []string {
	paths := make([]string, len(userRoutes))
	for i, route := range userRoutes {
		paths[i] = route.Path
	}
	return paths
}

// userHandler implements one user-facing endpoint. The request body is
// forwarded byte-for-byte to the TEE (bound by BodyHash), but the model field
// is read out first because it drives provider selection.
type userHandler struct {
	h     *hub.Hub
	cfg   serveConfig
	route userRoute
}

func (c *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		// A body that stopped arriving is the deadline the server set (see
		// defaultRequestReadTimeout) expiring: the client stalled, which is a
		// 408. Any other read failure is a body the Hub cannot use, which is a
		// 400.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			writeJSONError(w, http.StatusRequestTimeout, "request body timed out")
			log.Printf("api path=%s err=body read timeout", c.route.Path)
			return
		}
		writeJSONError(w, http.StatusBadRequest, "read body")
		return
	}
	var req struct {
		Model    string `json:"model"`
		Provider string `json:"provider,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Model == "" {
		writeJSONError(w, http.StatusBadRequest, "model is required")
		return
	}

	// Tenant resolution: the caller identifies itself with a key, which either
	// resolves through the Hub's key map to its tenant or (in open mode) is the
	// tenant. A request with no key, or a key the map does not hold, is refused
	// before anything is dispatched.
	tenant, ok := c.cfg.Tenants.resolve(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "missing or invalid api key")
		log.Printf("api model=%q path=%s err=unauthorized", req.Model, c.route.Path)
		return
	}

	flusher, _ := w.(http.Flusher)

	rc := http.NewResponseController(w)
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()
	writeDeadline := func() { _ = rc.SetWriteDeadline(time.Now().Add(defaultResponseWriteTimeout)) }

	// The user-visible status and headers are committed from the TEE's
	// response-start frame, not from the first relayed byte: the Hub must know
	// whether the upstream answered 200 or 401/429 before it shows the buyer
	// anything. Dispatch failures that happen before any start (unknown model,
	// quota, no serving provider) return a proper JSON error with a
	// meaningful status instead.
	var (
		started bool
		status  int
	)
	commit := func(resp tee.Response) {
		if started {
			return
		}
		started = true
		status = int(resp.StatusCode)
		if status == 0 {
			// No response start (an exchange that never produced a response):
			// fall back to the streaming default, as before.
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		// The upstream's relayed headers override the defaults: a 401 JSON
		// error keeps its application/json, a 200 stream keeps its
		// text/event-stream. Del-then-Add replaces the default value rather
		// than appending a second one, while still preserving a multi-value
		// upstream header.
		for name, values := range resp.Headers {
			w.Header().Del(name)
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		writeDeadline()
		w.WriteHeader(status)
	}
	isSuccess := func() bool { return status >= 200 && status < 300 }

	var chunks int
	onChunk := func(chunk []byte) error {
		// The chunk is already the upstream's SSE bytes — mockprovider
		// frames `data: {…}` and the data path relays raw body bytes, so
		// re-wrapping here would emit `data: data: {…}` and break every
		// OpenAI SDK. The Hub's only job is byte-pass-through.
		commit(tee.Response{})
		writeDeadline()
		if _, werr := w.Write(chunk); werr != nil {
			return werr
		}
		chunks++
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	var outcome hub.Outcome
	if req.Provider != "" {
		outcome, err = c.h.ExecuteForProvider(r.Context(), tenant, req.Model, req.Provider, body,
			func(provider string) (jobs.Spec, error) {
				return shared.BuildSpec(provider, req.Model, c.cfg.HostFor(provider), c.route.Path, c.cfg.Query, body, c.cfg.Max)
			}, onChunk, commit)
	} else {
		outcome, err = c.h.ExecuteForModel(r.Context(), tenant, req.Model, body,
			func(provider string) (jobs.Spec, error) {
				return shared.BuildSpec(provider, req.Model, c.cfg.HostFor(provider), c.route.Path, c.cfg.Query, body, c.cfg.Max)
			}, onChunk, commit)
	}
	if !started {
		// Nothing was committed to the wire: either a dispatch failure, or
		// every provider failed before its response began and the last attempt
		// came back as a verified failure receipt with no Go error (status
		// zero, no bytes). Both must reach the buyer as a proper error — an
		// empty implicit 200 would say "succeeded" with no body and no SSE
		// content type.
		if err == nil {
			err = errors.New("no provider produced a response")
		}
		writeJSONError(w, apiErrorStatus(err), err.Error())
		log.Printf("api model=%q path=%s tenant=%q err=%v", req.Model, c.route.Path, tenant, err)
		return
	}
	// A committed 2xx stream is a success only when the receipt says the
	// upstream completed it. A provider that answered 200 and then died
	// mid-body — crash, reset, timeout after the first byte, or the TEE's own
	// byte cap — is attested as CompletionTruncated and priced at zero. Ending
	// such a stream with [DONE] would present a partial answer as a finished
	// one, so on the routes that fabricate the terminator the truncation is
	// reported like any committed failure and the marker is withheld.
	truncated := err == nil && isSuccess() &&
		outcome.Receipt.Receipt.Completion != proof.CompletionComplete
	writeDeadline()
	if err != nil {
		// The response is committed. For a 2xx stream the failure is reported
		// as an SSE error frame; for a non-2xx upstream status the upstream's
		// own error body already tells the story, and splicing an SSE frame
		// into it would corrupt the error the buyer is reading. Either way
		// nothing settles: hub.Execute returned no verified receipt to settle
		// against, so the failure is logged and the response ends here.
		if isSuccess() {
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(err))
		}
	}
	if c.route.Done && truncated {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sseError(errors.New("upstream response ended before completion")))
	}
	if c.route.Done && isSuccess() && !truncated {
		// OpenAI-compatible chat streams terminate with an explicit done marker,
		// which the mock upstream does not emit. Appended after an error frame
		// too, so a client that started reading a 2xx stream is never left
		// waiting for a terminator that cannot come. Never appended to a
		// non-2xx response, whose body is the complete error already. An
		// upstream that completed with an empty body still needs the marker,
		// hence the commit here.
		commit(tee.Response{})
		writeDeadline()
		fmt.Fprint(w, "data: [DONE]\n\n")
	}
	if started && flusher != nil {
		flusher.Flush()
	}

	log.Printf("api model=%q path=%s tenant=%q provider=%q status=%d chunks=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, c.route.Path, tenant, outcome.Receipt.Receipt.Provider, status, chunks,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

// modelsHandler answers GET /v1/models: the buyer-facing market directory.
//
// The endpoint exposes two views. The default is the model-aggregated
// directory: each model an online agent declared it can serve appears once, at
// the lowest current per-request book price. The optional ?q= query filters
// that view by a case-insensitive substring of the model name, so a buyer can
// look up an exact model or scan a family ("deepseek" returns every
// deepseek-* listing).
//
// Two declarations switch to the expanded market view, where the same model
// served by two sources appears as two rows:
//
//	?provider=NAME      every model one source offers
//	?model=NAME         every source offering a model (substring)
//
// A buyer who names no source gets the cheapest server by default; one who
// names a source — either to survey it or to pin a request to it — gets that
// source's rows.
func modelsHandler(h *hub.Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		provider, model := query.Get("provider"), query.Get("model")
		var quotes []hub.ModelQuote
		switch {
		case provider != "" || model != "":
			quotes = h.MarketQuotes(provider, model)
		case query.Get("q") != "":
			quotes = h.SearchModels(query.Get("q"))
		default:
			quotes = h.ModelDirectory()
		}
		if quotes == nil {
			quotes = []hub.ModelQuote{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Models []hub.ModelQuote `json:"models"`
		}{Models: quotes})
	}
}

// policiesHandler answers GET /v1/policies: the deployment whitelist a buyer or
// seller can check up front, without asking the TEE. It mirrors the /v1/models
// directory — a read-only view of deployment config, not an execution path.
//
// The response is the one document the enclave runs with: the hosts it may
// reach, the request families permitted on them, and its hash
// (TokenHive.Policy.v1 over the canonical encoding). A buyer who pins the hash
// can spot a rotated whitelist; a seller can confirm the whitelist it is
// admitted under. There is no per-provider view to ask for, because there is no
// per-provider policy.
//
// The policy is nil only when it could not be loaded; the endpoint says so
// rather than inventing a whitelist the enclave did not run with.
func policiesHandler(p *policy.Policy) http.HandlerFunc {
	type ruleView struct {
		Methods       []string `json:"methods"`
		Path          string   `json:"path"`
		AllowStream   bool     `json:"allow_stream,omitempty"`
		QueryKeys     []string `json:"query_keys,omitempty"`
		AllowAnyQuery bool     `json:"allow_any_query,omitempty"`
	}
	type policyView struct {
		Hosts            []string   `json:"hosts"`
		Rules            []ruleView `json:"rules"`
		MaxResponseBytes uint64     `json:"max_response_bytes"`
		MaxBodyBytes     uint64     `json:"max_body_bytes"`
		AllowedHeaders   []string   `json:"allowed_headers"`
		IssuedAt         int64      `json:"issued_at"`
		ExpiresAt        int64      `json:"expires_at"`
	}
	type response struct {
		PolicyHash  string      `json:"policy_hash"`
		Policy      *policyView `json:"policy"`
		Unavailable bool        `json:"unavailable,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		out := response{}
		if p == nil {
			out.Unavailable = true
		} else {
			if h, err := p.Hash(); err == nil {
				out.PolicyHash = hex.EncodeToString(h[:])
			}
			view := &policyView{
				Hosts:            p.Hosts,
				Rules:            make([]ruleView, 0, len(p.Rules)),
				MaxResponseBytes: p.Limits.MaxResponseBytes,
				MaxBodyBytes:     p.Limits.MaxBodyBytes,
				AllowedHeaders:   p.Limits.AllowedHeaders,
				IssuedAt:         p.IssuedAt,
				ExpiresAt:        p.ExpiresAt,
			}
			for _, rule := range p.Rules {
				view.Rules = append(view.Rules, ruleView{
					Methods:       rule.Methods,
					Path:          rule.Path,
					AllowStream:   rule.AllowStream,
					QueryKeys:     rule.QueryKeys,
					AllowAnyQuery: rule.AllowAnyQuery,
				})
			}
			out.Policy = view
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// admitAgainstPolicy is the deployment's admission check for a dialing agent.
//
// A seller chooses what it charges and which models it declares; it does not get
// to choose what the enclave will accept. So before an agent becomes
// schedulable the Hub looks up, by host and path, whether the deployment is
// willing to reach the upstream this agent's jobs will egress to. That upstream
// is per-provider — the agent's own host from the Hub's routing (a
// -provider-hosts override when one is configured, otherwise the Hub-wide
// -host) — because one seller's token is only good at its own vendor. An agent
// whose models could only be served on a path the whitelist does not cover
// would otherwise be scheduled and then refused inside the TEE — a refusal the
// seller never sees the reason for. Refusing at bring-up says so where the
// seller is standing.
//
// The whole route surface is checked, because a buyer picks the route and the
// Hub picks the seller: a model is only really admitted if the deployment admits
// every surface it could be asked for on.
func admitAgainstPolicy(p *policy.Policy, hostFor func(string) string) func(hub.AgentRegister) error {
	return func(reg hub.AgentRegister) error {
		if p == nil {
			return fmt.Errorf("no deployment policy loaded: refusing agent %q", reg.Provider)
		}
		host := hostFor(reg.Provider)
		type route struct{ path, method string }
		routes := []route{{realtimePath, http.MethodGet}}
		for _, r := range userRoutes {
			routes = append(routes, route{r.Path, http.MethodPost})
		}
		for _, r := range routes {
			if err := p.AllowsRoute(host, r.path, r.method); err != nil {
				return fmt.Errorf("agent %q: upstream %s%s is not admitted: %w",
					reg.Provider, host, r.path, err)
			}
		}
		return nil
	}
}

// apiErrorStatus maps a dispatch failure to an HTTP status. A provider that
// simply cannot serve the model is a 404; a market with every agent offline
// is a 503 (the model may exist — the supply is what is down); quota
// exhaustion and an exceeded in-flight share are both 429 (the request was
// fine, the tenant is already asking for as much as it may), and an exhausted
// spend budget is a 402 (refusing on price is not the same complaint as
// refusing on rate); anything else is a 502 upstream failure.
func apiErrorStatus(err error) int {
	switch {
	case errors.Is(err, hub.ErrNoProviderForModel), errors.Is(err, hub.ErrUnknownProvider):
		return http.StatusNotFound
	case errors.Is(err, hub.ErrNoProvidersOnline):
		return http.StatusServiceUnavailable
	case errors.Is(err, hub.ErrBudgetExceeded):
		return http.StatusPaymentRequired
	case errors.Is(err, hub.ErrQuotaExceeded), errors.Is(err, hub.ErrTooManyInflight):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":{"message":%q}}`, msg)
}

// sseError renders an error safely for a one-line SSE data field.
func sseError(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

// sessionPath is the user-facing streaming-session endpoint. A user opens a
// WebSocket here, the Hub learns the model from the first frame, selects the
// cheapest provider, and relays the full-duplex session through the TEE.
//
// realtimePath is the upstream path that session is relayed to. The two differ
// — the session is a Hub-shaped endpoint in front of a provider-shaped one — so
// the whitelist is written against realtimePath while the route is mounted at
// sessionPath, and the admission check below names both explicitly rather than
// deriving one from the other.
const (
	sessionPath  = "/v1/session"
	realtimePath = "/v1/realtime"
)

// sessionUpgrader upgrades the user's HTTP request to a WebSocket. Origin is
// unrestricted — the consumer is an API key holder, not a browser, so there is
// no origin header to police; the trust gate is the tenant header, exactly like
// the request routes.
var sessionUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// sessionHandler serves the streaming-session endpoint. It is the session
// counterpart of userHandler: read the model out of the first frame, let the
// scheduler pick the provider, relay the bytes, settle. The user's frames travel
// byte-for-byte; only the model field of the first frame is ever examined.
type sessionHandler struct {
	h   *hub.Hub
	cfg serveConfig
}

func (c *sessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := sessionUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	// Bound every user frame the relay reads (first frame and the uplink stream)
	// so a hostile client cannot blow the Hub's memory with an oversized message.
	conn.SetReadLimit(16 << 20)

	// The first frame is read here so the model can drive provider selection,
	// then handed back to the link, which replays it to the provider — reading
	// it costs the provider nothing and the bytes still travel unchanged.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, first, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	var req struct {
		Model    string `json:"model"`
		Provider string `json:"provider,omitempty"`
	}
	if err := json.Unmarshal(first, &req); err != nil || req.Model == "" {
		return
	}

	tenant, ok := c.cfg.Tenants.resolve(r)
	if !ok {
		return
	}

	build := func(provider string) (jobs.Spec, error) { return c.buildSession(req.Model, provider) }
	var outcome hub.SessionOutcome
	if req.Provider != "" {
		outcome, err = c.h.RunRealtimeForProvider(r.Context(), tenant, req.Model, req.Provider, build, &sessionLink{conn: conn, first: first})
	} else {
		outcome, err = c.h.RunRealtime(r.Context(), tenant, req.Model, build, &sessionLink{conn: conn, first: first})
	}
	log.Printf("session model=%q tenant=%q provider=%q uplink=%d downlink=%d charged=%.2f commission=%.2f buyer=%.2f err=%v",
		req.Model, tenant, outcome.Provider, outcome.UplinkBytes, outcome.DownlinkBytes,
		float64(outcome.Charged)/microsPerUnit, float64(outcome.Commission)/microsPerUnit,
		float64(outcome.Buyer)/microsPerUnit, err)
}

// buildSession frames the session spec for a provider. Identical across providers
// except the provider name, exactly as buildSpec frames request specs. The model
// is the one the Hub read out of the user's first frame and routed and priced
// on, and it is carried into the spec so the session receipt attests it.
func (c *sessionHandler) buildSession(model, provider string) (jobs.Spec, error) {
	jobID := make([]byte, jobs.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		return jobs.Spec{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return jobs.Spec{}, err
	}
	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            jobID,
		Provider:         provider,
		Model:            model,
		Method:           "GET",
		Host:             c.cfg.HostFor(provider),
		Path:             realtimePath,
		Query:            c.cfg.Query,
		Headers:          map[string]string{},
		BodyHash:         shared.BodyHash(nil),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: c.cfg.Max,
		Stream:           true,
		Session:          true,
	}, nil
}

// sessionLink adapts the user WebSocket to the Hub's RealtimeLink seam. Read
// yields the user's uplink — the first frame is replayed so the model read out
// of it still reaches the provider — and Write delivers the provider's downlink.
//
// The TEE tunnel is a transparent byte pipe that relays payload bytes verbatim;
// WebSocket frame semantics are the Hub's business, so this adapter owns them
// on both directions:
//
//   - Uplink: the user WebSocket driver (gorilla) already strips the user's
//     frame, leaving a raw payload. A provider's parser, however, expects a legal
//     masked client frame, so Read re-wraps each payload in one before it is
//     handed to the tunnel.
//   - Downlink: the tunnel yields the provider's raw server frames (possibly
//     split or bundled across tunnel messages), so Write decodes the frame stream
//     and re-emits each data frame's payload to the user as a fresh message.
//
// Like the TEE tunnel it is a full-duplex pipe: the Hub relays the two directions
// on separate goroutines, so the user socket is locked per direction and never
// across a blocking read (which would deadlock the session).
type sessionLink struct {
	conn *websocket.Conn

	readMu  sync.Mutex // serializes the uplink reader (one reader only)
	writeMu sync.Mutex // serializes the downlink writer (one writer only)

	// mu guards buf/readErr; the wire I/O happens after releasing it.
	mu      sync.Mutex
	first   []byte
	buf     []byte
	readErr error
	lastOp  int

	// down frames the incoming provider (server) frame stream. Only the downlink
	// writer touches it, so it is guarded by writeMu.
	down *hub.WsFrameDecoder
}

// Read returns the next provider-bound chunk: a legal masked client frame built
// from the user's message (or the replayed first frame). The bytes are exactly
// what the provider's own parser must accept.
func (l *sessionLink) Read(p []byte) (int, error) {
	l.readMu.Lock()
	defer l.readMu.Unlock()
	l.mu.Lock()
	// Pull one raw payload out of first/buf, then frame it below.
	var payload []byte
	if len(l.first) > 0 {
		payload = l.first
		l.first = nil
	} else {
		for len(l.buf) == 0 {
			if l.readErr != nil {
				err := l.readErr
				l.mu.Unlock()
				return 0, err
			}
			l.mu.Unlock()

			mt, msg, werr := l.conn.ReadMessage()
			l.mu.Lock()
			if werr != nil {
				l.readErr = werr
				l.mu.Unlock()
				return 0, werr
			}
			l.buf = msg
			l.lastOp = mt
		}
		payload = l.buf
		l.buf = nil
	}
	op := l.lastOp
	if op != websocket.BinaryMessage {
		op = websocket.TextMessage
	}
	frame := hub.MaskClientFrame(frameOpcode(op), payload)
	n := copy(p, frame)
	l.mu.Unlock()
	// Frame is at most payload length + 10 and p is at least the caller's 32 KiB
	// buffer, so a single user message always fits in one handed chunk. Assert
	// against a future buffer shrink rather than silently returning a partial.
	if n < len(frame) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func frameOpcode(mt int) byte {
	if mt == websocket.BinaryMessage {
		return hub.WSOpBinary
	}
	return hub.WSOpText
}

// Write consumes a tunnel downlink chunk (raw provider frames), decodes it, and
// re-emits each data frame's payload to the user as a fresh WebSocket message.
// It returns len(p) because every byte fed in is accounted for; a close frame
// (or a broken user socket) stops forwarding.
func (l *sessionLink) Write(p []byte) (int, error) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if l.down == nil {
		l.down = hub.NewWsFrameDecoder()
	}
	for _, f := range l.down.Feed(p) {
		if f.Terminal {
			break
		}
		if f.Opcode != hub.WSOpText && f.Opcode != hub.WSOpBinary {
			continue // control frames are not user data
		}
		msgType := websocket.TextMessage
		if f.Opcode == hub.WSOpBinary {
			msgType = websocket.BinaryMessage
		}
		// Roll a write deadline with every frame: a user that stops reading
		// must not pin this goroutine — and the tunnel behind it — forever.
		_ = l.conn.SetWriteDeadline(time.Now().Add(defaultResponseWriteTimeout))
		if err := l.conn.WriteMessage(msgType, f.Data); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
