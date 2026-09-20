// Package provider implements the TokenHive Provider Agent: the process a quota
// contributor runs on their own machine so a TEE can egress through their
// network.
//
// The agent lives behind a home NAT, so it cannot be dialed: it dials the Hub
// and keeps one multiplexed WebSocket open (what the design calls the reverse
// tunnel). Registering with the Hub's AgentGate makes it online and schedulable;
// while that tunnel stays up, the Hub routes this provider's egress through it.
// The shared key it presents at dial-in is the only thing telling the Hub that
// this machine may claim to egress for its provider.
//
// The agent is deliberately dumb. For each relay stream the Hub opens on its
// tunnel it dials the named upstream host once — checked against a fixed
// allowlist — and then copies bytes in both directions without inspecting them.
// It cannot read the traffic it relays: the TEE's TLS session with the AI
// provider is end to end, and the agent sees only the encrypted bytes of a
// session it is not party to.
//
// What the agent enforces, and all it enforces:
//
//   - The allowlist. An agent that forwarded to arbitrary hosts would turn a
//     contributor's machine into a general-purpose proxy; the allowlist keeps
//     the exposure to "AI provider endpoints", which is what the contributor
//     signed up for.
//
//   - A cap on how many relays it serves at once (MaxRelayConns), so one Hub
//     cannot occupy the contributor's machine, plus an idle timeout on each
//     relay (RelayIdle), so an abandoned stream cannot hold an upstream
//     connection open forever.
//
//   - Byte counters over what it relayed (Stats). The bytes stay opaque — they
//     are a TLS session the agent is not party to — so counts and outcomes are
//     the only facts the contributor can be shown.
package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

// Agent errors.
var (
	ErrEmptyAllowlist = errors.New("provider agent: allowlist must not be empty")
	ErrNoGateURL      = errors.New("provider agent: no Hub gate URL")
	ErrNoSharedKey    = errors.New("provider agent: no shared key")
	ErrNoProvider     = errors.New("provider agent: no provider name")

	// ErrCleartextGate means the Hub gate URL would carry this seller's secrets
	// over a plaintext connection to a host that is not this machine. The
	// dial-in key is what tells the Hub this machine may egress for the
	// provider, and the key the agent seals its token to is fetched over the
	// same hop from the Hub (see credentialKey): against a remote ws:// both are
	// readable and rewritable by anyone on the path, and a rewritten inbox key
	// is a token handed to an attacker. Loopback is the one cleartext hop a
	// network attacker cannot rewrite, so it stays allowed for the local
	// simulation and tests; anything further needs wss://, or an explicit opt-in
	// (AllowCleartextGate) from someone who knows the hop is trusted.
	ErrCleartextGate = errors.New("provider agent: refusing a non-loopback Hub gate over plaintext ws://")
)

// AgentConfig assembles an Agent.
type AgentConfig struct {
	// HubGateURL is the Hub's AgentGate WebSocket endpoint the agent dials to
	// come online, e.g. ws://127.0.0.1:18085/v1/agent. Required.
	HubGateURL string

	// SharedKey is the preset secret the agent presents at dial-in. It must
	// match this provider's entry in the Hub's -agent-keys map, or the gate
	// refuses the tunnel. Required.
	SharedKey []byte

	// Self announces the agent on registration: which provider it egresses for,
	// an optional display label, and — when SelfPrice is set — the price it
	// wants to charge. A nil SelfPrice means the agent accepts the Hub's
	// platform default. Required: Provider must be set.
	Self hub.AgentRegister

	// Credential is the provider's access token together with the header it is
	// presented in. It is the one secret the seller owns; it never appears on
	// the wire in plaintext. When set, each registration fetches the Hub's
	// published TEE inbox key, seals this credential to it (tee.Envelope), and
	// the Hub relays only the ciphertext onward. A zero Credential (no token)
	// registers without an envelope — the Hub's gate refuses such registrations
	// when it hosts agents, so this only matters for agent-only relay tests.
	Credential tee.Secret

	// AllowedTargets lists the exact "host:port" upstreams the agent will dial.
	// Anything else is refused before a single byte egresses. It must be
	// non-empty: an agent that forwards anywhere is a public proxy.
	AllowedTargets []string

	// ConnectTimeout bounds dialing the Hub and dialing each upstream. Zero means
	// 10s.
	ConnectTimeout time.Duration

	// ReconnectDelay is the pause before the first reconnect after the tunnel
	// drops. Each consecutive failed attempt doubles it up to MaxReconnectDelay,
	// so a Hub that is briefly unreachable cannot be hammered at a fixed rate.
	// Zero means 1s.
	ReconnectDelay time.Duration

	// MaxReconnectDelay caps the backoff. Zero means 30s.
	MaxReconnectDelay time.Duration

	// ModelsURL, when set, is fetched once before the agent comes online and
	// the model list it returns declares this agent's upstream capability to
	// the Hub. It follows the OpenAI /v1/models convention: a JSON object whose
	// "data" array holds objects with an "id" field. A plain newline-separated
	// list is accepted as a fallback.
	//
	// A fetch failure is fatal: the agent reports the error and refuses to come
	// online rather than silently registering as if it served anything. When
	// unset and Self.Models is empty the agent declares no models, which the
	// Hub reads as "serves anything" (relay-only deployments, tests).
	ModelsURL string

	// RootCAs, when set, replaces the system pool for the agent's control-plane
	// HTTPS fetches (the ModelsURL discovery). The simulation injects the
	// mock provider's throwaway CA here; production leaves it nil and trusts
	// the public roots.
	RootCAs *x509.CertPool

	// AllowCleartextGate permits a HubGateURL that is plaintext ws:// to a host
	// other than this machine's loopback: an explicit "I know this hop is
	// trusted" for a deployment that terminates TLS in front of the Hub on a
	// private network, and for nothing else. See ErrCleartextGate.
	AllowCleartextGate bool

	// DialTarget replaces the outbound upstream dial. Test injection point; nil
	// uses the standard dialer.
	DialTarget func(ctx context.Context, network, addr string) (net.Conn, error)

	// Tap, when set, receives a copy of every byte the agent relays on either
	// wire (the tunnel to the Hub and the tunnel to the provider). It is a
	// test/demo affordance only — used by the local simulation to prove the
	// agent sees only the encrypted bytes of a TLS session it is not party to.
	// Never set in production; the relay must stay dumb.
	Tap io.Writer

	// MaxRelayConns caps how many relay streams the agent serves at once. Zero
	// means no cap; the agent binary ships DefaultMaxRelayConns. Streams past
	// the cap are refused outright rather than queued, so the Hub learns the
	// machine is full and can route to another provider instead of waiting.
	//
	// It bounds the contributor's exposure, not the Hub's: the Hub's fair-share
	// cap is per tenant and the TEE pools connections per provider, but only the
	// agent can decide how much of its own machine and its own upstream
	// connections it will commit.
	MaxRelayConns int

	// RelayIdle tears a relay stream down once it has carried no bytes in either
	// direction for this long. Zero means no watchdog; the agent binary ships
	// DefaultRelayIdle.
	//
	// It must sit above every bound the Hub and the TEE put on a job, so the
	// agent never gives up on a stream its counterpart still considers live. The
	// Hub ships -attempt-timeout 3m and the TEE -request-timeout 2m, which is
	// where DefaultRelayIdle's 5m comes from.
	RelayIdle time.Duration
}

// Agent is the Provider Agent reverse-tunnel client. It is safe to Run once.
type Agent struct {
	cfg AgentConfig
	hdr http.Header

	// slots bounds concurrently served relays; nil means no bound (see
	// MaxRelayConns).
	slots chan struct{}

	// meter counts what the agent relayed and what it turned away (see Stats).
	meter relayMeter

	// models is the list resolved from ModelsURL before the first dial (see
	// prepareModels). It stays empty when no automatic discovery is configured,
	// which the Hub reads as "serves anything".
	models []string
}

// NewAgent validates the configuration and returns a ready agent.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.HubGateURL == "" {
		return nil, ErrNoGateURL
	}
	if len(cfg.SharedKey) == 0 {
		return nil, ErrNoSharedKey
	}
	if cfg.Self.Provider == "" {
		return nil, ErrNoProvider
	}
	if len(cfg.AllowedTargets) == 0 {
		return nil, ErrEmptyAllowlist
	}
	if cfg.Credential.Token != "" {
		if err := cfg.Credential.Validate(); err != nil {
			return nil, err
		}
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.ReconnectDelay <= 0 {
		cfg.ReconnectDelay = time.Second
	}
	if cfg.MaxReconnectDelay <= 0 {
		cfg.MaxReconnectDelay = 30 * time.Second
	}
	if err := checkGateTransport(cfg.HubGateURL, cfg.AllowCleartextGate); err != nil {
		return nil, err
	}
	a := &Agent{cfg: cfg}
	if cfg.MaxRelayConns > 0 {
		a.slots = make(chan struct{}, cfg.MaxRelayConns)
	}
	a.hdr = http.Header{}
	a.hdr.Set(hub.AgentKeyHeader, string(cfg.SharedKey))
	// Name the provider on the dial-in too, so a Hub configured with
	// per-provider keys can bind this tunnel to exactly this provider before
	// upgrading. A Hub with only a shared key ignores the header.
	a.hdr.Set(hub.AgentProviderHeader, cfg.Self.Provider)
	return a, nil
}

// checkGateTransport refuses a cleartext dial-in to anything but loopback (see
// ErrCleartextGate). It runs at construction rather than at dial time so a
// misconfigured seller learns at startup, not on the first reconnect.
func checkGateTransport(gateURL string, allowCleartext bool) error {
	parsed, err := url.Parse(gateURL)
	if err != nil {
		return fmt.Errorf("provider agent: parse Hub gate URL: %w", err)
	}
	if parsed.Scheme == "wss" || allowCleartext {
		return nil
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrCleartextGate, gateURL)
}

// Run keeps the agent online until ctx is cancelled, reconnecting after every
// tunnel drop. register is one full connection cycle: dial, register, and relay
// until the tunnel ends.
//
// Automatic model discovery happens before the first dial (see
// prepareModels): a ModelsURL that cannot be fetched is a configuration
// error, reported here so the operator sees it instead of an agent that
// silently comes online claiming to serve anything.
//
// The context also interrupts an in-flight cycle: without it, a graceful stop
// would leave the tunnel open (runOnce blocks in io.Copy on the control
// stream) and the Hub would keep the provider online. runOnce registers the
// interrupt with the live tunnel so cancellation closes the connection, which
// is exactly what a killed process does — the Hub sees the drop and revokes
// the credential.
//
// Reconnects back off: a failed attempt doubles the pause up to
// MaxReconnectDelay, and a clean connection resets it to ReconnectDelay. A Hub
// that is briefly unreachable therefore gets a widening gap between attempts
// rather than a fixed-rate hammer, which is the whole point — an agent must
// not amplify a Hub outage into a connection storm. Each pause is then
// jittered (see jittered), so agents that all went offline together do not
// come back in the same instant.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prepareModels(); err != nil {
		return err
	}
	delay := a.cfg.ReconnectDelay
	for {
		err := a.runOnce(ctx)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			delay = a.cfg.ReconnectDelay
		} else {
			next := delay * 2
			if next <= 0 || next > a.cfg.MaxReconnectDelay {
				next = a.cfg.MaxReconnectDelay
			}
			delay = next
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jittered(delay)):
		}
	}
}

// jittered returns a delay in [0, d): full jitter on the backoff pause. The
// doubling still bounds how fast a hopeless retry loop spins, but the phase is
// now random, so a fleet of agents that lost its tunnel at the same instant
// (a TEE or Hub restart) reconnects spread across the window instead of
// arriving in lockstep waves that spike the Hub and the TEE together.
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(d)))
}

// runOnce runs one connection cycle: dial the Hub gate, register, and relay
// until the tunnel drops. It returns when the tunnel ends so Run can reconnect.
func (a *Agent) runOnce(ctx context.Context) error {
	dialer := websocket.Dialer{HandshakeTimeout: a.cfg.ConnectTimeout}
	conn, resp, err := dialer.DialContext(ctx, a.cfg.HubGateURL, a.hdr)
	if err != nil {
		return fmt.Errorf("dial hub gate: %w", err)
	}
	defer conn.Close()
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("hub gate: %s", resp.Status)
	}

	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.High)
	defer mux.Close()
	mux.Serve(a.handleRelay)

	// Interrupt this cycle when the run context is cancelled: closing the
	// connection unblocks the control-stream copy below and tells the Hub the
	// agent went offline (which revokes the credential).
	stopOnCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stopOnCancel()

	reg, err := a.register()
	if err != nil {
		return err
	}
	register, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("encode registration: %w", err)
	}
	control, err := mux.Dial(register)
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer control.Close()

	// The control stream is the agent's lease on being online: it stays open
	// until the Hub tears the tunnel down or the connection drops, either of
	// which returns here and lets Run reconnect.
	if _, err := io.Copy(io.Discard, control); err != nil {
		// A tunnel that went down is how a lease usually ends — the Hub
		// restarted, the network blipped — so it is reported as the end of a
		// cycle that got online, not as a failure to get online: Run resets the
		// reconnect delay for it instead of doubling the wait, which for an
		// agent that has been serving traffic would otherwise ratchet to the
		// maximum and keep it offline for no reason.
		if errors.Is(err, tunnel.ErrTunnelFailed) {
			return nil
		}
		return err
	}
	return nil
}

// register seals the credential to the current TEE inbox key and returns the
// control-stream payload. Fetching and re-encrypting on every connection cycle
// keeps registrations correct across TEE restarts: a fresh TEE generates a
// fresh inbox key, and the agent's next dial picks it up.
//
// A configuration without a token skips the fetch entirely and registers
// without an envelope (relay-only deployments, tests).
func (a *Agent) register() (hub.AgentRegister, error) {
	reg := a.cfg.Self
	if len(a.models) > 0 {
		// Automatic discovery (ModelsURL) resolved before the first dial; the
		// discovered list is the declaration. An explicitly configured
		// Self.Models always wins over discovery.
		if len(reg.Models) == 0 {
			reg.Models = a.models
		}
	}
	if a.cfg.Credential.Token == "" {
		return reg, nil
	}

	pub, err := a.credentialKey()
	if err != nil {
		return reg, err
	}
	envelope, err := tee.EncryptCredential(pub, reg.Provider, a.cfg.Credential)
	if err != nil {
		return reg, fmt.Errorf("seal credential: %w", err)
	}
	reg.Credential = &envelope
	return reg, nil
}

// prepareModels resolves ModelsURL before the first dial, so a provider that
// asked for automatic model discovery but cannot reach its upstream fails
// here — Run returns the error and the agent never comes online — instead of
// registering as if it served anything. Self.Models, when configured
// explicitly, is used as-is and discovery is skipped. Models are resolved
// once per agent lifetime: re-fetching on every reconnect would probe the
// upstream on the very cadence the backoff exists to stop.
func (a *Agent) prepareModels() error {
	if a.cfg.ModelsURL == "" || len(a.cfg.Self.Models) > 0 {
		return nil
	}
	var auth http.Header
	if a.cfg.Credential.Token != "" {
		if name, value, err := a.cfg.Credential.Render(); err == nil {
			auth = http.Header{name: []string{value}}
		}
	}
	models, err := fetchModels(a.cfg.ModelsURL, a.httpClient(), auth)
	if err != nil {
		return fmt.Errorf("no models configured and fetching %s failed: %w", a.cfg.ModelsURL, err)
	}
	if len(models) == 0 {
		return fmt.Errorf("no models configured and %s returned an empty model list", a.cfg.ModelsURL)
	}
	a.models = models
	return nil
}

// fetchModels retrieves a model list following the OpenAI /v1/models shape:
// a JSON object with a "data" array of objects carrying an "id". A
// newline-delimited plain-text list is accepted as a fallback, so a provider
// can point ModelsURL at anything from a live API to a static file.
// auth, when non-nil, is applied to the request (many providers require the
// same credential on the models endpoint as on the inference endpoints).
func fetchModels(url string, client *http.Client, auth http.Header) ([]string, error) {
	// The credential is applied below, before the upstream is known to be who
	// it claims: over cleartext it would travel readable. Refuse rather than
	// leak it, and let the operator point -models-url at an https endpoint (the
	// conventional one already is).
	if len(auth) > 0 && !strings.HasPrefix(strings.ToLower(url), "https://") {
		return nil, fmt.Errorf("refusing to send the provider credential to the non-https models URL %s", url)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("models url: %w", err)
	}
	req.Header = auth
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch models: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch models: status %d", resp.StatusCode)
	}

	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read models: %w", err)
	}
	if jsonErr := json.Unmarshal(raw, &doc); jsonErr == nil && len(doc.Data) > 0 {
		ids := make([]string, 0, len(doc.Data))
		for _, d := range doc.Data {
			if d.ID != "" {
				ids = append(ids, d.ID)
			}
		}
		return ids, nil
	}

	// Fallback: one model ID per line.
	var ids []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ids = append(ids, line)
		}
	}
	return ids, nil
}

// credentialKey fetches the Hub's published TEE inbox public key. The Hub
// relays it from its credential plane; the agent never needs the TEE's address
// or its attestation — it encrypts to whatever key the Hub is currently
// delivering credentials to.
func (a *Agent) credentialKey() (tee.InboxPublic, error) {
	keyURL := a.hubHTTPURL() + "/v1/credential-key"
	pub, err := tee.CredentialKeyRequest(context.Background(), a.httpClient(), keyURL)
	if err != nil {
		return pub, fmt.Errorf("fetch inbox key: %w", err)
	}
	return pub, nil
}

// hubHTTPURL rewrites the dialed WebSocket gate URL into the Hub's HTTP base,
// e.g. ws://hub:port/v1/agent -> http://hub:port, and wss:// -> https://.
func (a *Agent) hubHTTPURL() string {
	base := strings.Replace(a.cfg.HubGateURL, "wss://", "https://", 1)
	base = strings.Replace(base, "ws://", "http://", 1)
	return strings.TrimSuffix(base, "/v1/agent")
}

// httpClient returns a bounded client for the control-plane HTTP calls the
// agent makes (model discovery and the credential-key fetch). It is
// deliberately separate from the WebSocket dialer: same server, different hop.
// RootCAs, when set, replaces the system pool so the simulation's agent can
// fetch the model list from the TLS mock provider.
func (a *Agent) httpClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if a.cfg.RootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: a.cfg.RootCAs, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: a.cfg.ConnectTimeout, Transport: transport}
}

// handleRelay decodes one Hub-opened relay and serves it: the frame names the
// upstream to dial, the allowlist decides whether it may be dialed, and
// serveRelay bridges the bytes. It runs on its own goroutine (the tunnel spawns
// one per open) and only ever moves bytes.
func (a *Agent) handleRelay(s *tunnel.Stream, open []byte) {
	defer s.Close()

	var up hub.UpstreamOpen
	if err := json.Unmarshal(open, &up); err != nil {
		return
	}
	if up.Host == "" || !a.allows(up.Host) {
		return
	}
	a.serveRelay(s, up)
}

// allows reports whether host is on the allowlist. Exact host:port match only:
// patterns would invite "close enough" targets that were never meant to be
// allowed.
func (a *Agent) allows(host string) bool {
	for _, allowed := range a.cfg.AllowedTargets {
		if host == allowed {
			return true
		}
	}
	return false
}

// dialTarget opens the outbound connection to the upstream host.
func (a *Agent) dialTarget(host string) (net.Conn, error) {
	dial := a.cfg.DialTarget
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.ConnectTimeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", host, err)
	}
	return conn, nil
}
