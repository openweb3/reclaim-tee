package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tunnel"
)

const testAgentSecret = "s3cret-agent-key"

var testUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// startEchoUpstream returns the host:port of a raw TCP server that echoes any
// bytes written to it.
func startEchoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

// miniHub plays the Hub's gate: authenticate the dial-in, receive the
// registration, then open a relay stream back toward the agent (the upstream the
// agent must dial is encoded in the registration's provider name). The relay
// stream is handed to the test so it can drive the echo directly. It exercises
// the agent's full reverse-tunnel lifecycle without depending on the rest of the
// Hub.
type miniHub struct {
	registrations chan hub.AgentRegister
	relays        chan *tunnel.Stream
	stop          chan struct{}

	// relayCount is how many relay streams the gate opens per registration.
	// Every test but the connection-cap one wants the single stream that comes
	// with a registration; that one needs several at the same instant.
	relayCount int
}

func (h *miniHub) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(hub.AgentKeyHeader) != testAgentSecret {
		http.Error(w, "bad key", http.StatusUnauthorized)
		return
	}
	conn, err := testUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	mux := tunnel.New(tunnel.WrapWS(conn), tunnel.Low)
	mux.Serve(func(control *tunnel.Stream, open []byte) {
		var reg hub.AgentRegister
		if err := json.Unmarshal(open, &reg); err != nil {
			_ = control.Close()
			return
		}
		h.registrations <- reg
		// Drain the control stream so it stays open (the agent's lease).
		go func() { _, _ = io.Copy(io.Discard, control) }()
		// Open relay streams toward the agent naming the upstream to dial. The
		// agent bridges them; we hand the pipes to the test.
		meta, _ := json.Marshal(hub.UpstreamOpen{Host: echoHostFor(reg.Provider)})
		for i := 0; i < h.relayCount; i++ {
			relay, err := mux.Dial(meta)
			if err != nil {
				return
			}
			h.relays <- relay
		}
	})
	// Keep the tunnel alive for the test's lifetime: block the handler instead of
	// letting it return (which would close the connection out from under the
	// agent's registration).
	<-h.stop
	_ = mux.Close()
	_ = conn.Close()
}

func startMiniHub(t *testing.T) (*miniHub, string) { return startMiniHubRelays(t, 1) }

// startMiniHubRelays is startMiniHub with the gate opening n relay streams per
// registration, for tests about how many the agent will serve at once.
func startMiniHubRelays(t *testing.T, n int) (*miniHub, string) {
	t.Helper()
	mh := &miniHub{
		registrations: make(chan hub.AgentRegister, 4),
		relays:        make(chan *tunnel.Stream, 8),
		stop:          make(chan struct{}),
		relayCount:    n,
	}
	srv := httptest.NewServer(http.HandlerFunc(mh.handler))
	t.Cleanup(func() {
		close(mh.stop)
		srv.Close()
	})
	return mh, "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent"
}

// echoHostFor recovers the upstream host the agent must reach from the provider
// name the miniHub chose for it. The tests name providers as their echo target,
// which keeps the relay open's meta self-consistent with the allowlist.
func echoHostFor(provider string) string {
	if i := strings.Index(provider, ":"); i >= 0 {
		return provider
	}
	return ""
}

func TestAgentRegistersAndRelays(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	selfPrice := &hub.RateCard{PerRequestMicros: 250_000}
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo, DisplayName: "home-1", SelfPrice: selfPrice},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	var reg hub.AgentRegister
	select {
	case reg = <-mh.registrations:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not register")
	}
	if reg.Provider != echo {
		t.Errorf("registered provider = %q, want %q", reg.Provider, echo)
	}
	if reg.SelfPrice == nil || reg.SelfPrice.PerRequestMicros != 250_000 {
		t.Errorf("registered self-price = %+v, want the declared card", reg.SelfPrice)
	}

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	msg := []byte("the quick brown fox jumps over the lazy dog")
	go func() { _, _ = relay.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(relay, back); err != nil {
		t.Fatalf("read relay echo: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("echo mismatch: %q", back)
	}
}

func TestAgentSampleOnlyMirrorsBytes(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	var tap bytes.Buffer
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
		Tap:            &tap,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	msg := []byte("plaintext-through-the-tap")
	go func() { _, _ = relay.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(relay, back); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if tap.Len() == 0 {
		t.Error("tap captured nothing")
	}
	if !strings.Contains(tap.String(), string(msg)) {
		t.Errorf("tap bytes %q missing the relayed bytes", tap.String())
	}
}

func TestAgentRefusesOutsideAllowlist(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	// Allowlist deliberately omits echo, so the relay open must be refused.
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{"127.0.0.1:1"},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	// The agent refuses to dial a host outside its allowlist and hangs up the
	// stream; the echo must never come back. A read that ends signals the
	// refusal; a read that succeeds is the failure.
	buf := make([]byte, 4)
	got := make(chan error, 1)
	go func() { _, err := relay.Read(buf); got <- err }()
	select {
	case err := <-got:
		if err == nil {
			t.Error("expected the relay to refuse the off-allowlist host, but it echoed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay stream neither echoed nor closed for an off-allowlist host")
	}
}

// probeRelay writes msg down a relay and reports whether it came back. It
// deliberately does not close the relay: the caller decides when the stream —
// and the agent's slot behind it — is released, which is what lets a test hold
// one relay open while probing others.
func probeRelay(t *testing.T, relay *tunnel.Stream, msg []byte) <-chan bool {
	t.Helper()
	result := make(chan bool, 1)
	go func() {
		back := make([]byte, len(msg))
		if _, err := relay.Write(msg); err != nil {
			result <- false
			return
		}
		_, err := io.ReadFull(relay, back)
		result <- err == nil && bytes.Equal(back, msg)
	}()
	return result
}

// waitProbe waits for a probe to finish. A relay the agent refused, or one it
// gave up on, ends the read without an echo, so a probe always completes for
// both outcomes — a probe that never completes is a hang, not a refusal.
func waitProbe(t *testing.T, result <-chan bool) bool {
	t.Helper()
	select {
	case ok := <-result:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("a relay neither echoed nor closed")
		return false
	}
}

// relayEchoes writes msg down a relay and reports whether it came back, closing
// the relay either way.
func relayEchoes(t *testing.T, relay *tunnel.Stream, msg []byte) bool {
	t.Helper()
	defer relay.Close()
	return waitProbe(t, probeRelay(t, relay, msg))
}

// TestAgentRefusesRelaysBeyondItsConnectionCap pins the contributor-side bound:
// the agent serves at most MaxRelayConns streams at once and refuses the rest
// outright. Refusing rather than queueing is what lets the Hub see that the
// machine is full and route the job to another provider, instead of waiting on
// one that has already said no.
func TestAgentRefusesRelaysBeyondItsConnectionCap(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHubRelays(t, 3)

	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
		MaxRelayConns:  1,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	relays := make([]*tunnel.Stream, 0, 3)
	for i := 0; i < 3; i++ {
		select {
		case r := <-mh.relays:
			relays = append(relays, r)
		case <-time.After(5 * time.Second):
			t.Fatalf("hub opened only %d of 3 relays", i)
		}
	}

	// Probe all three without closing any: the relay that won the slot must
	// still be holding it while the other two are handled, which is the state
	// the cap is about. Closing as we went could hand the slot to the next relay
	// and let a second one be served.
	results := make([]<-chan bool, len(relays))
	for i, r := range relays {
		results[i] = probeRelay(t, r, []byte("one-slot"))
	}
	served := 0
	for _, res := range results {
		if waitProbe(t, res) {
			served++
		}
	}
	for _, r := range relays {
		_ = r.Close()
	}

	if served != 1 {
		t.Fatalf("%d of 3 relays were served, want exactly 1 (the cap)", served)
	}
	stats := a.Stats()
	if stats.Accepted != 1 {
		t.Errorf("accepted = %d, want 1", stats.Accepted)
	}
	if stats.Refused != 2 {
		t.Errorf("refused = %d, want 2", stats.Refused)
	}
}

// TestAgentWithoutARelayCapServesEveryStream pins the opt-out: a zero cap means
// no bound and no bookkeeping, the same shape the Hub's controls use.
func TestAgentWithoutARelayCapServesEveryStream(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHubRelays(t, 3)

	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if a.slots != nil {
		t.Fatalf("an agent with no configured cap built a slot table: %+v", a.slots)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	msg := []byte("no-cap")
	for i := 0; i < 3; i++ {
		var relay *tunnel.Stream
		select {
		case relay = <-mh.relays:
		case <-time.After(5 * time.Second):
			t.Fatalf("hub opened only %d of 3 relays", i)
		}
		if !relayEchoes(t, relay, msg) {
			t.Fatalf("relay %d was refused despite no configured cap", i)
		}
	}
	if got := a.Stats().Refused; got != 0 {
		t.Fatalf("refused = %d, want 0 with no cap configured", got)
	}
}

// TestAgentClosesAnIdleRelay pins the idle watchdog: a relay that carries
// nothing is torn down by the agent itself. Nothing else would do it — a tunnel
// stream has no read deadline (its Read parks on a condition variable), so a
// relay whose peer has gone quiet stays parked, holding the contributor's
// upstream connection, until something closes it.
func TestAgentClosesAnIdleRelay(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
		RelayIdle:      100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	// Send nothing at all. The echo upstream only answers what it is given, so
	// the relay carries no bytes in either direction and the watchdog must fire.
	closed := make(chan error, 1)
	go func() { _, err := relay.Read(make([]byte, 1)); closed <- err }()
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("idle relay delivered bytes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never closed the idle relay")
	}
	if got := a.Stats().IdleClosed; got != 1 {
		t.Fatalf("idle-closed = %d, want 1", got)
	}
}

// TestAgentMetersRelayedBytes pins the usage counters: a contributor can see how
// many relays their machine carried and how many bytes crossed it. That is all
// there is to see — the bytes are a TLS session the agent is not party to — and
// it is what makes the machine's contribution auditable by its owner.
func TestAgentMetersRelayedBytes(t *testing.T) {
	echo := startEchoUpstream(t)
	mh, gateURL := startMiniHub(t)

	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: echo},
		AllowedTargets: []string{echo},
		ReconnectDelay: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()
	<-mh.registrations

	var relay *tunnel.Stream
	select {
	case relay = <-mh.relays:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not open a relay stream")
	}
	defer relay.Close()

	msg := []byte("count-these-bytes")
	go func() { _, _ = relay.Write(msg) }()
	back := make([]byte, len(msg))
	if _, err := io.ReadFull(relay, back); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Poll: the counters are written by the bridge's own goroutines, so the echo
	// arriving on this side does not order the last Add.
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats := a.Stats()
		if stats.Accepted == 1 && stats.Active == 1 && stats.Peak == 1 &&
			stats.RequestBytes == uint64(len(msg)) && stats.ResponseBytes == uint64(len(msg)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats = %s, want 1 relay active and %d bytes each way", stats, len(msg))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAgentRejectsWrongKey(t *testing.T) {
	_, gateURL := startMiniHub(t)
	a, err := NewAgent(AgentConfig{
		HubGateURL:     gateURL,
		SharedKey:      []byte("wrong-key"),
		Self:           hub.AgentRegister{Provider: "p1"},
		AllowedTargets: []string{"127.0.0.1:1"},
		ReconnectDelay: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	// Wrong key is refused at the gate; Run retries. Give it a couple attempts,
	// then cancel and confirm it unwinds cleanly.
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop after cancellation")
	}
}

func TestAgentRequiresConfig(t *testing.T) {
	if _, err := NewAgent(AgentConfig{}); err == nil {
		t.Fatal("expected an error for empty config")
	}
	if _, err := NewAgent(AgentConfig{HubGateURL: "ws://x"}); !errors.Is(err, ErrNoSharedKey) {
		t.Fatalf("error = %v, want ErrNoSharedKey", err)
	}
	if _, err := NewAgent(AgentConfig{HubGateURL: "ws://x", SharedKey: []byte("k")}); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("error = %v, want ErrNoProvider", err)
	}
	if _, err := NewAgent(AgentConfig{
		HubGateURL: "ws://x", SharedKey: []byte("k"), Self: hub.AgentRegister{Provider: "p"},
	}); !errors.Is(err, ErrEmptyAllowlist) {
		t.Fatalf("error = %v, want ErrEmptyAllowlist", err)
	}
}

// TestAgentRefusesACleartextGateOffLoopback pins the one hop the agent does not
// leave to chance. Over plaintext ws:// to a host that is not this machine, the
// dial-in key and the inbox key it seals its token to are both readable and
// rewritable by anyone on the path, and a rewritten inbox key is a token handed
// to whoever rewrote it.
func TestAgentRefusesACleartextGateOffLoopback(t *testing.T) {
	base := AgentConfig{
		SharedKey:      []byte("k"),
		Self:           hub.AgentRegister{Provider: "p"},
		AllowedTargets: []string{"api.example.com"},
	}
	cases := []struct {
		name  string
		gate  string
		allow bool
		ok    bool
	}{
		{"plaintext to a remote hub", "ws://hub.example/v1/agent", false, false},
		{"plaintext to loopback", "ws://127.0.0.1:18085/v1/agent", false, true},
		{"plaintext to localhost", "ws://localhost:18085/v1/agent", false, true},
		{"TLS to a remote hub", "wss://hub.example/v1/agent", false, true},
		{"plaintext opted in", "ws://hub.example/v1/agent", true, true},
	}
	for _, tc := range cases {
		cfg := base
		cfg.HubGateURL = tc.gate
		cfg.AllowCleartextGate = tc.allow
		_, err := NewAgent(cfg)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrCleartextGate) {
			t.Errorf("%s: error = %v, want %v", tc.name, err, ErrCleartextGate)
		}
	}
}

// TestAgentDiscoversModelsFromUpstream pins the no-config path: an agent with
// no explicit model list fetches the conventional /v1/models endpoint before
// it comes online and reports the discovered list at registration.
func TestAgentDiscoversModelsFromUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"gpt-4o"},{"id":"deepseek-pro"},{"id":"deepseek-flash"}]}`)
	}))
	defer srv.Close()

	a, err := NewAgent(AgentConfig{
		HubGateURL:     "ws://127.0.0.1:1/v1/agent",
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: "p"},
		AllowedTargets: []string{"api.example.com"},
		ModelsURL:      srv.URL + "/v1/models",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if err := a.prepareModels(); err != nil {
		t.Fatalf("prepareModels: %v", err)
	}
	got := a.models
	want := []string{"gpt-4o", "deepseek-pro", "deepseek-flash"}
	if len(got) != len(want) {
		t.Fatalf("discovered models = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("discovered models = %v, want %v", got, want)
		}
	}
}

// TestAgentRefusesToComeOnlineWithoutDiscoverableModels pins that a failed
// model discovery is fatal: the agent reports the error instead of silently
// registering as "serves anything".
func TestAgentRefusesToComeOnlineWithoutDiscoverableModels(t *testing.T) {
	// A models endpoint that answers 404 — no upstream model list to find.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	a, err := NewAgent(AgentConfig{
		HubGateURL:     "ws://127.0.0.1:1/v1/agent",
		SharedKey:      []byte(testAgentSecret),
		Self:           hub.AgentRegister{Provider: "p"},
		AllowedTargets: []string{"api.example.com"},
		ModelsURL:      srv.URL + "/v1/models",
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	if err := a.prepareModels(); err == nil {
		t.Fatal("prepareModels succeeded against a 404 models endpoint")
	}
}

// TestAgentDerivesHTTPBaseFromEitherGateScheme pins the scheme rewrite the
// credential-key fetch depends on: a TLS Hub gate (wss://) has to become
// https://, because http.NewRequest rejects a WebSocket scheme outright and the
// agent would then never register.
func TestAgentDerivesHTTPBaseFromEitherGateScheme(t *testing.T) {
	cases := map[string]string{
		"ws://127.0.0.1:18085/v1/agent":  "http://127.0.0.1:18085",
		"wss://hub.example:443/v1/agent": "https://hub.example:443",
	}
	for gate, want := range cases {
		a, err := NewAgent(AgentConfig{
			HubGateURL:     gate,
			SharedKey:      []byte(testAgentSecret),
			Self:           hub.AgentRegister{Provider: "p"},
			AllowedTargets: []string{"api.example.com"},
		})
		if err != nil {
			t.Fatalf("NewAgent(%s): %v", gate, err)
		}
		if got := a.hubHTTPURL(); got != want {
			t.Errorf("hubHTTPURL(%s) = %s, want %s", gate, got, want)
		}
	}
}

// TestAgentRefusesToLeakItsTokenToACleartextModelsURL pins that model discovery
// will not put the provider credential on the wire over http://: -models-url is
// operator input, and the same token also pays for inference.
func TestAgentRefusesToLeakItsTokenToACleartextModelsURL(t *testing.T) {
	auth := http.Header{"Authorization": []string{"Bearer secret"}}
	if _, err := fetchModels("http://models.example/v1/models", http.DefaultClient, auth); err == nil {
		t.Fatal("fetchModels sent a credential to a cleartext URL")
	}
}

// TestReconnectPauseIsJittered pins the two properties that stop a fleet of
// agents from reconnecting as one block: the pause stays inside the backoff
// window the doubling computed, and it is actually spread out inside it. A
// fixed pause would leave every agent that went offline at the same instant
// (a TEE or Hub restart) dialling in on the same tick.
func TestReconnectPauseIsJittered(t *testing.T) {
	if got := jittered(0); got != 0 {
		t.Fatalf("jittered(0) = %v, want 0", got)
	}

	const window = time.Second
	const samples = 400
	var total time.Duration
	distinct := make(map[time.Duration]struct{}, samples)
	for i := 0; i < samples; i++ {
		got := jittered(window)
		if got < 0 || got >= window {
			t.Fatalf("jittered(%v) = %v, want a pause inside [0,%v)", window, got, window)
		}
		total += got
		distinct[got] = struct{}{}
	}
	if len(distinct) < samples/2 {
		t.Fatalf("jitter collapsed to %d distinct pauses over %d samples: a fleet would still reconnect in lockstep", len(distinct), samples)
	}
	// Uniform over [0, window), so the mean sits near the middle of it.
	if mean := total / samples; mean < window/4 || mean > 3*window/4 {
		t.Fatalf("jittered mean = %v, want near %v", mean, window/2)
	}
}
