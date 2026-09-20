// Command agent is the TokenHive Provider Agent: a process a quota contributor
// runs on their own machine so a TEE can egress through their network. It is a
// thin wrapper over provider.NewAgent.
//
// The agent lives behind a home NAT, so it cannot be dialed: it dials the Hub's
// AgentGate and keeps the reverse tunnel open, reconnecting whenever it drops.
// While online, the Hub routes this provider's egress through it; the TEE's TLS
// session with the AI provider travels over that tunnel end to end, so the agent
// only ever sees encrypted bytes.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

func main() {
	gate := flag.String("hub", "ws://127.0.0.1:18085/v1/agent", "Hub AgentGate WebSocket URL the agent dials to come online")
	key := flag.String("key", "", "this provider's key to present at dial-in (must match its entry in the Hub's -agent-keys)")
	providerName := flag.String("provider", "", "provider this agent egresses for")
	name := flag.String("name", "", "optional human display label for this agent")
	price := flag.Int64("price", 0, "per-request price in micro-units; 0 accepts the Hub's platform default for this provider")
	targets := flag.String("targets", "127.0.0.1:18080", "comma-separated host:port the agent may dial (the AI provider endpoint)")
	models := flag.String("models", "", "comma-separated model IDs this agent's upstream serves; empty auto-discovers them from the upstream's conventional /v1/models endpoint")
	modelsURL := flag.String("models-url", "", "explicit URL to fetch the model list from; overrides the conventional discovery endpoint")
	caFile := flag.String("ca", "", "CA file to trust when fetching the model list over TLS (the simulation's mock provider CA)")
	tap := flag.String("tap", "", "file to mirror every relayed byte into (test/demo: proves the agent only sees ciphertext)")
	token := flag.String("token", "", "the provider's access token (API key). Required; sealed to the TEE at registration — the Hub never sees it")
	authScheme := flag.String("auth-scheme", "auto", "prefix before the token in the auth header: auto, a literal scheme (e.g. Bearer), or empty for a raw-token header")
	authHeader := flag.String("auth-header", "authorization", "request header the token travels in (e.g. authorization, x-api-key)")
	allowCleartext := flag.Bool("allow-cleartext-gate", false, "permit a -hub that is plaintext ws:// to a host other than loopback (only for a hop something else already protects)")
	timeout := flag.Duration("connect-timeout", 10*time.Second, "bounds dialing the Hub and each upstream")
	reconnect := flag.Duration("reconnect", time.Second, "pause between reconnect attempts after the tunnel drops")
	maxConns := flag.Int("max-conns", provider.DefaultMaxRelayConns, "how many relay streams to serve at once; streams past this are refused so the Hub can route to another provider (0 = unlimited)")
	relayIdle := flag.Duration("relay-idle", provider.DefaultRelayIdle, "tear a relay stream down once it has carried nothing this long; keep this above the Hub's -attempt-timeout (0 = no watchdog)")
	flag.Parse()

	if *key == "" {
		log.Fatal("agent requires -key")
	}
	if *providerName == "" {
		log.Fatal("agent requires -provider")
	}
	if *token == "" {
		log.Fatal("agent requires -token (the provider's access token)")
	}
	allowed := make([]string, 0, 4)
	for _, t := range strings.Split(*targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allowed = append(allowed, t)
		}
	}
	if len(allowed) == 0 {
		log.Fatal("agent requires at least one -target")
	}

	// Resolve the token's presentation shape. "auto" picks the convention that
	// matches the header the seller named, so the common cases need no config at
	// all: OpenAI and most services want "Authorization: Bearer <token>" (the
	// whole header is the token's home), while an x-api-key-style header carries
	// the raw token with no prefix (Anthropic, and most key-in-header services).
	scheme := *authScheme
	if strings.EqualFold(scheme, "auto") {
		if strings.EqualFold(*authHeader, "authorization") {
			scheme = "Bearer"
		} else {
			scheme = ""
		}
	}

	cfg := provider.AgentConfig{
		HubGateURL:         *gate,
		SharedKey:          []byte(*key),
		AllowedTargets:     allowed,
		AllowCleartextGate: *allowCleartext,
		ConnectTimeout:     *timeout,
		ReconnectDelay:     *reconnect,
		MaxRelayConns:      *maxConns,
		RelayIdle:          *relayIdle,
		Self: hub.AgentRegister{
			Provider:    *providerName,
			DisplayName: *name,
		},
		Credential: tee.Secret{
			Token:  *token,
			Scheme: scheme,
			Header: *authHeader,
		},
	}
	if *price > 0 {
		cfg.Self.SelfPrice = &hub.RateCard{PerRequestMicros: uint64(*price)}
	}
	if *tap != "" {
		f, err := os.Create(*tap)
		if err != nil {
			log.Fatalf("open tap file: %v", err)
		}
		cfg.Tap = f
	}
	if list := splitModels(*models); len(list) > 0 {
		cfg.Self.Models = list
		log.Printf("provider agent %s: declaring %d models explicitly", *providerName, len(list))
	} else {
		// No explicit model list: discover it from the upstream's conventional
		// models endpoint before coming online. A failure here is fatal — the
		// agent reports it and refuses to register — so a provider that meant
		// to declare capability but cannot reach its upstream is never silently
		// treated as "serves anything".
		discoverURL := *modelsURL
		if discoverURL == "" {
			discoverURL = "https://" + allowed[0] + "/v1/models"
			log.Printf("provider agent %s: no -models; will discover from %s", *providerName, discoverURL)
		}
		cfg.ModelsURL = discoverURL
		if *caFile != "" {
			pool, err := loadCAPool(*caFile)
			if err != nil {
				log.Fatalf("load CA: %v", err)
			}
			cfg.RootCAs = pool
		}
	}

	agent, err := provider.NewAgent(cfg)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("provider agent %s online via %s (allowlist: %v, price: %s, auth: %s%s, relays: %d concurrent, idle: %s)",
		*providerName, *gate, allowed, priceLabel(*price), *authHeader, schemeLabel(scheme), *maxConns, *relayIdle)
	err = agent.Run(ctx)
	// Report what the machine carried before leaving: the contributor is owed the
	// usage line whether the run ended on a signal or on a failure.
	log.Printf("provider agent %s stopped: %s", *providerName, agent.Stats())
	// A cancelled context is how a signal ends the run, not a failure — so it
	// exits cleanly. Anything else is a real error and must exit non-zero, or a
	// supervisor would not restart the agent.
	if err != nil && ctx.Err() == nil {
		log.Fatalf("provider agent %s: %v", *providerName, err)
	}
}

// splitModels parses a comma-separated model list, dropping empty fields.
func splitModels(list string) []string {
	var out []string
	for _, m := range strings.Split(list, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// loadCAPool reads a PEM CA file into a trust pool for the discovery fetch.
func loadCAPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return pool, nil
}

func priceLabel(micros int64) string {
	if micros <= 0 {
		return "platform default"
	}
	return strconv.FormatFloat(float64(micros)/1e6, 'f', -1, 64) + " units/request"
}

func schemeLabel(scheme string) string {
	if scheme == "" {
		return " (raw token)"
	}
	return " " + scheme
}
