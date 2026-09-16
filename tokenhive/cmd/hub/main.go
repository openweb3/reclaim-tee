// Command hub is the business side of TokenHive. It builds a JobSpec (without
// ever seeing the provider credential), calls the TEE's /v1/execute, forwards
// the streamed response to the "user", and settles the result.
//
// All of the business rules live in the hub package; this binary is only the
// wiring and the printing. That split is deliberate: the rules are the part
// that changes, and they are tested in-process against a scripted TEE, far
// from any flag parsing.
//
// Flags:
//
//	-audit        scan the receipt store, cryptographically verify every
//	              receipt, and report any ProviderSeq gaps
//	-drop N       withhold the receipt carrying ProviderSeq N from the store
//	              (simulates a Hub that hides a record from the provider)
//	-quota N      cap a tenant at N requests per -window (0 = unlimited)
//	-tenant-budgets T=M  cap tenant T's cumulative spend at M micro-units
//	-tenant-inflight N   cap a tenant at N concurrent jobs (0 = unlimited)
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/attest"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/alicloud"
	sevsnpverify "github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp/verify"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/tencent"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// microsPerUnit converts the rate card's integer micro-units into the units
// this binary prints. Only the display divides; every calculation stays in
// integers.
const microsPerUnit = 1_000_000

// evidenceCache resolves full attestation evidence for hash-only receipts this
// process has seen, layered on top of the restart-surviving evidence store the
// TEE publishes. A receipt carrying only an evidence hash resolves against what
// the Hub actually observed or the TEE recorded; the Hub never trusts an epoch
// it has not seen evidence for.
var evidenceCache attest.Cache

// defaultTenantInflight is how many jobs one tenant may run at once unless the
// operator says otherwise. Unlike the other tenant controls this one ships on:
// it is the fairness control for a shared provider, and a Hub that leaves it
// off hands whoever sends the most concurrent requests every connection that
// provider has. Eight concurrent jobs is well inside what one buyer drives and
// well inside the connection pool a provider's agent can hold, so several
// tenants fit at once — which is the whole point.
const defaultTenantInflight = 8

func main() {
	teeURL := flag.String("tee", "http://127.0.0.1:18090", "TEE base URL")
	serveAddr := flag.String("serve", "", "run as the OpenAI-compatible HTTP service on this address (empty = one-shot CLI mode)")
	provider := flag.String("provider", "openai-sim", "provider name")
	host := flag.String("host", "127.0.0.1:18080", "provider host:port (must match policy)")
	model := flag.String("model", "sim-mock-0.5b", "declared model (opaque to TEE)")
	query := flag.String("query", "", "provider URL query, e.g. fault=401|429|truncate|slow|big")
	tenant := flag.String("tenant", "tenant-demo-001", "tenant the request is attributed to for quota")
	maxBytes := flag.Uint64("max", 1<<20, "MaxResponseBytes cap sent to the TEE (bytes)")
	n := flag.Int("n", 1, "number of requests to send")
	commission := flag.Int("commission", 0, "Hub commission in basis points (100 = 1%)")
	maxJob := flag.Uint64("max-job-micros", 0, "per-job ceiling on what the buyer may be billed, in micro-units (0 = no ceiling)")
	drop := flag.Int("drop", 0, "withhold the receipt with this ProviderSeq from the store (0 = none)")
	quotaLimit := flag.Int64("quota", 0, "max requests per tenant per window (0 = unlimited)")
	quotaWindow := flag.Duration("window", time.Minute, "quota window")
	sessionTimeout := flag.Duration("session-timeout", 10*time.Minute, "max wall-clock lifetime of a streaming session (0 = unlimited)")
	sessionMax := flag.Uint64("session-max", 1<<20, "max downlink bytes a streaming session may relay (0 = unlimited)")
	sessionMaxUp := flag.Uint64("session-max-up", 1<<20, "max uplink bytes a streaming session may relay (0 = unlimited)")
	sessionIdle := flag.Duration("session-idle", 30*time.Second, "tear a session down if the provider streams nothing this long (0 = no watchdog)")
	attemptTimeout := flag.Duration("attempt-timeout", 3*time.Minute, "bound on one dispatch to a provider, including TEE time (0 = no bound; keep this above the TEE's -request-timeout)")
	agentKeys := flag.String("agent-keys", "", "per-provider agent keys as provider=key[,provider=key]; binds each tunnel to exactly one provider (required in serve mode)")
	relayKey := flag.String("relay-key", "", "key the TEE must present to dial /v1/relay (empty = unauthenticated relay)")
	tenantKeys := flag.String("tenant-keys", "", "user api keys as key=tenant[,key=tenant]; the key is verified and resolves to its tenant (empty = open mode: the presented key is the tenant)")
	tenantBudgets := flag.String("tenant-budgets", "", "per-tenant cumulative spend ceilings in micro-units, as tenant=micros[,tenant=micros]; a tenant absent from the map is uncapped")
	tenantInflight := flag.Int("tenant-inflight", defaultTenantInflight, "how many jobs one tenant may run at once; keeps one buyer from occupying every connection a shared provider has (0 = unlimited)")
	credential := flag.String("credential", "", "provider access token to register with the TEE before the request loop (simulation one-shot mode: the CLI holds the seller's token and delivers it sealed to -tee, as a dialing agent would through a resident Hub)")
	audit := flag.Bool("audit", false, "audit the receipt store for gaps and verify signatures")
	allowed := flag.String("allowed-platforms", "simulated", "comma-separated attestation platforms the Hub trusts (e.g. simulated,aws-sev-snp)")
	expectedApp := flag.String("expected-app", "", "for aws-sev-snp: the attested application identity the deployment trusts (snp-app:<sha256 hex>)")
	policyHash := flag.String("policy-set-hash", "", "hex digest the enclave must have bound into its evidence; empty skips the deployment-binding assertion (the Hub pins the platform, not the exact policy digest, at runtime)")
	evFetchURL := flag.String("evidence-fetch", "", "base URL for remote evidence retrieval (e.g. https://tee:18090); empty = resolve EvidenceHash from the local evidence store only")
	mtlsCA := flag.String("mtls-ca", "", "PEM file pinning the TEE's RA-TLS certificate (or the CA that signs it); the RA-TLS verification half of Hub↔TEE mTLS. Implies -tee is https://")
	mtlsCert := flag.String("mtls-cert", "", "client certificate the Hub presents to the TEE under mTLS; empty defaults to <simdir>/hub-client.pem")
	mtlsKey := flag.String("mtls-key", "", "private key for -mtls-cert; empty defaults to <simdir>/hub-client-key.pem")
	flag.Parse()

	store := hub.NewReceiptStore(filepath.Join(shared.ConfigDir(), "receipts"))

	teeTLS, err := buildTEEClientTLS(*mtlsCA, *mtlsCert, *mtlsKey)
	if err != nil {
		log.Fatalf("tee mtls: %v", err)
	}
	// -audit never talks to -tee, so the https:// constraint on the execute
	// channel does not apply to it; the mTLS client is still built so remote
	// evidence fetches trust the same pinned RA-TLS certificate.
	if teeTLS != nil && !strings.HasPrefix(*teeURL, "https://") && !*audit {
		log.Fatalf("-mtls-ca pins the TEE certificate, so -tee must be an https:// URL (got %q)", *teeURL)
	}
	var httpClient *http.Client
	var teeDialer *websocket.Dialer
	if teeTLS != nil {
		httpClient = &http.Client{Transport: &http.Transport{TLSClientConfig: teeTLS}}
		teeDialer = &websocket.Dialer{TLSClientConfig: teeTLS}
	}
	if *audit {
		runAudit(store, *provider, *allowed, *expectedApp, *policyHash, *evFetchURL, httpClient)
		return
	}

	// The Hub's market table: seller-reported prices. The whitelist policy is
	// a TEE concern and never reaches the Hub — the Hub prices from its own
	// rates, not from what the TEE will authorise.
	rates, err := shared.LoadRates()
	if err != nil {
		log.Fatalf("load rates: %v", err)
	}

	var quota *hub.Quota
	if *quotaLimit > 0 {
		quota, err = hub.NewQuota(*quotaLimit, *quotaWindow)
		if err != nil {
			log.Fatalf("quota: %v", err)
		}
	}
	perProviderKeys, err := parseAgentKeys(*agentKeys)
	if err != nil {
		log.Fatalf("agent-keys: %v", err)
	}
	tenants, err := parseTenantKeys(*tenantKeys)
	if err != nil {
		log.Fatalf("tenant-keys: %v", err)
	}
	budgets, err := parseBudgets(*tenantBudgets)
	if err != nil {
		log.Fatalf("tenant-budgets: %v", err)
	}

	teeClient := &hub.HTTPTEE{
		URL:        *teeURL + "/v1/execute",
		SessionURL: wsEndpoint(*teeURL, "/v1/session"),
		BaseURL:    *teeURL,
		Client:     httpClient,
		Dialer:     teeDialer,
	}
	verifier, err := buildVerifier(*allowed, *expectedApp, *policyHash, *evFetchURL, httpClient)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}
	h, err := hub.New(hub.Config{
		TEE:                  teeClient,
		Rates:                rates,
		Store:                store,
		Verify:               verifier.VerifyFunc(),
		Quota:                quota,
		Budgets:              budgets,
		MaxInflightPerTenant: *tenantInflight,
		Commission:           uint64(*commission),
		MaxJobMicros:         *maxJob,
		Withhold:             withholdSeq(*drop),
		SessionTimeout:       *sessionTimeout,
		SessionMaxDownBytes:  *sessionMax,
		SessionMaxUpBytes:    *sessionMaxUp,
		SessionIdle:          *sessionIdle,
		AttemptTimeout:       *attemptTimeout,
		AgentKeys:            perProviderKeys,
		RelaySecret:          []byte(*relayKey),
		Credentials:          teeClient,
	})
	if err != nil {
		log.Fatalf("build hub: %v", err)
	}

	// One-shot mode talks to the TEE directly, so it delivers the credential
	// itself (the resident serve mode receives it through dialing agents
	// instead). Defaults mirror what the provider agent applies: Bearer over
	// the authorization header.
	if *credential != "" && *serveAddr == "" {
		if err := h.RegisterCredential(context.Background(), *provider, tee.Secret{
			Token:  *credential,
			Header: "authorization",
			Scheme: "Bearer",
		}); err != nil {
			log.Fatalf("register credential: %v", err)
		}
	}

	// Resident user-facing mode: one OpenAI-compatible HTTP endpoint that routes
	// by model through the lowest-price scheduler. Serving refuses to start
	// without both the agent gate (per-provider keys) and the TEE relay key: a
	// Hub exposed to the network with either unauthenticated is a free egress
	// proxy through every seller's connection.
	if err := requireServeKeys(*serveAddr, *agentKeys, *relayKey); err != nil {
		log.Fatal(err)
	}
	if *serveAddr != "" {
		runServe(h, serveConfig{
			Addr:    *serveAddr,
			Host:    *host,
			Query:   *query,
			Max:     *maxBytes,
			Tenants: tenantResolver{keys: tenants},
		})
		return
	}

	body := []byte(`{"model":"` + *model + `","messages":[{"role":"user","content":"你是谁？"}],"stream":true}`)
	ctx := context.Background()

	for i := 1; i <= *n; i++ {
		fmt.Printf("\n=== request %d/%d ===\n", i, *n)
		spec, err := buildSpec(*provider, *host, "/v1/chat/completions", *query, body, *maxBytes)
		if err != nil {
			logf("build spec: %v", err)
			continue
		}
		outcome, err := h.Execute(ctx, *tenant, *model, spec, body, func(chunk []byte) error {
			fmt.Printf("[user sees] %s\n", chunk)
			return nil
		})
		if err != nil {
			logf("request: %v", err)
			continue
		}
		printOutcome(outcome)
	}
	printLedger(h.Ledger())
}

// requireServeKeys refuses to expose a Hub on the network without an
// authenticated agent gate and an authenticated TEE relay. In CLI one-shot mode
// (no -serve) nothing is exposed, so neither key is required.
func requireServeKeys(serveAddr, agentKeys, relayKey string) error {
	if serveAddr == "" {
		return nil
	}
	if agentKeys == "" {
		return errors.New("serve mode requires -agent-keys (per-provider agent keys)")
	}
	if relayKey == "" {
		return errors.New("serve mode requires -relay-key (TEE relay authentication)")
	}
	return nil
}

// wsEndpoint rewrites the TEE's http(s) base into the ws(s) WebSocket URL its
// /v1/session endpoint needs. The user passes one teeURL; keeping the session
// endpoint derived from it (rather than a second flag) means the two can never
// drift, and the scheme swap is the only difference gorilla/websocket rejects.
func wsEndpoint(base, path string) string {
	if strings.HasPrefix(base, "https://") {
		return "wss://" + strings.TrimPrefix(base, "https://") + path
	}
	return "ws://" + strings.TrimPrefix(base, "http://") + path
}

func printOutcome(outcome hub.Outcome) {
	r := outcome.Receipt.Receipt
	fmt.Printf("[receipt] provider=%s seq=%d requestBytes=%d responseBytes=%d chunks=%d status=%d completion=%s charged=%.2f commission=%.2f buyer=%.2f\n",
		r.Provider, r.ProviderSeq, r.RequestBytes, r.ResponseBytes, r.ChunkCount,
		r.StatusCode, r.Completion, float64(outcome.Charged)/microsPerUnit,
		float64(outcome.Commission)/microsPerUnit, float64(outcome.Buyer)/microsPerUnit)
	if !outcome.Stored {
		fmt.Printf("[withhold] receipt seq=%d kept out of the provider's store\n", r.ProviderSeq)
	}
}

func printLedger(ledger *hub.Ledger) {
	snap := ledger.Snapshot()
	fmt.Printf("\n--- ledger ---\n")
	fmt.Printf("requests dispatched : %d\n", snap.Dispatched)
	fmt.Printf("receipts verified  : %d\n", snap.Verified)
	fmt.Printf("receipts settled   : %d\n", snap.Settled)
	fmt.Printf("provider revenue   : %.2f units (price is provider-owned)\n",
		float64(snap.Revenue)/microsPerUnit)
	fmt.Printf("hub commission     : %.2f units\n",
		float64(snap.Commission)/microsPerUnit)
	for provider, account := range snap.ByProvider {
		fmt.Printf("  %s : %d settled, %.2f units (+%.2f commission)\n",
			provider, account.Settled, float64(account.Revenue)/microsPerUnit,
			float64(account.Commission)/microsPerUnit)
	}
}

// runAudit verifies every stored receipt and reports ProviderSeq gaps. With an
// empty -provider it audits the whole store; a gap exits non-zero so scripts
// can fail on a missing receipt.
func runAudit(store *hub.ReceiptStore, provider, allowed, expectedApp, policyHash, evFetchURL string, evClient *http.Client) {
	verifier, err := buildVerifier(allowed, expectedApp, policyHash, evFetchURL, evClient)
	if err != nil {
		log.Fatalf("attestation: %v", err)
	}
	providers := []string{provider}
	if provider == "" {
		if providers, err = store.Providers(); err != nil {
			log.Fatalf("audit: %v", err)
		}
		if len(providers) == 0 {
			fmt.Println("no receipts stored")
			return
		}
	}
	failed := false
	for _, p := range providers {
		if !auditProvider(store, p, verifier) {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

// auditProvider verifies one provider's receipts; true means the store is
// healthy (no gaps, no bad receipts).
func auditProvider(store *hub.ReceiptStore, provider string, verifier *attest.Verifier) bool {
	report, err := store.Audit(provider, verifier.VerifyFunc())
	if err != nil {
		fmt.Printf("[%s] audit: %v\n", provider, err)
		return false
	}
	if report.Total == 0 {
		fmt.Printf("[%s] no receipts stored\n", provider)
		return true
	}
	fmt.Printf("[%s] verified %d/%d receipts (allowed platforms: %v)\n",
		provider, report.Verified, report.Total, verifier.AllowedPlatforms())
	if report.Complete() {
		fmt.Printf("    sequence complete: 1..%d, no gaps\n", report.MaxSeq)
		return true
	}
	fmt.Printf(">>> [%s] GAP DETECTED: provider was used at least %d times but is missing receipts %v\n",
		provider, report.MaxSeq, report.Missing)
	return false
}

// buildTEEClientTLS assembles the Hub's client TLS config for the Hub↔TEE
// channel. It pins the TEE's RA-TLS certificate (or its signing CA), which is
// the deployment's out-of-band statement "this certificate is the attested
// TEE"; and it presents the Hub's own client certificate so the TEE admits it.
// Without -mtls-ca it returns nil (plain HTTP/WSS-less operation). The cert and
// key default to the simulation identity so a local mTLS run needs no flags
// beyond the pin.
func buildTEEClientTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	if caFile == "" {
		if certFile != "" || keyFile != "" {
			return nil, errors.New("-mtls-cert/-mtls-key require -mtls-ca")
		}
		return nil, nil
	}
	if certFile == "" {
		certFile = filepath.Join(shared.ConfigDir(), shared.MTLSClientCertPath)
	}
	if keyFile == "" {
		keyFile = filepath.Join(shared.ConfigDir(), shared.MTLSClientKeyPath)
	}
	if err := shared.EnsureMTLSCerts(); err != nil {
		return nil, err
	}
	return shared.ClientMTLSConfig(caFile, certFile, keyFile)
}

// buildVerifier assembles the attestation trust root from the operator's
// allowlist. A platform the operator advertises as trusted but that has no
// evidence verifier wired here is a wiring error and fails loudly at startup,
// not at the first receipt. AWS SEV-SNP is additionally refused without a
// valid application pin: platform authenticity alone is not an image trust
// root, so an allowlist entry without -expected-app would accept receipts
// from any hardware-valid SNP application.
func buildVerifier(allowed, expectedApp, policyHash, evFetchURL string, evClient *http.Client) (*attest.Verifier, error) {
	lists, err := splitCSV(allowed)
	if err != nil {
		return nil, err
	}
	for _, p := range lists {
		if p != platform.PlatformAWSSEVSNP {
			continue
		}
		digest := strings.TrimPrefix(expectedApp, "snp-app:")
		if digest == expectedApp {
			return nil, fmt.Errorf("-allowed-platforms includes %q: -expected-app must pin the attested application identity as snp-app:<sha256 hex>", platform.PlatformAWSSEVSNP)
		}
		if len(digest) != 64 {
			return nil, fmt.Errorf("-expected-app %q is not a valid snp-app:<sha256 hex> pin", expectedApp)
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("-expected-app %q is not a valid snp-app:<sha256 hex> pin", expectedApp)
		}
	}
	byPlatform := map[string]platform.EvidenceVerifier{
		simulated.Platform: simulated.Verifier{},
		platform.PlatformAWSSEVSNP: sevsnpverify.Verifier{
			ExpectedApp: expectedApp,
		},
		// Cloud skeleton verifiers, reserved for future support: wired so an
		// allowlist entry is honest, but every receipt is refused with
		// ErrAttestationNotImplemented until the attestation paths land.
		platform.PlatformAlibabaCloud: alicloud.Verifier{},
		platform.PlatformTencentCloud: tencent.Verifier{},
	}
	fetcher, err := buildFetcher(evFetchURL, evClient)
	if err != nil {
		return nil, err
	}
	cfg := attest.Config{
		AllowedPlatforms: lists,
		ByPlatform:       byPlatform,
		Fetcher:          fetcher,
	}
	// The deployment binding is opt-in. At runtime the Hub pins the platform
	// trust root, not the exact policy digest: policy files are rewritten with a
	// fresh IssuedAt on every startup, so deriving the hash here would race the
	// TEE's own binding and reject valid receipts. An operator who wants the
	// strongest bound (prove the enclave ran a specific whitelist config)
	// passes the digest explicitly.
	if policyHash != "" {
		h, err := hex.DecodeString(policyHash)
		if err != nil {
			return nil, fmt.Errorf("parse -policy-set-hash: %w", err)
		}
		if len(h) != 32 {
			return nil, fmt.Errorf("-policy-set-hash must be a 32-byte hex digest, got %d bytes", len(h))
		}
		copy(cfg.PolicySetHash[:], h)
	}
	return attest.New(cfg)
}

// splitCSV splits a comma-separated allowlist, trimming whitespace.
func splitCSV(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty -allowed-platforms")
	}
	return out, nil
}

// buildFetcher assembles the evidence retrieval path in resolution order: the
// in-memory cache of epochs this process has verified, then the restart-surviving
// local store, then an optional remote /v1/evidence endpoint. Each layer is
// tried in turn until one holds the bytes. The remote layer reuses the Hub's
// mTLS client so it trusts the same pinned RA-TLS certificate and presents the
// same client certificate as the Hub↔TEE channel.
func buildFetcher(evFetchURL string, evClient *http.Client) (attest.Fetcher, error) {
	backend := &evidence.Chain{}
	backend.Add(&evidenceCache)
	if store, err := shared.LoadEvidenceStore(); err == nil {
		backend.Add(store)
	}
	if evFetchURL != "" {
		httpFetcher, err := evidence.NewHTTPFetcher(evFetchURL, evClient)
		if err != nil {
			return nil, err
		}
		backend.Add(httpFetcher)
	}
	return backend, nil
}

// withholdSeq models a Hub that hides one execution from the provider. The
// point of the exercise is that hiding it still leaves a numbered hole.
func withholdSeq(seq int) func(uint64) bool {
	if seq <= 0 {
		return nil
	}
	target := uint64(seq)
	return func(seq uint64) bool { return seq == target }
}

// parsePairs splits a "key=value,key=value" flag into its entries, rejecting a
// malformed entry rather than silently ignoring it.
func parsePairs(spec string) ([][2]string, error) {
	if spec == "" {
		return nil, nil
	}
	var out [][2]string
	for _, entry := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("entry %q is not key=value", entry)
		}
		out = append(out, [2]string{k, v})
	}
	return out, nil
}

// parseBudgets turns the -tenant-budgets flag into the per-tenant cumulative
// ceilings. A malformed entry is a startup failure rather than a silently
// dropped cap: a typo must not leave a tenant unbudgeted by accident.
func parseBudgets(spec string) (map[string]uint64, error) {
	pairs, err := parsePairs(spec)
	if err != nil {
		return nil, err
	}
	if pairs == nil {
		return nil, nil
	}
	budgets := make(map[string]uint64, len(pairs))
	for _, p := range pairs {
		micros, err := strconv.ParseUint(p[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("tenant %q: ceiling %q is not a number", p[0], p[1])
		}
		budgets[p[0]] = micros
	}
	return budgets, nil
}

// parseAgentKeys turns the -agent-keys flag into the per-provider key map. A
// provider name that could never be registered is rejected here, so a typo is a
// startup failure rather than a key that silently matches nothing.
func parseAgentKeys(spec string) (map[string][]byte, error) {
	pairs, err := parsePairs(spec)
	if err != nil {
		return nil, err
	}
	if pairs == nil {
		return nil, nil
	}
	keys := make(map[string][]byte, len(pairs))
	for _, p := range pairs {
		if err := jobs.ValidateProviderName(p[0]); err != nil {
			return nil, err
		}
		keys[p[0]] = []byte(p[1])
	}
	return keys, nil
}

// parseTenantKeys turns the -tenant-keys flag into the user key -> tenant map.
func parseTenantKeys(spec string) (map[string]string, error) {
	pairs, err := parsePairs(spec)
	if err != nil {
		return nil, err
	}
	if pairs == nil {
		return nil, nil
	}
	keys := make(map[string]string, len(pairs))
	for _, p := range pairs {
		keys[p[0]] = p[1]
	}
	return keys, nil
}

func buildSpec(provider, host, path, query string, body []byte, maxBytes uint64) (jobs.Spec, error) {
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
		Method:           "POST",
		Host:             host,
		Path:             path,
		Query:            query,
		Headers:          map[string]string{"Content-Type": "application/json"},
		BodyHash:         hashBodyBytes(body),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: maxBytes,
		Stream:           true,
	}, nil
}

func hashBodyBytes(body []byte) []byte {
	h := jobs.HashBody(body)
	return h[:]
}

func logf(format string, args ...any) { fmt.Printf("[hub] "+format+"\n", args...) }
