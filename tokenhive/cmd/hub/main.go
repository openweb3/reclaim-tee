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

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/attest"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/alicloud"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/tencent"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// microsPerUnit converts the rate card's integer micro-units into the units
// this binary prints. Only the display divides; every calculation stays in
// integers.
const microsPerUnit = 1_000_000

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
	providerHosts := flag.String("provider-hosts", "", "per-provider upstream hosts as provider=host:port[,provider=host:port]; a provider absent from the map is served at -host (needed when sellers span several vendors)")
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
	expectedApp := flag.String("expected-app", "", "for aws-sev-snp: the attested application identity the deployment trusts (snp-app:<sha256 hex>). Gates both the receipt verifier and, under -tee-verify=attestation, the Hub↔TEE handshake, so the two cannot disagree about which enclave is trusted")
	policyHash := flag.String("policy-hash", "", "hex digest the enclave must have bound into its evidence; empty skips the deployment-binding assertion (the Hub pins the platform, not the exact policy digest, at runtime)")
	// On an SNP bundle the deployment whitelist lives inside the measured tar at
	// ./policy; point this there so the /v1/policies view (what buyers and sellers
	// are told the enclave will accept) is the same bytes the enclave enforces.
	policyDir := flag.String("policy-dir", "", "directory holding the deployment whitelist (policy.cbor); empty = the measured bundle's policy/ when it has one, else TOKENHIVE_SIM_DIR")
	evFetchURL := flag.String("evidence-fetch", "", "base URL for remote evidence retrieval (e.g. https://tee:18090); empty = resolve EvidenceHash from the local evidence store only")
	teeVerify := flag.String("tee-verify", teeVerifyPin, "how the Hub authenticates the TEE's RA-TLS certificate: pin (the leaf or CA named by -mtls-ca) or attestation (verify the SEV-SNP evidence the certificate embeds, pinned to -expected-app). Attestation mode needs nothing redistributed when the TEE rotates its epoch, which is what lets a long-lived TEE keep its evidence fresh")
	mtlsCA := flag.String("mtls-ca", "", "PEM file pinning the TEE's RA-TLS certificate (or the CA that signs it); the RA-TLS verification half of Hub↔TEE mTLS under -tee-verify=pin. Implies -tee is https://")
	mtlsCert := flag.String("mtls-cert", "", "client certificate the Hub presents to the TEE under mTLS; empty defaults to <simdir>/hub-client.pem")
	mtlsKey := flag.String("mtls-key", "", "private key for -mtls-cert; empty defaults to <simdir>/hub-client-key.pem")
	flag.Parse()

	if err := validateTEEChannel(*teeVerify, *mtlsCA, *allowed, *audit); err != nil {
		log.Fatal(err)
	}

	store := hub.NewReceiptStore(filepath.Join(shared.ConfigDir(), "receipts"))

	teeTLS, err := buildTEEClientTLS(teeChannelConfig{
		Mode:        *teeVerify,
		CAFile:      *mtlsCA,
		CertFile:    *mtlsCert,
		KeyFile:     *mtlsKey,
		ExpectedApp: *expectedApp,
	})
	if err != nil {
		log.Fatalf("tee mtls: %v", err)
	}
	// -audit never talks to -tee, so the https:// constraint on the execute
	// channel does not apply to it; the mTLS client is still built so remote
	// evidence fetches trust the same TEE certificate.
	if teeTLS != nil && !strings.HasPrefix(*teeURL, "https://") && !*audit {
		log.Fatalf("the Hub verifies the TEE's certificate, so -tee must be an https:// URL (got %q)", *teeURL)
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

	// The Hub's market table: seller-reported prices. Pricing never consults the
	// whitelist — the Hub prices from its own rates, not from what the TEE will
	// authorise. (The whitelist does reach the Hub, for admission and
	// /v1/policies; see below. It just has nothing to say about the price.)
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
	perProviderHosts, err := parseProviderHosts(*providerHosts)
	if err != nil {
		log.Fatalf("provider-hosts: %v", err)
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
	// The deployment whitelist, loaded once and shared by everything the Hub
	// does with it: the /v1/policies view, and the admission check every dialing
	// agent passes before it can become schedulable. Best-effort — a Hub brought
	// up before any TEE materialized the fixtures still starts, but it reports
	// the whitelist unavailable and admits nobody, rather than admitting sellers
	// the enclave would then refuse job by job.
	//
	// It resolves through the same rule the TEE uses: an explicit -policy-dir
	// wins, then the measured bundle's copy, then the state directory. A Hub
	// inside a bundle has to enforce what that bundle carries, or it would
	// admit and price against rules the attestation says nothing about. The Hub
	// is not the enclave, so it does not require a whitelist the way the TEE
	// does: unconfigured-and-unavailable is reported and nothing is admitted,
	// never a panic — but an explicitly configured directory that holds no
	// whitelist is an operator error and fails fast, rather than silently
	// falling back to a default nobody chose.
	if resolved, err := shared.ResolvePolicyDir(*policyDir, false); err != nil {
		log.Fatalf("resolve policy dir: %v", err)
	} else if resolved != "" {
		shared.SetPolicyDir(resolved)
	}
	var policyDoc *policy.Policy
	if policyDoc, err = shared.LoadPolicy(); err != nil {
		log.Printf("policy unavailable: %v", err)
	}

	// The resident routing every spec-framing site and the agent admission
	// check share: one Hub-wide default upstream, overridden per provider
	// where sellers span several vendors. Built once so the admission check
	// judges each agent on the exact host its own jobs will egress to.
	serveCfg := serveConfig{
		Addr:          *serveAddr,
		Host:          *host,
		ProviderHosts: perProviderHosts,
		Query:         *query,
		Max:           *maxBytes,
		Tenants:       tenantResolver{keys: tenants},
		Policy:        policyDoc,
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
		AdmitAgent:           admitAgainstPolicy(policyDoc, serveCfg.HostFor),
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
		if *drop != 0 {
			log.Fatal("serve mode refuses -drop (withholding a settled receipt from the store is a test hook, not a deployment mode)")
		}
		if *tenantKeys == "" {
			log.Printf("warning: serve mode without -tenant-keys runs open mode, where the presented key is the tenant: quota, inflight and budget limits then apply per self-chosen name, so set -tenant-keys in production")
		}
		runServe(h, serveCfg)
		return
	}

	body := []byte(`{"model":"` + *model + `","messages":[{"role":"user","content":"你是谁？"}],"stream":true}`)
	ctx := context.Background()

	for i := 1; i <= *n; i++ {
		fmt.Printf("\n=== request %d/%d ===\n", i, *n)
		spec, err := shared.BuildSpec(*provider, *model, serveCfg.HostFor(*provider), "/v1/chat/completions", *query, body, *maxBytes)
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

// The two ways the Hub can be told to trust the TEE's RA-TLS certificate. Both
// demand the certificate and present the Hub's own client identity; they differ
// in what makes the TEE's certificate acceptable.
const (
	// teeVerifyPin trusts a leaf the deployment distributed out of band: the
	// certificate, or the CA that signs it, named by -mtls-ca. The trust
	// statement is "this exact certificate", which is why it cannot survive the
	// TEE rotating its epoch — the rotation produces a leaf the pin does not name.
	teeVerifyPin = "pin"

	// teeVerifyAttestation trusts the proof the handshake already carries: the
	// certificate's embedded SEV-SNP evidence is verified against the AWS and AMD
	// roots, bound to that certificate's own key so evidence cannot be spliced
	// onto a key it did not attest, and narrowed to the measured application by
	// -expected-app. Nothing is pinned, so a rotated epoch is accepted on its own
	// evidence and the TEE can keep the proof fresh indefinitely.
	teeVerifyAttestation = "attestation"
)

// teeChannelConfig says how the Hub is told to authenticate the TEE.
type teeChannelConfig struct {
	// Mode is teeVerifyPin (the default) or teeVerifyAttestation.
	Mode string
	// CAFile pins the TEE's certificate. It is the whole trust statement in pin
	// mode, and in attestation mode it is refused rather than ignored: an
	// operator who leaves it set would believe the leaf is still pinned.
	CAFile string
	// CertFile/KeyFile are the Hub's own client identity, which the TEE demands
	// in either mode.
	CertFile string
	KeyFile  string
	// ExpectedApp is the application pin attestation mode verifies the TEE
	// against; see validateApplicationPin.
	ExpectedApp string
}

// validateTEEChannel refuses a channel configuration that cannot survive the
// peer it is aimed at. There is exactly one such case today: a pinned
// certificate against a TEE that rotates its attested epoch.
//
// On aws-sev-snp the TEE replaces its RA-TLS leaf every few hours, so a pin
// authenticates until the first rotation and then fails every re-dial — hours
// into a run, and reading like an ordinary TLS problem. When aws-sev-snp is the
// only platform the Hub trusts and a certificate is actually pinned, no peer
// the pin could be for exists, so say so at startup rather than let it fail
// later. A mixed allowlist is left alone: it exists so one Hub can face a
// simulated peer (whose epoch is fixed, where a pin is right) beside a real one.
// -audit never dials the TEE it names, so it keeps whatever configuration the
// operator chose.
func validateTEEChannel(mode, caFile, allowed string, audit bool) error {
	if audit || mode != teeVerifyPin || caFile == "" {
		return nil
	}
	platforms, err := splitCSV(allowed)
	if err != nil {
		return err
	}
	if len(platforms) == 1 && platforms[0] == platform.PlatformAWSSEVSNP {
		return fmt.Errorf("-tee-verify=pin pins a certificate an aws-sev-snp TEE replaces every few hours, so it stops authenticating within one refresh interval; use -tee-verify=attestation with -expected-app=snp-app:<sha256> and drop -mtls-ca")
	}
	return nil
}

// buildTEEClientTLS assembles the Hub's client TLS config for the Hub↔TEE
// channel. It returns nil when nothing pins or attests the TEE, which is how the
// local simulation runs: plain HTTP, no certificate to check. The Hub's cert and
// key default to the simulation identity, so a local mTLS run needs no flags
// beyond the trust statement.
func buildTEEClientTLS(opts teeChannelConfig) (*tls.Config, error) {
	switch opts.Mode {
	case teeVerifyPin:
		if opts.CAFile == "" {
			if opts.CertFile != "" || opts.KeyFile != "" {
				return nil, errors.New("-mtls-cert/-mtls-key require -mtls-ca")
			}
			return nil, nil
		}
		certFile, keyFile, err := hubClientIdentity(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, err
		}
		return mtls.ClientMTLSConfig(opts.CAFile, certFile, keyFile)

	case teeVerifyAttestation:
		if opts.CAFile != "" {
			return nil, errors.New("-mtls-ca pins a certificate the handshake no longer consults; drop it with -tee-verify=attestation")
		}
		if err := validateApplicationPin(opts.ExpectedApp); err != nil {
			return nil, fmt.Errorf("-tee-verify=attestation: %w", err)
		}
		certFile, keyFile, err := hubClientIdentity(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, err
		}
		// The attested key is the identity, exactly as in pin mode: RA-TLS
		// certificates are not DNS names, so there is nothing to match against
		// a hostname. Failing closed is the verifier's job, and it runs before
		// the handshake completes.
		return mtls.ClientTLSConfigWithVerifier(certFile, keyFile,
			rootShared.VerifyRATLSPeer(rootShared.RATLSVerifyOptions{
				ExpectedImageDigest: opts.ExpectedApp,
				Logger:              rootShared.NewNopLogger(),
			}))
	}
	return nil, fmt.Errorf("-tee-verify %q is not a mode: want %s or %s", opts.Mode, teeVerifyPin, teeVerifyAttestation)
}

// hubClientIdentity resolves the Hub's own mTLS identity, materializing the
// simulation fixtures when the operator named no files. The defaults come from
// the same place EnsureMTLSCerts writes to (shared.HubIdentityPaths), so a
// deployment cannot present a certificate from one location while the fixtures
// were maintained at another. Both verification modes need this: the TEE demands
// a client certificate either way.
func hubClientIdentity(certFile, keyFile string) (string, string, error) {
	if certFile != "" && keyFile != "" {
		return certFile, keyFile, nil
	}
	if err := shared.EnsureMTLSCerts(); err != nil {
		return "", "", err
	}
	defaultCert, defaultKey := shared.HubIdentityPaths()
	if certFile == "" {
		certFile = defaultCert
	}
	if keyFile == "" {
		keyFile = defaultKey
	}
	return certFile, keyFile, nil
}

// applicationPinPrefixSEVSNP spells an AWS SEV-SNP application identity the way
// the verifier reports it: PCR 8's app hash, hex-encoded. sha256HexLength is the
// hex length of the digest it names.
const (
	applicationPinPrefixSEVSNP = "snp-app:"
	sha256HexLength            = 64
)

// validateApplicationPin checks the deployment's application pin. It is the one
// definition of the pin's shape, shared by the two places that consume it — the
// receipt verifier's allowlist and the Hub↔TEE handshake — so a deployment
// cannot end up trusting receipts from one enclave and a TLS peer that attests
// to another.
//
// An empty pin is an error rather than "no assertion": platform authenticity
// alone would admit any hardware-valid SNP application, which is precisely the
// gap the pin exists to close.
func validateApplicationPin(pin string) error {
	digest := strings.TrimPrefix(pin, applicationPinPrefixSEVSNP)
	if digest == pin {
		return fmt.Errorf("-expected-app must pin the attested application identity as %s<sha256 hex>", applicationPinPrefixSEVSNP)
	}
	if len(digest) != sha256HexLength {
		return fmt.Errorf("-expected-app %q is not a valid %s<sha256 hex> pin", pin, applicationPinPrefixSEVSNP)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("-expected-app %q is not a valid %s<sha256 hex> pin", pin, applicationPinPrefixSEVSNP)
	}
	return nil
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
		if err := validateApplicationPin(expectedApp); err != nil {
			return nil, fmt.Errorf("-allowed-platforms includes %q: %w", platform.PlatformAWSSEVSNP, err)
		}
	}
	byPlatform := map[string]platform.EvidenceVerifier{
		simulated.Platform: simulated.Verifier{},
		platform.PlatformAWSSEVSNP: sevsnp.Verifier{
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
	// trust root, not the exact policy digest: the shipped whitelist is
	// deterministic (policy.Default stamps a constant IssuedAt, so rebuilding
	// never moves the hash on its own), and demanding a pre-registered digest
	// would turn every whitelist rotation — which is a redeploy by design —
	// into a Hub flag rotation as well. An operator who wants the strongest
	// bound (prove the enclave ran a specific whitelist config) passes the
	// digest explicitly.
	if policyHash != "" {
		h, err := hex.DecodeString(policyHash)
		if err != nil {
			return nil, fmt.Errorf("parse -policy-hash: %w", err)
		}
		if len(h) != 32 {
			return nil, fmt.Errorf("-policy-hash must be a 32-byte hex digest, got %d bytes", len(h))
		}
		copy(cfg.PolicyHash[:], h)
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
// restart-surviving local store the TEE publishes, then an optional remote
// /v1/evidence endpoint. Each layer is tried in turn until one holds the bytes.
// The remote layer reuses the Hub's mTLS client so it trusts the same pinned
// RA-TLS certificate and presents the same client certificate as the Hub↔TEE
// channel.
//
// There is deliberately no in-memory layer here. The Hub sees an epoch's
// evidence only inside the receipts it verifies, so every layer it could keep
// one in would be empty forever; the two below are the sources that actually
// hold bytes, and an inert layer in front of them would only replace the real
// "no evidence stored" error with a lookup that cannot hit.
func buildFetcher(evFetchURL string, evClient *http.Client) (attest.Fetcher, error) {
	backend := &evidence.Chain{}
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

// parseProviderHosts turns the -provider-hosts flag into the per-provider
// upstream map: which AI-service host:port the TEE is asked to reach for each
// seller. A provider name that could never be registered is rejected here, so
// a typo is a startup failure rather than an override that silently matches
// nothing; a malformed host is rejected for the same reason. The TEE
// re-validates every spec's host at execution — this only exists to fail fast
// on operator typos, and an override for a provider with no agent online yet
// is inert, not an error.
func parseProviderHosts(spec string) (map[string]string, error) {
	pairs, err := parsePairs(spec)
	if err != nil {
		return nil, err
	}
	if pairs == nil {
		return nil, nil
	}
	hosts := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if err := jobs.ValidateProviderName(p[0]); err != nil {
			return nil, err
		}
		if err := validateUpstreamHost(p[1]); err != nil {
			return nil, fmt.Errorf("provider %q: %w", p[0], err)
		}
		hosts[p[0]] = p[1]
	}
	return hosts, nil
}

// validateUpstreamHost is the flag parser's shape check for an upstream
// host:port: non-empty, bounded, and carrying no scheme, path, or userinfo.
// Anything finer (numeric ports, plain DNS names) is enforced by the job
// layer on every spec the TEE executes.
func validateUpstreamHost(host string) error {
	if host == "" {
		return fmt.Errorf("upstream host is empty")
	}
	if len(host) > jobs.MaxHostLength {
		return fmt.Errorf("upstream host %q exceeds %d bytes", host, jobs.MaxHostLength)
	}
	if strings.ContainsAny(host, " \t\r\n/@?") {
		return fmt.Errorf("upstream host %q must be host or host:port", host)
	}
	return nil
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

func logf(format string, args ...any) { fmt.Printf("[hub] "+format+"\n", args...) }
