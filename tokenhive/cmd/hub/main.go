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
//	-accounts PATH  ledger database (SQLite); buyer, seller and platform
//	              balances; required in serve mode
//	-ledger-sync  full|normal|off  how hard a committed charge is made
//	              (default full = fsync; off is simulation only)
//	-tenant-deposits T=M  seed tenant T's balance at M micro-units, applied
//	              only when the ledger is created by this start
//	-tenant-inflight N   cap a tenant at N concurrent jobs (0 = unlimited)
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
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
	accountsPath := flag.String("accounts", "", "ledger database file (SQLite): buyer prepaid balances, seller payables and the Hub's commission; every job holds its per-job ceiling against the buyer's balance and the charge is committed in one transaction; required in serve mode")
	tenantDeposits := flag.String("tenant-deposits", "", "seed buyer balances in micro-units as tenant=micros[,tenant=micros]; applied only when the ledger is empty (first creation), so a restart never re-funds a drained tenant")
	ledgerSync := flag.String("ledger-sync", string(hub.SyncFull), "how hard a committed charge is made: full (fsync every commit), normal (survives a process crash) or off (simulation only, refused in serve mode)")
	tenantInflight := flag.Int("tenant-inflight", defaultTenantInflight, "how many jobs one tenant may run at once; keeps one buyer from occupying every connection a shared provider has (0 = unlimited)")
	credential := flag.String("credential", "", "provider access token to register with the TEE before the request loop (simulation one-shot mode: the CLI holds the seller's token and delivers it sealed to -tee, as a dialing agent would through a resident Hub)")
	audit := flag.Bool("audit", false, "audit the receipt store for gaps and verify signatures")
	flag.Parse()

	store := hub.NewReceiptStore(filepath.Join(shared.ConfigDir(), "receipts"))

	if *audit {
		runAudit(store, *provider)
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
	deposits, err := parseDeposits(*tenantDeposits)
	if err != nil {
		log.Fatalf("tenant-deposits: %v", err)
	}
	var accounts *hub.Accounts
	if *accountsPath != "" {
		acc, fresh, err := hub.OpenAccounts(*accountsPath, deposits, hub.WithSync(hub.SyncMode(*ledgerSync)))
		if err != nil {
			log.Fatalf("accounts: %v", err)
		}
		defer func() { _ = acc.Close() }()
		accounts = acc
		if !fresh && len(deposits) > 0 {
			log.Printf("ledger %s already has history; -tenant-deposits ignored (balances are on disk)", *accountsPath)
		}
		if *ledgerSync != string(hub.SyncFull) {
			log.Printf("ledger %s runs with synchronous=%s: committed charges may not survive a power cut", *accountsPath, *ledgerSync)
		}
	}

	teeClient := &hub.HTTPTEE{
		URL:        *teeURL + "/v1/execute",
		SessionURL: wsEndpoint(*teeURL, "/v1/session"),
		BaseURL:    *teeURL,
	}
	h, err := hub.New(hub.Config{
		TEE:                  teeClient,
		Rates:                rates,
		Store:                store,
		Verify:               verifyReceipt,
		Quota:                quota,
		Accounts:             accounts,
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
	// without the agent gate (per-provider keys), the TEE relay key, the ledger
	// with a per-job ceiling, and a durability setting real money may run on: a
	// Hub exposed to the network with any of those missing either lets
	// unauthenticated traffic through, serves buyers with no money for free, or
	// loses charges it already told a buyer and a seller were booked.
	if err := requireServeKeys(*serveAddr, *agentKeys, *relayKey, accounts, *maxJob, hub.SyncMode(*ledgerSync)); err != nil {
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
// authenticated agent gate, an authenticated TEE relay, and prepaid billing
// with a per-job ceiling: without the keys the process is an open proxy, and
// without billing a buyer with an empty balance is served for free — the
// exact failure prepaid mode exists to close. In CLI one-shot mode (no
// -serve) nothing is exposed, so none of this is required.
func requireServeKeys(serveAddr, agentKeys, relayKey string, accounts *hub.Accounts, maxJob uint64, sync hub.SyncMode) error {
	if serveAddr == "" {
		return nil
	}
	if agentKeys == "" {
		return errors.New("serve mode requires -agent-keys (per-provider agent keys)")
	}
	if relayKey == "" {
		return errors.New("serve mode requires -relay-key (TEE relay authentication)")
	}
	if accounts == nil {
		return errors.New("serve mode requires -accounts (the SQLite ledger): without it a tenant with no money is served anyway")
	}
	if maxJob == 0 {
		return errors.New("serve mode requires -max-job-micros > 0: the prepaid hold is sized by the per-job ceiling")
	}
	if sync == hub.SyncOff {
		return errors.New("serve mode refuses -ledger-sync off: a committed charge must reach the disk before it is served")
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

func runAudit(store *hub.ReceiptStore, provider string) {
	report, err := store.Audit(provider, verifyReceipt)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	if report.Total == 0 {
		fmt.Printf("no receipts stored for provider %q\n", provider)
		return
	}
	fmt.Printf("verified %d/%d receipts for provider %q\n", report.Verified, report.Total, provider)

	// The deployment binding: receipts issued by a TEE deployed with the
	// current whitelist carry that policy-set hash in their evidence. When the
	// local deployment config exists, compare; receipts whose evidence lacks
	// the binding (issued by an unbound epoch) are flagged as warnings.
	expectedHash, haveDeployment := localPolicySetHash()
	if haveDeployment {
		fmt.Printf("expected deployment policy-set hash: %x\n", expectedHash)
	}

	// Evidence is checked separately from the signature: a receipt can be
	// perfectly signed and still point at an attestation that no longer
	// resolves, which is a cache problem rather than a forgery.
	receipts, err := store.List(provider)
	if err != nil {
		logf("list receipts: %v", err)
	}
	for _, signed := range receipts {
		id, err := signed.Receipt.Identity()
		if err != nil {
			fmt.Printf("  [WARN] seq=%d: identity: %v\n", signed.Receipt.ProviderSeq, err)
			continue
		}
		if haveDeployment {
			if err := simulated.CheckEvidenceForDeployment(id, expectedHash); err != nil {
				fmt.Printf("  [WARN] seq=%d: deployment binding: %v\n", signed.Receipt.ProviderSeq, err)
				continue
			}
			continue
		}
		if err := simulated.CheckEvidence(id); err != nil {
			fmt.Printf("  [WARN] seq=%d: evidence: %v\n", signed.Receipt.ProviderSeq, err)
		}
	}

	if report.Complete() {
		fmt.Printf("sequence complete: 1..%d, no gaps\n", report.MaxSeq)
		return
	}
	fmt.Printf(">>> GAP DETECTED: provider was used at least %d times but is missing receipts %v\n",
		report.MaxSeq, report.Missing)
}

// localPolicySetHash loads the deployment policy config the way cmd/tee does
// and returns the hash a correctly-deployed TEE would have bound into its
// evidence. haveDeployment is false when no policy config exists locally, in
// which case callers fall back to binding-free evidence checks.
func localPolicySetHash() (hash [32]byte, haveDeployment bool) {
	set, err := shared.LoadPolicySetAll()
	if err != nil {
		return hash, false
	}
	hash, err = set.Hash()
	if err != nil {
		logf("hash policy set: %v", err)
		return hash, false
	}
	return hash, true
}

// verifyReceipt checks a receipt's signature and attestation. The allowed
// platform list is the trust root; in the simulation it is the software epoch.
func verifyReceipt(signed proof.SignedReceipt) error {
	return proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}})
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

// parseDeposits turns the -tenant-deposits flag into the first-boot seed
// balances. A malformed entry is a startup failure rather than a silently
// unfunded tenant: a typo must not leave a tenant without money by accident.
func parseDeposits(spec string) (map[string]uint64, error) {
	pairs, err := parsePairs(spec)
	if err != nil {
		return nil, err
	}
	if pairs == nil {
		return nil, nil
	}
	deposits := make(map[string]uint64, len(pairs))
	for _, p := range pairs {
		micros, err := strconv.ParseUint(p[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("tenant %q: balance %q is not a number", p[0], p[1])
		}
		if micros == 0 {
			return nil, fmt.Errorf("tenant %q: balance is zero, which would fund nothing", p[0])
		}
		deposits[p[0]] = micros
	}
	return deposits, nil
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
