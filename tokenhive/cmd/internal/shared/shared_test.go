package shared

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
)

// TestWritePolicyDirRoundTrips pins the "bake the whitelist into a policy
// directory" contract that -policy-dir, -emit-policy-dir and pack.sh rely on:
// WritePolicyDir materializes the deployment whitelist in the layout the loader
// reads, and SetPolicyDir redirects the loader to it — so the whitelist an SNP
// bundle carries (and the Hub advertises on /v1/policies) is the same document
// the TEE enforces, byte for byte.
func TestWritePolicyDirRoundTrips(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	policyDir := filepath.Join(simDir, "policy")
	if err := WritePolicyDir(policyDir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}

	// Before the override is set, the loader points at the .sim dir, which holds
	// no policy.cbor, so loading must fail: nothing is silently inherited.
	if _, err := LoadPolicy(); err == nil {
		t.Fatal("LoadPolicy from an empty .sim should fail")
	}
	if got := PolicyDir(); got != simDir {
		t.Fatalf("PolicyDir() before override = %q, want %q", got, simDir)
	}

	SetPolicyDir(policyDir)
	if got := PolicyDir(); got != policyDir {
		t.Fatalf("PolicyDir() after override = %q, want %q", got, policyDir)
	}

	loaded, err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy from the policy dir: %v", err)
	}
	want := defaultPolicy(t)
	if len(loaded.Hosts) != len(want.Hosts) {
		t.Fatalf("hosts = %v, want %v", loaded.Hosts, want.Hosts)
	}
	for i := range want.Hosts {
		if loaded.Hosts[i] != want.Hosts[i] {
			t.Fatalf("host %d = %q, want %q", i, loaded.Hosts[i], want.Hosts[i])
		}
	}
	if len(loaded.Rules) != len(want.Rules) {
		t.Fatalf("%d rules, want %d", len(loaded.Rules), len(want.Rules))
	}

	// Reloading must yield the same bytes, hence the same hash: that is what
	// lets the hash stand in for the whitelist in a receipt or an audit log.
	again, err := LoadPolicy()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	gotHash, err := loaded.Hash()
	if err != nil {
		t.Fatalf("hash loaded policy: %v", err)
	}
	againHash, err := again.Hash()
	if err != nil {
		t.Fatalf("hash reloaded policy: %v", err)
	}
	if gotHash != againHash {
		t.Fatalf("policy hash changed across a reload: %x vs %x", gotHash, againHash)
	}
}

// TestStalePerProviderPoliciesAreIgnored pins the retirement of the per-provider
// layout. A policies/<provider>.cbor left behind by the multi-policy era must
// not change what the enclave enforces: sellers do not get to bring their own
// rules, and neither do their leftovers.
func TestStalePerProviderPoliciesAreIgnored(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	if err := WritePolicyDir(simDir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}
	before, err := LoadPolicy()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	beforeHash, err := before.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// A wider whitelist, at the path an older deployment would have used.
	stale := defaultPolicy(t)
	stale.Hosts = append(stale.Hosts, "evil.example.com")
	enc, err := stale.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode stale policy: %v", err)
	}
	staleDir := filepath.Join(simDir, "policies")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatalf("make stale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "openai-sim.cbor"), enc, 0o644); err != nil {
		t.Fatalf("write stale policy: %v", err)
	}

	after, err := LoadPolicy()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	afterHash, err := after.Hash()
	if err != nil {
		t.Fatalf("hash after: %v", err)
	}
	if beforeHash != afterHash {
		t.Fatal("a leftover per-provider policy changed the deployment whitelist")
	}
	if err := after.AllowsRoute("evil.example.com", "/v1/chat/completions", "POST"); err == nil {
		t.Fatal("a leftover per-provider policy widened the hosts the enclave reaches")
	}
}

// TestDefaultPolicyCoversTheRealAPIs pins the two upstreams the public default
// whitelist exists to admit, on the shapes the Hub serves them with: a seller
// onboards against this document, so dropping either API would silently make
// every seller of that shape unadmittable.
func TestDefaultPolicyCoversTheRealAPIs(t *testing.T) {
	p := defaultPolicy(t)

	for _, r := range []struct{ host, path, method string }{
		{"api.openai.com", "/v1/chat/completions", "POST"},
		{"api.openai.com", "/v1/responses", "POST"},
		{"api.anthropic.com", "/v1/messages", "POST"},
		{"chatgpt.com", "/backend-api/codex/responses", "POST"},
		// The Codex model catalog the market serves its buyers' Codex.
		{"chatgpt.com", "/backend-api/codex/models", "GET"},
		// Anthropic's token count, under the /v1/messages rule.
		{"api.anthropic.com", "/v1/messages/count_tokens", "POST"},
	} {
		if err := p.AllowsRoute(r.host, r.path, r.method); err != nil {
			t.Errorf("%s %s%s not admitted by the default policy: %v", r.method, r.host, r.path, err)
		}
	}

	// The bounds a market request must fit: 8 MiB each way, the request headers
	// the market's Codex and Claude adapters send, and the Messages beta query.
	if p.Limits.MaxBodyBytes != 8<<20 || p.Limits.MaxResponseBytes != 8<<20 {
		t.Errorf("limits = body %d, response %d; want 8 MiB each", p.Limits.MaxBodyBytes, p.Limits.MaxResponseBytes)
	}
	for _, header := range []string{"content-type", "chatgpt-account-id", "originator", "session-id", "anthropic-version", "anthropic-beta", "x-claude-code-session-id", "x-stainless-helper-method",
		// What the Codex client sends a subscription on every request.
		"x-openai-internal-codex-responses-lite", "x-codex-beta-features", "x-codex-turn-state", "x-codex-turn-metadata", "x-codex-window-id", "x-codex-parent-thread-id", "x-openai-subagent", "x-codex-routing-hint",
		// A request body the market compressed.
		"content-encoding"} {
		if !p.Limits.HeaderAllowed(header) {
			t.Errorf("header %q is not allowed", header)
		}
	}
	// Claude requests always carry the beta query.
	beta := false
	for _, rule := range p.Rules {
		if rule.Path == "/v1/messages" {
			for _, key := range rule.QueryKeys {
				beta = beta || key == "beta"
			}
		}
	}
	if !beta {
		t.Error("the Messages rule does not admit the beta query")
	}

	// A host the deployment does not reach is still refused, so admitting the
	// real APIs did not turn the whitelist into a wildcard.
	if err := p.AllowsRoute("evil.example.com", "/v1/chat/completions", "POST"); err == nil {
		t.Error("the default policy admitted a host it does not name")
	}
}

// TestResolvePolicyDir pins the one rule for where a whitelist comes from: an
// explicit setting must hold a policy.cbor in every mode (a configured
// directory without one is an operator error, never a cue to fall back); the
// measured bundle wins over the state directory; and on a real deployment
// (require) a missing whitelist is an error, while the simulation stays
// lenient. On top of that, require lets an explicit setting only restate the
// measured bytes, never replace them.
func TestResolvePolicyDir(t *testing.T) {
	root := t.TempDir()
	old := bundleRoot
	bundleRoot = root
	t.Cleanup(func() { bundleRoot = old })

	measured := filepath.Join(root, "policy")
	if err := WritePolicyDir(measured); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}
	opDir := t.TempDir()
	if err := WritePolicyDir(opDir); err != nil {
		t.Fatalf("WritePolicyDir(operator): %v", err)
	}
	// A valid whitelist that is NOT the measured one: same shape, one extra
	// host, so resolving against it exercises the override refusal rather
	// than a parse failure.
	otherDir := t.TempDir()
	other := defaultPolicy(t)
	other.Hosts = append(append([]string{}, other.Hosts...), "extra.example.com")
	if err := writePolicy(otherDir, other); err != nil {
		t.Fatalf("writePolicy(other): %v", err)
	}

	cases := []struct {
		name       string
		configured string
		require    bool
		want       string
		wantErr    bool
	}{
		{"bundle present, lenient", "", false, measured, false},
		{"bundle present, required", "", true, measured, false},
		{"explicit setting wins", opDir, false, opDir, false},
		// A deployed TEE must not invent a default for itself.
		{"explicit setting missing, required", "/operator/policy", true, "", true},
		// A configured directory without a whitelist is an operator error even
		// where the simulation is otherwise lenient: falling back would
		// silently enforce rules nobody chose.
		{"explicit setting missing, lenient", "/operator/policy", false, "", true},
		// A byte-identical restatement of the measured whitelist is allowed on
		// a deployment: it enforces exactly what the attestation covers.
		// (WritePolicyDir is deterministic, so opDir carries the same bytes.)
		{"explicit restatement wins, required", opDir, true, opDir, false},
		// A differing whitelist smuggled in through configuration is refused
		// on a deployment, even though it is perfectly valid on its own.
		{"explicit override refused, required", otherDir, true, "", true},
		// ... while the simulation still lets an operator point at any valid
		// whitelist, which is what makes local policy experiments cheap.
		{"explicit override wins, lenient", otherDir, false, otherDir, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolvePolicyDir(tc.configured, tc.require)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolvePolicyDir(%q, %v) = %q, want error", tc.configured, tc.require, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolvePolicyDir(%q, %v): %v", tc.configured, tc.require, err)
			}
			if got != tc.want {
				t.Fatalf("ResolvePolicyDir(%q, %v) = %q, want %q", tc.configured, tc.require, got, tc.want)
			}
		})
	}

	// A bundle that carries no whitelist is satisfied leniently (the caller
	// decides the fallback, so a missing measured policy is never quietly
	// replaced by an unrelated file) but is an error for a deployment that
	// requires one — including when an explicit whitelist was configured:
	// without measured bytes there is nothing the attestation covers, so there
	// is nothing a deployment may enforce.
	empty := t.TempDir()
	bundleRoot = empty
	if got, err := ResolvePolicyDir("", false); err != nil || got != "" {
		t.Fatalf("ResolvePolicyDir(lenient, no policy) = %q, %v; want empty, nil", got, err)
	}
	if _, err := ResolvePolicyDir("", true); err == nil {
		t.Fatal("ResolvePolicyDir(required, no policy) must fail, got nil")
	}
	if _, err := ResolvePolicyDir(opDir, true); err == nil {
		t.Fatal("ResolvePolicyDir(required, explicit policy, no measured copy) must fail, got nil")
	}
}

// TestEnsureDefaultsLeavesAConfiguredPolicyAlone pins that the fixture writer
// does not drop a second, generated whitelist beside a directory the operator
// configured. Two policy files, one enforced and one merely present, is exactly
// how the policy a deployment runs drifts from the policy it measures.
func TestEnsureDefaultsLeavesAConfiguredPolicyAlone(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)
	t.Cleanup(func() { SetPolicyDir("") })

	SetPolicyDir(t.TempDir())
	if err := EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	if _, err := os.Stat(filepath.Join(simDir, "policy.cbor")); err == nil {
		t.Fatal("EnsureDefaults wrote a whitelist beside a configured policy directory")
	}
	// The rate table is not policy: the Hub still needs it.
	if _, err := os.Stat(filepath.Join(simDir, "rates.json")); err != nil {
		t.Fatalf("EnsureDefaults must still write the rate table: %v", err)
	}

	// With nothing configured, the simulation's own whitelist is materialized
	// and loadable.
	SetPolicyDir("")
	if err := EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	if _, err := LoadPolicy(); err != nil {
		t.Fatalf("the simulation whitelist should be loadable: %v", err)
	}
}

// TestDefaultPolicyIsReproducible pins that the shipped whitelist is a function
// of the code alone. Its bytes are measured, so a document that changed on
// every generation would move SNP_APP_HASH with no code change and leave the
// artifact irreproducible — which is also what lets a build re-emit the policy
// on every run instead of freezing a copy that silently goes stale.
func TestDefaultPolicyIsReproducible(t *testing.T) {
	first, err := defaultPolicy(t).Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Round-trip through the filesystem as well, so the encoder and the loader
	// are in the loop and not just the in-memory document.
	dir := t.TempDir()
	if err := WritePolicyDir(dir); err != nil {
		t.Fatalf("WritePolicyDir: %v", err)
	}
	t.Cleanup(func() { SetPolicyDir("") })
	SetPolicyDir(dir)
	loaded, err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	again, err := loaded.Hash()
	if err != nil {
		t.Fatalf("hash loaded: %v", err)
	}
	if first != again {
		t.Fatal("the default whitelist is not reproducible across generations")
	}
}

// TestDefaultPolicyDoesNotLapse pins the "the public default whitelist is
// open-ended" contract. The default policy is what every seller onboards
// against, so a finite window would eventually start refusing every job with
// ErrPolicyExpired while the policy file itself still looked correct — a
// failure that only shows up as refusals, long after the change that caused it.
func TestDefaultPolicyDoesNotLapse(t *testing.T) {
	// ~year 36812: far past any finite grant yet still a representable
	// timestamp, so an open-ended policy passes and a term of years fails.
	far := time.Unix(1<<40, 0)

	p := defaultPolicy(t)
	if err := p.Validate(); err != nil {
		t.Fatalf("policy.Default().Validate: %v", err)
	}
	if err := p.ValidateAt(far); err != nil {
		t.Fatalf("default policy lapsed before t=%d: %v", far.Unix(), err)
	}
}

// defaultPolicy is the shipped deployment whitelist, for the tests that need to
// compare a loaded policy against it. It is policy.Default — the document in
// tokenhive/policy/whitelist.json — reached through the same call the runtime
// makes, so a document that stopped parsing fails here rather than in a test
// fixture that had its own copy.
func defaultPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Default()
	if err != nil {
		t.Fatalf("policy.Default: %v", err)
	}
	return p
}

// TestEnsureMTLSCertsWritesTheIdentityAsASet pins that the simulation's Hub
// identity is one artifact, not three files. A client certificate means nothing
// next to a CA that did not sign it or a key that is not its own, so a partial
// directory must be rebuilt whole — topping up only the files that are missing
// pairs a fresh CA and key with a surviving certificate, and the mismatch then
// surfaces as "private key does not match public key" while the Hub loads its
// own identity, nowhere near the deletion that caused it.
func TestEnsureMTLSCertsWritesTheIdentityAsASet(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	// What a partially wiped working directory leaves behind: a previous
	// generation's certificate, with its CA and key gone.
	_, staleCertPEM, _, err := mtls.GenHubClientCerts()
	if err != nil {
		t.Fatalf("GenHubClientCerts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(simDir, MTLSClientCertPath), staleCertPEM, 0o644); err != nil {
		t.Fatalf("write stale certificate: %v", err)
	}

	if err := EnsureMTLSCerts(); err != nil {
		t.Fatalf("EnsureMTLSCerts: %v", err)
	}

	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(simDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return b
	}

	// The certificate that survived was replaced, so the CA on disk signs the
	// certificate on disk...
	caPEM := read(MTLSClientCAPath)
	certPEM := read(MTLSClientCertPath)
	if string(certPEM) == string(staleCertPEM) {
		t.Fatal("the stale certificate was kept beside a freshly generated CA")
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("hub CA is not a PEM block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse hub CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	block, _ = pem.Decode(certPEM)
	if block == nil {
		t.Fatal("hub certificate is not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse hub certificate: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("hub certificate is not signed by the CA beside it: %v", err)
	}
	// ... and the key is the one that certificate belongs to.
	if _, err := tls.LoadX509KeyPair(
		filepath.Join(simDir, MTLSClientCertPath),
		filepath.Join(simDir, MTLSClientKeyPath),
	); err != nil {
		t.Fatalf("certificate and key do not form a pair: %v", err)
	}

	// A complete set is reused, not rewritten: the TEE is already trusting this
	// CA, and rotating it would break a running deployment.
	before := map[string]string{}
	for _, name := range []string{MTLSClientCAPath, MTLSClientCertPath, MTLSClientKeyPath} {
		before[name] = string(read(name))
	}
	if err := EnsureMTLSCerts(); err != nil {
		t.Fatalf("EnsureMTLSCerts (second call): %v", err)
	}
	for name, want := range before {
		if got := string(read(name)); got != want {
			t.Errorf("%s was rewritten although the set was already complete", name)
		}
	}
}

// TestEnsureMTLSCertsRebuildsAMismatchedSet is the case a presence check cannot
// see: every file is there, and together they are not one identity. Two minting
// calls give a CA from one generation and a certificate/key from another — the
// subjects and serials are fixed, the keys are not — which is what a
// hand-cleaned directory or two processes starting at once leaves behind. It has
// to be rebuilt rather than trusted.
func TestEnsureMTLSCertsRebuildsAMismatchedSet(t *testing.T) {
	simDir := t.TempDir()
	t.Setenv("TOKENHIVE_SIM_DIR", simDir)

	staleCA, _, _, err := mtls.GenHubClientCerts()
	if err != nil {
		t.Fatalf("GenHubClientCerts: %v", err)
	}
	_, freshCert, freshKey, err := mtls.GenHubClientCerts()
	if err != nil {
		t.Fatalf("GenHubClientCerts: %v", err)
	}
	for name, b := range map[string][]byte{
		MTLSClientCAPath:   staleCA,
		MTLSClientCertPath: freshCert,
		MTLSClientKeyPath:  freshKey,
	} {
		if err := os.WriteFile(filepath.Join(simDir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := EnsureMTLSCerts(); err != nil {
		t.Fatalf("EnsureMTLSCerts: %v", err)
	}

	// The CA that never signed the certificate on disk cannot still be there.
	got, err := os.ReadFile(filepath.Join(simDir, MTLSClientCAPath))
	if err != nil {
		t.Fatalf("read hub CA: %v", err)
	}
	if string(got) == string(staleCA) {
		t.Fatal("a complete-but-mismatched set was reused instead of rebuilt")
	}
	if err := loadHubMTLSIdentity(
		filepath.Join(simDir, MTLSClientCAPath),
		filepath.Join(simDir, MTLSClientCertPath),
		filepath.Join(simDir, MTLSClientKeyPath),
	); err != nil {
		t.Fatalf("rebuilt set is still not one identity: %v", err)
	}
}
