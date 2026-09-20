// Package shared holds the small, reusable pieces the simulation binaries
// (mockprovider, tee, faketee, hub, verify, agent) share: the .sim working
// directory, the Hub-predefined whitelist policy the TEE loads, the Hub's
// seller rate table, a throwaway test CA, and the one-shot credential
// registration the simulation-only CLI tools (hub -n, streamer) use when they
// talk to a TEE directly instead of through a resident Hub with dialing agents.
//
// Nothing here is production code. It exists so the simulation runs end to end
// on a laptop with zero external dependencies and zero real credentials, while
// still exercising the real tee.Service — the simulation never re-implements
// the TEE. The /v1/execute wire format is not here for that reason: it lives
// with tee.ServeExecute so that simulation and production speak one definition.
package shared

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// Default fixtures.
//
// providerName and providerCheap name the two seller agents the simulation runs:
// they are device identities, keyed by each agent's dial-in key and by the Hub's
// rate table. They are deliberately NOT upstreams — what a seller charges and
// which agent it is have nothing to do with which AI endpoint the deployment
// reaches, which is the whitelist's business (see policy.Default).
const (
	providerName  = "openai-sim"
	providerCheap = "cheap-sim"
)

// ConfigDir returns the simulation working directory. Override with
// TOKENHIVE_SIM_DIR to keep runs isolated.
func ConfigDir() string {
	if d := os.Getenv("TOKENHIVE_SIM_DIR"); d != "" {
		return d
	}
	return ".sim"
}

// policyDirOverride, when non-empty, points the whitelist loaders (and the Hub's
// /v1/policies view) at a directory other than the .sim working directory. On an
// SNP instance this is the policy directory baked inside the measured bundle, so
// the whitelist the enclave enforces and the whitelist the Hub advertises are the
// exact bytes covered by SNP_APP_HASH.
var policyDirOverride string

// SetPolicyDir redirects where the deployed whitelist policy is loaded from.
// Empty (the default) keeps the .sim working directory.
func SetPolicyDir(dir string) { policyDirOverride = dir }

// PolicyDir returns the directory the whitelist policy files are read from: the
// bundle policy dir when one was set, otherwise the .sim working directory.
func PolicyDir() string {
	if policyDirOverride != "" {
		return policyDirOverride
	}
	return ConfigDir()
}

// bundleRoot is where the SNP loader extracts the measured bundle. A variable
// so a test can point it at a fixture instead of /run/bundle.
var bundleRoot = "/run/bundle"

// ResolvePolicyDir is the one rule for where a whitelist comes from:
//
//  1. An explicitly configured directory (a flag or an environment variable),
//     when used, must hold a policy.cbor — in every mode. A configured
//     directory without one is an operator error, never a cue to fall back to
//     something else: silently enforcing a whitelist nobody chose is exactly
//     how the policy a deployment runs drifts from the policy it measures.
//  2. Otherwise the measured bundle's copy, when it carries one.
//  3. Otherwise the state directory, which is the simulation's: the caller
//     materializes the shipped default there.
//
// require selects the TEE's policy on a real deployment (the sevsnp platform):
// there the whitelist is mandatory, because its bytes are exactly what the
// attestation covers, so a missing policy is an operator error — the TEE must
// refuse to serve on a default it materialized for itself, not quietly start
// enforcing rules the fingerprint says nothing about. On top of that, an
// explicit setting may only restate the measured copy, never replace it: when
// the bundle carries a whitelist whose bytes differ from the configured one,
// resolving fails. Enforcing anything but the measured bytes would run rules
// the attestation describes nothing about, while every receipt kept carrying
// the bundle's identity.
//
// The deployment's binaries resolve through here — the TEE, the Hub, and the
// single-instance supervisor for the children it spawns — because a process
// that has a measured copy must use it. (faketee, the simulation stand-in, has
// no measured bundle to prefer and keeps reading the state directory.)
func ResolvePolicyDir(configured string, require bool) (string, error) {
	measured := filepath.Join(bundleRoot, "policy")
	measuredFile := filepath.Join(measured, "policy.cbor")
	_, measuredErr := os.Stat(measuredFile)

	if configured != "" {
		configuredFile := filepath.Join(configured, "policy.cbor")
		if _, err := os.Stat(configuredFile); err != nil {
			return "", fmt.Errorf("configured policy dir %s holds no whitelist at %s: %v", configured, configuredFile, err)
		}
		if require {
			if measuredErr != nil {
				return "", fmt.Errorf("no deployment whitelist at %s (a sevsnp bundle ships ./policy/policy.cbor; rebuild it): refusing to enforce the explicitly configured %s instead", measuredFile, configured)
			}
			same, err := samePolicyBytes(configuredFile, measuredFile)
			if err != nil {
				return "", fmt.Errorf("compare configured policy %s against measured %s: %v", configuredFile, measuredFile, err)
			}
			if !same {
				return "", fmt.Errorf("configured policy dir %s differs from the measured bundle's %s: on sevsnp the enclave must enforce the measured bytes, or the attestation describes rules it does not run", configured, measured)
			}
		}
		return configured, nil
	}

	if measuredErr == nil {
		return measured, nil
	}
	if require {
		return "", fmt.Errorf("no deployment whitelist at %s (a sevsnp bundle ships ./policy/policy.cbor; rebuild it)", measuredFile)
	}
	return "", nil
}

// samePolicyBytes reports whether two policy.cbor files carry identical bytes.
// A configured directory holding a byte-identical copy of the measured bundle's
// whitelist enforces exactly what the attestation covers, so it is a restatement,
// not an override. Read failures are errors, not "different": the caller is
// about to trust one of these files on the strength of the comparison.
func samePolicyBytes(a, b string) (bool, error) {
	if ae, err := filepath.Abs(a); err == nil {
		if be, err := filepath.Abs(b); err == nil && ae == be {
			return true, nil
		}
	}
	ab, err := os.ReadFile(a)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", a, err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", b, err)
	}
	return bytes.Equal(ab, bb), nil
}

// EnsureDefaults writes the fixture files if they are missing: the default
// whitelist policy (deployment config) and the Hub's seller-reported rate
// table. Credentials are intentionally NOT written:
// they arrive at runtime through agent registration (see the package comment).
func EnsureDefaults() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeIfAbsent(filepath.Join(dir, "rates.json"), DefaultRates()); err != nil {
		return err
	}
	// The fixtures materialize the default whitelist for a deployment that has
	// none — the simulation. When a policy directory was configured explicitly
	// (an SNP bundle's measured ./policy, or an operator's own directory), one
	// is already in force and writing a second, generated copy into the state
	// directory would only leave a file that looks authoritative and is not.
	if policyDirOverride == "" {
		p, err := policy.Default()
		if err != nil {
			return err
		}
		if err := writePolicy(dir, p); err != nil {
			return err
		}
	}
	return nil
}

// DefaultRates is the Hub's seller-reported market price list for the
// simulation. Prices are commercial data kept by the Hub — deliberately
// outside the Provider Policy, which is a whitelist, not a price sheet.
func DefaultRates() Rates {
	return Rates{
		// 1.00 unit per request; premium model carries a surcharge.
		providerName: hub.RateCard{PerRequestMicros: 1_000_000, ModelPremiumMicros: map[string]uint64{
			"sim-mock-large": 500_000, // 0.50 unit surcharge
		}},
		// 0.30 unit per request — the one the scheduler wants.
		providerCheap: hub.RateCard{PerRequestMicros: 300_000},
	}
}

// Rates is the Hub's market table: provider name to seller price card.
type Rates map[string]hub.RateCard

// LoadRates reads the Hub's rate table.
func LoadRates() (Rates, error) {
	var rates Rates
	if err := readJSON(filepath.Join(ConfigDir(), "rates.json"), &rates); err != nil {
		return nil, err
	}
	return rates, nil
}

// SealCredential fetches a TEE's inbox public key and seals a provider's token
// to it, returning the envelope a caller can carry into a job's spec.Credential.
// It is the sender half of agent registration for a caller that talks to a TEE
// directly (no dialing agent): the token travels sealed, and only the TEE
// holding the matching private key can open it. The TEE itself stores nothing —
// the sealed token lives wherever the caller puts it, and is presented on each
// job.
//
// teeBase is the TEE's root URL, e.g. http://127.0.0.1:18095.
func SealCredential(teeBase, provider string, secret tee.Secret) (tee.Envelope, error) {
	keyURL := strings.TrimSuffix(teeBase, "/") + "/v1/credential-key"
	pub, err := tee.CredentialKeyRequest(context.Background(), nil, keyURL)
	if err != nil {
		return tee.Envelope{}, fmt.Errorf("fetch inbox key: %w", err)
	}
	envelope, err := tee.EncryptCredential(pub, provider, secret)
	if err != nil {
		return tee.Envelope{}, fmt.Errorf("seal credential: %w", err)
	}
	return envelope, nil
}

// BuildSpec assembles the one-shot job spec the simulation tools send: every
// field a real Hub's spec carries, filled with what the caller varies and the
// defaults it does not. It lives here because more than one of those tools
// (cmd/hub -n, cmd/hub's user API, cmd/bench) has to emit the same shape — a
// bench whose spec differed from the Hub's would measure a different path than
// the one the Hub drives.
func BuildSpec(provider, model, host, path, query string, body []byte, maxBytes uint64) (jobs.Spec, error) {
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
		Method:           "POST",
		Host:             host,
		Path:             path,
		Query:            query,
		Headers:          map[string]string{"Content-Type": "application/json"},
		BodyHash:         BodyHash(body),
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		MaxResponseBytes: maxBytes,
		Stream:           true,
	}, nil
}

// BodyHash is the spec's body commitment in its wire form (a 32-byte array
// sliced), which jobs.Spec records as bytes.
func BodyHash(body []byte) []byte {
	h := jobs.HashBody(body)
	return h[:]
}

// writePolicy encodes and writes the deployment whitelist into dir as
// policy.cbor. The policy is unsigned: pricing lives in the Hub's rates.json (a
// commercial concern), and the whitelist itself is deployment config, whose
// integrity the TEE binds into its attestation measurement.
func writePolicy(dir string, p policy.Policy) error {
	enc, err := p.EncodeCanonical()
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("make policy dir: %w", err)
	}
	if err := os.WriteFile(policyPathIn(dir), enc, 0o644); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	return nil
}

// WritePolicyDir materializes the deployment whitelist into dir in the layout
// the loaders expect, without booting a TEE. pack.sh uses it so the whitelist
// travels inside the measured SNP bundle (covered by SNP_APP_HASH), and tests
// use it to produce a policy directory to point -policy-dir at.
//
// It writes policy.Default — the document in tokenhive/policy/whitelist.json.
// Nothing here defines the whitelist: this only puts it on disk in the layout a
// policy directory needs.
func WritePolicyDir(dir string) error {
	p, err := policy.Default()
	if err != nil {
		return err
	}
	return writePolicy(dir, p)
}

func policyPath() string             { return policyPathIn(PolicyDir()) }
func policyPathIn(dir string) string { return filepath.Join(dir, "policy.cbor") }

// LoadPolicy reads the deployment whitelist. There is exactly one, so the TEE
// that enforces it and the Hub that advertises and admits against it read the
// same bytes and agree by construction.
func LoadPolicy() (*policy.Policy, error) {
	b, err := os.ReadFile(policyPath())
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p policy.Policy
	if err := canonical.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return &p, nil
}

// WriteTEEIdentity persists the public identity of a sim epoch so the verifier
// (hub/verify) can resolve EvidenceHash without an inline attestation — exactly
// the "attestation cache" role a production verifier would fill from its own
// trust store.
func WriteTEEIdentity(id platform.Identity) error {
	return writeJSON(filepath.Join(ConfigDir(), "tee_identity.json"), id)
}

// EvidenceDir is where the TEE keeps the restart-surviving evidence store that
// lets a hash-only receipt (no inline evidence) verify online or offline.
func EvidenceDir() string { return filepath.Join(ConfigDir(), "evidence") }

// RecordTEEEvidence appends the given identity's full evidence to the local
// store so a verifier pointed at the same directory can resolve its
// EvidenceHash later. It is idempotent and cheap to call on every epoch build,
// and only a deployment that ships hash-only receipts needs it: an inline
// receipt carries its evidence, so nothing ever resolves the hash.
func RecordTEEEvidence(id platform.Identity) error {
	store, err := evidence.NewStore(EvidenceDir())
	if err != nil {
		return err
	}
	return store.Put(id)
}

// LoadEvidenceStore opens (creating if needed) the local evidence store.
func LoadEvidenceStore() (*evidence.Store, error) {
	return evidence.NewStore(EvidenceDir())
}

// CAPEMPath is where mockprovider drops its CA certificate for the TEE to trust.
func CAPEMPath() string { return filepath.Join(ConfigDir(), "ca.pem") }

// mTLS fixture paths for the Hub↔TEE channel.
const (
	// MTLSClientCAPath is the throwaway CA that signs the Hub's client
	// certificate; the TEE trusts it with -mtls-client-ca.
	MTLSClientCAPath = "hub-ca.pem"
	// MTLSClientCertPath / MTLSClientKeyPath are the Hub's own mTLS identity,
	// presented with -mtls-cert/-mtls-key.
	MTLSClientCertPath = "hub-client.pem"
	MTLSClientKeyPath  = "hub-client-key.pem"
	// MTLSServerCertPath is the TEE's RA-TLS leaf, published once at startup
	// when the epoch is fixed (the simulation) so the Hub's pin mode can name
	// it. A rotating epoch (sevsnp) presents a new leaf every rotation, which
	// no pin can name — attestation mode verifies the evidence instead.
	MTLSServerCertPath = "tee-cert.pem"
)

// HubIdentityPaths is where the simulation's Hub mTLS identity lives: the client
// certificate the Hub presents on the Hub↔TEE channel and the key that goes with
// it. EnsureMTLSCerts maintains exactly these two files under ConfigDir, so a
// caller that has to resolve the same defaults must ask here rather than spell
// the location out a second time — two spellings of one location is how a set
// gets written in one place and read from another.
func HubIdentityPaths() (certPath, keyPath string) {
	dir := ConfigDir()
	return filepath.Join(dir, MTLSClientCertPath), filepath.Join(dir, MTLSClientKeyPath)
}

// EnsureMTLSCerts writes the simulation's Hub mTLS identity when the working
// directory does not already hold a usable one: a throwaway CA (hub-ca.pem) and
// a client certificate it signs (hub-client.pem/key). The TEE's -mtls-client-ca
// trusts the former, and the Hub presents the latter with -mtls-cert/-mtls-key.
// Nothing here is production material — it exists so the mTLS wiring can be
// exercised end-to-end on a laptop.
//
// The three files are one identity, not three independent fixtures: a client
// certificate means nothing next to a CA that did not sign it or a key that is
// not its own. So reuse is decided by asking whether the set still works as one
// — see loadHubMTLSIdentity — and anything else is rebuilt whole. Deciding per
// file (what this used to do, one writePEMIfAbsent per file) cannot see a
// mismatch at all: it tops up the files that are absent and trusts the ones that
// are there, so a directory that lost one file, or that two processes raced to
// create, keeps a triple that never belonged together. The failure then lands
// far from its cause — "tls: private key does not match public key" while the
// Hub loads its own identity, or a peer refusing a chain that never existed.
func EnsureMTLSCerts() error {
	caPath := filepath.Join(ConfigDir(), MTLSClientCAPath)
	certPath, keyPath := HubIdentityPaths()

	if loadHubMTLSIdentity(caPath, certPath, keyPath) == nil {
		return nil
	}
	caPEM, certPEM, keyPEM, err := mtls.GenHubClientCerts()
	if err != nil {
		return err
	}
	files := []struct {
		path string
		pem  []byte
	}{
		{caPath, caPEM},
		{certPath, certPEM},
		{keyPath, keyPEM},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.pem, 0o644); err != nil {
			return err
		}
	}
	// Read back what was just written rather than assuming it is coherent: a
	// concurrent writer interleaving here, or a directory that cannot take the
	// files properly, has to surface now — as a startup failure — and not later
	// as a handshake that fails for no visible reason.
	return loadHubMTLSIdentity(caPath, certPath, keyPath)
}

// loadHubMTLSIdentity reads the simulation's Hub mTLS identity as one unit,
// reporting nil only when the three files are usable together: the CA parses,
// the key belongs to the certificate, and the certificate is a client
// certificate that CA signed. It is the whole reuse decision for
// EnsureMTLSCerts, so no partially replaced set can pass for a working one.
func loadHubMTLSIdentity(caPath, certPath, keyPath string) error {
	pool, err := mtls.LoadCAPath(caPath)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("hub client certificate does not chain to %s: %w", caPath, err)
	}
	return nil
}

// WriteTEECert publishes the leaf certificate a TEE listener presents.
func WriteTEECert(cfg *tls.Config) error {
	return mtls.WriteTEECert(cfg, filepath.Join(ConfigDir(), MTLSServerCertPath))
}

// LoadCAPool reads the CA certificate mockprovider wrote, for the TEE's TLS
// trust roots.
func LoadCAPool() (*x509.CertPool, error) {
	pool, err := mtls.LoadCAPath(CAPEMPath())
	if err != nil {
		return nil, fmt.Errorf("%w (did mockprovider start with TLS?)", err)
	}
	return pool, nil
}

func writeIfAbsent(path string, v any) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return writeJSON(path, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so a crash cannot leave a truncated file that later
	// reads back as a valid document describing nothing — the same reason the
	// evidence store stages and renames its entries.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return json.Unmarshal(b, v)
}
