// Command tee is the TokenHive TEE process. It enforces the provider's signed
// policy, injects the credential, opens a real TLS connection to the provider
// (optionally egressing through a Provider Agent), and signs a receipt binding
// RequestBytes and the monotonic ProviderSeq.
//
// It runs the REAL tee.Service on every execution path. What differs between
// the local simulation and a production deployment is only the assembly — the
// attestation platform, the receipt evidence policy, and the upstream TLS
// trust roots — and this binary exposes each of those as a switch so the same
// code serves both:
//
//	-platform simulated   software attestation epoch (default; local sim)
//	-platform sevsnp      AWS SEV-SNP RA-TLS epoch (real enclave). Compiled
//	                      only with `-tags sevsnp`; see epoch_sevsnp.go.
//	-evidence             embed attestation evidence in every receipt so each
//	                      one verifies offline (default true; the simulation
//	                      has no evidence cache to fetch from). Production sets
//	                      false and resolves EvidenceHash via the evidence
//	                      retrieval path (see the C4 checklist, §8).
//	-ca <path>            root CA PEM for the upstream (provider) TLS; empty in
//	                      sevsnp mode means the system trust store, which is
//	                      what production wants for api.openai.com etc. The
//	                      simulated default keeps loading the sim test CA so
//	                      the harness stays hermetic.
//
// The Hub↔TEE channel is deliberately separate: local sims run plain HTTP, and
// production enables mTLS at the listener using the platform adapter's
// ServerTLSConfig (RA-TLS certificates). -mtls switches the listener to that
// mode; -mtls-client-ca names the CA that signs Hub client certificates.
//
// An attested RA-TLS certificate expires — on AWS the NitroTPM chain inside the
// leaf is valid for hours — so the process rotates the epoch in place for as
// long as it serves, and a Hub in attestation mode verifies each rotation from
// the handshake itself instead of pinning a leaf that would go stale. See
// ratls_refresh.go.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// defaultPlatform is what the harness and the local simulation use: a software
// attestation epoch whose evidence shape matches a real SEV-SNP report but
// whose trust root is just a generated key.
const defaultPlatform = "simulated"

func main() {
	// Under the measured loader the loader launches this binary twice: once as a
	// root-only attestation broker (which owns /dev/sev-guest, /dev/tpm0) and once
	// as the unprivileged app connected to it. When env marks this process as the
	// broker, serve attestation requests in a loop and exit instead of running the
	// TEE service (the same split tee_k/tee_t use).
	if broker, err := rootShared.RunSNPAttestationBrokerIfRequested(); broker {
		if err != nil {
			fmt.Fprintln(os.Stderr, "SNP attestation broker failed:", err)
			os.Exit(1)
		}
		return
	}

	// Every CLI flag falls back to an environment variable of the same semantics
	// so the measured app can be configured purely through the loader's instance-
	// metadata env injection (see deploy/snp-image/loader fetchMetadataEnv) with no
	// rebuild: the SHA-256-measured bundle stays byte-identical while runtime
	// routing (relay URL, ports, bootstrap token) comes from VM metadata.
	addr := flag.String("addr", rootShared.GetEnvOrDefault("TEE_ADDR", "127.0.0.1:18090"), "listen address")
	relay := flag.String("relay", rootShared.GetEnvOrDefault("TEE_RELAY", ""), "Hub TeeRelay WebSocket URL: every provider connection egresses as a stream over the Hub's reverse tunnel")
	// The relay key is part of the same env-driven surface: the measured app
	// authenticates to the Hub's TeeRelay with it, so a Hub that only admits an
	// authenticated egress path cannot be bypassed by anything that reaches the
	// listener, and the instance can be pointed at that Hub by metadata alone.
	relayKey := flag.String("relay-key", rootShared.GetEnvOrDefault("TEE_RELAY_KEY", ""), "key to present to the Hub's TeeRelay endpoint (empty = the Hub requires none)")
	maxConns := flag.Int("max-conns", rootShared.GetEnvIntOrDefault("TEE_MAX_CONNS", 0), "max resident provider connections per (provider, host) (0 = default 32)")
	requestTimeout := flag.Duration("request-timeout", rootShared.GetEnvDurationOrDefault("TEE_REQUEST_TIMEOUT", 2*time.Minute), "bound on a single provider exchange, including streaming sessions (0 = no bound)")
	seqPath := flag.String("seq", os.Getenv("TEE_SEQ"), "ProviderSeq store file (default <simdir>/seqstore.json)")
	platformName := flag.String("platform", rootShared.GetEnvOrDefault("TEE_PLATFORM", defaultPlatform), "attestation platform: simulated, sevsnp")
	includeEvidence := flag.Bool("evidence", rootShared.GetEnvBoolOrDefault("TEE_EVIDENCE", true), "embed attestation evidence in every receipt (false = resolve EvidenceHash via evidence retrieval)")
	caFile := flag.String("ca", os.Getenv("TEE_CA"), "root CA PEM for provider TLS; empty = sim test CA on simulated, system roots on sevsnp")
	serveMTLS := flag.Bool("mtls", rootShared.GetEnvBoolOrDefault("TEE_MTLS", false), "serve the Hub-facing API over mutual TLS: the platform's RA-TLS server certificate (sevsnp) or the sim test certificate (simulated), demanding a Hub client certificate")
	mtlsClientCA := flag.String("mtls-client-ca", rootShared.GetEnvOrDefault("TEE_MTLS_CLIENT_CA", ""), "PEM CA(s) that sign Hub client certificates; empty defaults to <simdir>/hub-ca.pem (required with -mtls)")
	// On an SNP instance the deployment whitelist is baked inside the measured
	// bundle at a fixed path. Pointing this flag there means the policy the
	// enclave enforces IS the measured copy in the bundle tar, whose digest the
	// loader exports as SNP_APP_HASH — so a rotated whitelist changes the attestation
	// fingerprint instead of silently widening what the enclave will accept.
	policyDir := flag.String("policy-dir", rootShared.GetEnvOrDefault("TEE_POLICY_DIR", ""), "directory holding the deployment whitelist (policy.cbor); empty = the measured bundle's policy/ when it has one, else TOKENHIVE_SIM_DIR. A configured directory without a policy.cbor is always an error; on the sevsnp platform the measured bundle's copy additionally wins — an explicit dir may only restate its exact bytes, never replace them")
	emitPolicyDir := flag.String("emit-policy-dir", "", "write the deployment whitelist policy to this directory and exit (used by pack.sh to bake the policy into the measured bundle)")
	flag.Parse()

	// Emission mode is a build-time helper for pack.sh: it materializes the
	// whitelist on the pack machine (where this sevsnp binary may not even run)
	// only when a host can execute it; the bundle otherwise stages an operator-provided
	// policy directory. Either way the policy lands inside the measured bundle tar.
	if *emitPolicyDir != "" {
		if err := shared.WritePolicyDir(*emitPolicyDir); err != nil {
			log.Fatalf("emit policy dir: %v", err)
		}
		return
	}
	// The Hub-facing API spends provider credentials and allocates ProviderSeq
	// numbers, and in the clear it authenticates nothing: /v1/execute trusts
	// whoever asks and /v1/credential-key hands out the inbox key to whoever
	// asks. Serving that beyond this host needs -mtls, which demands a Hub
	// client certificate; anything else keeps it on loopback.
	if !*serveMTLS {
		if err := requireCleartextLoopback(*addr); err != nil {
			log.Fatalf("%v; serve -mtls to expose the Hub-facing API beyond this host", err)
		}
	}
	if resolved, err := shared.ResolvePolicyDir(*policyDir, *platformName == "sevsnp"); err != nil {
		// On the SNP path the whitelist is part of the measured bundle and its
		// absence is an operator error: the attestation covers its exact bytes,
		// so the TEE must not invent a default for itself.
		log.Fatalf("resolve policy dir: %v", err)
	} else if resolved != "" {
		shared.SetPolicyDir(resolved)
		log.Printf("whitelist policy directory: %s", resolved)
	}

	// Fixtures are idempotent and live under TOKENHIVE_SIM_DIR (default .sim):
	// on a real deployment that directory is mounted by the provisioning path
	// with the operator's real provider policies and credentials instead. The
	// call is unconditional so the loader below never fails differently between
	// sim and cloud — only the file contents differ.
	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}
	if *serveMTLS {
		if err := shared.EnsureMTLSCerts(); err != nil {
			log.Fatalf("ensure mtls fixtures: %v", err)
		}
	}

	// The whitelist is part of this enclave's measured configuration: load it
	// before the epoch so its hash can be bound into the attestation evidence.
	// A receipt then proves not just "the trusted image ran" but "the trusted
	// image ran with exactly this policy".
	policyDoc, err := shared.LoadPolicy()
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	policyHash, err := policyDoc.Hash()
	if err != nil {
		log.Fatalf("hash policy: %v", err)
	}

	assembly, err := buildEpoch(*platformName, policyHash)
	if err != nil {
		log.Fatalf("build platform epoch: %v", err)
	}
	epoch, serverTLS := assembly.Epoch, assembly.ServerTLS
	// A logger failure is not worth refusing to start an enclave over: nothing
	// below depends on the sink, and the console fallback is fine.
	logger, err := rootShared.NewLoggerFromEnv("tokenhive-tee")
	if err != nil {
		log.Printf("structured logger unavailable (%v); publications and rotations will go unlogged", err)
		logger = rootShared.NewNopLogger()
	}
	// The certificate the Hub-facing listener presents, when it is mTLS: the
	// platform's RA-TLS config plus the Hub client CA. It is assembled before the
	// service runtime because publishing it is part of what the runtime does.
	var leafTLS *tls.Config
	if *serveMTLS {
		if serverTLS == nil {
			log.Fatalf("platform %q provides no RA-TLS server certificate; cannot serve -mtls", *platformName)
		}
		clientCAPath := *mtlsClientCA
		if clientCAPath == "" {
			clientCAPath = filepath.Join(shared.ConfigDir(), shared.MTLSClientCAPath)
		}
		leafTLS, err = mtls.ServerMTLSConfig(serverTLS, clientCAPath)
		if err != nil {
			log.Fatalf("mtls server config: %v", err)
		}
	}
	log.Printf("policy hash bound into attestation evidence: %x", policyHash)

	// The credential inbox: the TEE's own keypair for accepting agent-registered
	// tokens. The private half never leaves this process and nothing about it is
	// persisted, so a restart rotates the key and agents re-register with the
	// fresh public half. The TEE stores no access token at all: each job brings
	// its provider's token sealed to this key, and the private half is the only
	// way to open it.
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		log.Fatalf("generate inbox key: %v", err)
	}

	// Data path: real TLS to the provider over the Hub's reverse tunnel. The TLS
	// session terminates inside the TEE, so the credential never exists on a
	// wire the agent controls.
	upstreamTLS, err := upstreamTLSConfig(*platformName, *caFile)
	if err != nil {
		log.Fatalf("upstream TLS config: %v", err)
	}
	cm, err := transport.NewChannelManager(transport.ChannelConfig{
		Scheme:          "https",
		RelayURL:        *relay,
		RelayHeaders:    relayHeaders(*relayKey),
		MaxConnsPerHost: *maxConns,
		TLSClientConfig: upstreamTLS,
	})
	if err != nil {
		log.Fatalf("build channel manager: %v", err)
	}
	defer cm.Close()

	if *seqPath == "" {
		*seqPath = filepath.Join(shared.ConfigDir(), "seqstore.json")
	}
	store, err := tee.NewFileSeqStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	signer := proof.NewSigner(epoch)
	signer.IncludeEvidence = *includeEvidence

	// liveSigner tracks the process's current receipt signer across rotations.
	// Services built from the template below sign session-final receipts with
	// whatever it holds, so a session that outlives its opening epoch still
	// finishes under fresh evidence. Every rotation stores its adopted signer
	// here (see adopt); a stale cell only ever means the pipeline is down past
	// its margin, which the service refuses loudly instead of signing.
	liveSigner := &atomic.Pointer[proof.Signer]{}

	svcConfig := tee.Config{
		Policy:         policyDoc,
		Transport:      cm,
		Signer:         signer,
		SignerCell:     liveSigner,
		Seq:            store,
		InboxKey:       inbox,
		RequestTimeout: *requestTimeout,
	}
	// svcRuntime holds the receipt signer, which is bound to the attested epoch
	// key and is replaced whenever the platform rotates that key. The inbox key
	// above is the other, deliberately independent half: it is generated once
	// and never persisted, so a restart — not a rotation — is what makes agents
	// re-register. Handlers reach the current service through it, so a rotation
	// takes effect on the next request without dropping the listener. Building
	// the runtime publishes the startup epoch — identity and evidence — the
	// same way a rotation publishes the ones after it (see publish).
	svcRuntime, err := newServiceRuntime(svcConfig, epoch, logger)
	if err != nil {
		log.Fatalf("publish startup epoch: %v", err)
	}
	// A fixed epoch (the simulation) never rotates, so its leaf is stable and
	// pinning it is sound: publish it once for the Hub's -tee-verify=pin mode.
	// A rotating epoch (sevsnp) is verified by evidence, never by pin.
	if assembly.Refresher == nil && leafTLS != nil {
		if err := shared.WriteTEECert(leafTLS); err != nil {
			log.Fatalf("publish tee certificate: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeExecute(svcRuntime.get(), w, r)
	})
	mux.HandleFunc("/v1/session", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeSession(svcRuntime.get(), w, r)
	})
	// Credential plane: GET /v1/credential-key publishes the TEE's inbox public
	// key, which provider agents fetch (through the Hub) to encrypt their tokens
	// to. There is nothing else here — the TEE stores no token, so it has no
	// set/drop endpoints; envelopes live in the Hub's credential store and ride
	// onto each job.
	mux.HandleFunc("/v1/credential-key", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeCredentialKey(inbox, w, r)
	})
	// Evidence retrieval: serves the restart-surviving evidence store so a Hub
	// or auditor can resolve a hash-only receipt's EvidenceHash against a real
	// (possibly rotated) epoch this TEE presented. GET /v1/evidence/<hex-hash>
	// returns raw evidence bytes; GET /v1/evidence lists the stored hashes.
	evStore, err := shared.LoadEvidenceStore()
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	evidence.NewHTTPServer(evStore, mux)

	// Keep the attested epoch inside its evidence's validity for as long as this
	// process serves. The buildEpoch comment explains why the assembly carries a
	// refresher here and not on the simulated platform.
	//
	// The context is intentionally the process's, with no cancellation: the
	// refresher must run for exactly as long as the listener serves, and there is
	// no state in which stopping it early is right — a cancelled loop adopts its
	// last snapshot once and returns, leaving the epoch to age out while the
	// listener keeps answering with it. Both serving paths below end the process
	// (log.Fatal on a listener error) rather than unwinding through a shutdown
	// sequence, and swallowing SIGTERM/SIGINT to cancel here would replace the
	// default "die on signal" with "ignore signal" — a deployment hazard well
	// beyond the tidiness it would buy.
	if assembly.Refresher != nil {
		go runEpochRefresh(context.Background(), assembly.Refresher, svcRuntime, logger)
	}

	if *serveMTLS {
		log.Printf("tee (platform=%s, includeEvidence=%t, mtls) listening on https://%s",
			*platformName, *includeEvidence, *addr)
		// The three hooks below are what lets a rotation reach connections that
		// are already up: the certificate they presented belongs to the epoch
		// that accepted them, so they are stamped on arrival, refused if a
		// request reaches them from a later epoch, and closed once they fall
		// idle rather than kept alive into an epoch whose receipts they can no
		// longer be paired with.
		server := &http.Server{
			Addr:        *addr,
			Handler:     svcRuntime.conns.guard(mux),
			TLSConfig:   leafTLS,
			ConnContext: svcRuntime.conns.accept,
			ConnState:   svcRuntime.conns.track,
		}
		log.Fatal(server.ListenAndServeTLS("", ""))
	}

	log.Printf("tee (platform=%s, includeEvidence=%t) listening on http://%s",
		*platformName, *includeEvidence, *addr)
	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		// ReadHeaderTimeout drops a client that stalls in the request line or
		// headers instead of pinning a connection. ReadTimeout and WriteTimeout
		// stay zero: /v1/session hijacks its connection into a long-lived
		// WebSocket, and /v1/execute answers with an SSE stream, so neither
		// endpoint has a bounded read or write window a deadline could safely
		// describe. The execute body itself is bounded inside ServeExecute.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// requireCleartextLoopback refuses to serve the TEE's plaintext Hub-facing API
// on an address reachable beyond this host. The listener authenticates nothing
// without -mtls, so anything that can open a socket to it can submit jobs,
// spend a provider's sequence numbers out of band, and use the enclave as an
// egress proxy; keeping it on loopback is what makes that a local-only concern.
func requireCleartextLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to serve the plaintext TEE API on non-loopback address %q", addr)
}

// relayHeaders builds the headers the TEE presents when dialing the Hub's
// relay endpoint. An empty key means the Hub's relay requires none.
func relayHeaders(key string) http.Header {
	if key == "" {
		return nil
	}
	return http.Header{hub.RelayKeyHeader: {key}}
}

// upstreamTLSConfig returns the TLS trust roots for provider connections.
//
// The simulated platform loads the throwaway test CA mockprovider generates,
// keeping the local harness hermetic. sevsnp (production) uses the system
// trust store — api.openai.com and friends sign with public CAs — unless an
// explicit -ca file overrides it.
func upstreamTLSConfig(platformName, caFile string) (*tls.Config, error) {
	switch {
	case caFile != "":
		pool, err := mtls.LoadCAPath(caFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool}, nil

	case platformName == "sevsnp":
		// System trust store: the ChannelManager treats a nil TLSClientConfig
		// as platform defaults, so nil is the explicit "system roots" choice.
		return nil, nil

	default:
		pool, err := shared.LoadCAPool()
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool}, nil
	}
}
