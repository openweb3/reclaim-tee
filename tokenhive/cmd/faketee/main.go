// Command faketee is the in-memory A-layer TEE used for fast Hub business
// tests. Like cmd/tee it runs the REAL tee.Service, but instead of dialing a
// provider it answers with a fixed, deterministic SSE stream. No network and
// no real credential egress are involved, so the Hub's pricing, ledger, and
// ProviderSeq gap-detection logic can iterate in milliseconds.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/evidence"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// mockChunks is the fixed, deterministic response stream. Because it never
// changes, the TEE's StreamHash is stable and the Hub can make golden
// assertions against it.
var mockChunks = []string{
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"role":"assistant","content":"你好"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"，我是由 TokenHive 托管的"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{"content":"模拟模型，不调用任何真实大模型。"}}]}`,
	`{"id":"chatcmpl-sim1","object":"chat.completion.chunk","choices":[{"delta":{},"finish_reason":"stop"}]}`,
}

// scriptedTransport is an in-memory tee.Transport returning a fixed SSE stream.
// It lets the A-layer fake exercise the real tee.Service without a provider.
//
// To mirror the real HTTP transport's contract exactly, non-2xx "fault" codes
// are surfaced as a status code with a NIL error (the exchange completed; the
// provider simply said no), and a mid-stream disconnect is surfaced as a
// non-EOF error — which is what makes the TEE attest CompletionTruncated
// rather than CompletionFailed. This keeps the simulated path faithful to the
// genuine one so the Hub-side logic is tested against real semantics.
type scriptedTransport struct{}

// fakeHeaders mirrors what a real OpenAI-compatible upstream sends on a 200:
// the SSE content type. The 401/429 fault paths carry the JSON content type
// and a retry hint, so the harness can assert the Hub relays them verbatim.
var fakeHeaders = map[string][]string{
	"content-type": {"text/event-stream"},
}

func (scriptedTransport) Do(ctx context.Context, req tee.Request, onChunk func([]byte) error, onStart ...tee.StartFunc) (tee.Response, error) {
	fault := queryParam(req.Query, "fault")

	start := func(status uint32, headers map[string][]string) tee.Response {
		resp := tee.Response{StatusCode: status, Headers: headers}
		if len(onStart) > 0 && onStart[0] != nil {
			onStart[0](resp)
		}
		return resp
	}

	// Provider returned an error status. Like the real transport, this is NOT
	// an error from the exchange's point of view — the bytes arrived, the
	// provider just declined. The receipt records the status code.
	switch fault {
	case "401":
		return start(401, map[string][]string{"content-type": {"application/json"}}), nil
	case "429":
		return start(429, map[string][]string{
			"content-type": {"application/json"},
			"retry-after":  {"30"},
		}), nil
	}

	emit := func() error {
		for _, c := range mockChunks {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := onChunk([]byte(c)); err != nil {
				return err
			}
		}
		return nil
	}

	// Normal completion.
	if fault != "truncate" {
		start(200, fakeHeaders)
		if err := emit(); err != nil {
			return tee.Response{StatusCode: 200}, err
		}
		return tee.Response{StatusCode: 200}, nil
	}

	// Mid-stream disconnect: relay the first two chunks, then fail the
	// connection the way a dropped provider socket would. The TEE attests the
	// partial transcript as CompletionTruncated.
	start(200, fakeHeaders)
	for i, c := range mockChunks {
		if i == 2 {
			break
		}
		if err := onChunk([]byte(c)); err != nil {
			return tee.Response{StatusCode: 200}, err
		}
	}
	return tee.Response{StatusCode: 200}, &tee.StageError{
		Stage: tee.StageBody,
		Err:   errors.New("simulated provider dropped the connection mid-stream"),
	}
}

// queryParam fetches the value of a single key from an already-escaped query
// string (e.g. "fault=401&other=x"). It mirrors how the real transport hands
// the spec's raw query to the provider URL untouched.
func queryParam(query, key string) string {
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		name, val, hasVal := strings.Cut(kv, "=")
		if name == key {
			if hasVal {
				return val
			}
			return ""
		}
	}
	return ""
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "listen address")
	seqPath := flag.String("seq", "", "ProviderSeq store file (default <simdir>/seqstore.json)")
	serveMTLS := flag.Bool("mtls", false, "serve the Hub-facing API over mutual TLS (sim test certificate, demanding a Hub client certificate)")
	mtlsClientCA := flag.String("mtls-client-ca", "", "PEM CA(s) that sign Hub client certificates; empty defaults to <simdir>/hub-ca.pem (required with -mtls)")
	flag.Parse()

	if err := shared.EnsureDefaults(); err != nil {
		log.Fatalf("ensure defaults: %v", err)
	}
	if *serveMTLS {
		if err := shared.EnsureMTLSCerts(); err != nil {
			log.Fatalf("ensure mtls fixtures: %v", err)
		}
	}

	policyDoc, err := shared.LoadPolicy()
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	policyHash, err := policyDoc.Hash()
	if err != nil {
		log.Fatalf("hash policy: %v", err)
	}

	// Like the real TEE, the A-layer fake binds its loaded whitelist into the
	// simulated attestation evidence, so receipts it produces are comparable
	// to the real TEE's.
	epoch, err := simulated.NewDeploymentEpoch(policyHash)
	if err != nil {
		log.Fatalf("create sim epoch: %v", err)
	}
	if err := shared.WriteTEEIdentity(epoch.Identity()); err != nil {
		log.Fatalf("write tee identity: %v", err)
	}
	// Record the epoch in the restart-surviving evidence store so a hash-only
	// receipt (from a TEE with -evidence=false) still verifies offline. The
	// /v1/evidence endpoint serves the same store to a remote Hub.
	if err := shared.RecordTEEEvidence(epoch.Identity()); err != nil {
		log.Fatalf("record tee evidence: %v", err)
	}

	// The A-layer fake never egresses: its transport answers with canned bytes,
	// so the execution path only needs to decrypt a job's envelope. Like the real
	// TEE it stores no credential — it holds an inbox key, and each job brings its
	// provider's token sealed to it. The credential-key endpoint is served so the
	// agent-registration/one-shot sealing path can be exercised end to end.
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		log.Fatalf("generate inbox key: %v", err)
	}

	signer := proof.NewSigner(epoch)
	// Self-contained receipts so the offline verifier needs no external
	// attestation cache (see plan P0).
	signer.IncludeEvidence = true

	if *seqPath == "" {
		*seqPath = filepath.Join(shared.ConfigDir(), "seqstore.json")
	}
	store, err := tee.NewFileSeqStore(*seqPath)
	if err != nil {
		log.Fatalf("open seqstore: %v", err)
	}

	svc, err := tee.NewService(tee.Config{
		Policy:    policyDoc,
		Transport: scriptedTransport{},
		Signer:    signer,
		Seq:       store,
		InboxKey:  inbox,
	})
	if err != nil {
		log.Fatalf("build service: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/execute", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeExecute(svc, w, r)
	})
	// Credential plane, mirroring cmd/tee: agents (or one-shot tools) fetch the
	// inbox key, seal their token to it, and present the envelope on each job.
	mux.HandleFunc("/v1/credential-key", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeCredentialKey(inbox, w, r)
	})
	// Evidence retrieval, mirroring cmd/tee: serve the restart-surviving store
	// so a remote Hub or auditor resolves a hash-only receipt's EvidenceHash.
	evStore, err := shared.LoadEvidenceStore()
	if err != nil {
		log.Fatalf("open evidence store: %v", err)
	}
	evidence.NewHTTPServer(evStore, mux)

	if *serveMTLS {
		clientCAPath := *mtlsClientCA
		if clientCAPath == "" {
			clientCAPath = filepath.Join(shared.ConfigDir(), shared.MTLSClientCAPath)
		}
		serverTLS := mtls.PlatformServerTLS(epoch)
		if serverTLS == nil {
			log.Fatalf("simulated platform provides no RA-TLS server certificate; cannot serve -mtls")
		}
		cfg, err := mtls.ServerMTLSConfig(serverTLS, clientCAPath)
		if err != nil {
			log.Fatalf("mtls server config: %v", err)
		}
		if err := shared.WriteTEECert(cfg); err != nil {
			log.Fatalf("publish tee certificate: %v", err)
		}
		log.Printf("faketee (in-memory A-layer TEE, real service, mtls) listening on https://%s", *addr)
		server := &http.Server{Addr: *addr, Handler: mux, TLSConfig: cfg}
		log.Fatal(server.ListenAndServeTLS("", ""))
	}

	log.Printf("faketee (in-memory A-layer TEE, real service) listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
