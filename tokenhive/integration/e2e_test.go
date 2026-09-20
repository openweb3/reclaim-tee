package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/transport"
)

// refuseTEE is a Hub TEE seam that refuses every job. e2eStack never routes a
// dispatch through it — it exists only to satisfy hub.New's wiring requirements.
type refuseTEE struct{}

func (refuseTEE) Execute(context.Context, jobs.Spec, []byte, func([]byte) error, ...func(tee.Response)) (hub.Result, error) {
	return hub.Result{}, errUnwired
}
func (refuseTEE) OpenSession(context.Context, jobs.Spec) (hub.SessionConn, error) {
	return nil, errUnwired
}

var errUnwired = errors.New("hub TEE not wired for direct dispatch in this harness")

// memStore is a Hub receipt store that accepts everything and keeps nothing. It
// satisfies hub.New's Store requirement; no dispatch reaches it in e2eStack.
type memStore struct{}

func (memStore) Put(string, proof.SignedReceipt) error { return nil }

// executeEventually runs a job, retrying until it succeeds. The retry exists
// only to absorb the startup race between the reverse-tunnel agent dialing the
// Hub and the first job arriving: while no agent is registered yet, the Hub
// closes the relay stream and the job fails at the TLS handshake, consuming
// nothing. Once the agent is online the first attempt succeeds.
//
// A failed attempt surfaces in one of two ways: as an error (a refusal, before
// the wire) or as a Result whose StatusCode is zero (a request put on the wire
// that never got a response). Both are retried — the second because an empty
// relay handshake is indistinguishable, from the result alone, from a provider
// that is simply not reachable yet.
//
// Each attempt is a new job: the id and nonce are re-minted per try, as a Hub
// dispatch does, and spec is updated in place so the caller verifies its
// receipt against the attempt that actually ran. The enclave refuses a job ID
// it has already seen (see tee.ErrJobReplayed), so a retry that reused one
// would be the last attempt.
func executeEventually(t *testing.T, service *tee.Service, spec *jobs.Spec, body []byte,
	onChunk func([]byte) error) (*tee.Result, error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last *tee.Result
	var err error
	for {
		attempt := *spec
		attempt.JobID = randomBytes(t, jobs.JobIDLength)
		attempt.Nonce = randomBytes(t, jobs.MinNonceLength)
		*spec = attempt
		last, err = service.Execute(context.Background(), tee.Job{Spec: attempt, Body: body}, onChunk)
		if err == nil && last.StatusCode != 0 {
			return last, nil
		}
		if time.Now().After(deadline) {
			return last, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The tests in this file are the end-to-end milestone demo: every layer is the
// real implementation, including the network. The only things faked are the
// AI provider (an httptest server speaking OpenAI-style SSE) and the
// attestation epoch (a P-256 key instead of hardware evidence).
//
// The path under test, in full:
//
//	tee.Service -> transport.ChannelManager -> Hub.TeeRelay
//	          -> provider.Agent (reverse tunnel) -> mock provider
//
// The provider's access token is not provisioned into the TEE at boot. It is
// registered at runtime: the agent dials the Hub's AgentGate, fetches the
// Hub-published TEE inbox key, seals the token to it, and registers; the Hub
// stores the ciphertext envelope. The TEE holds no token — each spec in this
// test carries the envelope (as spec.Credential) that an agent registered and
// a Hub dispatcher would attach on its way out.

var e2eEvents = [][]byte{
	[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"),
	[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n"),
	[]byte("data: [DONE]\n\n"),
}

// policyFor is the deployment whitelist for the e2e path, with the host
// parameterised: the path targets a local mock provider, not api.openai.com.
func policyFor(host string) policy.Policy {
	return policy.Policy{
		Version: policy.VersionV1,
		Hosts:   []string{host},
		Rules: []policy.Rule{{
			Methods:     []string{"POST"},
			Path:        "/v1/chat/completions",
			AllowStream: true,
		}},
		Limits: policy.Limits{
			MaxResponseBytes: 1 << 20,
			MaxBodyBytes:     1 << 16,
			AllowedHeaders:   []string{"content-type"},
		},
		IssuedAt:  now.Unix() - 3600,
		ExpiresAt: now.Unix() + 3600,
	}
}

// localChatCompletion is chatCompletion pointed at the mock provider's host.
func localChatCompletion(t *testing.T, host string) (jobs.Spec, []byte) {
	t.Helper()
	spec, body := chatCompletion(t)
	spec.Host = host
	return spec, body
}

// e2eStack assembles the full reverse-tunnel outbound path around a mock
// provider and returns a service ready to execute jobs against it, plus the
// canonical-CBOR credential envelope the test must attach to every spec it
// runs (the same envelope an agent registers and a Hub attaches on dispatch).
//
// The token travels exactly as the product would: the agent dials the Hub,
// fetches the Hub-published TEE inbox key, seals the provider's secret to it,
// and registers only ciphertext; the Hub — which only ever held the envelope —
// stores it and would attach it to dispatched jobs. The test drives tee.Service
// directly (bypassing the Hub's dispatcher), so it seals its own copy of the
// secret to the same inbox key for the spec.
func e2eStack(t *testing.T, target string, srv *httptest.Server) (*tee.Service, []byte) {
	t.Helper()
	const agentSecret = "s3cret-e2e-agent"

	// ---- the TEE's insides: whitelist and inbox key. It stores no credential.
	policies := policyFor(target)
	if err := policies.Validate(); err != nil {
		t.Fatalf("deployment policy: %v", err)
	}
	inbox, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("inbox key: %v", err)
	}

	// ---- the TEE's HTTP surface, serving its inbox public key so agents can
	// fetch it. The Hub relays that key to dialing agents.
	var service *tee.Service
	teeMux := http.NewServeMux()
	teeMux.HandleFunc("/v1/credential-key", func(w http.ResponseWriter, r *http.Request) {
		tee.ServeCredentialKey(inbox, w, r)
	})
	teeSrv := httptest.NewServer(teeMux)
	t.Cleanup(teeSrv.Close)

	// ---- the Hub: reverse-tunnel endpoints plus the credential relay. Its TEE
	// seam is a stub (the test drives tee.Service directly); its credential
	// plane is the real HTTP client against the TEE server above.
	h, err := hub.New(hub.Config{
		TEE:         refuseTEE{},
		Rates:       map[string]hub.RateCard{"openai": {PerRequestMicros: 100}},
		Store:       memStore{},
		Verify:      func(proof.SignedReceipt) error { return nil },
		AgentKeys:   map[string][]byte{"openai": []byte(agentSecret)},
		Credentials: &hub.HTTPTEE{BaseURL: teeSrv.URL},
	})
	if err != nil {
		t.Fatalf("new hub: %v", err)
	}
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	hubMux := http.NewServeMux()
	hubMux.Handle("/v1/agent", h.AgentGate(upgrader))
	hubMux.Handle("/v1/relay", h.TeeRelay(upgrader))
	hubMux.HandleFunc("/v1/credential-key", h.CredentialKeyHandler)
	hubSrv := httptest.NewServer(hubMux)
	t.Cleanup(hubSrv.Close)
	hubWS := "ws" + strings.TrimPrefix(hubSrv.URL, "http")

	// ---- the contributor's machine: an agent that dials the Hub, registers
	// the provider's token (sealed to the TEE inbox key it fetches through the
	// Hub), and relays only to the mock provider.
	agent, err := provider.NewAgent(provider.AgentConfig{
		HubGateURL:     hubWS + "/v1/agent",
		SharedKey:      []byte(agentSecret),
		Self:           hub.AgentRegister{Provider: "openai"},
		Credential:     tee.Secret{Token: "sk-e2e-secret", Header: "authorization", Scheme: "Bearer"},
		AllowedTargets: []string{target},
	})
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	t.Cleanup(stopAgent)
	go func() { _ = agent.Run(agentCtx) }()

	// ---- the TEE's connection-resident data path, egressing through the Hub's
	// TeeRelay and the agent's reverse tunnel. The provider name on the job
	// ("openai") must match the registered agent's, which is how the Hub routes
	// the stream. Built after the Hub server exists so the relay URL is known;
	// the agent dials in on its own reconnect loop.
	outbound, err := transport.NewChannelManager(transport.ChannelConfig{
		Scheme:         "http",
		AllowPlaintext: true,
		RelayURL:       hubWS + "/v1/relay",
	})
	if err != nil {
		t.Fatalf("new transport: %v", err)
	}
	t.Cleanup(func() { _ = outbound.Close() })

	service, err = tee.NewService(tee.Config{
		Policy:    &policies,
		Transport: outbound,
		Signer:    proof.NewSigner(newEpoch(t)),
		Clock:     func() time.Time { return now },
		Seq:       tee.NewMemorySeqStore(),
		InboxKey:  inbox,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	// The credential the tests must carry on their specs, sealed to the same
	// inbox key the agent registered against.
	env, err := tee.EncryptCredential(inbox.Public(), "openai",
		tee.Secret{Token: "sk-e2e-secret", Header: "authorization", Scheme: "Bearer"})
	if err != nil {
		t.Fatalf("seal e2e credential: %v", err)
	}
	cred, err := env.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode e2e credential: %v", err)
	}

	// Egress readiness is a race between the agent's reverse-tunnel dial and the
	// first job: until the agent's tunnel is routed by the Hub, the job fails at
	// the relay handshake (consuming nothing). executeEventually absorbs it.
	return service, cred
}

// TestEndToEndSSEThroughProviderAgent runs one chat completion through every
// real layer and checks the receipt from the verifier's side: signature, spec
// hash, transcript, completion, and the absence of the credential from the
// proof.
func TestEndToEndSSEThroughProviderAgent(t *testing.T) {
	var sawAuth atomic.Value
	var sawBody atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("mock provider read body: %v", err)
		}
		sawAuth.Store(r.Header.Get("Authorization"))
		sawBody.Store(string(body))

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for _, event := range e2eEvents {
			_, _ = w.Write(event)
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	service, cred := e2eStack(t, target, srv)
	spec, body := localChatCompletion(t, target)
	spec.Credential = cred

	var relayed [][]byte
	result, err := executeEventually(t, service, &spec, body, func(chunk []byte) error {
		relayed = append(relayed, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}

	// The credential crossed the agent's tunnel and arrived as its registered
	// shape described it. This mock runs plain HTTP, so the agent's relay
	// would have shown any tampering (or the missing credential) as-is.
	if got, _ := sawAuth.Load().(string); got != "Bearer sk-e2e-secret" {
		t.Errorf("provider saw Authorization %q", got)
	}
	if got, _ := sawBody.Load().(string); got != string(body) {
		t.Errorf("provider saw body %q, want %q", got, string(body))
	}

	// The stream was relayed as it arrived, not buffered and dumped.
	if len(relayed) < 2 {
		t.Errorf("got %d relayed chunks, want the SSE events as they arrive", len(relayed))
	}
	var transcript bytes.Buffer
	for _, chunk := range relayed {
		transcript.Write(chunk)
	}
	var want bytes.Buffer
	for _, event := range e2eEvents {
		want.Write(event)
	}
	if !bytes.Equal(transcript.Bytes(), want.Bytes()) {
		t.Errorf("relayed transcript diverges from what the provider sent")
	}

	// Verifier's side: signature first, then the hash comparisons.
	encoded, err := result.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	verified, err := proof.DecodeAndVerify(encoded, proof.VerifyOptions{
		Now:              now.Add(time.Minute),
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		MaxAge:           time.Hour,
	})
	if err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !covers(verified.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
	if !verified.Receipt.MatchesStream(relayed) {
		t.Fatal("receipt does not cover the relayed transcript")
	}
	if verified.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %v, want complete", verified.Receipt.Completion)
	}
	if verified.Receipt.ChunkCount != uint64(len(relayed)) {
		t.Errorf("receipt chunk count = %d, relayed = %d", verified.Receipt.ChunkCount, len(relayed))
	}
	if bytes.Contains(encoded, []byte("sk-e2e-secret")) {
		t.Fatal("credential leaked into the receipt")
	}
}

// TestEndToEndMidStreamDisconnect runs the same path with a provider that
// drops the connection mid-transcript. The service must return a result (not
// an error) whose receipt attests a truncated exchange — this is the evidence
// a Hub needs in order not to charge for a response that never finished.
func TestEndToEndMidStreamDisconnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write(e2eEvents[0])
		flusher.Flush()
		// Drop with the transcript unfinished: no further events, no clean
		// terminator, through the agent's tunnel like any real outage.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	service, cred := e2eStack(t, target, srv)
	spec, body := localChatCompletion(t, target)
	spec.Credential = cred

	var relayed [][]byte
	result, err := executeEventually(t, service, &spec, body, func(chunk []byte) error {
		relayed = append(relayed, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute returned %v; a mid-flight failure must arrive as a result with a receipt", err)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	if !result.Truncated {
		t.Error("result does not report truncation")
	}
	if len(relayed) == 0 {
		t.Error("nothing was relayed before the disconnect")
	}

	// The receipt for a failed exchange is worth exactly as much as one for a
	// success — it must verify and cover the job either way.
	if err := proof.Verify(result.Receipt, proof.VerifyOptions{
		Now:    now.Add(time.Minute),
		MaxAge: time.Hour,
	}); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	if !covers(result.Receipt.Receipt, spec) {
		t.Fatal("receipt does not cover the executed spec")
	}
	if !result.Receipt.Receipt.MatchesStream(relayed) {
		t.Fatal("receipt does not cover the partial transcript")
	}
}
