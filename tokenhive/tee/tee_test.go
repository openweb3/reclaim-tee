package tee

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// baseTime pins the clock for every test. Receipt timestamps are signed, so a
// moving clock would make assertions about them unwritable.
var baseTime = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// testEpoch stands in for an attested key epoch. It exercises the real
// signature path — platform.SigningDigest and ECDSA over P-256 — so a receipt
// it produces verifies exactly like one from a real enclave. What it fakes is
// only the attestation hardware.
type testEpoch struct {
	key      *ecdsa.PrivateKey
	identity platform.Identity
}

func newTestEpoch(t *testing.T) *testEpoch {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	evidence := []byte("synthetic sev-snp attestation report")

	return &testEpoch{
		key: key,
		identity: platform.Identity{
			Platform:        "sev-snp",
			AttestationType: "sevsnp-vtpm",
			ApplicationID:   "tokenhive-tee-test",
			Evidence:        evidence,
			EvidenceHash:    sha256.Sum256(evidence),
			PublicKeyDER:    publicKeyDER,
			KeyID:           sha256.Sum256(publicKeyDER),
		},
	}
}

func (e *testEpoch) Identity() platform.Identity { return platform.CloneIdentity(e.identity) }

func (e *testEpoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := ecdsa.SignASN1(rand.Reader, e.key, digest[:])
	if err != nil {
		return platform.Signature{}, err
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.identity.KeyID,
		Value:     value,
	}, nil
}

// fakeTransport is a scripted provider. It records what it was asked to send
// so that tests can assert on the exact bytes that would have carried the
// credential, and it can be told to fail partway through a stream.
type fakeTransport struct {
	mu       sync.Mutex
	requests []Request

	statusCode uint32
	headers    map[string][]string
	chunks     [][]byte

	// failAfter is the number of chunks to deliver before failing with err.
	// Negative means deliver everything.
	failAfter int
	err       error

	// afterStart, when non-nil, makes Do fire the response start and then
	// return it as the error before delivering any chunk: a connection that
	// died after its headers arrived but before its first body byte.
	afterStart error
}

func (f *fakeTransport) Do(_ context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	chunks := f.chunks
	statusCode := f.statusCode
	headers := f.headers
	failAfter := f.failAfter
	scriptedErr := f.err
	afterStart := f.afterStart
	f.mu.Unlock()

	resp := Response{StatusCode: statusCode, Headers: headers}
	// The response start is reported as soon as the headers are parsed, before
	// any chunk — the same ordering the real transport honours. A failAfter-0
	// scripted failure models a connection that died before its response
	// headers arrived, so no start is emitted then; afterStart models the
	// opposite — headers arrived, and the body read then failed.
	if statusCode != 0 && !(failAfter == 0 && scriptedErr != nil) && len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	if afterStart != nil {
		return resp, afterStart
	}
	// failAfter counts chunks delivered before the failure, so the limit is
	// checked before delivering rather than after.
	for i, chunk := range chunks {
		if failAfter >= 0 && i >= failAfter {
			return resp, scriptedErr
		}
		if onChunk != nil {
			if err := onChunk(chunk); err != nil {
				return resp, err
			}
		}
	}
	// Covers failing before the first chunk (failAfter 0) and failing after the
	// last one (failAfter == len(chunks)).
	if failAfter >= 0 && failAfter <= len(chunks) {
		return resp, scriptedErr
	}
	return resp, nil
}

func (f *fakeTransport) sent() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

func (f *fakeTransport) lastRequest(t *testing.T) Request {
	t.Helper()
	requests := f.sent()
	if len(requests) == 0 {
		t.Fatal("transport was never called")
	}
	return requests[len(requests)-1]
}

// newInbox builds a fresh credential inbox key for the test service.
func newInbox(t *testing.T) *InboxKey {
	t.Helper()
	inbox, err := GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	return inbox
}

// testEnv is a fully wired service plus the pieces tests need to poke at.
type testEnv struct {
	service   *Service
	transport *fakeTransport
	inbox     *InboxKey
	secret    Secret
	policy    policy.Policy
	epoch     *testEpoch
}

type envOption func(*Config)

// newTestEnv assembles a service that authorises POST /v1/chat/completions on
// api.openai.com and streams two chunks back. Like the real TEE it stores no
// credential: it holds an inbox key, and each spec brings the provider's token
// sealed to it (see spec).
func newTestEnv(t *testing.T, opts ...envOption) *testEnv {
	t.Helper()

	doc := defaultPolicy()
	if err := doc.Validate(); err != nil {
		t.Fatalf("default test policy: %v", err)
	}

	inbox := newInbox(t)

	transport := &fakeTransport{
		statusCode: 200,
		chunks:     [][]byte{[]byte("event: a\n\n"), []byte("event: b\n\n")},
		failAfter:  -1,
	}

	epoch := newTestEpoch(t)

	cfg := Config{
		Policy:    &doc,
		Transport: transport,
		Signer:    proof.NewSigner(epoch),
		Clock:     func() time.Time { return baseTime },
		Seq:       NewMemorySeqStore(),
		InboxKey:  inbox,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	return &testEnv{
		service:   service,
		transport: transport,
		inbox:     inbox,
		secret:    Secret{Token: "sk-test-credential", Header: "authorization", Scheme: "Bearer"},
		policy:    *cfg.Policy,
		epoch:     epoch,
	}
}

// setSecret swaps the credential the next spec carries. Sealing happens at spec
// build time, so call it before spec and rebuild the spec afterwards.
func (e *testEnv) setSecret(s Secret) { e.secret = s }

// spec builds a spec for the policy the helpers install by default, carrying
// the test credential sealed to the inbox — the same envelope a provider agent
// registers and the Hub attaches to a job.
func (e *testEnv) spec(t *testing.T, body []byte) jobs.Spec {
	t.Helper()

	spec := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            randomBytes(t, jobs.JobIDLength),
		Provider:         "openai",
		Model:            "gpt-4o",
		Method:           "POST",
		Host:             "api.openai.com",
		Path:             "/v1/chat/completions",
		Headers:          map[string]string{"content-type": "application/json"},
		BodyHash:         slice32(jobs.HashBody(body)),
		Nonce:            randomBytes(t, jobs.MinNonceLength),
		ExpiresAt:        baseTime.Add(5 * time.Minute).Unix(),
		MaxResponseBytes: 1 << 20,
		Stream:           true,
	}
	if e.secret.Header != "" {
		spec.Credential = e.sealed(t)
	}
	return spec
}

// sealed returns the canonical-CBOR envelope now registered for the test
// credential, as it would appear inside jobs.Spec.Credential.
func (e *testEnv) sealed(t *testing.T) []byte {
	t.Helper()
	env, err := EncryptCredential(e.inbox.Public(), "openai", e.secret)
	if err != nil {
		t.Fatalf("seal credential: %v", err)
	}
	enc, err := env.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode credential: %v", err)
	}
	return enc
}

// specNoCredential builds a spec that will be refused for carrying no sealed
// credential — the job a provider gets when the Hub failed to attach one.
func (e *testEnv) specNoCredential(t *testing.T, body []byte) jobs.Spec {
	spec := e.spec(t, body)
	spec.Credential = nil
	return spec
}

// defaultPolicy is the baseline every test starts from: one streaming chat
// completions rule. The credential's injection shape is no longer part of the
// policy — it travels with the token and lives in the TEE's credential store
// (see Secret) — so the policy is purely the whitelist.
func defaultPolicy() policy.Policy {
	return policy.Policy{
		Version: policy.VersionV1,
		Hosts:   []string{"api.openai.com"},
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
		IssuedAt:  baseTime.Add(-time.Hour).Unix(),
		ExpiresAt: baseTime.Add(time.Hour).Unix(),
	}
}

// withPolicy builds the test service under a policy derived from the default
// one. The deployment whitelist is fixed when the enclave is configured and
// never changes afterwards, so a test that needs different rules configures a
// different enclave instead of rotating one underneath a running service.
func withPolicy(mutate func(*policy.Policy)) envOption {
	return func(cfg *Config) {
		next := defaultPolicy()
		mutate(&next)
		cfg.Policy = &next
	}
}

func slice32(digest [32]byte) []byte { return digest[:] }

func randomBytes(t *testing.T, length int) []byte {
	t.Helper()
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return out
}

// verifyReceipt runs the full check a verifier performs: signature first, then
// the hash comparison that ties the receipt to a particular job.
func verifyReceipt(t *testing.T, signed proof.SignedReceipt, spec jobs.Spec) {
	t.Helper()

	if err := proof.Verify(signed, proof.VerifyOptions{Now: baseTime.Add(time.Minute)}); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
	specHash, err := spec.Hash()
	if err != nil {
		t.Fatalf("hash spec: %v", err)
	}
	if !bytes.Equal(signed.Receipt.JobSpecHash, specHash[:]) {
		t.Fatal("receipt does not cover the executed spec")
	}
}

// TestExecuteHappyPath runs a streamed job end to end and checks that the
// receipt attests to precisely what happened: the spec that ran, the policy
// that allowed it, and the bytes that came back.
func TestExecuteHappyPath(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	var received [][]byte
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, func(chunk []byte) error {
		received = append(received, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result == nil {
		t.Fatal("no result")
	}

	if len(received) != 2 {
		t.Fatalf("relayed %d chunks, want 2", len(received))
	}
	if result.Receipt.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %v, want complete", result.Receipt.Receipt.Completion)
	}
	if result.Truncated {
		t.Fatal("stream reported as truncated")
	}
	if result.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", result.StatusCode)
	}
	if result.ChunkCount != 2 {
		t.Fatalf("chunk count = %d, want 2", result.ChunkCount)
	}

	verifyReceipt(t, result.Receipt, spec)

	// The digest must match the transcript the caller actually received, not
	// merely be well-formed.
	if !result.Receipt.Receipt.MatchesStream(received) {
		t.Fatal("receipt does not cover the relayed transcript")
	}

	// The policy revision that authorised the spend must be named, or a
	// provider cannot audit what rules were in force.
	if len(result.PolicyHash) != 32 {
		t.Fatalf("policy hash length = %d, want 32", len(result.PolicyHash))
	}
}

// TestExecuteAttestsTheModel pins the model into the receipt. The Hub prices a
// job — flat fee plus the model premium — by the model it declared for it, so
// the receipt has to name that model or the charge can never be reconciled
// against the provider's own upstream bill.
func TestExecuteAttestsTheModel(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o-mini"}`)
	spec := env.spec(t, body)
	spec.Model = "gpt-4o-mini"

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := result.Receipt.Receipt.Model; got != "gpt-4o-mini" {
		t.Fatalf("receipt model = %q, want %q", got, "gpt-4o-mini")
	}
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteRefusesAnUnusableModelName checks the declared model is bounded and
// control-free before any work is spent: it is signed into a receipt and written
// to a log line, so a model that could forge structure in either must not be
// dispatchable.
func TestExecuteRefusesAnUnusableModelName(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	spec.Model = strings.Repeat("m", jobs.MaxModelLength+1)

	if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); !errors.Is(err, jobs.ErrInvalidModel) {
		t.Fatalf("error = %v, want %v", err, jobs.ErrInvalidModel)
	}
}

// TestExecuteAttestsResponseStart pins the response-start half of the new
// protocol: the onStart callback fires exactly once, before the first chunk,
// with the upstream status and only the allowlisted headers; the receipt binds
// that exact start via ResponseHeadersHash; and a header outside the allowlist
// never reaches the callback or the digest.
func TestExecuteAttestsResponseStart(t *testing.T) {
	env := newTestEnv(t)
	env.transport.headers = map[string][]string{
		"Content-Type": {"text/event-stream"},
		"Retry-After":  {"30"},
		"Set-Cookie":   {"session=secret"},
	}

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	var (
		started    []Response
		firstChunk bool
		chunks     int
	)
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body},
		func(chunk []byte) error {
			chunks++
			if len(started) == 0 {
				firstChunk = true
			}
			return nil
		},
		func(resp Response) {
			started = append(started, resp)
		})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Exactly one start, delivered before the first chunk, with the status and
	// only the allowlisted headers.
	if len(started) != 1 {
		t.Fatalf("onStart fired %d times, want 1", len(started))
	}
	if firstChunk {
		t.Fatal("a chunk arrived before the response start")
	}
	if started[0].StatusCode != 200 {
		t.Fatalf("start status = %d, want 200", started[0].StatusCode)
	}
	if _, ok := started[0].Headers["Set-Cookie"]; ok {
		t.Fatal("a non-allowlisted header reached the start callback")
	}
	if got := started[0].Headers["Content-Type"]; len(got) != 1 || got[0] != "text/event-stream" {
		t.Errorf("start content-type = %v, want [text/event-stream]", got)
	}
	if got := started[0].Headers["Retry-After"]; len(got) != 1 || got[0] != "30" {
		t.Errorf("start retry-after = %v, want [30]", got)
	}

	// The receipt binds the start: the signed hash must equal the digest of
	// the forwarded (allowlisted) set, and differ from a digest that included
	// the filtered header.
	want := HashResponseHeaders(ForwardResponseHeaders(env.transport.headers))
	if !bytes.Equal(result.Receipt.Receipt.ResponseHeadersHash, want[:]) {
		t.Fatal("receipt does not bind the forwarded response headers")
	}
	unfiltered := HashResponseHeaders(env.transport.headers)
	if bytes.Equal(result.Receipt.Receipt.ResponseHeadersHash, unfiltered[:]) {
		t.Fatal("receipt binds headers that were never forwarded")
	}

	// A receipt with a start must still verify end to end.
	verifyReceipt(t, result.Receipt, spec)
	if chunks != 2 {
		t.Fatalf("relayed %d chunks, want 2", chunks)
	}
}

// TestExecuteSignsNoResponseStartWhenNothingArrived pins the complement: an
// exchange that never produced a response has no start to attest, so the
// receipt carries no ResponseHeadersHash at all.
func TestExecuteSignsNoResponseStartWhenNothingArrived(t *testing.T) {
	env := newTestEnv(t)
	env.transport.chunks = nil
	env.transport.failAfter = 0
	env.transport.err = errors.New("connection refused")

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil,
		func(Response) { t.Fatal("no response means no start frame") })
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionFailed {
		t.Fatalf("completion = %v, want failed", result.Receipt.Receipt.Completion)
	}
	if len(result.Receipt.Receipt.ResponseHeadersHash) != 0 {
		t.Fatal("failed exchange carries a response headers hash")
	}
}

// TestExecuteInjectsCredential asserts the registered secret reaches the wire
// exactly as its header/scheme describe, and that the caller's own headers
// survive alongside it.
func TestExecuteInjectsCredential(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err != nil {
		t.Fatalf("execute: %v", err)
	}

	sent := env.transport.lastRequest(t)
	if got := sent.Headers["authorization"]; got != "Bearer sk-test-credential" {
		t.Fatalf("authorization = %q, want %q", got, "Bearer sk-test-credential")
	}
	if got := sent.Headers["content-type"]; got != "application/json" {
		t.Fatalf("content-type = %q, want the caller's header preserved", got)
	}
	if sent.Method != "POST" || sent.Host != "api.openai.com" || sent.Path != "/v1/chat/completions" {
		t.Fatalf("request = %s %s%s, want the spec's target", sent.Method, sent.Host, sent.Path)
	}
	if !bytes.Equal(sent.Body, body) {
		t.Fatal("request body was altered in flight")
	}
}

// TestCredentialIsAbsentFromTheReceipt is the property the whole TEE exists
// for. The receipt is published to the Hub and to auditors; if the secret ever
// reached it, isolation would be theatre.
func TestCredentialIsAbsentFromTheReceipt(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	encoded, err := result.Receipt.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	if bytes.Contains(encoded, []byte("sk-test-credential")) {
		t.Fatal("receipt contains the provider credential")
	}
}

// TestExecuteRejectsBodyMismatch guards against a job carrying a body it does
// not describe. Every other check would pass — the spec is well formed, the
// policy allows the route — which is exactly why this has to be checked
// separately.
func TestExecuteRejectsBodyMismatch(t *testing.T) {
	env := newTestEnv(t)
	spec := env.spec(t, []byte(`{"model":"gpt-4o"}`))

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: []byte(`{"model":"evil"}`)}, nil)
	if !errors.Is(err, ErrBodyMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrBodyMismatch)
	}
	if result != nil {
		t.Fatal("refused job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("refused job reached the transport")
	}
}

// TestExecuteRejectsPolicyViolation asserts that a route the policy never
// listed cannot be reached, and that refusing costs no network traffic — a
// rejected job must not even dial the provider.
func TestExecuteRejectsPolicyViolation(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	spec.Path = "/v1/account/billing"

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, policy.ErrPathNotAllowed) {
		t.Fatalf("error = %v, want %v", err, policy.ErrPathNotAllowed)
	}
	if result != nil {
		t.Fatal("refused job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("policy refusal still sent a request")
	}
}

// TestExecuteSignsAFailedExchange is the reason failures are attested at all.
// A Hub holding this receipt can prove the provider never answered, which is
// what stops it charging for a response it did not get.
func TestExecuteSignsAFailedExchange(t *testing.T) {
	env := newTestEnv(t)
	env.transport.chunks = nil
	env.transport.failAfter = 0
	env.transport.err = errors.New("connection refused")

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("a failed exchange is not an error to surface: %v", err)
	}
	if result == nil {
		t.Fatal("failed exchange produced no receipt")
	}
	if result.Receipt.Receipt.Completion != proof.CompletionFailed {
		t.Fatalf("completion = %v, want failed", result.Receipt.Receipt.Completion)
	}
	if result.ResponseBytes != 0 || result.ChunkCount != 0 {
		t.Fatalf("counted %d chunks / %d bytes for an exchange that produced none",
			result.ChunkCount, result.ResponseBytes)
	}
	if result.StatusCode != 0 {
		t.Fatalf("status = %d, want 0 when no response arrived", result.StatusCode)
	}

	// The receipt is only useful if it verifies.
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteSignsATruncatedStream covers the mid-stream drop: bytes arrived,
// then the provider stopped. The receipt must describe the partial transcript
// rather than declaring success or claiming nothing happened.
func TestExecuteSignsATruncatedStream(t *testing.T) {
	env := newTestEnv(t)
	env.transport.chunks = [][]byte{[]byte("event: a\n\n"), []byte("event: b\n\n"), []byte("event: c\n\n")}
	env.transport.failAfter = 2
	env.transport.err = errors.New("connection reset")

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	var received [][]byte
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, func(chunk []byte) error {
		received = append(received, append([]byte(nil), chunk...))
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	if !result.Truncated {
		t.Fatal("result not marked truncated")
	}
	if len(received) != 2 {
		t.Fatalf("relayed %d chunks, want the 2 that arrived", len(received))
	}
	if !result.Receipt.Receipt.MatchesStream(received) {
		t.Fatal("receipt does not cover the partial transcript")
	}
	// The status is real: the provider did answer before dropping the stream.
	if result.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 preserved across a mid-stream failure", result.StatusCode)
	}
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteKeepsTheStatusOnceTheStartArrived pins the case where the
// response start was relayed but the body read failed before yielding a byte:
// the receipt must still attest the start's real status and headers (and call
// the exchange truncated), or the Hub would reject it as contradicting the
// start frame it was shown.
func TestExecuteKeepsTheStatusOnceTheStartArrived(t *testing.T) {
	env := newTestEnv(t)
	env.transport.afterStart = errors.New("connection reset after headers")

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	var starts int
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil,
		func(resp Response) {
			starts++
			if resp.StatusCode != 200 {
				t.Errorf("start status = %d, want 200", resp.StatusCode)
			}
		})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if starts != 1 {
		t.Fatalf("onStart fired %d times, want 1", starts)
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200 preserved once the response started", result.StatusCode)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Errorf("completion = %v, want truncated (headers arrived, body did not)", result.Receipt.Receipt.Completion)
	}
	if len(result.Receipt.Receipt.ResponseHeadersHash) == 0 {
		t.Error("receipt must still bind the start's headers")
	}
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteEnforcesTheResponseCap asserts the size limit is applied by the
// service, not merely requested of the transport. A transport that ignored the
// cap would otherwise be able to make the TEE attest to an unbounded response.
func TestExecuteEnforcesTheResponseCap(t *testing.T) {
	// The policy would allow 10 bytes; the job asks for 8. The stricter of the
	// two governs, so the cap in force is 8.
	env := newTestEnv(t, withPolicy(func(p *policy.Policy) {
		p.Limits.MaxResponseBytes = 10
	}))

	env.transport.chunks = [][]byte{
		[]byte("1234"),
		[]byte("5678"),
		[]byte("90123456"),
	}

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	spec.MaxResponseBytes = 8

	var relayed int
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, func(chunk []byte) error {
		relayed += len(chunk)
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	if relayed != 8 {
		t.Fatalf("relayed %d bytes, want exactly the 8 the job allowed", relayed)
	}

	// Bytes past the cap are still counted rather than trimmed to fit: the
	// receipt reports what arrived, so a verifier can see both the overflow
	// and the truncation.
	if result.ResponseBytes != 16 {
		t.Fatalf("response bytes = %d, want 16 (everything that arrived)", result.ResponseBytes)
	}
	if result.ChunkCount != 3 {
		t.Fatalf("chunk count = %d, want 3", result.ChunkCount)
	}
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteMarksTruncationWhenTheConsumerStops covers the case where the
// provider streamed fine but the caller stopped accepting it. The transcript is
// partial from the caller's point of view, and saying so is the honest thing to
// sign.
func TestExecuteMarksTruncationWhenTheConsumerStops(t *testing.T) {
	env := newTestEnv(t)
	env.transport.chunks = [][]byte{[]byte("aaaa"), []byte("bbbb"), []byte("cccc")}

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	stop := errors.New("consumer gone")
	var seen int
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, func(chunk []byte) error {
		seen++
		if seen == 2 {
			return stop
		}
		return nil
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.Truncated {
		t.Fatal("consumer stopping did not mark the result truncated")
	}
	if result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %v, want truncated", result.Receipt.Receipt.Completion)
	}
	// The chunk that was refused still entered the digest: the provider did
	// send it, and the receipt describes the provider's behaviour, not the
	// consumer's appetite.
	if result.ChunkCount != 2 || result.ResponseBytes != 8 {
		t.Fatalf("counted %d chunks / %d bytes, want 2 / 8", result.ChunkCount, result.ResponseBytes)
	}
	verifyReceipt(t, result.Receipt, spec)
}

// TestExecuteRefusesCredentialClash covers a job that occupies the header the
// credential belongs in.
//
// jobs.Validate already rejects the reserved headers, so with the default
// "authorization" credential this is unreachable from outside. It is reachable
// when a provider uses a header of its own — Anthropic's x-api-key, say — and
// then the only thing standing between the caller and a forged identity is
// this check. Overwriting silently would turn the guard into a no-op.
func TestExecuteRefusesCredentialClash(t *testing.T) {
	// The registered secret occupies x-api-key (a raw-key provider like
	// Anthropic), which the whitelist also lets callers set. A job that sets it
	// itself must be refused: silently overwriting would turn the guard into a
	// no-op and let a caller forge the provider's identity.
	env := newTestEnv(t, withPolicy(func(p *policy.Policy) {
		p.Limits.AllowedHeaders = []string{"content-type", "x-api-key"}
	}))
	env.setSecret(Secret{Token: "sk-test-credential", Header: "x-api-key"})

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	spec.Headers = map[string]string{
		"content-type": "application/json",
		"x-api-key":    "caller-supplied",
	}

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrCredentialClash) {
		t.Fatalf("error = %v, want %v", err, ErrCredentialClash)
	}
	if result != nil {
		t.Fatal("clashing job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("clashing job reached the transport")
	}
}

// TestCredentialHeaderScheme covers the two shapes a registered secret may
// declare: a prefixed "Bearer <token>" on the authorization header, and a raw
// token that is the whole header value (e.g. Anthropic's x-api-key). The shape
// is part of the secret the agent registered, not of the policy.
func TestCredentialHeaderScheme(t *testing.T) {
	t.Run("bearer on authorization", func(t *testing.T) {
		env := newTestEnv(t)
		body := []byte(`{"model":"gpt-4o"}`)
		spec := env.spec(t, body)
		if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := env.transport.lastRequest(t).Headers["authorization"]; got != "Bearer sk-test-credential" {
			t.Fatalf("authorization = %q", got)
		}
	})

	t.Run("raw key on x-api-key", func(t *testing.T) {
		env := newTestEnv(t)
		env.setSecret(Secret{Token: "sk-test-credential", Header: "x-api-key"})

		body := []byte(`{"model":"gpt-4o"}`)
		spec := env.spec(t, body)
		if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err != nil {
			t.Fatalf("execute: %v", err)
		}
		// No scheme in the registered secret, so the token is the whole header.
		if got := env.transport.lastRequest(t).Headers["x-api-key"]; got != "sk-test-credential" {
			t.Fatalf("x-api-key = %q, want the bare secret", got)
		}
	})
}

// TestExecuteRejectsAnUnsafeSecret guards against a registered token carrying
// CRLF being spliced into the header block, which would let whoever controls
// the token append headers of their own. Secrets are validated at registration
// (Secret.Validate); this asserts the execution path still refuses one that
// bypassed registration (a test store seeded directly).
func TestExecuteRejectsAnUnsafeSecret(t *testing.T) {
	env := newTestEnv(t)
	env.setSecret(Secret{Token: "sk-good\r\nX-Injected: yes", Header: "authorization", Scheme: "Bearer"})

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidSecret)
	}
	if result != nil {
		t.Fatal("job with an unsafe secret produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("unsafe secret reached the wire")
	}
}

// TestExecuteWithoutCredential asserts that a policy admission is not by itself
// enough: with no secret loaded there is nothing to authenticate with, and the
// job must not go out unauthenticated.
func TestExecuteWithoutCredential(t *testing.T) {
	env := newTestEnv(t)

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.specNoCredential(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("error = %v, want %v", err, ErrNoCredential)
	}
	if result != nil {
		t.Fatal("credential-less job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("job went out without a credential")
	}
}

// TestSecretValidateAndRender pins the registration-time shape checks: what
// may enter the store (Secret.Validate) and what lands on the wire (Render).
func TestSecretValidateAndRender(t *testing.T) {
	// No header + no token means no authentication, which is valid.
	if err := (Secret{}).Validate(); err != nil {
		t.Fatalf("empty secret should mean no auth: %v", err)
	}

	// A declared header must carry a token; token and scheme need a header.
	for _, bad := range []Secret{
		{Header: "authorization"},
		{Token: "sk-x"},
		{Scheme: "Bearer"},
		{Token: "sk-x", Scheme: "Bearer"},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("secret %+v: error = %v, want %v", bad, err, ErrInvalidSecret)
		}
	}

	// Header names that would tamper with framing are refused.
	for _, name := range []string{"", "host", "content-length", "x api key", "x\r\nevil"} {
		if err := (Secret{Token: "sk-x", Header: name}).Validate(); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("header %q: error = %v", name, err)
		}
	}

	// Tokens must not carry control characters or surrounding whitespace.
	for _, token := range []string{"", "sk-\r\nx-evil: 1", "sk-\n", "sk-\x00", " sk-x "} {
		if err := (Secret{Token: token, Header: "authorization"}).Validate(); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("token %q: error = %v", token, err)
		}
	}

	// Render turns the validated shape into wire headers.
	s := Secret{Token: "sk-x", Header: "authorization", Scheme: "Bearer"}
	if name, value, err := s.Render(); err != nil || name != "authorization" || value != "Bearer sk-x" {
		t.Fatalf("render = (%q, %q, %v)", name, value, err)
	}
	raw := Secret{Token: "secret", Header: "x-api-key"}
	if name, value, err := raw.Render(); err != nil || name != "x-api-key" || value != "secret" {
		t.Fatalf("raw render = (%q, %q, %v)", name, value, err)
	}
}

// TestExecuteRejectsExpiredJob pins the freshness check to the injected clock
// rather than wall time.
func TestExecuteRejectsExpiredJob(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	spec.ExpiresAt = baseTime.Add(-time.Minute).Unix()

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, jobs.ErrExpired) {
		t.Fatalf("error = %v, want %v", err, jobs.ErrExpired)
	}
	if result != nil {
		t.Fatal("expired job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("expired job reached the transport")
	}
}

// TestExecuteRejectsOversizedBody checks the request-side cap. It is the
// counterpart to the response cap and equally easy to forget.
func TestExecuteRejectsOversizedBody(t *testing.T) {
	env := newTestEnv(t, withPolicy(func(p *policy.Policy) {
		p.Limits.MaxBodyBytes = 4
	}))

	body := []byte(`{"model":"gpt-4o","messages":[]}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error = %v, want %v", err, ErrBodyTooLarge)
	}
	if result != nil {
		t.Fatal("oversized job produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("oversized body reached the transport")
	}
}

// TestExecuteRejectsJobOverPolicyCap is the mirror of the truncation test: a job
// asking for more than the provider allows is refused outright rather than
// quietly capped, because a Hub that wants a megabyte when ten bytes were
// offered is not a job the policy meant to permit.
func TestExecuteRejectsJobOverPolicyCap(t *testing.T) {
	env := newTestEnv(t, withPolicy(func(p *policy.Policy) {
		p.Limits.MaxResponseBytes = 10
	}))

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	// testSpec defaults to 1 MiB, well past the 10 byte policy cap.

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, policy.ErrLimitExceeded) {
		t.Fatalf("error = %v, want %v", err, policy.ErrLimitExceeded)
	}
	if result != nil {
		t.Fatal("job over the policy cap produced a receipt")
	}
	if len(env.transport.sent()) != 0 {
		t.Fatal("job over the policy cap reached the transport")
	}
}

// TestServiceRequiresConfiguration asserts a half-built service cannot be
// constructed. Each of these missing pieces would otherwise fail on the first
// job, at which point the mistake is much harder to attribute.
func TestServiceRequiresConfiguration(t *testing.T) {
	complete := func() Config {
		doc := defaultPolicy()
		return Config{
			Policy:    &doc,
			Transport: &fakeTransport{failAfter: -1},
			Signer:    proof.NewSigner(newTestEpoch(t)),
			Seq:       NewMemorySeqStore(),
			InboxKey:  newInbox(t),
		}
	}

	cases := []struct {
		name string
		want error
		edit func(*Config)
	}{
		{"no policy", ErrNoPolicy, func(c *Config) { c.Policy = nil }},
		{"no inbox key", ErrNoInboxKey, func(c *Config) { c.InboxKey = nil }},
		{"no transport", ErrNoTransport, func(c *Config) { c.Transport = nil }},
		{"no signer", ErrNoSigner, func(c *Config) { c.Signer = nil }},
		{"no seq store", ErrNoSeqStore, func(c *Config) { c.Seq = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := complete()
			tc.edit(&cfg)
			if _, err := NewService(cfg); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestServiceWithoutTransportIsUnconstructible pins a subtle one: a service
// with no transport must fail at wiring time, not at job time.
//
// If it merely failed each job, the failure would land inside the execution
// path — and everything in that path produces a receipt. The TEE would then
// sign a CompletionFailed proof for a request it never attempted, which is a
// signed statement that is not true.
func TestServiceWithoutTransportIsUnconstructible(t *testing.T) {
	doc := defaultPolicy()
	_, err := NewService(Config{
		Policy:   &doc,
		Signer:   proof.NewSigner(newTestEpoch(t)),
		Seq:      NewMemorySeqStore(),
		InboxKey: newInbox(t),
	})
	if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("error = %v, want %v", err, ErrNoTransport)
	}
}

// TestSubmitterVerifierGatesJobs pins the behaviour of the optional submitter
// hook on both sides of its default.
func TestSubmitterVerifierGatesJobs(t *testing.T) {
	body := []byte(`{"model":"gpt-4o"}`)

	t.Run("absent means allow", func(t *testing.T) {
		env := newTestEnv(t)
		spec := env.spec(t, body)
		if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err != nil {
			t.Fatalf("execute with no verifier: %v", err)
		}
	})

	t.Run("present and refusing", func(t *testing.T) {
		rejection := errors.New("unknown submitter")
		var seen jobs.Spec
		env := newTestEnv(t, func(c *Config) {
			c.SubmitterVerifier = func(_ context.Context, spec jobs.Spec) error {
				seen = spec
				return rejection
			}
		})

		spec := env.spec(t, body)
		result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
		if !errors.Is(err, rejection) {
			t.Fatalf("error = %v, want the verifier's rejection", err)
		}
		if result != nil {
			t.Fatal("rejected submitter still produced a receipt")
		}
		if len(env.transport.sent()) != 0 {
			t.Fatal("rejected submitter reached the transport")
		}
		// The hook sees the spec as submitted, unmodified.
		if !bytes.Equal(seen.BodyHash, spec.BodyHash) {
			t.Fatal("verifier did not receive the submitted spec")
		}
	})

	t.Run("runs before every other check", func(t *testing.T) {
		// An expired, unauthorised, malformed job must still be stopped by the
		// submitter hook first: identifying the caller is cheaper than
		// anything else and must not be skippable by crafting a bad job.
		called := false
		env := newTestEnv(t, func(c *Config) {
			c.SubmitterVerifier = func(context.Context, jobs.Spec) error {
				called = true
				return errors.New("nope")
			}
		})

		spec := env.spec(t, body)
		spec.ExpiresAt = baseTime.Add(-time.Hour).Unix()
		if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err == nil {
			t.Fatal("expired job from a rejected submitter was executed")
		}
		if !called {
			t.Fatal("submitter hook was skipped for an invalid spec")
		}
	})
}

// TestReceiptBindsThePolicyRevision asserts the receipt names the policy that
// was actually in force, so a provider auditing a spend can tell which revision
// of its own rules permitted it.
func TestReceiptBindsThePolicyRevision(t *testing.T) {
	env := newTestEnv(t)

	want, err := env.policy.Hash()
	if err != nil {
		t.Fatalf("hash policy: %v", err)
	}

	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Equal(result.Receipt.Receipt.PolicyHash, want[:]) {
		t.Fatal("receipt names the wrong policy revision")
	}
}

// TestExecuteConcurrent runs jobs in parallel because that is the normal case:
// one enclave serves many jobs at once against a policy set that is being
// rotated underneath it.
func TestExecuteConcurrent(t *testing.T) {
	env := newTestEnv(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				body := []byte(fmt.Sprintf(`{"model":"gpt-4o","n":%d}`, j))
				spec := env.spec(t, body)
				// The clock is shared, so the spec must be rebuilt each time
				// to keep its job ID unique.
				result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
				if err != nil {
					t.Errorf("execute: %v", err)
					return
				}
				specHash, err := spec.Hash()
				if err != nil {
					t.Errorf("hash spec: %v", err)
					return
				}
				if !bytes.Equal(result.Receipt.Receipt.JobSpecHash, specHash[:]) {
					t.Error("receipt covers the wrong spec under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()

	if got := len(env.transport.sent()); got != 8*32 {
		t.Fatalf("transport saw %d requests, want %d", got, 8*32)
	}
}
