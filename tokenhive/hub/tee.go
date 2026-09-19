package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// Errors returned by the TEE client.
var (
	// ErrNoReceipt means the stream ended without a receipt frame. The chunks
	// may still have been delivered, so this is not the same as a refusal: it
	// is a job that happened and left nothing to settle against.
	ErrNoReceipt = errors.New("tee stream ended without a receipt frame")
	// ErrTEERefused means the TEE answered with an error frame: it declined
	// the job before touching a credential.
	ErrTEERefused = errors.New("tee refused the job")
)

// Result is what one call to the TEE produced.
type Result struct {
	// Chunks are the response bytes, in order. They are what the receipt's
	// StreamHash commits to.
	Chunks [][]byte
	// Status is the upstream status code from the response-start frame. Zero
	// when the exchange never produced a response, which is also when the
	// binding checks below are skipped.
	Status uint32
	// Headers are the upstream response headers the TEE relayed in the
	// response-start frame (the allowlist, see tee.ForwardResponseHeaders).
	// The receipt's ResponseHeadersHash commits to exactly this set.
	Headers map[string][]string
	// Receipt is the signed proof. Verify it before relying on it.
	Receipt proof.SignedReceipt
}

// TEE is the entire Hub↔TEE seam.
//
// The narrowness is the point. Every piece of Hub business — pricing, quota,
// ledger, scheduling — sits behind this interface, so all of it can be
// exercised against an in-memory stand-in without a TEE, a network, or a real
// credential.
type TEE interface {
	// Execute runs a job and reports the forwarded chunks and the receipt.
	// onChunk receives each response chunk as it arrives and may be nil.
	// onStart, when given, receives the response start — upstream status plus
	// the relayed headers — once, before the first chunk, so the Hub can
	// commit its own response status before relaying any body byte.
	//
	// On error the Result is still returned when the TEE got far enough to
	// produce one: a job that failed mid-flight has something to prove, and
	// the Hub needs it to show it did not get what it was paying for.
	Execute(ctx context.Context, spec jobs.Spec, body []byte, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error)

	// OpenSession establishes a streaming session to a provider through the
	// TEE and returns an opaque, metered tunnel (read = downlink, write =
	// uplink). The tunnel's Receipt is the terminal session receipt. A TEE
	// that does not support sessions returns ErrSessionUnsupported.
	OpenSession(ctx context.Context, spec jobs.Spec) (SessionConn, error)
}

// SessionConn is a transparent streaming tunnel to a provider. It deliberately
// exposes only byte movement and the terminal receipt: WebSocket frame
// semantics, JSON payloads and close handshakes are the Hub's business, and the
// TEE never interprets any of them.
//
// Read returns provider downlink bytes. Write sends uplink bytes, which are
// relayed verbatim into the provider tunnel. After the provider closes, Read
// returns io.EOF and Receipt returns the signed session receipt.
type SessionConn interface {
	io.Reader
	io.Writer
	io.Closer
	// Receipt returns the signed session receipt once the tunnel has ended.
	// Before the provider has closed it returns an error.
	Receipt() (proof.SignedReceipt, error)
}

// CredentialService is the optional credential plane of a Hub's TEE. In the
// agent-registration design the TEE itself never stores a token — it holds only
// the private half of its inbox key — so the only control-plane thing a Hub can
// ask of it is its publishable inbox key, which provider agents encrypt to.
//
// It is deliberately a separate interface rather than more methods on TEE:
// request/response execution is the one capability every Hub needs, while the
// inbox key only matters when agents dial in at all. The AgentGate relays the
// key (via CredentialKeyHandler) to agents that are about to register a token.
type CredentialService interface {
	// CredentialKey returns the TEE's inbox public key — the target provider
	// agents encrypt their tokens to. Fetching it on demand (rather than
	// caching it in the Hub) means a rotated TEE key is picked up on the
	// agent's next registration.
	CredentialKey(ctx context.Context) (tee.InboxPublic, error)
}

// ErrNoCredentialService is returned by the Hub's credential-key relay when the
// configured TEE does not expose the credential plane. A Hub that cannot
// publish a TEE key to its agents must not host agent registration.
var ErrNoCredentialService = errors.New("tee does not support agent credential registration")

// ErrSessionUnsupported is returned when the TEE behind the Hub cannot open
// streaming sessions.
var ErrSessionUnsupported = errors.New("tee does not support streaming sessions")

// HTTPTEE calls a TEE's /v1/execute over HTTP. It is the production
// implementation of TEE (and of CredentialService, when BaseURL is set).
type HTTPTEE struct {
	// URL is the full execute endpoint, e.g. http://127.0.0.1:18090/v1/execute.
	URL string
	// SessionURL is the full WebSocket session endpoint, e.g.
	// ws://127.0.0.1:18090/v1/session. Empty means sessions are unsupported.
	SessionURL string
	// BaseURL is the TEE's root, e.g. http://127.0.0.1:18090. It is what the
	// credential-key plane is derived from (/v1/credential-key); without it the
	// Hub cannot publish the TEE's inbox key to dialing agents.
	BaseURL string
	// Client is the HTTP client to use. Defaults to http.DefaultClient. Under
	// mTLS it must carry the pinned RA-TLS root and the Hub's client identity.
	Client *http.Client
	// Dialer is the WebSocket dialer OpenSession uses. Defaults to
	// websocket.DefaultDialer. Under mTLS it must carry the same TLS config as
	// Client, or sessions would connect in plaintext while execute goes TLS.
	Dialer *websocket.Dialer

	// keyMu guards keyCall, the in-flight credential-key fetch. Agents pull
	// the TEE inbox key through the Hub on every reconnect, so a fleet that
	// reconnects in a wave would otherwise become one request per agent
	// against the TEE. Sharing the in-flight fetch collapses that wave.
	keyMu   sync.Mutex
	keyCall *credentialKeyCall
}

// credentialKeyCall is one in-flight CredentialKey fetch, shared by every
// caller that arrives while it is running.
type credentialKeyCall struct {
	done chan struct{}
	key  tee.InboxPublic
	err  error
}

// Execute implements TEE.
func (t *HTTPTEE) Execute(ctx context.Context, spec jobs.Spec, body []byte, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	if t.URL == "" {
		return Result{}, errors.New("hub: TEE URL is empty")
	}
	enc, err := tee.Job{Spec: spec, Body: body}.EncodeCanonical()
	if err != nil {
		return Result{}, fmt.Errorf("encode execute request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(enc))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", tee.ExecuteContentType)

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	// Capture the certificate of the connection that will carry the answer, so
	// the receipt can be bound to it once it arrives (see bindConnection).
	var (
		spkiMu   sync.Mutex
		peerSPKI []byte
	)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			spki := tlsPeerSPKI(info.Conn)
			spkiMu.Lock()
			peerSPKI = spki
			spkiMu.Unlock()
		},
	}))

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Result{}, fmt.Errorf("tee http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// A backstop on what one response may cost this Hub in memory. The TEE
	// enforces MaxResponseBytes itself, so an honest peer never trips this; a
	// peer that ignores its own spec would otherwise stream until the attempt
	// times out, with every chunk retained for settlement.
	limit := spec.MaxResponseBytes
	var total uint64
	guard := func(chunk []byte) error {
		total += uint64(len(chunk))
		if limit > 0 && total > limit {
			return fmt.Errorf("%w: read %d bytes, cap %d", ErrResponseTooLarge, total, limit)
		}
		if onChunk != nil {
			return onChunk(chunk)
		}
		return nil
	}
	res, err := readSSE(resp.Body, guard, onStart...)
	if err != nil {
		return res, err
	}
	// The receipt must describe the job the Hub asked for, and be signed by the
	// key the connection that carried it presented.
	if err := bindReceipt(spec, res.Receipt.Receipt); err != nil {
		return res, err
	}
	spkiMu.Lock()
	spki := peerSPKI
	spkiMu.Unlock()
	if err := bindConnection(spki, secureChannel(t.URL), res.Receipt.Receipt); err != nil {
		return res, err
	}
	return res, nil
}

// ErrResponseTooLarge means the TEE streamed more response bytes than the job's
// spec allowed. The TEE bounds a response itself, so this is the Hub's backstop
// against a peer that does not: without it the Hub would buffer an unbounded
// body, because the chunks are retained to settle against.
var ErrResponseTooLarge = errors.New("tee response exceeds the job's response cap")

// ErrReceiptSpecMismatch means a receipt does not describe the job the Hub
// dispatched. The signature and attestation can both be genuine — the TEE is
// real — while the receipt names a different request; pricing, attribution and
// the provider's audit all assume the receipt proves *this* exchange, so such a
// receipt must never settle.
var ErrReceiptSpecMismatch = errors.New("receipt does not describe the dispatched job")

// bindReceipt checks that a receipt names the request the Hub actually sent:
// the same spec hash, provider, host, path and declared model. The Hub authors
// the spec and signs nothing, so the receipt's own JobSpecHash is the only
// thing tying the attested response back to the request; nothing else compares
// it. The model is compared alongside the rest because it is the key the charge
// is computed from, and a receipt that names another one would settle a job
// against a price nobody quoted.
func bindReceipt(spec jobs.Spec, r proof.Receipt) error {
	want, err := spec.Hash()
	if err != nil {
		return fmt.Errorf("hash dispatched spec: %w", err)
	}
	switch {
	case r.Provider != spec.Provider:
		return fmt.Errorf("%w: receipt provider %q, dispatched %q", ErrReceiptSpecMismatch, r.Provider, spec.Provider)
	case r.Host != spec.Host:
		return fmt.Errorf("%w: receipt host %q, dispatched %q", ErrReceiptSpecMismatch, r.Host, spec.Host)
	case r.Path != spec.Path:
		return fmt.Errorf("%w: receipt path %q, dispatched %q", ErrReceiptSpecMismatch, r.Path, spec.Path)
	case r.Model != spec.Model:
		return fmt.Errorf("%w: receipt model %q, dispatched %q", ErrReceiptSpecMismatch, r.Model, spec.Model)
	case !streamHashEq(r.JobSpecHash, want[:]):
		return fmt.Errorf("%w: spec hash %x, dispatched %x", ErrReceiptSpecMismatch, r.JobSpecHash, want)
	}
	return nil
}

// ErrReceiptNotBoundToConnection means the receipt was signed by a key other
// than the one the connection that carried it presented. RA-TLS exists so a
// receipt and the certificate it arrived over are the same attested epoch;
// without this check a rotated or forged key could sign a receipt the Hub would
// accept on evidence it never saw on that connection.
var ErrReceiptNotBoundToConnection = errors.New("receipt signing key is not the certificate the connection presented")

// bindConnection checks that a receipt's signing key is the key the connection
// that carried it presented. peerSPKI is empty on a plaintext channel — the
// local simulation — and there is then no peer identity to bind and nothing to
// assert.
//
// requirePeer is what keeps that skip from being a way out: it says the channel
// is TLS, so a certificate was presented and read. An empty peerSPKI there means
// the capture failed, not that there was nothing to bind, and the receipt is
// refused rather than accepted on a check that did not run.
func bindConnection(peerSPKI []byte, requirePeer bool, r proof.Receipt) error {
	if len(peerSPKI) == 0 {
		if requirePeer {
			return fmt.Errorf("%w: TLS channel presented no certificate to bind", ErrReceiptNotBoundToConnection)
		}
		return nil
	}
	if r.Attestation == nil {
		return fmt.Errorf("%w: receipt carries no attestation", ErrReceiptNotBoundToConnection)
	}
	if !bytes.Equal(peerSPKI, r.Attestation.KeyID) {
		return fmt.Errorf("%w: connection SPKI %x, receipt key %x", ErrReceiptNotBoundToConnection, peerSPKI, r.Attestation.KeyID)
	}
	return nil
}

// secureChannel reports whether a Hub↔TEE URL carries TLS, and therefore
// whether a receipt arriving over it must be bound to the certificate that
// carried it. It reads the scheme the Hub was configured with rather than what
// a dial happened to reveal, so a transport that hides its connection cannot
// turn the binding off.
func secureChannel(url string) bool {
	return strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "wss://")
}

// spkiDigest is the identity of a certificate: SHA-256 over its
// SubjectPublicKeyInfo, which is exactly the receipt's Attestation.KeyID (see
// proof.AttestationRef and platform.Identity, both over the same DER).
func spkiDigest(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}

// tlsPeerSPKI returns the SPKI digest of the certificate a connection
// presented, or nil when conn is not a TLS connection or presented none.
func tlsPeerSPKI(conn net.Conn) []byte {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return spkiDigest(certs[0])
}

// spkiCapture records the SPKI digest of the certificate a dialer's handshake
// accepted. The handshake may complete on a different goroutine than the one
// that asked for the connection, so the two sides are ordered rather than left
// to luck.
type spkiCapture struct {
	mu     sync.Mutex
	digest []byte
}

func (c *spkiCapture) set(digest []byte) {
	c.mu.Lock()
	c.digest = digest
	c.mu.Unlock()
}

func (c *spkiCapture) get() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.digest
}

// CredentialKey implements CredentialService.
//
// Concurrent callers share one TEE round-trip. That is the whole mitigation:
// the result is handed to every waiter and then dropped, so the next caller
// reads the TEE again. Caching the key for a TTL would be cheaper still but
// wrong here — the key rotates on every TEE restart, and for the whole TTL
// window after one the Hub would hand every reconnecting agent the dead key,
// whose sealed envelopes the new TEE can no longer open. Collapsing only the
// in-flight request has no such window.
func (t *HTTPTEE) CredentialKey(ctx context.Context) (tee.InboxPublic, error) {
	if t.BaseURL == "" {
		return tee.InboxPublic{}, errors.New("hub: TEE BaseURL is empty")
	}

	t.keyMu.Lock()
	if t.keyCall != nil {
		call := t.keyCall
		t.keyMu.Unlock()
		<-call.done
		return call.key, call.err
	}
	call := &credentialKeyCall{done: make(chan struct{})}
	t.keyCall = call
	t.keyMu.Unlock()

	call.key, call.err = tee.CredentialKeyRequest(ctx, t.Client, t.BaseURL+"/v1/credential-key")
	close(call.done)

	t.keyMu.Lock()
	if t.keyCall == call {
		t.keyCall = nil
	}
	t.keyMu.Unlock()
	return call.key, call.err
}

// readSSE parses the response stream, handing each chunk to onChunk and
// stopping at the receipt or error frame.
//
// Chunks are collected as well as forwarded because the Hub settles against
// them: it must be able to show the receipt attests exactly the bytes it
// delivered, which needs the bytes, not just the fact of delivery.
//
// The start frame is parsed into the result and reported through onStart
// before any chunk is forwarded, so the caller can commit its response status
// ahead of the first body byte.
func readSSE(r io.Reader, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	stream := tee.NewSSEStream(r)
	var (
		result   Result
		receipt  string
		teeErr   string
		startErr error
	)
	for {
		frame, err := stream.Next()
		if err != nil {
			// The stream ended, cleanly or not. Either way the frames already
			// read are the exchange's result, so the verdict below decides.
			break
		}
		switch frame.Type {
		case "", "message":
			// Keyed on the presence of a data line rather than on the
			// accumulated length: an empty chunk is a real chunk and must be
			// kept, or the count and the stream hash stop matching the receipt.
			if frame.HasData {
				// Two copies on purpose: the chunks kept here are what the Hub
				// settles against, and the caller may write into the one it is
				// handed without being able to alter the evidence.
				result.Chunks = append(result.Chunks, []byte(frame.Data))
				if onChunk != nil {
					// A consumer that stopped taking bytes — a client that will not
					// read, a link that broke — ends the exchange here. Ignoring the
					// error instead leaves the Hub pulling a body nobody receives,
					// which is how a stalled reader becomes unbounded buffering.
					if cerr := onChunk([]byte(frame.Data)); cerr != nil {
						return result, cerr
					}
				}
			}
		case tee.EventStart:
			var start struct {
				Status  uint32              `json:"status"`
				Headers map[string][]string `json:"headers,omitempty"`
			}
			if err := json.Unmarshal([]byte(frame.Data), &start); err != nil {
				startErr = fmt.Errorf("decode response start frame: %w", err)
				break
			}
			result.Status = start.Status
			result.Headers = start.Headers
			if len(onStart) > 0 && onStart[0] != nil {
				onStart[0](tee.Response{StatusCode: start.Status, Headers: start.Headers})
			}
		case tee.EventReceipt:
			receipt = frame.Data
		case tee.EventError:
			teeErr = frame.Data
		}
	}

	switch {
	case startErr != nil:
		return result, startErr
	case teeErr != "":
		return result, fmt.Errorf("%w: %s", ErrTEERefused, teeErr)
	case receipt == "":
		return result, ErrNoReceipt
	}
	signed, err := tee.DecodeReceiptFrame(receipt)
	if err != nil {
		return result, err
	}
	result.Receipt = signed
	return result, nil
}
