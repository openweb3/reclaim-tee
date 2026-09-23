package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	// ErrTEERefused means the TEE answered with an error frame. It declines a
	// job before touching a credential, and — in the one case that is not free
	// — refuses to sign a receipt for an exchange whose evidence aged out while
	// it ran. Either way there is no receipt to settle against.
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
//
// A request the TEE refuses because a rotation retired the connection under it
// is retried once, transparently, on a connection the client's pool cannot
// have handed over. That refusal is the only failure a healthy rotation can
// put in front of a buyer, and it is retryable by construction rather than by
// judgement: epochConnections.guard answers before the service runs, so the
// refused attempt allocated no sequence number, spent no credential, and never
// reached a provider — and since the refusal is an HTTP status rather than a
// stream, no byte ever reached onChunk. Retrying it is therefore exactly as
// safe as the first attempt, and far cheaper than handing the buyer a failure
// the TEE caused by keeping its own evidence fresh.
//
// Every other failure is returned as it was. In particular a transport error
// on a connection that was already in flight is NOT retried: there the service
// may well have executed and billed the job, and a retry would do it twice.
func (t *HTTPTEE) Execute(ctx context.Context, spec jobs.Spec, body []byte, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	if t.URL == "" {
		return Result{}, errors.New("hub: TEE URL is empty")
	}
	enc, err := tee.ExecuteRequest{Spec: spec, Body: body}.EncodeCanonical()
	if err != nil {
		return Result{}, fmt.Errorf("encode execute request: %w", err)
	}
	res, err := t.execute(ctx, enc, false, onChunk, onStart...)
	if !errors.Is(err, tee.ErrEpochRetired) {
		return res, err
	}
	return t.execute(ctx, enc, true, onChunk, onStart...)
}

// execute performs one dispatch. freshConnection routes this request around the
// client's connection pool, which is what the retry above needs: every pooled
// connection to a rotating TEE is one the rotation may have retired, and the
// pool does not learn that until it tries to use them.
//
// req.Close alone does not do that on HTTP/1. There the flag is read when the
// response comes back, to decide whether the connection may be kept — the
// transport's hunt for an existing connection never looks at it — so a retry
// carrying it can still be handed a pooled connection, which after a rotation
// is precisely the retired one it is trying to leave behind. (HTTP/2 reads it
// on the way in instead: a request asking to close gets a connection of its
// own.) The pool is therefore evicted explicitly, and that is the part which
// makes the retry dial — and so complete a handshake — again on either
// protocol.
func (t *HTTPTEE) execute(ctx context.Context, enc []byte, freshConnection bool, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(enc))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", tee.ExecuteContentType)
	req.Close = freshConnection

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	if freshConnection {
		client.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		message := strings.TrimSpace(string(b))
		if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(tee.EpochRetiredHeader) != "" {
			return Result{}, fmt.Errorf("%w: %s", tee.ErrEpochRetired, message)
		}
		return Result{}, fmt.Errorf("tee http %d: %s", resp.StatusCode, message)
	}
	return readSSE(resp.Body, onChunk, onStart...)
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
					_ = onChunk([]byte(frame.Data))
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
