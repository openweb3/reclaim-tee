package tee

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrResponseBodyTooLarge means the transport produced more bytes than the job
// was allowed to receive. The response is not discarded — it is truncated, and
// the receipt is signed with CompletionTruncated so a verifier can tell a
// partial response from a whole one.
var ErrResponseBodyTooLarge = errors.New("response body exceeds the allowed size")

// ErrNoTransport means the service was built without a transport. It is a
// wiring error, not a runtime one: a service that cannot reach a provider must
// refuse to be constructed rather than fail every job with a receipt claiming
// the provider never answered.
var ErrNoTransport = errors.New("no transport configured")

// Request is an outbound provider request, assembled from a job spec plus the
// credential the TEE injected.
//
// The headers here are the final set. The transport must not add, rewrite, or
// remove any of them: what it sends is what the receipt will describe, and a
// transport that quietly "helps" would desynchronise the two.
type Request struct {
	Method string
	// Provider names which provider's network egress this request must ride.
	// The data path keys its connection pool by (Provider, Host): two providers
	// hitting the same host still egress through their own agents, so upstream
	// always sees the source IP of the provider whose credential is being spent.
	Provider string
	Host     string
	Path     string
	Query    string
	// Headers is the exact header set to put on the wire. The TEE has already
	// merged the caller's allowed headers with the injected credential.
	Headers map[string]string
	Body    []byte

	// Stream asks for a streaming response. The transport reports each chunk
	// through the Execute callback rather than buffering one body.
	Stream bool

	// MaxResponseBytes is the hard cap on response bytes. The transport is
	// expected to stop at or before this, and the service enforces it
	// regardless of what the transport does.
	MaxResponseBytes uint64

	// Timeout bounds the whole exchange. Zero means no service-level deadline
	// beyond the context.
	Timeout time.Duration

	// JobID identifies the job this request belongs to. It is never put on the
	// wire: a transport uses it to name the job in a line about a connection,
	// which is the only way a failure at this layer can be tied to the request
	// that needed it. Empty means the caller supplied none.
	JobID []byte
}

// Response is what the provider sent back, minus the body.
//
// The body is never materialised here. It flows through the chunk callback as
// it arrives so that a long stream can be relayed and digested without ever
// being held in memory in full.
//
// Headers are the full upstream header set as parsed. The service filters it
// down to the relay allowlist (see ForwardResponseHeaders) before the start
// callback fires, so the Hub only ever sees headers the receipt will attest.
type Response struct {
	StatusCode uint32
	Headers    map[string][]string
}

// StartFunc is the shape of the response-start callback. It is invoked once,
// after the response headers have been parsed and before the first chunk, with
// the status and the allowlisted headers the Hub may act on.
type StartFunc func(Response)

// Transport performs one provider request.
//
// The chunk callback is invoked once per received body chunk, in arrival
// order. It must return an error if the caller wants the exchange stopped;
// the transport should then close the connection. It may be nil when the
// caller does not want the body at all — the service still digests it, which
// is the whole point of the receipt.
//
// The start callback (variadic so existing callers that only move bytes are
// unchanged) is invoked exactly once, after the response headers are parsed
// and before the first chunk. nil or omitted means the caller discards the
// start; the service still hashes the headers into the receipt either way.
//
// A transport that performs its own network work may mark the stages it owns on
// the record carried by ctx (see TimingsFrom): acquiring a connection, dialling,
// the TLS handshake, the write, the wait for the response headers and the body
// are all intervals only the transport can measure. Marking a nil record is a
// no-op, so an uninstrumented caller needs no branch.
//
// Implementations must not retry. A retry would send the credential twice and
// produce a response that no longer corresponds to a single signed execution.
type Transport interface {
	Do(ctx context.Context, req Request, onChunk func(chunk []byte) error, onStart ...StartFunc) (Response, error)
}

// ChunkFunc is the shape of the per-chunk callback. It exists so that callers
// can name the type in signatures without restating the closure form.
type ChunkFunc func(chunk []byte) error

// SessionConn is the transparent bidirectional byte pipe to a provider after an
// Upgrade handshake. It is deliberately just Read/Write/Close: the transport
// accepts raw bytes on Write and surfaces raw provider bytes on Read, doing no
// application framing of its own. Anything a session carries — WebSocket
// frames, JSON payloads, close handshakes — is the Hub's business, not the
// TEE's, which is exactly the boundary that keeps the TEE's work to a minimum.
type SessionConn interface {
	io.Reader
	io.Writer
	io.Closer
}

// SessionOpener is a Transport that can additionally establish a streaming
// session. Not every transport supports this — a strict request/response relay
// has nothing to upgrade to — so it is asserted with a type assertion rather
// than folded into Transport, keeping request/response transports valid.
type SessionOpener interface {
	// OpenSession dials the provider (through its Agent when configured),
	// completes TLS, writes the Upgrade request, and verifies the 101
	// Switching Protocols response. Once it returns, the SessionConn is a
	// transparent byte pipe in both directions. Only bytes the caller writes
	// through the pipe are counted as uplink; the handshake's own bytes are not
	// metered.
	OpenSession(ctx context.Context, req Request) (SessionConn, error)
}
