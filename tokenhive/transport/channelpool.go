package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// channel is one resident upstream connection: a TLS (or plain, in tests)
// socket with a persistent buffered reader, owned by the TEE and shared across
// jobs while it stays healthy.
//
// A channel is used by exactly one Do at a time. The pool hands it out, the
// caller runs one exchange, then the pool either reuses it (idle) or closes it.
type channel struct {
	conn net.Conn
	br   *bufio.Reader
	pool *channelPool

	// lastUsed is when the channel was last returned to the idle pool, used to
	// reap connections that outlive the idle window.
	lastUsed time.Time
	// wrote counts bytes actually written to this connection. A zero value at
	// exchange failure means nothing left the TEE, so the request is safe to
	// re-dial exactly once.
	wrote int
	// cold reports that this checkout dialed a new connection rather than
	// reusing a pooled one. Set by acquire on every checkout, and read only
	// when the exchange fails — it is what tells a failure that cost a
	// connection from one that cost nothing.
	cold bool
}

// wroteNothing reports whether no bytes were written to the wire.
func (ch *channel) wroteNothing() bool { return ch.wrote == 0 }

// fail tags an exchange failure with the stage it happened in, so the reason
// survives all the way to the Hub (see tee.ClassifyFailure) instead of being
// flattened into "the response did not finish".
func (ch *channel) fail(stage string, err error) error {
	return &tee.StageError{Stage: stage, Cold: ch.cold, Err: err}
}

// channelPool is the resident-connection pool for one (provider, host). It
// tracks how many connections are alive and reaps those idle past the window.
//
// active counts every live connection (idle or checked out) and is the bound
// the per-host cap enforces; a healthy connection keeps its slot while it is
// idle. Waiter notification is a closed-and-replaced channel rather than a
// bare condition variable, because an acquirer must be able to wait on "a
// connection came back" OR "my context ended" — and a condition variable
// cannot select on a context.
type channelPool struct {
	mgr *ChannelManager
	key string

	mu     sync.Mutex
	notify chan struct{}
	active int
	closed bool
	idle   []*channel
}

func newChannelPool(mgr *ChannelManager, key string) *channelPool {
	return &channelPool{mgr: mgr, key: key, notify: make(chan struct{})}
}

// wakeLocked wakes every goroutine waiting in acquire. Caller holds p.mu.
func (p *channelPool) wakeLocked() {
	close(p.notify)
	p.notify = make(chan struct{})
}

// acquire takes an idle connection when one exists, otherwise it reserves a
// slot for a brand-new one — dial is true then — waiting until a connection is
// returned to the idle set, a slot is freed, or the pool shuts down. The wait
// honours ctx, so a caller queued behind the cap gives up promptly instead of
// pinning its execution resources on a pool that may never free up.
func (p *channelPool) acquire(ctx context.Context) (ch *channel, dial bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.closed {
			return nil, false, net.ErrClosed
		}
		p.expireIdleLocked()
		if n := len(p.idle); n > 0 {
			ch := p.idle[n-1]
			p.idle = p.idle[:n-1]
			return ch, false, nil
		}
		if p.active < p.mgr.maxConns {
			p.active++
			return nil, true, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		notify := p.notify
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			p.mu.Lock()
			return nil, false, ctx.Err()
		case <-notify:
		}
		p.mu.Lock()
	}
}

// releaseSlot frees a slot reserved by a connection that failed to dial.
func (p *channelPool) releaseSlot() {
	p.mu.Lock()
	p.active--
	p.wakeLocked()
	p.mu.Unlock()
}

// reuse returns a healthy connection to the idle set, refreshing its clock. A
// waiter may be parked waiting for exactly this connection, so the idle set
// growing is a wakeup event.
func (p *channelPool) reuse(ch *channel) {
	ch.lastUsed = time.Now()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.drop(ch)
		return
	}
	p.idle = append(p.idle, ch)
	p.wakeLocked()
	p.mu.Unlock()
}

// drop closes a connection and frees its slot.
func (p *channelPool) drop(ch *channel) {
	_ = ch.conn.Close()
	p.mu.Lock()
	p.active--
	p.wakeLocked()
	p.mu.Unlock()
}

// expireIdle closes idle connections past the idle window. It is the lock-taking
// entry point for the manager's background sweeper.
func (p *channelPool) expireIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireIdleLocked()
}

// expireIdleLocked closes idle connections past the idle window. Caller holds
// p.mu.
func (p *channelPool) expireIdleLocked() {
	now := time.Now()
	kept := p.idle[:0]
	closedAny := false
	for _, ch := range p.idle {
		if now.Sub(ch.lastUsed) > p.mgr.idleTimeout {
			p.active--
			_ = ch.conn.Close()
			closedAny = true
			continue
		}
		kept = append(kept, ch)
	}
	p.idle = kept
	if closedAny {
		p.wakeLocked()
	}
}

// close closes every idle connection and marks the pool shut so nothing more
// is handed out. Connections currently checked out are unaffected.
func (p *channelPool) close() {
	p.mu.Lock()
	p.closed = true
	p.wakeLocked()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, ch := range idle {
		p.drop(ch)
	}
}

// exchange runs one full provider exchange on this channel: writes the
// hand-serialised request, reads the response, relays body chunks, and reports
// whether the connection may be reused.
//
// The returned status is meaningful even when err is non-nil: a request that
// reached the provider has a status to attest even if the body never finished.
//
// Its three stages are marked on the record carried by ctx: the write, the wait
// for the response headers, and the body relay. The wait is the one that
// dominates a real request, and it is entirely the provider's and the relay
// chain's — nothing in this function is waiting on itself.
func (ch *channel) exchange(ctx context.Context, req tee.Request, onChunk func([]byte) error, bufSize int, onStart []tee.StartFunc) (keep bool, status tee.Response, err error) {
	tm := tee.TimingsFrom(ctx)
	ch.wrote = 0

	requestBytes, err := buildRequestBytes(req)
	if err != nil {
		return false, tee.Response{}, err
	}

	// Clear any deadline a previous exchange's cancellation poke may have left,
	// then bound this exchange by the caller's deadline. The socket deadline
	// must not survive into the pool, so it is cleared again before a reusable
	// connection is returned — after the cancellation poke is stopped, so a
	// poke that fired at the worst moment cannot poison the pooled socket.
	_ = ch.conn.SetDeadline(time.Time{})
	clearOnReturn := false
	if dl, ok := ctx.Deadline(); ok {
		_ = ch.conn.SetDeadline(dl)
		clearOnReturn = true
	}

	// A cancellation without a deadline (a caller hanging up, a Hub request
	// aborted) must still interrupt a blocked read: there is no way to unblock
	// a socket Read except closing it or expiring its deadline, and neither the
	// provider nor the caller may send another byte. Poke the deadline the
	// instant the context is done so the exchange fails promptly and the pool
	// discards the connection instead of pinning a goroutine on a dead peer.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = ch.conn.SetDeadline(time.Now()) })
	defer func() {
		// Stop the poke first: if the context was already done, stop returns
		// false but the poke has run (or is running), so the clear below is what
		// keeps a reusable connection clean.
		stopOnCancel()
		if clearOnReturn && keep {
			_ = ch.conn.SetDeadline(time.Time{})
		}
	}()

	tm.Mark(tee.StageWrite)
	n, werr := ch.conn.Write(requestBytes)
	ch.wrote = n
	if werr != nil {
		return false, tee.Response{}, ch.fail(tee.StageWrite, fmt.Errorf("write request: %w", werr))
	}
	if n != len(requestBytes) {
		return false, tee.Response{}, ch.fail(tee.StageWrite, io.ErrShortWrite)
	}

	tm.Mark(tee.StageTTFB)
	// ReadResponse consumes framing from the persistent buffered reader so a
	// Content-Length or chunked body is understood even though we wrote the
	// request bytes ourselves.
	resp, err := http.ReadResponse(ch.br, &http.Request{Method: req.Method})
	if err != nil {
		return false, tee.Response{}, ch.fail(tee.StageTTFB, fmt.Errorf("read response headers: %w", err))
	}
	status = tee.Response{StatusCode: uint32(resp.StatusCode), Headers: resp.Header}

	// The body stage opens before the response start is reported, so ttfb ends
	// exactly where the headers were parsed. That leaves the start frame — which
	// the caller writes and flushes, and which can block on a caller that is not
	// reading — charged to the relay rather than to the provider's thinking time.
	tm.Mark(tee.StageBody)

	// The response start is reported the moment the headers are parsed, before
	// a single body byte moves: the caller must be able to commit its own
	// status (a 200 stream vs a 401 error) ahead of the first chunk.
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](status)
	}

	// "Keep" is decided before reading the body: a response signalled close
	// (resp.Close) must not be pooled, whatever happens to the bytes after.
	keep = !resp.Close

	buf := make([]byte, bufSize)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if cerr := onChunk(buf[:n]); cerr != nil {
				_ = resp.Body.Close()
				return false, status, ch.fail(tee.StageBody, cerr)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			keep = false
			_ = resp.Body.Close()
			return false, status, ch.fail(tee.StageBody, rerr)
		}
	}
	_ = resp.Body.Close()
	return keep, status, nil
}

// buildRequestBytes renders a tee.Request as a raw HTTP/1.1 message without any
// standard-library editorialising.
//
// The response framing (Content-Length, chunked) is understood on read by
// http.ReadResponse; the request itself is written byte-for-byte. There is no
// gzip, no retry, no redirect, and no environment proxy here — every byte is
// one the TEE decided to send, so the signed receipt can describe it exactly.
func buildRequestBytes(req tee.Request) ([]byte, error) {
	var buf bytes.Buffer

	target := req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, target)
	fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	fmt.Fprintf(&buf, "Connection: keep-alive\r\n")
	for name, value := range req.Headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
	}
	// Always explicit, including zero, so a bodyless request still carries a
	// legal Content-Length: 0 the same way the standard library rendered it.
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(req.Body))
	buf.WriteString("\r\n")
	buf.Write(req.Body)
	return buf.Bytes(), nil
}

// Session is a transparent byte pipe to a provider after an Upgrade handshake.
// The buffered reader that consumed the 101 may already hold the provider's
// first downstream bytes, so Read drains it before touching the socket. It does
// no framing of its own — its only job is to carry bytes between the TEE's
// relay and the provider, exactly as the plan's "transparent byte pipe" after
// the handshake.
type Session struct {
	conn net.Conn
	br   *bufio.Reader
}

// Read returns the provider's next bytes, preferring anything the handshake
// already buffered.
func (s *Session) Read(p []byte) (int, error) {
	if s.br.Buffered() > 0 {
		return s.br.Read(p)
	}
	return s.conn.Read(p)
}

// Write sends bytes uplink to the provider verbatim.
func (s *Session) Write(p []byte) (int, error) { return s.conn.Write(p) }

// Close closes the underlying provider connection.
func (s *Session) Close() error { return s.conn.Close() }

// buildUpgradeBytes renders a tee.Request as an HTTP/1.1 Upgrade (WebSocket)
// handshake. Unlike buildRequestBytes it sends no body and adds the protocol's
// own handshake headers; the Host and the caller's headers — which include the
// injected provider credential — are carried through unchanged. The handshake
// bytes are not counted toward RequestBytes; only post-upgrade writes are.
func buildUpgradeBytes(req tee.Request) ([]byte, error) {
	var buf bytes.Buffer

	target := req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, target)
	fmt.Fprintf(&buf, "Host: %s\r\n", req.Host)
	fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&buf, "Upgrade: websocket\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Key: %s\r\n", newWebSocketKey())
	for name, value := range req.Headers {
		fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
	}
	buf.WriteString("\r\n")
	return buf.Bytes(), nil
}

// newWebSocketKey returns a fresh Sec-WebSocket-Key: the base64 of 16 random
// bytes, which is exactly what the WebSocket handshake spec prescribes.
func newWebSocketKey() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		// crypto/rand never fails on this platform; if it somehow does, a stale
		// but well-formed key keeps the upgrade parseable rather than panicking.
		return base64.StdEncoding.EncodeToString([]byte("00000000000000000000"))
	}
	return base64.StdEncoding.EncodeToString(nonce[:])
}
