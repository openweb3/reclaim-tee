package tee

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// A session is unbounded work, so the deadline its receipt must be signed
// before cannot be enforced by bounding the session — it is enforced by ending
// it. These tests cover the ending itself, the rotation it has to follow, and
// the evidence it must leave alone.

// blockingSessionConn is a provider tunnel that delivers a prefix and then
// holds the connection open: a stream still in progress. Close releases it with
// a clean end of stream, which is what makes it useful — the difference between
// a session the provider finished and one the TEE cut is visible in the receipt
// only if the end of stream alone would not have been marked truncated.
type blockingSessionConn struct {
	mu     sync.Mutex
	prefix []byte
	closed chan struct{}
	once   sync.Once
}

func newBlockingSessionConn(prefix []byte) *blockingSessionConn {
	return &blockingSessionConn{prefix: prefix, closed: make(chan struct{})}
}

func (c *blockingSessionConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	<-c.closed
	return 0, io.EOF
}

func (c *blockingSessionConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *blockingSessionConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// cellEnv builds a service that serves whatever signer a test stores in cell —
// the same shape the refresh loop uses — on a real clock, because the deadline
// is a wall-clock instant and a pinned one would never arrive.
func cellEnv(t *testing.T, cell *atomic.Pointer[proof.Signer]) *testEnv {
	t.Helper()
	return newTestEnv(t,
		func(c *Config) { c.SignerCell = cell },
		withClock(time.Now),
	)
}

// relayOverWebsocket serves one session through relaySession over a real
// WebSocket, so a test drives the seam the Hub drives: Binary frames are tunnel
// bytes and the closing Text frame is the terminal marker.
func relayOverWebsocket(t *testing.T, ss *Session) (*websocket.Conn, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := sessionUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		relaySession(conn, ss)
	}))
	peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial the session relay: %v", err)
	}
	return peer, func() {
		_ = peer.Close()
		server.Close()
	}
}

// readSessionTerminal reads downlink frames until the terminal Text message,
// which it returns alongside the bytes that preceded it. A session that ends
// without one is the failure this whole mechanism exists to prevent, so it
// fails the test rather than returning.
func readSessionTerminal(t *testing.T, peer *websocket.Conn) ([]byte, []byte) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(30 * time.Second))
	var downlink []byte
	for {
		mt, msg, err := peer.ReadMessage()
		if err != nil {
			t.Fatalf("session ended without a terminal message: %v", err)
		}
		if mt == websocket.BinaryMessage {
			downlink = append(downlink, msg...)
			continue
		}
		return downlink, msg
	}
}

// TestSessionEndsBeforeTheSigningDeadline is the whole point of the watcher: a
// provider that never ends its stream must not be able to run a session past
// the point where its receipt could still be signed. The cut is what turns an
// unattestable session — every byte relayed, upstream paid, nothing settleable
// — into a truncated receipt for the bytes that did arrive.
//
// Decoding a receipt at all is the assertion that it was signed in time:
// Receipt refuses when the live signer is inside the margin, so the success of
// this read is the property, and the KeyID pins it to the epoch that was cut.
func TestSessionEndsBeforeTheSigningDeadline(t *testing.T) {
	conn := newBlockingSessionConn([]byte("first-frame"))
	cell := &atomic.Pointer[proof.Signer]{}
	// Three seconds of leaf beyond the signing margin, less the handoff, leaves
	// the session between one and two seconds of relaying before the cut — long
	// enough that the frame below is delivered first, which is what the receipt
	// then has to account for. A real NitroTPM leaf is second-granularity, so
	// this is as short as the window can be made without a fake clock, and a
	// fake clock is what the deadline cannot be measured with.
	epoch := epochWithNitroLeaf(t, time.Now().Add(rootShared.SNPSigningMargin+3*time.Second))
	cell.Store(proof.NewSigner(epoch))
	env := cellEnv(t, cell)
	ss := newCellSession(t, env, cell, conn)

	peer, stop := relayOverWebsocket(t, ss)
	defer stop()

	start := time.Now()
	downlink, terminal := readSessionTerminal(t, peer)
	elapsed := time.Since(start)

	if elapsed > SessionIdleTimeout {
		t.Fatalf("the session ran %s, which is past the idle watchdog — the deadline was not what ended it", elapsed)
	}
	signed, err := DecodeSessionReceipt(terminal)
	if err != nil {
		t.Fatalf("session ended with %q instead of a receipt: %v", terminal, err)
	}
	if got := signed.Receipt.Completion; got != proof.CompletionTruncated {
		t.Fatalf("completion = %q, want %q for a stream the TEE ended", got, proof.CompletionTruncated)
	}
	if string(signed.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("the cut receipt was signed under a different epoch than the one it was cut for")
	}
	if string(downlink) != "first-frame" {
		t.Fatalf("delivered %q, want the frame the provider managed to send", downlink)
	}
	if signed.Receipt.ResponseBytes != uint64(len("first-frame")) {
		t.Fatalf("attested response bytes = %d, want the bytes that were delivered",
			signed.Receipt.ResponseBytes)
	}
}

// TestTheCutFollowsTheRotation: the deadline belongs to the signer the process
// serves now, not the one the session opened under. A rotation publishes an
// epoch that expires later, so the session it lands on gets that much more room
// — cutting it on the opening epoch's schedule would end a session that fresh
// evidence could have carried to its natural end.
//
// The wait is deliberately longer than the opening epoch's whole remaining
// margin: without the watcher re-reading the live signer the cut would already
// have happened, and the assertions below would see a truncated receipt under
// the opening key.
func TestTheCutFollowsTheRotation(t *testing.T) {
	conn := newBlockingSessionConn([]byte("first-frame"))
	cell := &atomic.Pointer[proof.Signer]{}
	opening := epochWithNitroLeaf(t, time.Now().Add(rootShared.SNPSigningMargin+3*time.Second))
	cell.Store(proof.NewSigner(opening))
	env := cellEnv(t, cell)
	ss := newCellSession(t, env, cell, conn)

	peer, stop := relayOverWebsocket(t, ss)
	defer stop()

	rotated := epochWithNitroLeaf(t, time.Now().Add(rootShared.SNPSigningMargin+30*time.Second))
	cell.Store(proof.NewSigner(rotated))

	// Past the instant the opening epoch's deadline would have cut the session.
	time.Sleep(3 * time.Second)
	// Now let the provider end the session on its own terms.
	if err := conn.Close(); err != nil {
		t.Fatalf("close the provider tunnel: %v", err)
	}

	downlink, terminal := readSessionTerminal(t, peer)
	signed, err := DecodeSessionReceipt(terminal)
	if err != nil {
		t.Fatalf("session ended with %q instead of a receipt: %v", terminal, err)
	}
	if got := signed.Receipt.Completion; got != proof.CompletionComplete {
		t.Fatalf("completion = %q, want %q: the session was cut on a deadline a rotation had already moved",
			got, proof.CompletionComplete)
	}
	if string(signed.Receipt.Attestation.KeyID) != string(rotated.identity.KeyID[:]) {
		t.Fatal("the terminal receipt does not name the epoch the session was still able to use")
	}
	if string(downlink) != "first-frame" {
		t.Fatalf("delivered %q, want the frame the provider sent", downlink)
	}
}

// TestWatchSigningDeadlineIgnoresUntrackedEvidence: evidence without a readable
// NitroTPM leaf carries no expiry on the TEE side, so there is no deadline for
// a session to be cut at — the same tracked=false that keeps Execute from
// inventing a bound. The simulation and the harness both run on evidence like
// this, and a watcher that fired there would end every session early for a
// deadline that does not exist.
func TestWatchSigningDeadlineIgnoresUntrackedEvidence(t *testing.T) {
	env := cellEnv(t, &atomic.Pointer[proof.Signer]{})
	stop := make(chan struct{})
	defer close(stop)

	select {
	case <-env.service.watchSigningDeadline(stop):
		t.Fatal("an epoch with no readable leaf produced a deadline out of nothing")
	case <-time.After(100 * time.Millisecond):
	}
}
