package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// fakeConn is a net.Conn that records only what this bookkeeping does to it.
type fakeConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// TestRotationRetiresConnectionsWithoutCuttingRequests states the whole contract
// in one place: a connection the rotation finds idle goes immediately, one that
// is mid-request survives until it has answered, and one accepted afterwards is
// left alone. The middle case is the one worth a test — cutting it would turn a
// request that was about to be answered consistently into a failed one.
func TestRotationRetiresConnectionsWithoutCuttingRequests(t *testing.T) {
	e := newEpochConnections()
	idle, serving := &fakeConn{}, &fakeConn{}
	for _, c := range []net.Conn{idle, serving} {
		e.accept(context.Background(), c)
		e.track(c, http.StateActive)
	}
	e.track(idle, http.StateIdle)

	e.rotate()

	if !idle.isClosed() {
		t.Fatal("an idle connection from the previous epoch was left in the peer's pool")
	}
	if serving.isClosed() {
		t.Fatal("a request in flight was cut by the rotation")
	}
	e.track(serving, http.StateIdle)
	if !serving.isClosed() {
		t.Fatal("a connection from the previous epoch was kept alive after answering")
	}

	fresh := &fakeConn{}
	e.accept(context.Background(), fresh)
	e.track(fresh, http.StateActive)
	e.track(fresh, http.StateIdle)
	if fresh.isClosed() {
		t.Fatal("a connection accepted under the current epoch was retired")
	}
}

// TestGuardRefusesRequestsFromARetiredEpoch covers what closing a connection
// cannot: a request that reached this process over a stale connection anyway —
// a peer that put one on an idle connection in the instant before the close, or
// a new HTTP/2 stream on a connection an older one is still holding active. It
// has to be refused before the service spends a sequence number or an upstream
// exchange on a receipt the Hub would reject.
func TestGuardRefusesRequestsFromARetiredEpoch(t *testing.T) {
	e := newEpochConnections()
	served := 0
	handler := e.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
	}))
	conn := &fakeConn{}
	ctx := e.accept(context.Background(), conn)
	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest("POST", "/v1/execute", nil).WithContext(ctx))
		return recorder
	}
	if got := request(); got.Code != http.StatusOK || served != 1 {
		t.Fatal("a request from the current epoch was refused", got.Code, served)
	}

	e.rotate()

	got := request()
	if got.Code != http.StatusServiceUnavailable {
		t.Fatal("a request over a retired connection was served", got.Code)
	}
	if served != 1 {
		t.Fatal("a retired connection reached the service")
	}
	if got.Header().Get("Connection") != "close" {
		t.Fatal("an HTTP/1.1 peer was not told to drop the retired connection")
	}
	// The marker is what lets the Hub retry this refusal automatically instead
	// of guessing whether the request was already executed.
	if got.Header().Get(tee.EpochRetiredHeader) != "1" {
		t.Fatal("a retired-epoch refusal was not marked, so a peer cannot tell it from any other 503")
	}
}

// TestRotationDoesNotStrandAHijackedSession states the boundary: a WebSocket
// the handler owns is not this bookkeeping's to close, and a rotation must not
// leave it holding a reference to it either.
func TestRotationDoesNotStrandAHijackedSession(t *testing.T) {
	e := newEpochConnections()
	session := &fakeConn{}
	e.accept(context.Background(), session)
	e.track(session, http.StateActive)
	e.track(session, http.StateHijacked)

	e.rotate()

	if session.isClosed() {
		t.Fatal("a rotation cut a live session out from under its handler")
	}
	e.mu.Lock()
	tracked := len(e.accepted) + len(e.idle)
	e.mu.Unlock()
	if tracked != 0 {
		t.Fatal("a hijacked connection was left in the bookkeeping", tracked)
	}
}

// TestRotationForcesPeersToReconnect is the property a verifier depends on:
// after a rotation no peer keeps answering over a connection whose certificate
// belongs to the previous epoch, so the next request re-handshakes and sees the
// key its receipts will name.
func TestRotationForcesPeersToReconnect(t *testing.T) {
	e := newEpochConnections()
	server := httptest.NewUnstartedServer(e.guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.RemoteAddr)
	})))
	server.Config.ConnContext = e.accept
	server.Config.ConnState = e.track
	server.Start()
	defer server.Close()

	client := server.Client()
	get := func() (int, string) {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	status, first := get()
	if status != http.StatusOK {
		t.Fatal("the first request was refused", status)
	}
	if _, reused := get(); reused != first {
		t.Fatal("the test client is not reusing connections, so it cannot show one being retired")
	}

	e.rotate()
	// The close travels to the peer, which only learns of it when it next reads.
	// Until it does, guard answers 503 over the retired connection rather than
	// serving it — either way the peer must end up on a new one.
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, next := get()
		if status == http.StatusOK && next != first {
			return
		}
		if status == http.StatusOK {
			t.Fatal("a peer kept being served over a connection from the previous epoch")
		}
		if time.Now().After(deadline) {
			t.Fatal("a peer never reached a connection from the current epoch")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
