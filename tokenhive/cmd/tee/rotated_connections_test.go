package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
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
		e.track(c, http.StateNew)
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
	e.track(fresh, http.StateNew)
	e.track(fresh, http.StateActive)
	e.track(fresh, http.StateIdle)
	if fresh.isClosed() {
		t.Fatal("a connection accepted under the current epoch was retired")
	}
}

// TestRotationForcesPeersToReconnect is the property a verifier depends on:
// after a rotation no peer keeps answering over a connection whose certificate
// belongs to the previous epoch, so the next request re-handshakes and sees the
// key its receipts will name.
func TestRotationForcesPeersToReconnect(t *testing.T) {
	e := newEpochConnections()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.RemoteAddr)
	}))
	server.Config.ConnState = e.track
	server.Start()
	defer server.Close()

	client := server.Client()
	get := func() string {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	first := get()
	if reused := get(); reused != first {
		t.Fatal("the test client is not reusing connections, so it cannot show one being retired")
	}

	e.rotate()
	// The close travels to the peer, which only learns of it when it next reads.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if next := get(); next != first {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a peer kept serving over a connection from the previous epoch")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
