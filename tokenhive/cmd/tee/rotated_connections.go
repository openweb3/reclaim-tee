package main

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// epochConnections retires the connections a rotation leaves behind.
//
// A rotation replaces the key this process signs receipts with, but it does not
// replace the certificate an already-established TLS connection presented: that
// was fixed at its handshake. A new request put on such a connection would be
// served by an epoch the process has already left, so it is refused and the peer
// is told to reconnect — cheaper than executing a request the process is in the
// middle of rotating out from under.
//
// This is not what makes a receipt trustworthy, and it is not a pairing check.
// Nothing here compares a receipt to the connection that carried it: this Hub
// pins the attested application on both halves rather than comparing them to
// each other — the handshake under -tee-verify=attestation and the receipt
// verifier both check -expected-app — and the service keeps the pairing only
// where keeping it is free. An exchange admitted under one epoch and signed
// under the next is settled with the newer key rather than abandoned (see
// Service.perform), and a session that outlives a rotation is signed the same
// way (see Session.Receipt), so a receipt may well name a later key than the
// connection it arrives on. What remains here is the narrower invariant that
// costs nothing: no request is served over a connection the process has stopped
// signing for.
//
// The connection is the part that can be retired, so it is, in two steps that
// cover each other:
//
//   - accept stamps every connection with the epoch it was accepted under, and
//     guard refuses a request that arrives under a later one. This is the part
//     that has to be per request rather than per connection: an HTTP/2
//     connection can start a new stream while an old one still holds it active,
//     and a peer can put a request on an idle connection in the instant between
//     a rotation and the close below.
//   - track closes those connections — at the rotation if they are idle, and
//     otherwise the moment they fall idle — so the refusal above stays a
//     backstop rather than something a peer meets on the normal path.
//
// A request already in flight when the rotation lands is not cut here: the
// service prefers the signer the exchange started under and falls back to the
// live one when that signer has run out of room, so cutting it would turn an
// answer this process is still able to produce and attest into a failure.
type epochConnections struct {
	// current is the epoch this process signs under, counted rather than named:
	// what matters is only whether a connection predates it. It is read on every
	// request, so it is atomic rather than behind the mutex below.
	current atomic.Int64

	// mu guards the bookkeeping: every live connection with the epoch it was
	// accepted under, and the subset that is between requests and so closable.
	mu       sync.Mutex
	accepted map[net.Conn]int64
	idle     map[net.Conn]bool
}

// acceptedEpoch keys the epoch stamp in a connection's context.
type acceptedEpoch struct{}

func newEpochConnections() *epochConnections {
	return &epochConnections{accepted: map[net.Conn]int64{}, idle: map[net.Conn]bool{}}
}

// accept is the listener's ConnContext hook, and the one place a connection's
// epoch is decided. The stamp goes into the connection's context as well as the
// bookkeeping so guard reads what was recorded at the handshake rather than
// re-deriving it later, when the two could no longer agree.
func (e *epochConnections) accept(ctx context.Context, c net.Conn) context.Context {
	epoch := e.current.Load()
	e.mu.Lock()
	e.accepted[c] = epoch
	e.mu.Unlock()
	return context.WithValue(ctx, acceptedEpoch{}, epoch)
}

// guard refuses a request that reached this process over a connection from an
// earlier epoch, before the service can spend a sequence number, a credential
// or an upstream exchange on bytes this process is already rotating away from.
// Answering 503 says what is true — this connection is retired, open another —
// and costs the peer a reconnect rather than a request it was charged for.
//
// The 503 carries tee.EpochRetiredHeader so the Hub can tell this refusal from
// any other 503 and retry it on a fresh connection. Without the marker a Hub
// could only guess, and guessing wrong is expensive: retrying a refusal the
// service had already acted on would execute — and bill — the same job twice.
// The marker is what makes the retry safe to automate, because nothing behind
// this handler has run for that request.
func (e *epochConnections) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if epoch, stamped := r.Context().Value(acceptedEpoch{}).(int64); stamped && epoch != e.current.Load() {
			// Connection is HTTP/1.1's way of saying this; HTTP/2 rejects the
			// header outright and ends the connection through track instead.
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			w.Header().Set(tee.EpochRetiredHeader, "1")
			http.Error(w, "connection belongs to a retired attestation epoch; reconnect", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// track is the listener's ConnState hook. StateNew is deliberately not handled:
// accept has already registered the connection, and recording it a second time
// could stamp it with a later epoch than its context carries.
//
// StateHijacked ends this bookkeeping's interest in a connection because it
// ends the server's: /v1/session upgrades to a WebSocket the handler owns, and
// closing it from here would cut a live session out from under it. A session
// that outlives a rotation signs with the rotated key on purpose (see
// Session.Receipt) — unbounded work cannot be held to the epoch it opened
// under — so the pairing a session presents is the service's to describe, not
// something the listener can retire.
func (e *epochConnections) track(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateActive:
		e.mu.Lock()
		delete(e.idle, c)
		e.mu.Unlock()
	case http.StateIdle:
		// A connection that fell idle under an epoch it did not start in has
		// just finished the last request it could answer consistently.
		e.mu.Lock()
		epoch, known := e.accepted[c]
		stale := known && epoch != e.current.Load()
		if stale {
			delete(e.accepted, c)
			delete(e.idle, c)
		} else {
			e.idle[c] = true
		}
		e.mu.Unlock()
		if stale {
			c.Close()
		}
	case http.StateClosed, http.StateHijacked:
		e.mu.Lock()
		delete(e.accepted, c)
		delete(e.idle, c)
		e.mu.Unlock()
	}
}

// rotate records that this process has adopted another epoch and closes the
// connections already sitting idle under the previous one, so a peer's pooled
// connection is gone before its next request rather than after it. Connections
// still serving are left to track, which closes them as they fall idle.
//
// The epoch moves first. A connection that slips into a request between that
// and its close is then already stale to guard, which refuses it — the close
// races the peer, the stamp does not.
func (e *epochConnections) rotate() {
	epoch := e.current.Add(1)
	e.mu.Lock()
	stale := make([]net.Conn, 0, len(e.idle))
	for c := range e.idle {
		if e.accepted[c] != epoch {
			stale = append(stale, c)
			delete(e.accepted, c)
			delete(e.idle, c)
		}
	}
	e.mu.Unlock()
	// Closing outside the lock: Close blocks on the connection, not on this
	// map, and it makes the server report StateClosed from that connection's
	// own goroutine, which takes the same lock.
	for _, c := range stale {
		c.Close()
	}
}
