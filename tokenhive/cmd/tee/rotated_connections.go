package main

import (
	"net"
	"net/http"
	"sync"
)

// epochConnections retires the connections a rotation leaves behind.
//
// A rotation replaces the key this process signs receipts with, but it does not
// replace the certificate an already-established TLS connection presented: that
// was fixed at its handshake. A verifier that binds a receipt to the connection
// that carried it — which is the whole point of RA-TLS, and what the Hub does —
// then sees a receipt naming the rotated key arrive over a certificate carrying
// the previous one, and is right to refuse the pair. Nothing is wrong with
// either half; they simply belong to different epochs.
//
// The connection is the part that can be retired, so it is. A peer that has to
// re-handshake re-verifies the hardware evidence on the way in and gets the
// certificate whose key its receipts will name, which is the pairing it is
// checking for anyway.
//
// Retirement waits for the connection to be idle. An in-flight request holds
// the service it started under and finishes signing with that epoch's key, so
// it is already consistent with the certificate it is answering over — cutting
// it would turn a correct answer into a failed one. A connection is closed when
// it is idle at the rotation, or the moment it becomes idle after one.
type epochConnections struct {
	mu sync.Mutex
	// current is the epoch this process is signing under, counted rather than
	// named: what matters is only whether a connection predates it.
	current int64
	// accepted maps a live connection to the epoch it was accepted under, and
	// idle holds the subset that is between requests and therefore closable.
	accepted map[net.Conn]int64
	idle     map[net.Conn]bool
}

func newEpochConnections() *epochConnections {
	return &epochConnections{accepted: map[net.Conn]int64{}, idle: map[net.Conn]bool{}}
}

// track is the listener's ConnState hook. It is called for every connection the
// server accepts, including hijacked ones, which leave through StateHijacked
// and are then owned by the handler rather than by this bookkeeping.
func (e *epochConnections) track(c net.Conn, state http.ConnState) {
	e.mu.Lock()
	switch state {
	case http.StateNew:
		e.accepted[c] = e.current
	case http.StateActive:
		delete(e.idle, c)
	case http.StateIdle:
		// A connection that went idle under an epoch it did not start in has
		// just finished the last request it could answer consistently.
		if accepted, known := e.accepted[c]; known && accepted != e.current {
			delete(e.accepted, c)
			e.mu.Unlock()
			c.Close()
			return
		}
		e.idle[c] = true
	case http.StateClosed, http.StateHijacked:
		delete(e.accepted, c)
		delete(e.idle, c)
	}
	e.mu.Unlock()
}

// rotate records that this process has adopted another epoch and closes the
// connections already sitting idle under the previous one, so a peer's pooled
// connection is gone before its next request rather than after it. Connections
// still serving are left to track, which closes them as they fall idle.
func (e *epochConnections) rotate() {
	e.mu.Lock()
	e.current++
	stale := make([]net.Conn, 0, len(e.idle))
	for c := range e.idle {
		if e.accepted[c] != e.current {
			stale = append(stale, c)
			delete(e.accepted, c)
			delete(e.idle, c)
		}
	}
	e.mu.Unlock()
	// Closing outside the lock: Close blocks on the connection, not on this map,
	// and track is called from the connection's own goroutine.
	for _, c := range stale {
		c.Close()
	}
}
