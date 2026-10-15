// Package metrics carries the TEE's instrumentation out of the enclave.
//
// The enclave's own channel is the serial console: about 64 KiB, shared with
// boot messages, kernel output and TLS handshake errors, and exhausted by a few
// hundred instrumented requests. So the TEE also keeps its records behind a
// listener an operator pulls from. The detail is then bounded by a ring in
// memory rather than by the console, and the console window becomes a courtesy
// copy instead of the only one.
//
// What this endpoint serves is internal telemetry: which stage of which request
// took how long, keyed by a random job ID. It carries no user payload, no
// credential and no key material — the TEE's record of a request names the
// provider, the host and the shape of the call, never what was asked or
// answered. That is the boundary the rest of this package lives inside too (see
// tee.TimingRecord), and it is why the endpoint is read-only and
// unauthenticated by design: a deployment restricts it at the network layer, so
// a scraper does not have to be handed a certificate to ask a question whose
// answer has no secrets in it. It listens on loopback unless a deployment says
// otherwise.
package metrics

import (
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// DefaultRetain is how many request records a store keeps when a caller names
// no size.
//
// Four thousand records is a few megabytes of bookkeeping (a record is under a
// kilobyte, mostly its stage list), which is nothing on the instances this runs
// on. In exchange it is about an hour of continuous traffic at one request a
// second and days at the rate a profiling session actually runs, so a puller
// has to be asleep at the wheel to lose the window it wanted.
const DefaultRetain = 4096

// maxRetain bounds what a caller can ask for, so a typo in a flag cannot turn
// into an unbounded allocation on an instance whose memory is not the TEE's to
// spend. A retained record and its stage list run to roughly half a kilobyte,
// so this is about thirty megabytes: large next to the default, small next to
// the enclave's memory, and a ceiling a deployment can see rather than one it
// discovers.
const maxRetain = 1 << 16

// entry is one retained record with the sequence number it was stored under.
//
// The sequence is assigned by the store rather than taken from the record: it
// is what a puller pages with, and it has to keep meaning "later" even after
// the ring has evicted the records in between.
type entry struct {
	seq uint64
	rec tee.TimingRecord
}

// Store retains the TEE's instrumentation for an external pull.
//
// It is a tee.TimingSink, and it is safe for concurrent use: records arrive
// from handler goroutines and from a stall watcher per in-flight request, while
// a puller reads the ring from its own connection.
type Store struct {
	service string
	retain  int

	mu        sync.Mutex
	ring      []entry
	head      int
	count     int
	next      uint64
	total     uint64
	dropped   uint64
	aggregate *tee.TimingAggregate
}

// NewStore returns a store retaining retain records. A retain of zero or less
// means DefaultRetain, and anything past maxRetain is refused down to it.
func NewStore(service string, retain int) *Store {
	if retain <= 0 {
		retain = DefaultRetain
	}
	if retain > maxRetain {
		retain = maxRetain
	}
	return &Store{
		service: service,
		retain:  retain,
		ring:    make([]entry, retain),
		next:    1,
	}
}

// Retain is how many records the store keeps.
func (s *Store) Retain() int { return s.retain }

// TimingRequest implements tee.TimingSink.
//
// A stall is stored like any other record: it is the one report that describes a
// request that has not finished, and a pull that dropped it would lose exactly
// the condition somebody started looking for.
func (s *Store) TimingRequest(rec tee.TimingRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count == s.retain {
		// Full: the oldest record's slot is the one the new record takes.
		s.ring[s.head] = entry{seq: s.next, rec: rec}
		s.head = (s.head + 1) % s.retain
		s.dropped++
	} else {
		s.ring[(s.head+s.count)%s.retain] = entry{seq: s.next, rec: rec}
		s.count++
	}
	s.next++
	s.total++
}

// TimingAggregate implements tee.TimingSink: the last summary the TEE emitted is
// kept so that one pull returns both the detail and the shape of it.
func (s *Store) TimingAggregate(agg tee.TimingAggregate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := agg
	kept.Stages = append([]tee.TimingStat(nil), agg.Stages...)
	s.aggregate = &kept
}

// snapshot is what one pull returns: the records the ring holds plus the state
// of the ring itself.
type snapshot struct {
	service   string
	entries   []entry
	retained  int
	total     uint64
	dropped   uint64
	aggregate *tee.TimingAggregate
}

// snapshot returns every retained record, oldest first.
//
// There is no paging and no filtering: a pull is "everything you have", which is
// what an operator asking the TEE what happened wants, and the ring is small
// enough (four thousand records is a couple of megabytes) that asking for less
// would only add a query surface and a class of wrong answers about where a
// window starts. A caller that polls keeps its own cursor by sequence.
func (s *Store) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := snapshot{
		service:   s.service,
		retained:  s.count,
		total:     s.total,
		dropped:   s.dropped,
		aggregate: s.aggregate,
	}
	snap.entries = make([]entry, 0, s.count)
	for i := 0; i < s.count; i++ {
		snap.entries = append(snap.entries, s.ring[(s.head+i)%s.retain])
	}
	return snap
}
