package hub

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// ScriptedTEE is an in-memory stand-in for the TEE, for exercising Hub
// business rules at the cost of a function call.
//
// Pricing, quota, the ledger and gap detection are the parts of this system
// most likely to change, and all of them are pure logic once the TEE sits
// behind one interface. Running them against this keeps the loop in
// milliseconds and — more importantly — lets a test dictate exactly what the
// receipt says, including things a real TEE would rarely produce on demand: a
// 429, a truncated completion, a sequence number with a hole in it, a response
// large enough to overflow a price.
//
// This stands in for the TEE, not for the receipts. Build its replies with
// ScriptReceipt so the invariants the Hub checks are the real ones, and a
// stand-in cannot quietly disable the check it is supposed to be testing.
type ScriptedTEE struct {
	// Reply returns the result for the nth call, counted from 1. Nil means
	// every call fails; it is required so that a test cannot accidentally
	// run against an empty script and pass by doing nothing.
	Reply func(call int, spec jobs.Spec) (Result, error)

	// OpenReply, if set, returns a session tunnel for the nth session open.
	// When nil, OpenSession returns ErrSessionUnsupported. The two call
	// counters are independent so request/response and session tests can be
	// scripted without cross-talk.
	OpenReply func(call int, spec jobs.Spec) (SessionConn, error)

	mu        sync.Mutex
	calls     int
	openCalls int
}

// Execute implements TEE.
//
// A result whose Status is non-zero implies a response start: the receipt is
// bound to that start (its ResponseHeadersHash is filled in from the result's
// Headers, exactly as the real TEE signs what it forwarded), and onStart fires
// before the chunks, matching the real TEE's frame order. Chunks are forwarded
// before an error is returned, matching the real TEE: a job that failed
// mid-flight still delivered bytes, and the Hub has to be able to prove what
// it got.
func (s *ScriptedTEE) Execute(_ context.Context, spec jobs.Spec, _ []byte, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	s.mu.Lock()
	s.calls++
	call := s.calls
	s.mu.Unlock()

	if s.Reply == nil {
		return Result{}, errors.New("scripted tee has no Reply set")
	}
	res, err := s.Reply(call, spec)
	// A real enclave always answers about the job it was handed, so the scripted
	// one does too: a test that could script a receipt naming another request
	// would be testing a Hub behaviour no real TEE can produce, and one that
	// forgot to fill the binding in would quietly exercise less than it looks
	// like. (What such a receipt should do to the Hub is pinned in tee_test.go,
	// against the real client.)
	if specHash, herr := spec.Hash(); herr == nil {
		res.Receipt.Receipt.Provider = spec.Provider
		res.Receipt.Receipt.Host = spec.Host
		res.Receipt.Receipt.Path = spec.Path
		res.Receipt.Receipt.Model = spec.Model
		res.Receipt.Receipt.JobSpecHash = specHash[:]
	}
	if res.Status != 0 {
		// Bind the receipt to the start the Hub is about to be shown. The
		// receipt may already carry a hash (a test that crafts one); filling
		// it only when empty would let a stale hash survive, so the start
		// always wins — it is the ground truth for what the Hub acted on.
		h := tee.HashResponseHeaders(res.Headers)
		res.Receipt.Receipt.ResponseHeadersHash = h[:]
		if len(onStart) > 0 && onStart[0] != nil {
			onStart[0](tee.Response{StatusCode: res.Status, Headers: res.Headers})
		}
	}
	for _, chunk := range res.Chunks {
		if onChunk == nil {
			break
		}
		if cerr := onChunk(chunk); cerr != nil {
			return Result{Chunks: res.Chunks, Status: res.Status, Headers: res.Headers}, cerr
		}
	}
	return res, err
}

// Calls reports how many times Execute has been invoked. A test asserting that
// quota blocked dispatch checks this is zero rather than inferring it from the
// error, so a Hub that dispatched anyway cannot pass.
func (s *ScriptedTEE) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// OpenSession implements TEE. It dispatches to OpenReply if set, otherwise it
// reports sessions as unsupported — a Hub wired to a scripted (request/response
// only) stand-in must not silently gain a session it cannot back.
func (s *ScriptedTEE) OpenSession(_ context.Context, spec jobs.Spec) (SessionConn, error) {
	s.mu.Lock()
	s.openCalls++
	call := s.openCalls
	s.mu.Unlock()

	if s.OpenReply == nil {
		return nil, ErrSessionUnsupported
	}
	conn, err := s.OpenReply(call, spec)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// OpenCalls reports how many times OpenSession has been invoked.
func (s *ScriptedTEE) OpenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openCalls
}

// ScriptReceipt fills in the StreamHash that commits a receipt to chunks, so
// the receipt passes the check the Hub performs before settling.
//
// Without this a test has to compute the hash itself, and a test that gets it
// wrong produces a Hub that reports ErrStreamMismatch for a reason that has
// nothing to do with what it meant to test.
func ScriptReceipt(chunks [][]byte, r proof.Receipt) proof.Receipt {
	if len(r.JobID) == 0 {
		r.JobID = make([]byte, proof.JobIDLength)
		if _, err := rand.Read(r.JobID); err != nil {
			panic("scripted receipt: random job id: " + err.Error())
		}
	}
	hash := proof.HashResponseStream(r.JobID, chunks)
	r.StreamHash = hash[:]
	return r
}
