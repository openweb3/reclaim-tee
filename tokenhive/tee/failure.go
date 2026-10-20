package tee

import (
	"context"
	"errors"
	"net"
	"strings"
)

// A failed exchange used to reach the Hub as one of two completion states, and
// the reason died inside the TEE. That is enough to decide whether to charge
// and not enough to decide who to tell: a TEE that ran out of its own time
// looked exactly like a provider that dropped the stream, and the Hub told the
// provider to go check its network.
//
// This file is the missing half. It names the reason in a closed vocabulary and
// keeps the phase it happened in, so the Hub can route it to the component that
// owns it.
//
// What is here is observation, not blame. Whether a class is the provider's to
// answer for is the Hub's business — it is the party that schedules providers,
// writes their failure pages, and knows which of them is behind a tunnel that
// just went quiet. The TEE only says what it saw.

// FailureClass names why an exchange did not complete.
//
// The vocabulary is closed and small on purpose: every value maps to a
// different thing for an operator to go and look at, and a class that would
// send two operators to the same place does not belong here.
type FailureClass string

const (
	// FailureRequestTimeout is the exchange's own Request.Timeout elapsing
	// while it was still running — the TEE stopped waiting, nobody else did.
	// The stage says what it was waiting on: a dial that never returned, a
	// TLS handshake that never finished, headers that never arrived, a body
	// that stalled mid-stream.
	FailureRequestTimeout FailureClass = "request_timeout"

	// FailureCallerGone is the caller leaving: writing a chunk to it failed,
	// or the exchange's context was cancelled. The Hub hung up, or the buyer
	// did and the Hub cut the request with it.
	//
	// A cancellation the TEE raises itself, the exchange-budget stop-loss in
	// Execute, lands here too. It is not the caller's doing, but it is the same
	// fact from the provider's side: the exchange was ended on this side of the
	// tunnel, not upstream. That is the only thing this class is for.
	FailureCallerGone FailureClass = "caller_gone"

	// FailureResponseTooLarge is the job's MaxResponseBytes cap being reached.
	// The cap is the Hub's own policy, applied by the TEE, so the response was
	// cut by the side that asked for it.
	FailureResponseTooLarge FailureClass = "response_too_large"

	// FailureDial is no stream to the provider being established at all: the
	// relay tunnel is down, the provider's agent is not attached, or opening
	// the stream never returned. Nothing was sent and nothing was spent.
	//
	// A dial that times out is a dial failure, not a request timeout: the
	// exchange never got far enough to be waiting on the upstream, and what
	// stalls here is the tunnel, not the provider's thinking.
	FailureDial FailureClass = "dial_failed"

	// FailureTLSHandshake is the TLS handshake to the upstream failing. It
	// terminates inside the TEE over a stream that is already open, so it is
	// either the upstream's certificate or this enclave's trust store — never
	// the bytes of a request.
	FailureTLSHandshake FailureClass = "tls_handshake_failed"

	// FailureUpstreamClosed is the connection ending with no status line at
	// all, or in the middle of the body.
	//
	// It is the widest class here, because from inside the TEE the cases are
	// one event: the stream ended. The upstream closing, a reset somewhere on
	// the way through, and the Hub closing a stream it could not attach to an
	// agent all look the same from here — a relay stream cannot tell a refusal
	// from a close, since the peer's only way to refuse is to close. A Hub
	// asking "was anyone even attached?" already knows the answer.
	FailureUpstreamClosed FailureClass = "upstream_closed"

	// FailureReadTimeout is a read timing out for a reason that is not the
	// exchange's own bound — an inner deadline, a socket timeout the transport
	// did not set from Request.Timeout. Kept apart from FailureRequestTimeout
	// because the two point at different things: one at the TEE's
	// configuration, the other at whatever set the clock that expired.
	FailureReadTimeout FailureClass = "read_timeout"

	// FailureOther is a failure this version cannot place. It is also where a
	// Hub lands on a class a newer TEE invented, and that is deliberate: an
	// unrecognised class must never be read as "the provider did it".
	FailureOther FailureClass = "other"
)

// Failure is why an exchange did not complete, as the TEE observed it.
//
// It travels on the wire as the payload of an `event: failure` frame, and it is
// deliberately not signed. A receipt's field set is frozen the moment a
// signature covers it, and this vocabulary is still being learned: which
// classes exist, and what a Hub should do with each, will change as failures
// actually happen. The frame rides the attested TLS connection, so its
// provenance is the measured enclave like everything else on that connection;
// what it is not is portable evidence, and nothing settles on it today. When
// something does, it gets a receipt field — and by then the classes worth
// signing will be known rather than guessed.
type Failure struct {
	// Class is what went wrong.
	Class FailureClass `json:"class"`

	// Stage is the phase of the exchange it happened in, one of the Stage*
	// names the timing record uses. Present when the transport could tell,
	// which is every failure that crossed the wire; empty for a refusal or a
	// local error that never reached a connection.
	Stage string `json:"stage,omitempty"`

	// Cold reports that the exchange had opened a new connection, so the
	// failure is the cost of establishing one rather than of using it.
	Cold bool `json:"cold,omitempty"`
}

// String renders the failure the way it reads in a log or an error detail:
// `dial_failed (cold, stage=dial)`. The class alone when there is nothing to
// add, which is the common case for a failure the caller caused.
func (f Failure) String() string {
	if f.Stage == "" && !f.Cold {
		return string(f.Class)
	}
	var b strings.Builder
	b.WriteString(string(f.Class))
	b.WriteString(" (")
	if f.Cold {
		b.WriteString("cold")
		if f.Stage != "" {
			b.WriteString(", ")
		}
	}
	if f.Stage != "" {
		b.WriteString("stage=")
		b.WriteString(f.Stage)
	}
	b.WriteString(")")
	return b.String()
}

// ClassifyFailure names why an exchange did not complete, and returns nil for
// one that did.
//
// The three inputs are the three things the service can still see once the
// transport has returned:
//
//   - err, what Transport.Do returned — carrying a *StageError when the failure
//     crossed the wire, and ErrRequestTimeout when the TEE's own bound ended it;
//   - stopErr, what the relay callback raised: the byte cap, or the caller's own
//     failure while it was being written to;
//   - contextErr, the exchange context's Err() — the only way to tell "the
//     caller cancelled me" from "the socket broke", since a cancelled exchange
//     surfaces as an ordinary socket timeout once the transport pokes the
//     deadline.
//
// The order of the cases is the whole design, because several of them are true
// at once:
//
//  1. What the relay raised beats what the transport returned: if the caller
//     stopped taking bytes, the transport's "i/o timeout" describes the
//     consequence, not the cause.
//  2. Stage before deadline. A dial that timed out is a tunnel that never
//     opened, and calling it request_timeout would point an operator at the
//     TEE's timeout configuration instead of at the thing that never answered.
//  3. Deadline before read timeout, for the same reason in the other
//     direction: the exchange's own bound is a fact about this deployment,
//     while "a read timed out" is a fact about the wire.
//  4. Anything left at a wire stage is a connection that ended early. That is
//     the only way an exchange gets that far and returns an error that is not
//     a timeout, so it needs no error-type matching — which matters, because
//     a relayed stream reports a deadline as io.EOF, not as a net.Error.
func ClassifyFailure(err, stopErr, contextErr error) *Failure {
	if err == nil && stopErr == nil {
		return nil
	}
	failure := &Failure{Class: FailureOther}
	var stage *StageError
	if errors.As(err, &stage) {
		failure.Stage, failure.Cold = stage.Stage, stage.Cold
	}

	switch {
	case errors.Is(stopErr, ErrResponseBodyTooLarge):
		failure.Class = FailureResponseTooLarge
	case stopErr != nil:
		failure.Class = FailureCallerGone
	case failure.Stage == StageDial:
		failure.Class = FailureDial
	case failure.Stage == StageTLS:
		failure.Class = FailureTLSHandshake
	case errors.Is(err, ErrRequestTimeout):
		failure.Class = FailureRequestTimeout
	case errors.Is(contextErr, context.Canceled):
		failure.Class = FailureCallerGone
	case isTimeout(err):
		failure.Class = FailureReadTimeout
	case failure.Stage == StageWrite, failure.Stage == StageTTFB, failure.Stage == StageBody:
		failure.Class = FailureUpstreamClosed
	}
	return failure
}

// isTimeout reports whether err is a timeout the transport did not attribute to
// Request.Timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
