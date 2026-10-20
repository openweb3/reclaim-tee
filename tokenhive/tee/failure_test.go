package tee

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)

// TestClassifyFailure pins the vocabulary the Hub routes on: what the TEE saw
// has to come out as one class, and the cases that are true at the same time
// have to resolve the way the ordering in ClassifyFailure argues.
func TestClassifyFailure(t *testing.T) {
	at := func(stage string, cold bool, err error) error {
		return &StageError{Stage: stage, Cold: cold, Err: err}
	}
	timeout := func(err error) error {
		// Exactly what the transport does: both sentinels stay reachable
		// through the chain, so errors.Is finds ErrRequestTimeout and
		// errors.As still finds the stage.
		return fmt.Errorf("%w: %w", ErrRequestTimeout, err)
	}
	// os.ErrDeadlineExceeded is a net.Error whose Timeout is true, which is
	// what a socket read reports when a deadline fires under it.
	readDeadline := os.ErrDeadlineExceeded

	for _, tc := range []struct {
		name    string
		err     error
		stopErr error
		ctxErr  error
		want    *Failure
		wantNil bool
	}{
		{
			name:    "a completed exchange has no failure",
			wantNil: true,
		},
		{
			name: "no stream to the provider",
			err:  at(StageDial, true, errors.New("connection refused")),
			want: &Failure{Class: FailureDial, Stage: StageDial, Cold: true},
		},
		{
			name: "the handshake never finished",
			err:  at(StageTLS, true, errors.New("x509: certificate signed by unknown authority")),
			want: &Failure{Class: FailureTLSHandshake, Stage: StageTLS, Cold: true},
		},
		{
			name: "the TEE's own bound expired",
			err:  timeout(at(StageTTFB, true, readDeadline)),
			want: &Failure{Class: FailureRequestTimeout, Stage: StageTTFB, Cold: true},
		},
		{
			// A dial that times out never became a wait on the upstream, so it
			// is the tunnel's failure and not the exchange's own bound.
			name: "a dial that ran out of time is still a dial failure",
			err:  timeout(at(StageDial, true, readDeadline)),
			want: &Failure{Class: FailureDial, Stage: StageDial, Cold: true},
		},
		{
			name:    "the byte cap stopped it",
			err:     at(StageBody, false, ErrResponseBodyTooLarge),
			stopErr: ErrResponseBodyTooLarge,
			want:    &Failure{Class: FailureResponseTooLarge, Stage: StageBody},
		},
		{
			// The caller's own error is what the transport returns, so the
			// class has to come from the relay rather than from the transport.
			name:    "the caller stopped taking bytes",
			err:     at(StageBody, false, errors.New("write: broken pipe")),
			stopErr: errors.New("write: broken pipe"),
			want:    &Failure{Class: FailureCallerGone, Stage: StageBody},
		},
		{
			name:   "the caller cancelled while the TEE waited",
			err:    at(StageTTFB, true, readDeadline),
			ctxErr: context.Canceled,
			want:   &Failure{Class: FailureCallerGone, Stage: StageTTFB, Cold: true},
		},
		{
			// A cancellation reaches whatever the exchange was doing. A dial
			// that never returned reports the same context error a stall does,
			// and it is still the caller who ended it.
			name:   "the caller cancelled a dial",
			err:    at(StageDial, true, context.Canceled),
			ctxErr: context.Canceled,
			want:   &Failure{Class: FailureCallerGone, Stage: StageDial, Cold: true},
		},
		{
			name: "the upstream hung up before its status line",
			err:  at(StageTTFB, true, io.EOF),
			want: &Failure{Class: FailureUpstreamClosed, Stage: StageTTFB, Cold: true},
		},
		{
			name: "the upstream hung up mid-body",
			err:  at(StageBody, false, io.ErrUnexpectedEOF),
			want: &Failure{Class: FailureUpstreamClosed, Stage: StageBody},
		},
		{
			name: "a write that never landed",
			err:  at(StageWrite, false, io.ErrClosedPipe),
			want: &Failure{Class: FailureUpstreamClosed, Stage: StageWrite},
		},
		{
			name: "a read deadline this layer did not set",
			err:  at(StageBody, false, readDeadline),
			want: &Failure{Class: FailureReadTimeout, Stage: StageBody},
		},
		{
			name: "a failure with nowhere to put it",
			err:  errors.New("something else"),
			want: &Failure{Class: FailureOther},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyFailure(tc.err, tc.stopErr, tc.ctxErr)
			switch {
			case tc.wantNil:
				if got != nil {
					t.Fatalf("ClassifyFailure = %+v, want nil for a completed exchange", got)
				}
			case got == nil:
				t.Fatalf("ClassifyFailure = nil, want %+v", tc.want)
			case got.Class != tc.want.Class:
				t.Errorf("class = %q, want %q", got.Class, tc.want.Class)
			case got.Stage != tc.want.Stage:
				t.Errorf("stage = %q, want %q", got.Stage, tc.want.Stage)
			case got.Cold != tc.want.Cold:
				t.Errorf("cold = %v, want %v", got.Cold, tc.want.Cold)
			}
		})
	}
}

// TestFailureRendersTheWayAnOperatorReadsIt pins the string a Hub puts into a
// failure detail or a log line.
func TestFailureRendersTheWayAnOperatorReadsIt(t *testing.T) {
	for _, tc := range []struct {
		failure Failure
		want    string
	}{
		{Failure{Class: FailureCallerGone}, "caller_gone"},
		{Failure{Class: FailureDial, Stage: StageDial, Cold: true}, "dial_failed (cold, stage=dial)"},
		{Failure{Class: FailureUpstreamClosed, Stage: StageBody}, "upstream_closed (stage=body)"},
		{Failure{Class: FailureDial, Cold: true}, "dial_failed (cold)"},
	} {
		if got := tc.failure.String(); got != tc.want {
			t.Errorf("Failure.String() = %q, want %q", got, tc.want)
		}
	}
}
