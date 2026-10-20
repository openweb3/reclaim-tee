package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// stageOf digs the stage out of a Do error. Every failure that crossed the wire
// has to carry one: without it the Hub can only say "the response did not
// finish", which is what it could say before any of this existed.
func stageOf(t *testing.T, err error) *tee.StageError {
	t.Helper()
	var staged *tee.StageError
	if !errors.As(err, &staged) {
		t.Fatalf("error %v carries no stage", err)
	}
	if staged.Stage == "" {
		t.Fatal("stage is empty; a failure that crossed the wire must name its phase")
	}
	return staged
}

// TestDoNamesTheStageAFailureHappenedIn pins that the three phases that look
// identical from outside — no stream, no headers, no rest of the body — are
// distinguishable from the error alone, and that cold says whether the exchange
// paid for a connection.
func TestDoNamesTheStageAFailureHappenedIn(t *testing.T) {
	t.Run("dial", func(t *testing.T) {
		// A port nothing listens on: the dial fails before a stream exists.
		gone := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		host := hostOf(gone)
		gone.Close()

		cm := newTestManager(t)
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "POST", Host: host, Path: "/v1/x", Body: []byte("{}")}),
			func([]byte) error { return nil })
		staged := stageOf(t, err)
		if staged.Stage != tee.StageDial {
			t.Errorf("stage = %q, want %q for a connection that was never opened", staged.Stage, tee.StageDial)
		}
		if !staged.Cold {
			t.Error("cold = false on a dial failure; the exchange never had a connection to reuse")
		}
	})

	t.Run("ttfb", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		}))
		defer srv.Close()

		cm := newTestManager(t)
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
			func([]byte) error { return nil })
		if staged := stageOf(t, err); staged.Stage != tee.StageTTFB {
			t.Errorf("stage = %q, want %q before any response byte", staged.Stage, tee.StageTTFB)
		}
	})

	t.Run("body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "data: one\n\n")
			w.(http.Flusher).Flush()
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		}))
		defer srv.Close()

		cm := newTestManager(t)
		_, err := cm.Do(context.Background(),
			testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
			func([]byte) error { return nil })
		if staged := stageOf(t, err); staged.Stage != tee.StageBody {
			t.Errorf("stage = %q, want %q for a stream cut mid-body", staged.Stage, tee.StageBody)
		}
	})
}

// TestDoMarksItsOwnTimeout pins the one failure the transport alone can
// attribute: Request.Timeout is applied here, so when it fires the exchange
// context is still healthy and the error underneath is an ordinary socket
// timeout. Without the tag the service reads that as the upstream going quiet
// and blames the provider for the TEE's own bound.
func TestDoMarksItsOwnTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	cm := newTestManager(t)
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}"), Timeout: 50 * time.Millisecond}),
		func([]byte) error { return nil })
	if !errors.Is(err, tee.ErrRequestTimeout) {
		t.Fatalf("error = %v, want an error carrying tee.ErrRequestTimeout", err)
	}
	if staged := stageOf(t, err); staged.Stage != tee.StageTTFB {
		t.Errorf("stage = %q, want %q: the bound expired while waiting for headers", staged.Stage, tee.StageTTFB)
	}
}

// TestDoLeavesAnUntimedExchangeUntagged is the other half: a caller that set no
// bound of its own must never see the TEE's timeout sentinel, or the Hub would
// read every broken connection as the TEE having given up.
func TestDoLeavesAnUntimedExchangeUntagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	cm := newTestManager(t)
	_, err := cm.Do(context.Background(),
		testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")}),
		func([]byte) error { return nil })
	if errors.Is(err, tee.ErrRequestTimeout) {
		t.Fatalf("error = %v was tagged as the TEE's own timeout, but no bound was ever set", err)
	}
}

// TestDoReportsAWarmConnectionAsWarm pins that a pooled connection is reported
// as such: the same failure on a warm connection is a different thing to look
// at than one that never got a connection up.
func TestDoReportsAWarmConnectionAsWarm(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			fmt.Fprint(w, "data: one\n\n")
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer srv.Close()

	cm := newTestManager(t)
	first := testReq(tee.Request{Method: "POST", Host: hostOf(srv), Path: "/v1/x", Body: []byte("{}")})
	if _, err := cm.Do(context.Background(), first, func([]byte) error { return nil }); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err := cm.Do(context.Background(), first, func([]byte) error { return nil })
	if staged := stageOf(t, err); staged.Cold {
		t.Error("cold = true on a reused connection; the failure cost no dial")
	}
}

// racingClock is a context whose deadline has passed while Err still reports
// nil: the instant between a connection's deadline firing and the context's
// own timer waking up. That window is unreachable with the standard library's
// contexts, which is why it is spelled out here — it is exactly the window in
// which a timeout must not be mistaken for a closed upstream.
type racingClock struct{ deadline time.Time }

func (c racingClock) Deadline() (time.Time, bool) { return c.deadline, true }
func (c racingClock) Done() <-chan struct{}       { return nil }
func (c racingClock) Err() error                  { return nil }
func (c racingClock) Value(any) any               { return nil }

// TestTimedOutDecidesOnTheClockNotJustTheContext pins the one boundary where
// the two clocks here disagree. The connection deadline and the context
// deadline are two timers for the same instant, and a socket can report its
// own expiry before the context's timer wakes the goroutine that sets Err. If
// the tag were decided on Err alone, that microsecond would turn the TEE's own
// timeout into an upstream close, and the Hub would hand the provider a failure
// the TEE caused.
func TestTimedOutDecidesOnTheClockNotJustTheContext(t *testing.T) {
	sentinel := errors.New("i/o timeout")
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name    string
		ctx     context.Context
		timeout time.Duration
		err     error
		want    bool
	}{
		{"no failure to tag", expired, time.Minute, nil, false},
		{"no bound of its own", expired, 0, sentinel, false},
		{"the context already says so", expired, time.Minute, sentinel, true},
		{"the deadline passed before the context noticed",
			racingClock{deadline: time.Now().Add(-time.Millisecond)}, time.Minute, sentinel, true},
		{"still inside the bound",
			racingClock{deadline: time.Now().Add(time.Hour)}, time.Minute, sentinel, false},
		{"the caller cancelled, not the bound", cancelled, time.Minute, sentinel, false},
		{"a context with no deadline at all", context.Background(), time.Minute, sentinel, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(timedOut(tc.ctx, tc.timeout, tc.err), tee.ErrRequestTimeout); got != tc.want {
				t.Errorf("tagged = %v, want %v (err %v)", got, tc.want, timedOut(tc.ctx, tc.timeout, tc.err))
			}
		})
	}
}
