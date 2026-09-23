package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestListenerLogCollapsesRepeatedHandshakeFailures is the guard for the console
// being the last diagnostic channel. A fail-closed listener logs one line per
// rejected handshake, and a Hub that keeps asking produces several a second; a
// real incident left the serial console holding 679 copies of one sentence and
// nothing else, the loader's boot lines having been evicted within minutes.
//
// The collapsed line must still carry the reason and a count: an operator has to
// be able to tell "still failing, N more" from "recovered".
func TestListenerLogCollapsesRepeatedHandshakeFailures(t *testing.T) {
	var buf bytes.Buffer
	clock := time.Unix(1_700_000_000, 0)
	l := newListenerLog(&buf)
	l.now = func() time.Time { return clock }

	line := func(port int) []byte {
		return []byte("2026/09/20 07:35:35 http: TLS handshake error from 10.0.1.151:" +
			itoa(port) + ": TEE platform is not ready\n")
	}
	for i := 0; i < 50; i++ {
		if n, err := l.Write(line(33000 + i)); err != nil || n != len(line(33000+i)) {
			t.Fatalf("Write = (%d, %v), want the full length and no error", n, err)
		}
	}
	got := buf.String()
	if n := strings.Count(got, "TEE platform is not ready"); n != listenerLogVerbatim {
		t.Fatalf("printed %d verbatim lines, want %d: the console would be consumed by one condition", n, listenerLogVerbatim)
	}
	if strings.Contains(got, "more since the last report") {
		t.Fatal("reported a suppressed count inside the report interval")
	}

	// Past the interval the condition re-reports itself with the count, so a
	// listener that is still refusing handshakes is not mistaken for a recovered
	// one — the failure mode a plain "log once" would introduce.
	clock = clock.Add(2 * listenerLogReport)
	if _, err := l.Write(line(34000)); err != nil {
		t.Fatal(err)
	}
	got = buf.String()
	if !strings.Contains(got, "more since the last report") {
		t.Fatal("no suppressed-count line after the report interval")
	}
	if !strings.Contains(got, "TEE platform is not ready") {
		t.Fatal("the collapsed line dropped the reason it is collapsing")
	}
	if !strings.Contains(got, "more since the last report): TEE platform is not ready") {
		t.Fatal("the collapsed line did not count the suppressed failures")
	}
}

// TestListenerLogKeepsDistinctReasons: collapsing keys on the reason, not on
// "some handshake failed". Two different failures are two different incidents.
func TestListenerLogKeepsDistinctReasons(t *testing.T) {
	var buf bytes.Buffer
	l := newListenerLog(&buf)
	for _, reason := range []string{"TEE platform is not ready", "remote error: tls: bad certificate"} {
		for i := 0; i < 5; i++ {
			if _, err := l.Write([]byte("2026/09/20 07:35:35 http: TLS handshake error from 10.0.1.151:33" +
				itoa(i) + ": " + reason + "\n")); err != nil {
				t.Fatal(err)
			}
		}
	}
	got := buf.String()
	for _, want := range []string{"TEE platform is not ready", "bad certificate"} {
		if !strings.Contains(got, want) {
			t.Fatalf("collapsing merged two distinct failures; %q is missing from:\n%s", want, got)
		}
	}
}

// TestHandshakeReasonDropsThePeerAddress pins the normalisation: the address is
// the only part that differs between two lines describing one condition, so it
// must not be part of the key — nor, when the line has no address at all, may
// the reason be mangled into something unrecognisable.
func TestHandshakeReasonDropsThePeerAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026/09/20 07:35:35 http: TLS handshake error from 10.0.1.151:33474: TEE platform is not ready", "TEE platform is not ready"},
		{"http: TLS handshake error from [::1]:443: read: connection reset by peer", "read: connection reset by peer"},
		{"http: TLS handshake error", "http: TLS handshake error"},
		{"totally unrelated line", "totally unrelated line"},
	}
	for _, c := range cases {
		if got := handshakeReason(c.in); got != c.want {
			t.Errorf("handshakeReason(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
