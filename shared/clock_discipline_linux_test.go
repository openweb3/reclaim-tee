//go:build linux && !mobile

package shared

import (
	"net"
	"testing"
	"time"
)

func TestSntpOffset(t *testing.T) {
	base := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		t1, t2, t3, t4 time.Time
		want           time.Duration
	}{
		{
			// Symmetric 40ms path, server exactly aligned with us: the local
			// clock is correct and the offset must come out as zero.
			name: "aligned clock yields no offset",
			t1:   base,
			t2:   base.Add(20 * time.Millisecond),
			t3:   base.Add(20 * time.Millisecond),
			t4:   base.Add(40 * time.Millisecond),
			want: 0,
		},
		{
			// Server clock is 5s ahead of ours. On a symmetric path both halves
			// report it, so the offset is the full 5s and the local clock is
			// behind by that much.
			name: "local clock behind by 5s",
			t1:   base,
			t2:   base.Add(5*time.Second + 20*time.Millisecond),
			t3:   base.Add(5*time.Second + 20*time.Millisecond),
			t4:   base.Add(40 * time.Millisecond),
			want: 5 * time.Second,
		},
		{
			// Asymmetric path (server replied faster than it received): the two
			// halves disagree by 10ms and the average absorbs half of it, which
			// is the property that makes the handshake cancel round-trip delay.
			name: "asymmetric latency splits evenly",
			t1:   base,
			t2:   base.Add(5*time.Second + 10*time.Millisecond),
			t3:   base.Add(5*time.Second + 20*time.Millisecond),
			t4:   base.Add(40 * time.Millisecond),
			want: 5*time.Second - 5*time.Millisecond,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sntpOffset(tc.t1, tc.t2, tc.t3, tc.t4); got != tc.want {
				t.Fatalf("offset = %v, want %v", got, tc.want)
			}
		})
	}
}

// The timestamp codec is what makes the offset exact, so it is pinned against
// known NTP encodings rather than only round-tripped through itself: a full
// second plus a half must come back bit-identical. The 2037 case covers the
// era rollover: the wire format wraps to a 1900-era value there, and only era
// inference can decode it back to the date that was sent.
func TestNTPTimestampRoundTrip(t *testing.T) {
	tests := []time.Time{
		time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 10, 12, 0, 0, 500000000, time.UTC),
		time.Date(2037, 6, 1, 0, 0, 1, 500000000, time.UTC),
	}
	for _, want := range tests {
		b := make([]byte, 8)
		putNTPTimestamp(b, want)
		if got := ntpTimestamp(b); !got.Equal(want) {
			t.Fatalf("round trip of %v = %v", want, got)
		}
	}
}

// A guest that has drifted for a month is still tens of seconds behind, far
// inside the ceiling. This asserts the decoder maps the NTP epoch offset
// correctly, since an off-by-epoch bug here would silently shift every
// correction by 68 years.
func TestNTPTimestampEpochOffset(t *testing.T) {
	b := make([]byte, 8)
	putNTPTimestamp(b, time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC))
	if got := ntpTimestamp(b).Unix(); got != 0 {
		t.Fatalf("unix epoch decoded as %d, want 0", got)
	}
}

// The ceiling is the guard that stops one bad reply from moving the clock by an
// arbitrary amount. Only the refusal path is exercised here: the accepting path
// calls clock_settime, and a unit test has no business stepping the clock of
// whatever machine it runs on.
func TestApplyClockStepRejectsAbsurdOffset(t *testing.T) {
	for _, absurd := range []time.Duration{maxClockStep + time.Second, -(maxClockStep + time.Second)} {
		if err := applyClockStep(absurd); err == nil {
			t.Fatalf("a %v correction must be refused", absurd)
		}
	}
	// A zero offset must be a no-op rather than a syscall: the common case is a
	// guest whose clock is already right, and that path must stay side-effect free.
	if err := applyClockStep(0); err != nil {
		t.Fatalf("a zero correction should be a no-op, got %v", err)
	}
}

// The reply checks are what keep an off-path attacker from steering the clock
// with a single injected packet, so each rejection path is exercised against a
// real socket rather than a mock.
func TestQuerySNTPRejectsBadReplies(t *testing.T) {
	tests := []struct {
		name    string
		respond func(req []byte) []byte
	}{
		{
			name: "client mode is not a server reply",
			respond: func(req []byte) []byte {
				resp := validReply(req)
				resp[0] = 0x23 // mode 3, echoed straight back
				return resp
			},
		},
		{
			name: "kiss-o'-death signals a unusable server",
			respond: func(req []byte) []byte {
				resp := validReply(req)
				resp[1] = 0 // stratum 0 == KoD
				return resp
			},
		},
		{
			name: "leap indicator says the clock is unsynchronized",
			respond: func(req []byte) []byte {
				resp := validReply(req)
				resp[0] = 0xE4 // LI 3, VN 4, mode 4
				return resp
			},
		},
		{
			name: "stratum 16 means the server has no reference either",
			respond: func(req []byte) []byte {
				resp := validReply(req)
				resp[1] = 16
				return resp
			},
		},
		{
			name: "origin stamp does not match what we sent",
			respond: func(req []byte) []byte {
				resp := validReply(req)
				resp[24]++ // corrupt the echoed origin
				return resp
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveOneReply(t, tc.respond)
			if _, err := querySNTP(srv, time.Second); err == nil {
				t.Fatal("expected the malformed reply to be rejected")
			}
		})
	}
}

// The positive path, with a server clock one second ahead: querySNTP must
// report the local clock as behind by roughly that amount. This is the only
// test that proves the wire format we actually send is one a server can answer.
func TestQuerySNTPAcceptsWellFormedReply(t *testing.T) {
	const serverLead = time.Second
	srv := serveOneReply(t, func(req []byte) []byte {
		resp := validReply(req)
		// Server receive/transmit stamps are stamped a second after our
		// transmit, and it answers on a link-local path fast enough that the
		// round trip is negligible.
		putNTPTimestamp(resp[32:40], time.Now().Add(serverLead))
		putNTPTimestamp(resp[40:48], time.Now().Add(serverLead))
		return resp
	})
	offset, err := querySNTP(srv, 2*time.Second)
	if err != nil {
		t.Fatalf("well-formed reply rejected: %v", err)
	}
	if offset < serverLead-50*time.Millisecond || offset > serverLead+50*time.Millisecond {
		t.Fatalf("offset = %v, want about %v", offset, serverLead)
	}
}

// validReply builds a server reply that passes every check, so each rejection
// test can corrupt exactly one field and attribute the rejection to it.
func validReply(req []byte) []byte {
	resp := make([]byte, 48)
	resp[0] = 0x24                // LI 0, VN 4, Mode 4 (server)
	resp[1] = 2                   // stratum 2
	copy(resp[24:32], req[40:48]) // origin echoes our transmit
	putNTPTimestamp(resp[32:40], time.Now().Add(-time.Millisecond))
	putNTPTimestamp(resp[40:48], time.Now())
	return resp
}

// serveOneReply starts a UDP listener that answers a single query with the given
// builder, and returns its address. The listener closes with the test.
func serveOneReply(t *testing.T, respond func(req []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 48)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pc.WriteTo(respond(buf[:n]), addr)
	}()
	return pc.LocalAddr().String()
}
