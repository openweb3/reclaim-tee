package main

import (
	"io"
	"strings"
	"sync"
	"time"
)

// listenerLog is the http.Server ErrorLog sink for the TEE's listeners. It
// exists because a fail-closed listener can erase the only diagnostics an
// enclave has.
//
// net/http logs one line per rejected handshake. While the TEE refuses
// handshakes — the state its attested epoch's margin puts it in — a Hub that
// keeps retrying produces several a second, and the serial console keeps ~64 KiB.
// A real incident showed the window holding nothing but 679 copies of "TEE
// platform is not ready" reaching back about five minutes, with the loader's
// boot lines, the [loader] SSL_CERT_FILE report and any kernel message about the
// attestation device long since evicted. The one channel that survives a broken
// log sink had been flooded by the reporter of a single condition.
//
// So identical failures are collapsed rather than repeated: the first few are
// printed verbatim, then at most one line a minute carrying the running count.
// The signal is preserved (an operator still sees that it is *still* failing,
// and how often), the reason is preserved (the first line is the full text), and
// the console is not consumed by it.
type listenerLog struct {
	out io.Writer
	// now is a seam for tests; nil means time.Now.
	now func() time.Time

	mu     sync.Mutex
	reason map[string]*reasonState
}

const (
	// listenerLogVerbatim is how many lines of one reason are printed in full
	// before collapsing to a periodic count.
	listenerLogVerbatim = 3
	// listenerLogReport is how often a collapsed reason re-reports itself.
	listenerLogReport = time.Minute
)

type reasonState struct {
	printed    int
	suppressed int
	lastReport time.Time
}

func newListenerLog(out io.Writer) *listenerLog {
	return &listenerLog{out: out, reason: make(map[string]*reasonState)}
}

func (l *listenerLog) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	key := handshakeReason(line)

	now := time.Now
	if l.now != nil {
		now = l.now
	}
	t := now()

	l.mu.Lock()
	st := l.reason[key]
	if st == nil {
		st = &reasonState{}
		l.reason[key] = st
	}
	st.suppressed++
	switch {
	case st.printed < listenerLogVerbatim:
		st.printed++
		st.suppressed = 0
		st.lastReport = t
		l.mu.Unlock()
		return len(p), l.emit(line + "\n")
	case t.Sub(st.lastReport) < listenerLogReport:
		l.mu.Unlock()
		return len(p), nil
	default:
		n := st.suppressed
		st.suppressed = 0
		st.lastReport = t
		l.mu.Unlock()
		return len(p), l.emit(suppressNote(t, key, n))
	}
}

func (l *listenerLog) emit(s string) error {
	_, err := io.WriteString(l.out, s)
	return err
}

// handshakeReason drops the peer address from a handshake error line so that
// identical failures collapse: "http: TLS handshake error from 10.0.1.151:33474:
// TEE platform is not ready" becomes "TEE platform is not ready". Addresses are
// exactly the part that differs between two lines describing one condition.
func handshakeReason(line string) string {
	const marker = "handshake error from "
	i := strings.Index(line, marker)
	if i < 0 {
		return line
	}
	rest := line[i+len(marker):]
	j := strings.Index(rest, ": ")
	if j < 0 {
		return rest
	}
	return rest[j+2:]
}

func suppressNote(t time.Time, key string, n int) string {
	return t.Format("2006/01/02 15:04:05") +
		" http: TLS handshake error (" + itoa(n) + " more since the last report): " + key + "\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
