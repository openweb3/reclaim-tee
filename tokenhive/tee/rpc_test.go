package tee

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// TestWriteStartFrame pins the exact bytes of the response-start frame: the
// upstream status and the relayed headers as JSON on one data line, emitted
// before the first chunk. The hub package parses this frame with encoding/json;
// this test fixes the wire format so the two halves cannot drift.
func TestWriteStartFrame(t *testing.T) {
	var buf bytes.Buffer
	writeStartFrame(&buf, Response{
		StatusCode: 200,
		Headers:    map[string][]string{"content-type": {"text/event-stream"}},
	})
	want := "event: start\ndata: {\"status\":200,\"headers\":{\"content-type\":[\"text/event-stream\"]}}\n\n"
	if got := buf.String(); got != want {
		t.Errorf("writeStartFrame() = %q, want %q", got, want)
	}
}

// TestWriteChunkFrame pins the exact bytes the server writes for one chunk.
//
// The client is tested against the same encodings in the hub package, but that
// only proves the two agree if the encodings themselves are right. This test
// is the other half: it fixes the wire format so a change here breaks here,
// rather than surfacing as receipts that no longer verify.
func TestWriteChunkFrame(t *testing.T) {
	cases := []struct {
		name  string
		chunk string
		want  string
	}{
		{"plain", "hello", "data: hello\n\n"},
		{"trailing space is payload", "hello ", "data: hello \n\n"},
		{"leading spaces survive the conventional space", "  hi", "data:   hi\n\n"},
		{"empty chunk is still a frame", "", "data: \n\n"},
		{"embedded newline becomes two data lines", "a\nb", "data: a\ndata: b\n\n"},
		{"trailing newline is preserved", "a\n", "data: a\ndata: \n\n"},
		{"bare newline", "\n", "data: \ndata: \n\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeChunkFrame(&buf, []byte(tc.chunk))
			if got := buf.String(); got != tc.want {
				t.Errorf("writeChunkFrame(%q) = %q, want %q", tc.chunk, got, tc.want)
			}
		})
	}
}

// TestJobRoundTrip checks the wire type survives canonical CBOR, which is what
// makes the Hub's client and this service interchangeable — and what lets one
// job object serve both endpoints.
func TestJobRoundTrip(t *testing.T) {
	body := []byte(`{"model":"m","stream":true}`)
	original := Job{
		Spec: jobs.Spec{
			Version:  jobs.VersionV1,
			JobID:    make([]byte, jobs.JobIDLength),
			Provider: "openai",
			Method:   "POST",
			Host:     "api.openai.com",
			Path:     "/v1/chat/completions",
			Headers:  map[string]string{"content-type": "application/json"},
			Nonce:    make([]byte, jobs.MinNonceLength),
		},
		Body: body,
	}
	encoded, err := original.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeJob(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Spec.Provider != original.Spec.Provider {
		t.Errorf("provider = %q, want %q", decoded.Spec.Provider, original.Spec.Provider)
	}
	if !bytes.Equal(decoded.Body, original.Body) {
		t.Errorf("body = %q, want %q", decoded.Body, original.Body)
	}
}

// TestServeExecuteBoundsTheRequestBody pins the read limit on the single RPC:
// the enclave must refuse an oversized body before it allocates for it. svc is
// deliberately nil — the size check has to fire before the service is ever
// consulted, so a nil service is the assertion that it did.
func TestServeExecuteBoundsTheRequestBody(t *testing.T) {
	oversize := bytes.Repeat([]byte("x"), MaxExecuteBody+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(oversize))
	rec := httptest.NewRecorder()
	ServeExecute(nil, rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body status = %d, want 413", rec.Code)
	}

	// A body exactly at the cap is not oversize: it is a (here malformed)
	// request that must be refused for its content, not its size.
	atCap := bytes.Repeat([]byte("x"), MaxExecuteBody)
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(atCap))
	rec = httptest.NewRecorder()
	ServeExecute(nil, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("at-cap body status = %d, want 400 (decode failure, not 413)", rec.Code)
	}
}

// TestServeExecuteClearsTheBodyReadDeadline pins both halves of the bound on
// reading the request body. Once the body is in hand the deadline must go: it
// sits on the same socket the SSE answer streams over, and net/http keeps a
// background read armed on that socket for the whole request, so a deadline
// left in place expires under a long execution, fails that background read,
// and makes the server cancel the request context — cutting a healthy job
// mid-stream for no reason but its duration. On the oversize path the opposite
// holds: bytes are still arriving and net/http drains up to 256 KiB of them
// after the handler returns, so the deadline must stay on or a peer dribbling
// an oversized chunked body pins the connection.
func TestServeExecuteClearsTheBodyReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  []byte
		clear bool
	}{
		{"body_in_hand", []byte("not-canonical-cbor"), true},
		{"oversize_body", bytes.Repeat([]byte("x"), MaxExecuteBody+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(tc.body))
			ServeExecute(nil, rec, req)

			if len(rec.deadlines) == 0 || rec.deadlines[0].IsZero() {
				t.Fatal("the body read was not bounded by a deadline")
			}
			cleared := len(rec.deadlines) == 2 && rec.deadlines[1].IsZero()
			if tc.clear && !cleared {
				t.Fatalf("read deadline left set (%v); it would cut any execution that outlives it", rec.deadlines)
			}
			if !tc.clear && cleared {
				t.Fatal("read deadline cleared with the body still arriving; the post-handler drain would be unbounded")
			}
			if len(rec.deadlines) > 2 {
				t.Fatalf("unexpected deadline churn: %v", rec.deadlines)
			}
		})
	}
}

// deadlineRecorder is an httptest.ResponseRecorder that also satisfies the
// SetReadDeadline half of http.ResponseController, recording what the handler
// asks the socket for.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}
