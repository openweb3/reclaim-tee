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

// TestExecuteRequestRoundTrip checks the wire type survives canonical CBOR,
// which is what makes the Hub's client and this service interchangeable.
func TestExecuteRequestRoundTrip(t *testing.T) {
	body := []byte(`{"model":"m","stream":true}`)
	original := ExecuteRequest{
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
	decoded, err := DecodeExecuteRequest(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Spec.Provider != original.Spec.Provider {
		t.Errorf("provider = %q, want %q", decoded.Spec.Provider, original.Spec.Provider)
	}
	if !bytes.Equal(decoded.Body, original.Body) {
		t.Errorf("body = %q, want %q", decoded.Body, original.Body)
	}
	if decoded.Job().Spec.Provider != original.Spec.Provider {
		t.Error("Job() must carry the spec through")
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

// TestServeExecuteClearsTheBodyReadDeadline pins that the bound on reading the
// request body does not outlive the read. The deadline is set on the same
// socket the SSE answer streams over, and net/http keeps a background read
// armed on that socket for the whole request: a deadline left in place expires
// under a long execution, fails that background read, and makes the server
// cancel the request context — cutting a healthy job mid-stream for no reason
// other than its duration. A wrapper that consumes the body before calling in
// (a logging or metering layer, a test harness) is enough to arm it.
func TestServeExecuteClearsTheBodyReadDeadline(t *testing.T) {
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader([]byte("not-canonical-cbor")))
	ServeExecute(nil, rec, req)

	if len(rec.deadlines) != 2 {
		t.Fatalf("SetReadDeadline calls = %d, want 2 (one bound, one clear)", len(rec.deadlines))
	}
	if rec.deadlines[0].IsZero() {
		t.Fatal("the body read was not bounded by a deadline")
	}
	if !rec.deadlines[1].IsZero() {
		t.Fatalf("the read deadline was left set (%v); it would cut any execution that outlives it", rec.deadlines[1])
	}
}
