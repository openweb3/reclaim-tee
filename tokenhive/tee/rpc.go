package tee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// The Hub↔TEE interface is a single RPC: POST /v1/execute carrying a canonical
// Job, answered by an SSE stream with three kinds of frame in a fixed order:
//
//  1. 响应开始 — event: start, one frame carrying the upstream status code and
//     the allowlisted response headers (see ForwardResponseHeaders), emitted
//     before any chunk. This is what lets the Hub decide how to handle the
//     stream before its first byte: a 200 with text/event-stream is relayed
//     as a stream, a 401 or 429 is surfaced as the error it is.
//  2. 响应片段 — data: frames carrying the raw response body, unchanged. The
//     receipt's stream hash commits to exactly these bytes.
//  3. 执行结束 — event: receipt, the signed proof of the exchange. The receipt
//     binds all three parts: the status (StatusCode), the forwarded headers
//     (ResponseHeadersHash), and the body (StreamHash).
//
// Everything else — pricing, quota, scheduling — lives on the Hub side of
// this seam.
const (
	// ExecuteContentType is the request content type of the single RPC.
	ExecuteContentType = "application/cbor"

	// EventStart names the first frame of a response: the upstream status code
	// plus the response headers the Hub is allowed to see, as JSON.
	EventStart = "start"

	// EventReceipt names the final SSE frame, whose data is the base64 of a
	// canonical SignedReceipt.
	EventReceipt = "receipt"

	// EventError names the frame a refusal produces. A refusal has no receipt,
	// so a caller that treats "no receipt frame" and "error frame" as the same
	// case loses the reason; they are deliberately distinct.
	EventError = "error"

	// MaxExecuteBody bounds the canonical-CBOR Job the TEE will read. A job
	// spec plus its request body is small; a caller declaring a gigabyte is not
	// submitting a job, it is attempting to exhaust the enclave's memory before
	// any policy check runs.
	MaxExecuteBody = 8 << 20

	// executeReadTimeout bounds how long the TEE spends reading that body, so
	// a peer that opens the stream and dribbles bytes cannot pin a connection.
	// It is deliberately local to /v1/execute: /v1/session hijacks its socket
	// into a WebSocket whose read deadline must stay clear for the session's
	// whole life.
	executeReadTimeout = 30 * time.Second
)

// startFrame is the JSON payload of an EventStart frame. Headers are a map so
// the encoding matches Go's http.Header shape; values keep the order the
// upstream sent them in. JSON escapes newlines, so the whole frame fits one
// SSE data line.
type startFrame struct {
	Status  uint32              `json:"status"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// DecodeJob parses the canonical-CBOR body of a job endpoint. Decoding
// enforces canonical form, so a request whose bytes were rewritten into an
// equivalent but non-canonical encoding is rejected rather than accepted under
// a different hash than the one it will be judged by.
func DecodeJob(data []byte) (Job, error) {
	var job Job
	if err := canonical.Unmarshal(data, &job); err != nil {
		return Job{}, err
	}
	return job, nil
}

// ServeExecute is the server half of the single RPC. It wraps the real
// Service: nothing here re-implements the TEE, it only adapts the execution
// result onto the wire.
//
// A refusal is reported as an EventError frame, so the caller learns why
// without a credential ever being touched.
func ServeExecute(svc *Service, w http.ResponseWriter, r *http.Request) {
	// Bound the request twice before reading a byte: a read deadline so a peer
	// that dribbles the body cannot pin the connection, and a size limit so a
	// declared length cannot allocate unbounded memory. The read of one extra
	// byte past the cap is what distinguishes "exactly at the cap" from "over
	// it" without trusting Content-Length.
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(executeReadTimeout))
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxExecuteBody+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(raw) > MaxExecuteBody {
		// The deadline stays on: bytes are still arriving, and net/http drains
		// up to 256 KiB of them after this handler returns so the connection can
		// be reused. Cleared here, that drain would be unbounded and a peer that
		// dribbles an oversized chunked body could pin the connection — exactly
		// what the deadline exists to prevent.
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	// The body is in hand and at EOF, so nothing is left for net/http to drain
	// and the bound has done its work. It must not outlive the read: the
	// deadline belongs to the same socket the streamed answer rides on, and
	// net/http keeps a background read armed on that socket for the life of the
	// request. Left set, it expires under a long execution, that background read
	// fails, and the server cancels the request context — cutting every job that
	// outlives the window mid-stream, however healthy it is. Bounding the body
	// read must not bound the answer.
	_ = control.SetReadDeadline(time.Time{})
	job, err := DecodeJob(raw)
	if err != nil {
		http.Error(w, "decode request: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	onChunk := func(chunk []byte) error {
		writeChunkFrame(w, chunk)
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	onStart := func(resp Response) {
		writeStartFrame(w, resp)
		if flusher != nil {
			flusher.Flush()
		}
	}

	res, err := svc.Execute(r.Context(), job, onChunk, onStart)
	if err != nil {
		writeEvent(w, flusher, EventError, err.Error())
		return
	}
	enc, err := res.Receipt.EncodeCanonical()
	if err != nil {
		writeEvent(w, flusher, EventError, "encode receipt: "+err.Error())
		return
	}
	writeEvent(w, flusher, EventReceipt, base64.StdEncoding.EncodeToString(enc))
}

// writeStartFrame emits the response-start frame: the upstream status and the
// allowlisted headers, as JSON on a single data line. It is always written
// before the first chunk frame, so a caller can commit its own response
// status before relaying a single body byte.
func writeStartFrame(w io.Writer, resp Response) {
	frame := startFrame{Status: resp.StatusCode, Headers: resp.Headers}
	enc, err := json.Marshal(frame)
	if err != nil {
		// Header names and values are strings; json.Marshal cannot fail on
		// them. A defensive fallback keeps a corrupt header from killing the
		// whole stream.
		enc = []byte(`{"status":` + fmt.Sprint(resp.StatusCode) + `}`)
	}
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", EventStart, enc)
}

// writeChunkFrame emits one response chunk as an SSE data event.
//
// The framing has to round-trip bytes exactly, because the receipt's stream
// hash covers the chunks the TEE wrote and the Hub checks it against the ones
// it read. Two details make that work:
//
//   - A chunk is written as one `data:` line per line it contains, since SSE
//     joins multi-line data with \n and a raw newline inside a chunk would
//     otherwise close the frame early and split one chunk into two.
//   - The conventional single space after `data:` is always emitted, and the
//     reader strips exactly one, so a chunk that itself begins with spaces
//     survives. Only leading whitespace is conventional; trailing whitespace is
//     payload and must not be trimmed, which is why this does not use a
//     general trim.
//
// A chunk is never skipped, including an empty one: StreamingHasher counts
// empty writes, so a dropped heartbeat would change both the chunk count and
// the hash, and every receipt for that job would fail to verify.
func writeChunkFrame(w io.Writer, chunk []byte) {
	for _, line := range bytes.Split(chunk, []byte("\n")) {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}

// writeEvent emits one SSE frame. Entries are flushed individually because the
// whole point of the stream is that the caller sees chunks as they arrive —
// a buffered stream would make TTFT unmeasurable and defeat the format.
func writeEvent(w http.ResponseWriter, flusher http.Flusher, event, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	if flusher != nil {
		flusher.Flush()
	}
}

// DecodeReceiptFrame parses the data line of an EventReceipt frame.
func DecodeReceiptFrame(data string) (proof.SignedReceipt, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return proof.SignedReceipt{}, fmt.Errorf("decode receipt frame: %w", err)
	}
	var signed proof.SignedReceipt
	if err := canonical.Unmarshal(raw, &signed); err != nil {
		return proof.SignedReceipt{}, fmt.Errorf("parse receipt: %w", err)
	}
	return signed, nil
}
