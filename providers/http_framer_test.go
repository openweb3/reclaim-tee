package providers

import (
	"fmt"
	"strings"
	"testing"
)

func TestHTTPResponseFramer(t *testing.T) {
	tests := []struct {
		name, method, response        string
		complete, invalid, invalidEOF bool
	}{
		{name: "content length", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", complete: true},
		{name: "content length trailing space", response: "HTTP/1.1 200 OK\r\nContent-Length: 5 \r\n\r\nhello", complete: true},
		{name: "content length trailing tab", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\t\r\n\r\nhello", complete: true},
		{name: "content length surrounding OWS", response: "HTTP/1.1 200 OK\r\nContent-Length: \t 5 \t\r\n\r\nhello", complete: true},
		{name: "zero length", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", complete: true},
		{name: "zero length OWS", response: "HTTP/1.1 200 OK\r\nContent-Length: 0 \t\r\n\r\n", complete: true},
		{name: "chunk trailers", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\nX-Trailer: value\r\n\r\n", complete: true},
		{name: "upgrade advertisement content length", response: "HTTP/1.1 200 OK\r\nUpgrade: h2,h2c\r\nConnection: Upgrade, Keep-Alive\r\nContent-Length: 5\r\n\r\nhello", complete: true},
		{name: "upgrade advertisement chunked", response: "HTTP/1.1 200 OK\r\nUpgrade: h2,h2c\r\nConnection: Upgrade, close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", complete: true},
		{name: "upgrade advertisement redirect", response: "HTTP/1.1 302 Found\r\nUpgrade: h2\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", complete: true},
		{name: "upgrade advertisement close delimited", response: "HTTP/1.1 404 Not Found\r\nUpgrade: h2,h2c\r\nConnection: Upgrade, close\r\n\r\nhello"},
		{name: "upgrade required response", response: "HTTP/1.1 426 Upgrade Required\r\nUpgrade: TLS/1.3\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n", complete: true},
		{name: "upgrade advertisement trailing bytes", response: "HTTP/1.1 200 OK\r\nUpgrade: h2,h2c\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\nx", invalid: true},
		{name: "upgrade advertisement ambiguous framing", response: "HTTP/1.1 200 OK\r\nUpgrade: h2,h2c\r\nConnection: Upgrade\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", invalid: true},
		{name: "unknown length", response: "HTTP/1.1 200 OK\r\n\r\nhello"},
		{name: "head no length", method: "HEAD", response: "HTTP/1.1 200 OK\r\n\r\n", complete: true},
		{name: "no content", response: "HTTP/1.1 204 No Content\r\n\r\n", complete: true},
		{name: "short body", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi", invalidEOF: true},
		{name: "missing zero chunk", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", invalidEOF: true},
		{name: "missing trailers end", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: value\r\n", invalidEOF: true},
		{name: "invalid trailer", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\ninvalid\r\n\r\n", invalid: true},
		{name: "framing trailer", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n", invalid: true},
		{name: "missing data CRLF", response: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello", invalidEOF: true},
		{name: "incomplete headers", response: "HTTP/1.1 200 OK\r\nContent-Length:", invalidEOF: true},
		{name: "trailing bytes", response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello", invalid: true},
		{name: "zero trailing bytes", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx", invalid: true},
		{name: "duplicate CL", response: "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", invalid: true},
		{name: "empty CL", response: "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n", invalid: true},
		{name: "OWS-only CL", response: "HTTP/1.1 200 OK\r\nContent-Length: \t \r\n\r\n", invalid: true},
		{name: "CL embedded space", response: "HTTP/1.1 200 OK\r\nContent-Length: 1 0\r\n\r\n", invalid: true},
		{name: "CL embedded tab", response: "HTTP/1.1 200 OK\r\nContent-Length: 1\t0\r\n\r\n", invalid: true},
		{name: "CL vertical tab", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\v\r\n\r\nhello", invalid: true},
		{name: "CL nonbreaking space", response: "HTTP/1.1 200 OK\r\nContent-Length: 5\u00a0\r\n\r\nhello", invalid: true},
		{name: "CL OWS extra body", response: "HTTP/1.1 200 OK\r\nContent-Length: 5 \t\r\n\r\nhello!", invalid: true},
		{name: "CL OWS short body", response: "HTTP/1.1 200 OK\r\nContent-Length: 5 \t\r\n\r\nhi", invalidEOF: true},
		{name: "ambiguous framing", response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", invalid: true},
		{name: "unsupported interim", response: "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", invalid: true},
		{name: "unsupported upgrade", response: "HTTP/1.1 101 Switching Protocols\r\n\r\n", invalid: true},
		{name: "unsupported HTTP2 upgrade", response: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n", invalid: true},
		{name: "unsupported websocket upgrade", response: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", invalid: true},
		{name: "unsupported connect", method: "CONNECT", response: "HTTP/1.1 200 OK\r\n\r\n", invalid: true},
		{name: "unsupported connect with upgrade advertisement", method: "CONNECT", response: "HTTP/1.1 200 OK\r\nUpgrade: h2\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n", invalid: true},
		{name: "unsupported head representation", method: "HEAD", response: "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", invalid: true},
		{name: "header limit", response: "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", maxResponseHeaderBytes), invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, step := range []int{1, 7, len(tt.response)} {
				f := NewHTTPResponseFramer(tt.method)
				var err error
				for offset := 0; offset < len(tt.response); offset += step {
					err = f.OnChunk([]byte(tt.response[offset:min(offset+step, len(tt.response))]))
					if err != nil {
						break
					}
				}
				if (err != nil) != tt.invalid {
					t.Fatalf("step %d: OnChunk error = %v, invalid=%v", step, err, tt.invalid)
				}
				if tt.invalid {
					if f.Complete() {
						t.Fatal("invalid response marked complete")
					}
					continue
				}
				if f.Complete() != tt.complete {
					t.Fatalf("step %d: complete=%v want=%v", step, f.Complete(), tt.complete)
				}
				if err := f.StreamEnded(); (err != nil) != tt.invalidEOF {
					t.Fatalf("step %d: EOF error=%v, invalidEOF=%v", step, err, tt.invalidEOF)
				}
			}
		})
	}
}

func TestHTTPResponseParserContentLengthOWS(t *testing.T) {
	for _, tc := range []struct {
		name, value, strictValue, body string
	}{
		{"space", "5 ", "5 ", "hello"},
		{"tab", "5\t", "5\t", "hello"},
		{"surrounding", " \t5 \t", "5 \t", "hello"},
		{"zero", " \t0 \t", "0 \t", ""},
	} {
		const statusLine = "HTTP/1.1 200 OK\r\n"
		headerLine := "Content-Length: " + tc.value
		const nextHeader = "X-After: keep"
		wire := statusLine + headerLine + "\r\n" + nextHeader + "\r\n\r\n" + tc.body
		for _, strict := range []bool{false, true} {
			for _, step := range []int{1, 7, len(wire)} {
				t.Run(fmt.Sprintf("%s/strict=%t/step=%d", tc.name, strict, step), func(t *testing.T) {
					p := newHTTPResponseParser(strict)
					input := []byte(wire)
					for offset := 0; offset < len(input); offset += step {
						if err := p.OnChunk(input[offset:min(offset+step, len(input))]); err != nil {
							t.Fatalf("OnChunk: %v", err)
						}
					}
					if !p.Response.Complete || string(p.Response.Body) != tc.body {
						t.Fatalf("complete=%t body=%q, want complete body=%q", p.Response.Complete, p.Response.Body, tc.body)
					}
					if err := p.StreamEnded(); err != nil {
						t.Fatalf("StreamEnded: %v", err)
					}
					wantValue := tc.value
					if strict {
						wantValue = tc.strictValue
					}
					if got := p.Response.Headers["content-length"]; got != wantValue {
						t.Errorf("stored Content-Length=%q, want %q", got, wantValue)
					}
					cl := p.Response.HeaderLowerToRanges["content-length"]
					if cl.Start != len(statusLine) || cl.Length != len(headerLine) {
						t.Errorf("Content-Length range=%+v, want start=%d length=%d", cl, len(statusLine), len(headerLine))
					}
					next := p.Response.HeaderLowerToRanges["x-after"]
					if next.Start != len(statusLine)+len(headerLine)+2 || next.Length != len(nextHeader) {
						t.Errorf("following header range changed: %+v", next)
					}
					bodyStart := len(wire) - len(tc.body)
					if p.Response.BodyStartIndex != bodyStart || p.Response.HeaderEndIdx != bodyStart-4 {
						t.Errorf("header/body offsets changed: header=%d body=%d", p.Response.HeaderEndIdx, p.Response.BodyStartIndex)
					}
					if string(input) != wire {
						t.Error("original response bytes changed")
					}
				})
			}
		}
	}
}
