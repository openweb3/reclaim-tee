package providers

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

const maxResponseHeaderBytes = 64 << 10

// HTTPResponseFramer detects the end of one authenticated HTTP response. It
// shares the strict provider parser, but never treats temporary silence as EOF.
// Interim responses and tunnels are unsupported by the existing proof parser.
type HTTPResponseFramer struct {
	parser  *HTTPResponseParser
	method  string
	headers []byte
	started bool
	err     error
}

func NewHTTPResponseFramer(requestMethod string) *HTTPResponseFramer {
	return &HTTPResponseFramer{parser: newHTTPResponseParser(true), method: requestMethod}
}

func (f *HTTPResponseFramer) Complete() bool { return f.err == nil && f.parser.Response.Complete }

func (f *HTTPResponseFramer) OnChunk(data []byte) error {
	if f.err != nil {
		return f.err
	}
	f.err = f.consume(data)
	return f.err
}

func (f *HTTPResponseFramer) consume(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if f.Complete() {
		return fmt.Errorf("application data follows complete HTTP response")
	}
	if !f.started {
		f.headers = append(f.headers, data...)
		end := bytes.Index(f.headers, []byte("\r\n\r\n"))
		if end < 0 {
			if len(f.headers) > maxResponseHeaderBytes {
				return fmt.Errorf("HTTP response headers exceed limit")
			}
			return nil
		}
		end += 4
		if end > maxResponseHeaderBytes {
			return fmt.Errorf("HTTP response headers exceed limit")
		}
		line, _, _ := bytes.Cut(f.headers[:end], []byte("\r\n"))
		parts := strings.SplitN(string(line), " ", 3)
		if len(parts) < 2 || (parts[0] != "HTTP/1.1" && parts[0] != "HTTP/1.0") || len(parts[1]) != 3 {
			return fmt.Errorf("invalid HTTP response status line")
		}
		status, err := strconv.Atoi(parts[1])
		if err != nil || status < 100 || status > 599 {
			return fmt.Errorf("invalid HTTP response status")
		}
		// Reject interim responses, including 101 protocol switches. An Upgrade
		// header on a final response does not switch protocols (RFC 9110, 7.8).
		if status < 200 {
			return fmt.Errorf("interim responses and protocol upgrades are unsupported by the proof parser")
		}
		if strings.EqualFold(f.method, "CONNECT") {
			return fmt.Errorf("CONNECT responses are unsupported")
		}
		if err := f.parser.OnChunk(f.headers[:end]); err != nil {
			return err
		}
		te := f.parser.Response.Headers["transfer-encoding"]
		if value, ok := f.parser.Response.Headers["content-length"]; ok && value == "" {
			return fmt.Errorf("empty Content-Length")
		}
		if _, ok := f.parser.Response.Headers["transfer-encoding"]; ok && te == "" {
			return fmt.Errorf("empty Transfer-Encoding")
		}
		if te != "" && !strings.EqualFold(strings.TrimSpace(te), "chunked") {
			return fmt.Errorf("unsupported HTTP Transfer-Encoding")
		}
		noBody := strings.EqualFold(f.method, "HEAD") || status == 204 || status == 304
		if noBody {
			// The downstream proof parser has no request-method context and
			// cannot validate a HEAD/304 representation length without a body.
			if te != "" || f.parser.remainingBodyBytes > 0 {
				return fmt.Errorf("bodyless response with representation framing is unsupported by the proof parser")
			}
			f.parser.remainingBodyBytes = 0
			f.parser.complete = true
			f.parser.Response.Complete = true
		}
		data = f.headers[end:]
		f.headers = nil
		f.started = true
	}
	if len(data) > 0 {
		if err := f.parser.OnChunk(data); err != nil {
			return err
		}
	}
	if f.parser.Response.Complete {
		// A single input can include extra bytes after the declared boundary.
		// StreamEnded checks this even when OnChunk just became complete.
		return f.parser.StreamEnded()
	}
	return nil
}

func (f *HTTPResponseFramer) StreamEnded() error {
	if f.err != nil {
		return f.err
	}
	f.err = f.parser.StreamEnded()
	return f.err
}
