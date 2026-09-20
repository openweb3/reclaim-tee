package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// OpenSession implements TEE by dialing the TEE's /v1/session WebSocket,
// submitting the upgrade handshake request, and handing back a raw byte tunnel.
//
// Two message orientations mirror the TEE seam: the request and the terminal
// receipt ride as Text/control, and every tunnel byte rides as Binary. The Hub
// never parses a frame here — it only moves bytes and remembers the receipt.
func (t *HTTPTEE) OpenSession(ctx context.Context, spec jobs.Spec) (SessionConn, error) {
	if t.SessionURL == "" {
		return nil, ErrSessionUnsupported
	}
	first, err := tee.Job{Spec: spec}.EncodeCanonical()
	if err != nil {
		return nil, fmt.Errorf("encode session request: %w", err)
	}

	dialer := t.Dialer
	if dialer == nil {
		dialer = websocket.DefaultDialer
	}
	// Capture the certificate of the connection that will carry the session's
	// terminal receipt, so the receipt can be bound to it (see bindConnection).
	// The hook rides the handshake the dialer already performs — it is handed the
	// state the chain check just accepted — instead of dialing TLS here, which
	// would mean reimplementing the part that decides what to trust. It goes on a
	// copy of the dialer's TLS config because one dialer serves every concurrent
	// session and none of them may see another's connection.
	capture := &spkiCapture{}
	local := *dialer
	cfg := local.TLSClientConfig
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	accepted := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if accepted != nil {
			if err := accepted(cs); err != nil {
				return err
			}
		}
		if len(cs.PeerCertificates) > 0 {
			capture.set(spkiDigest(cs.PeerCertificates[0]))
		}
		return nil
	}
	local.TLSClientConfig = cfg
	dialer = &local

	conn, _, err := dialer.DialContext(ctx, t.SessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial TEE session: %w", err)
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, first); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send session request: %w", err)
	}

	mt, ack, err := conn.ReadMessage()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read session ack: %w", err)
	}
	if mt != websocket.TextMessage {
		_ = conn.Close()
		return nil, fmt.Errorf("session ack was not text (type %d)", mt)
	}
	if err := tee.ParseSessionAck(ack); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrTEERefused, err)
	}

	return &sessionTunnel{
		conn:        conn,
		spec:        spec,
		peerSPKI:    capture.get(),
		requirePeer: secureChannel(t.SessionURL),
	}, nil
}

// sessionTunnel is the concrete SessionConn behind HTTPTEE.OpenSession.
//
// It is deliberately a full-duplex pipe: its Read and Write can run on separate
// goroutines at the same time (the Hub always runs them that way — one goroutine
// pulls the provider's downlink while another pushes the user's uplink). A
// WebSocket allows one concurrent reader and one concurrent writer, so the two
// directions are serialized with separate locks; a single shared lock across a
// blocking Read would deadlock the moment a provider sent downlink while the
// user was sending uplink.
//
// Read returns the provider's downlink bytes as they arrive from the TEE's
// Binary messages; once the TEE delivers the terminal receipt Text message the
// next Read yields io.EOF. Write forwards uplink bytes verbatim.
type sessionTunnel struct {
	conn *websocket.Conn

	// spec is the job this tunnel was opened for, kept so the terminal receipt
	// can be bound back to it (see bindReceipt).
	spec jobs.Spec

	// peerSPKI is the certificate the connection presented, and requirePeer says
	// whether the channel is TLS and therefore had to present one. Together they
	// bind the terminal receipt to the connection that carried it, exactly as the
	// request path does (see bindConnection).
	peerSPKI    []byte
	requirePeer bool

	readMu  sync.Mutex // serializes the downlink reader (one reader only)
	writeMu sync.Mutex // serializes the uplink writer (one writer only)

	// mu guards the shared state below; none of it is touched while blocking
	// on the wire, so a read goroutine holds it only briefly.
	mu          sync.Mutex
	rbuf        []byte
	receipt     proof.SignedReceipt
	haveReceipt bool
	closed      bool
	readErr     error
}

// Write forwards uplink bytes into the tunnel exactly as received.
func (s *sessionTunnel) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.mu.Unlock()
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read returns downlink bytes, preferring anything the last Binary message has
// left over, otherwise waiting for the next tunnel message.
func (s *sessionTunnel) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for {
		s.mu.Lock()
		if s.readErr != nil {
			s.mu.Unlock()
			return 0, s.readErr
		}
		if len(s.rbuf) > 0 {
			n := copy(p, s.rbuf)
			s.rbuf = s.rbuf[n:]
			s.mu.Unlock()
			return n, nil
		}
		s.mu.Unlock()

		mt, msg, err := s.conn.ReadMessage()
		if err != nil {
			s.mu.Lock()
			s.readErr = err
			s.mu.Unlock()
			return 0, err
		}
		switch mt {
		case websocket.BinaryMessage:
			s.mu.Lock()
			s.rbuf = msg
			s.mu.Unlock()
		case websocket.TextMessage:
			signed, derr := tee.DecodeSessionReceipt(msg)
			if derr != nil {
				s.mu.Lock()
				s.readErr = fmt.Errorf("decode session receipt: %w", derr)
				s.mu.Unlock()
				return 0, s.readErr
			}
			// The session receipt must describe the session the Hub opened, and
			// be signed by the key the connection that carried it presented. A
			// mismatched one settles nothing, so it is refused here rather than
			// handed on as if it accounted for this transcript.
			if berr := s.bind(signed.Receipt); berr != nil {
				s.mu.Lock()
				s.readErr = berr
				s.mu.Unlock()
				return 0, berr
			}
			s.mu.Lock()
			s.receipt = signed
			s.haveReceipt = true
			s.readErr = io.EOF
			s.mu.Unlock()
			return 0, io.EOF
		}
	}
}

// bind checks a terminal receipt against what this tunnel knows: the spec that
// was dispatched, and the certificate the connection presented.
func (s *sessionTunnel) bind(r proof.Receipt) error {
	if err := bindReceipt(s.spec, r); err != nil {
		return err
	}
	return bindConnection(s.peerSPKI, s.requirePeer, r)
}

func (s *sessionTunnel) Receipt() (proof.SignedReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.haveReceipt {
		return proof.SignedReceipt{}, fmt.Errorf("session receipt not yet available")
	}
	return s.receipt, nil
}

func (s *sessionTunnel) Close() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "hub done"))
	return s.conn.Close()
}
