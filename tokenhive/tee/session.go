// The Hub↔TEE streaming seam is a WebSocket on /v1/session. Its protocol is
// deliberately thin and mirrors the "build, relay, close" shape of §5.2 of the
// plan:
//
//  1. 建连段 — the Hub dials /v1/session as a WebSocket and sends one Binary
//     message holding a canonical SessionRequest (a JobSpec with Session set,
//     plus its empty body). The TEE runs the same refusal checks as Execute,
//     performs the Upgrade handshake to the provider, and replies with a Text
//     ack: {"ok":true} or {"error":"..."}.
//  2. 透传段 — after the ack every Binary message the Hub writes is forwarded
//     verbatim into the provider tunnel (counted as uplink), and every byte the
//     provider sends is delivered back as a Binary message (counted as downlink
//     and streamed into the receipt digest). No frame, JSON, or close semantics
//     are inspected here; the Hub owns them. The TEE only moves, counts, and
//     digests bytes.
//  3. 收尾段 — when either side closes, the TEE signs a session receipt
//     (StatusCode 101, RequestBytes = uplink total, ResponseBytes/ChunkCount/
//     StreamHash = downlink) and sends it as a final Text message before
//     closing the WebSocket. A session ends this way on its own terms only for
//     as long as the epoch its receipt must cite has room to sign one: the same
//     deadline an exchange is bounded by ends a session too, because a session
//     cannot be bounded in advance and an unattestable session settles nothing
//     (see Service.watchSigningDeadline).
//
// Two message orientations keep the two roles apart: tunnel bytes are always
// Binary, session control (ack, receipt) is always Text.
package tee

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// SessionIdleTimeout is how long a streaming session may go without any byte
// moving in either direction before the TEE tears it down. A session is
// otherwise unbounded: a Realtime-style conversation can legitimately run for
// many minutes, so a total-duration cap would kill healthy sessions — the
// watchdog exists only to stop a peer that vanished mid-conversation from
// wedging the tunnel forever.
const SessionIdleTimeout = 5 * time.Minute

// SessionAck is the success reply to a SessionRequest.
const SessionAck = `{"ok":true}`

// SessionRequest is the payload of the first Hub→TEE frame of a session: a
// JobSpec with Spec.Session set, bound to an empty body. The body-hash binding
// still applies, so the writer must commit to a digest of zero bytes exactly as
// a normal job commits to its payload.
type SessionRequest struct {
	Spec jobs.Spec `cbor:"1,keyasint"`
	Body []byte    `cbor:"2,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of the request.
func (r SessionRequest) EncodeCanonical() ([]byte, error) { return canonical.Marshal(r) }

// DecodeSessionRequest parses a canonical-CBOR SessionRequest.
func DecodeSessionRequest(data []byte) (SessionRequest, error) {
	var r SessionRequest
	if err := canonical.Unmarshal(data, &r); err != nil {
		return SessionRequest{}, err
	}
	return r, nil
}

// sessionUpgrader accepts the Hub's WebSocket. No origin restriction: the Hub
// and the TEE are both ours, and origin checks only matter for browsers.
var sessionUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// ServeSession is the server half of the streaming RPC. It is the "透明字节管
// 道" implementation: the TEE terminates TLS to the provider, relays raw bytes,
// and attests the transcript, while every piece of weather-proofing that a real
// WebSocket needs (ping/pong, fragmentation, close handshakes) is deliberately
// absent here and belongs to the Hub.
func ServeSession(svc *Service, w http.ResponseWriter, r *http.Request) {
	conn, err := sessionUpgrader.Upgrade(w, r, nil)
	if err != nil {
		// The upgrader has already written the error response.
		return
	}
	defer conn.Close()

	conn.SetReadLimit(64 << 20)

	// 建连段: one Binary message carrying the SessionRequest. The handshake is
	// bounded by a deadline so a Hub that connects and then never sends its
	// SessionRequest cannot pin the goroutine forever; once the request has
	// been acknowledged the deadline is lifted and the session may run as long
	// as bytes keep flowing (the idle watchdog in relaySession takes over).
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	mt, first, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		writeSessionClose(conn, websocket.ClosePolicyViolation, "no session request")
		return
	}
	if mt != websocket.BinaryMessage {
		writeSessionReply(conn, `{"error":"first frame must be binary"}`)
		return
	}
	req, err := DecodeSessionRequest(first)
	if err != nil {
		writeSessionReply(conn, `{"error":"decode session request: `+jsonErr(err)+`"}`)
		return
	}

	ss, err := svc.OpenSession(r.Context(), Job{Spec: req.Spec, Body: req.Body})
	if err != nil {
		writeSessionReply(conn, `{"error":"`+jsonErr(err)+`"}`)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(SessionAck)); err != nil {
		_ = ss.Close()
		return
	}

	relaySession(conn, ss)
}

// relaySession implements 透传段 and 收尾段 for ServeSession.
//
// The downlink pump owns the end of the session: the instant the provider
// indicates the stream is finished it signs the receipt and delivers it as the
// final Text message, then closes the WebSocket. The main goroutine only ever
// moves uplink bytes, so there is a single writer to the WebSocket and the TEE
// does no framing work of its own — the receipt therefore always reaches the
// Hub as the terminal marker, exactly as the 收尾段 of §5.2 promises.
//
// The pump owns every other ending too. Two watchers can end a session short of
// the provider's own end of stream — one for a peer that stopped moving bytes,
// one for an epoch that ran out of room to sign — and neither writes a receipt
// of its own: the pump is still the only thing that signs and sends one, so it
// keeps its single writer and the receipt still arrives as the terminal marker.
func relaySession(conn *websocket.Conn, ss *Session) {
	// An idle watchdog bounds the session so a peer that stops moving bytes
	// cannot wedge it forever. It is reset by every successful relay in either
	// direction — see note on SessionIdleTimeout: only silence kills a session,
	// not age. In the normal path the provider closes promptly and the pump
	// closes the conn on its own, which stops the watchdog in time.
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				last := time.Unix(0, lastActivity.Load())
				if time.Since(last) > SessionIdleTimeout {
					_ = conn.Close()
					return
				}
			}
		}
	}()
	touch := func() { lastActivity.Store(time.Now().UnixNano()) }
	defer close(stop)

	// The signing-deadline watcher is the other ending the provider does not
	// choose, and unlike the idle one it must not close the Websocket: the
	// receipt is what this session is worth, and it is signed and sent by the
	// pump only once the tunnel it reads from is gone. So it ends the provider
	// side and lets the pump finish the job — see Service.watchSigningDeadline
	// for why a session cannot simply be allowed to run past the deadline it
	// must be signed under.
	cutoff := ss.svc.watchSigningDeadline(stop)
	go func() {
		select {
		case <-stop:
		case <-cutoff:
			// The mark comes first, and not as a convenience: the close below
			// is what unblocks the pump, and a provider whose connection ends
			// on a clean read would otherwise leave the receipt claiming a
			// transcript that is missing everything after this instant.
			ss.markTruncated()
			_ = ss.Close()
		}
	}()

	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		_ = pumpDownlink(conn, ss, touch)
		// Whatever the outcome, the session is over: sign and send the receipt
		// as the terminal Text marker, then close so the main goroutine's
		// pending ReadMessage unwedges.
		_ = ss.Close()
		if res, rerr := ss.Receipt(); rerr != nil {
			_ = writeSessionReply(conn, `{"error":"sign session receipt: `+jsonErr(rerr)+`"}`)
		} else {
			_ = writeReceiptReply(conn, res.Receipt)
		}
		_ = conn.Close()
	}()

	// Uplink loop, on this goroutine: Hub WebSocket messages → provider tunnel.
	// Control frames are the Hub's weather-proofing, not ours; the library
	// already answers ping/pong and we forward nothing for them. The loop ends
	// when the Hub closes or the pump's conn.Close() aborts this read.
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		touch()
		if mt != websocket.BinaryMessage {
			continue
		}
		if _, werr := ss.Write(msg); werr != nil {
			break
		}
	}
	// The Hub vanished first: make sure the pump is not stuck relaying to a dead
	// peer before returning, then tear the tunnel down.
	_ = ss.Close()
	<-pumpDone
}

// pumpDownlink moves provider tunnel bytes to the Hub as Binary messages until
// the provider finishes. A clean EOF ends the relay with no error; any other
// provider error is surfaced so the terminal message can say so. A Hub that
// vanished mid-stream aborts the relay silently.
//
// touch is invoked after every successfully relayed frame so the session's
// idle watchdog can tell "quiet but alive" from "abandoned".
func pumpDownlink(conn *websocket.Conn, ss *Session, touch func()) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := ss.Read(buf)
		if n > 0 {
			if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				return nil
			}
			if touch != nil {
				touch()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// writeReceiptReply sends the signed session receipt as the final Text message.
func writeReceiptReply(conn *websocket.Conn, signed proof.SignedReceipt) error {
	enc, err := signed.EncodeCanonical()
	if err != nil {
		return err
	}
	reply, err := json.Marshal(map[string]string{
		"receipt": base64.StdEncoding.EncodeToString(enc),
	})
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, reply)
}

// writeSessionReply sends one Text control message.
func writeSessionReply(conn *websocket.Conn, payload string) error {
	return conn.WriteMessage(websocket.TextMessage, []byte(payload))
}

func writeSessionClose(conn *websocket.Conn, code int, reason string) {
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
}

// jsonErr keeps an untrusted or reasoned string safe for embedding in a JSON
// control message.
func jsonErr(err error) string {
	if err == nil {
		return ""
	}
	b, e := json.Marshal(err.Error())
	if e != nil {
		return "error"
	}
	s := string(b)
	if len(s) >= 2 {
		return s[1 : len(s)-1]
	}
	return s
}

// DecodeSessionReceipt parses the final Text message of a session into its
// signed receipt. It is the client half of writeReceiptReply.
func DecodeSessionReceipt(reply []byte) (proof.SignedReceipt, error) {
	var m struct {
		Receipt string `json:"receipt"`
	}
	if err := json.Unmarshal(reply, &m); err != nil {
		return proof.SignedReceipt{}, err
	}
	if m.Receipt == "" {
		return proof.SignedReceipt{}, errors.New("session reply carries no receipt")
	}
	raw, err := base64.StdEncoding.DecodeString(m.Receipt)
	if err != nil {
		return proof.SignedReceipt{}, err
	}
	var signed proof.SignedReceipt
	if err := canonical.Unmarshal(raw, &signed); err != nil {
		return proof.SignedReceipt{}, err
	}
	return signed, nil
}
