// The Hub↔TEE streaming seam is a WebSocket on /v1/session. Its protocol is
// deliberately thin and mirrors the "build, relay, close" shape of §5.2 of the
// plan:
//
//  1. 建连段 — the Hub dials /v1/session as a WebSocket and sends one Binary
//     message holding a canonical Job (a JobSpec with Session set, plus its
//     empty body — the same object /v1/execute carries, so the two endpoints
//     cannot drift about what a submitted job is). It runs the same refusal
//     checks as Execute,
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
//     closing the WebSocket.
//
// Two message orientations keep the two roles apart: tunnel bytes are always
// Binary, session control (ack, receipt) is always Text.
package tee

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// SessionIdleTimeout is how long a streaming session may go without any byte
// moving in either direction before the TEE tears it down. A session is
// otherwise unbounded: a Realtime-style conversation can legitimately run for
// many minutes, so a total-duration cap would kill healthy sessions — the
// watchdog exists only to stop a peer that vanished mid-conversation from
// wedging the tunnel forever.
const SessionIdleTimeout = 5 * time.Minute

// SessionAck is the success reply to a session request.
const SessionAck = `{"ok":true}`

// sessionAck is the JSON shape of a session reply: {"ok":true} once the tunnel
// is up, or {"error":"..."} when the TEE refused it before opening anything.
type sessionAck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// ParseSessionAck reports whether a session reply accepted the session, and the
// TEE's reason when it did not. It lives beside the ack it reads so the Hub and
// the session drivers cannot drift apart about the shape.
func ParseSessionAck(reply []byte) error {
	var ack sessionAck
	if err := json.Unmarshal(reply, &ack); err != nil {
		return fmt.Errorf("decode session ack %q: %w", reply, err)
	}
	if ack.Error != "" {
		// Quoted, not raw: the reason crosses a trust boundary and ends up in
		// the Hub's log line, so it must not be able to forge a line of its own.
		return fmt.Errorf("TEE refused session: %q", ack.Error)
	}
	if !ack.OK {
		return fmt.Errorf("session ack %q is neither ok nor an error", reply)
	}
	return nil
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
	job, err := DecodeJob(first)
	if err != nil {
		writeSessionReply(conn, `{"error":"decode session request: `+jsonErr(err)+`"}`)
		return
	}

	ss, err := svc.OpenSession(r.Context(), job)
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
func relaySession(conn *websocket.Conn, ss *Session) {
	// An idle watchdog bounds the session so a peer that stops moving bytes
	// cannot wedge it forever. It is reset by every successful relay in either
	// direction — see note on SessionIdleTimeout: only silence kills a session,
	// not age. In the normal path the provider closes promptly and the pump
	// closes the conn on its own, which stops the watchdog in time.
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	stopWatchdog := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatchdog:
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
	defer close(stopWatchdog)

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
