// Command streamer drives one streaming session (the C3 seam) end to end and
// verifies the terminal session receipt offline.
//
// It plays the Hub's side of the /v1/session WebSocket using the provider's
// own wire encoding: it sends the marker as a real WebSocket client frame
// (masked, exactly as the provider expects over the tunnel), collects the
// provider's server frames, and then checks a signed session receipt against
// every byte that actually moved — uplink RequestBytes, downlink ResponseBytes,
// the stream digest, and a fresh cryptographic verification of the signature.
//
// The TEE never interprets a frame here: it only handed bytes across. This
// driver proves that the upgrade tunnel and the session receipt are correct.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

func main() {
	teeURL := flag.String("tee", "ws://127.0.0.1:18090/v1/session", "TEE /v1/session WebSocket URL")
	provider := flag.String("provider", "openai-sim", "provider name (must match a policy the TEE holds)")
	host := flag.String("host", "127.0.0.1:18080", "provider host:port (must be in the policy)")
	path := flag.String("path", "/v1/realtime", "provider WebSocket endpoint path")
	marker := flag.String("marker", "streamtest-marker-42", "uplink payload the provider should echo back")
	credential := flag.String("credential", "", "provider access token; when set, it is registered with the TEE before the session (simulation one-shot mode — the streamer holds the seller's token and delivers it sealed, as a dialing agent would through a Hub)")
	flag.Parse()

	// The streamer talks to a TEE directly, so it seals the credential itself
	// and carries it on the session spec; a real Hub would receive it from a
	// dialing agent and attach it to the job instead.
	var cred []byte
	if *credential != "" {
		httpBase := strings.Replace(strings.Replace(*teeURL, "ws://", "http://", 1), "wss://", "https://", 1)
		httpBase = strings.TrimSuffix(httpBase, "/v1/session")
		env, err := shared.SealCredential(httpBase, *provider, tee.Secret{
			Token:  *credential,
			Header: "authorization",
			Scheme: "Bearer",
		})
		if err != nil {
			fail("seal credential: %v", err)
		}
		cred, err = env.EncodeCanonical()
		if err != nil {
			fail("encode credential: %v", err)
		}
	}

	spec := buildSpec(*provider, *host, *path)
	spec.Credential = cred

	first, err := tee.Job{Spec: spec}.EncodeCanonical()
	if err != nil {
		fail("encode session request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, *teeURL, nil)
	if err != nil {
		fail("dial TEE %s: %v", *teeURL, err)
	}
	defer conn.Close()

	// 建连段: one Binary message holding the canonical job.
	if err := conn.WriteMessage(websocket.BinaryMessage, first); err != nil {
		fail("send session request: %v", err)
	}

	// ack: {"ok":true} on Text, or an error we surface.
	mt, ack, err := conn.ReadMessage()
	if err != nil {
		fail("read session ack: %v", err)
	}
	if mt != websocket.TextMessage {
		fail("session ack was not text (type %d)", mt)
	}
	if err := tee.ParseSessionAck(ack); err != nil {
		fail("session ack: %v", err)
	}

	// 透传段 (uplink): a real masked client text frame carrying the marker.
	up := wsClientTextFrame([]byte(*marker))
	if err := conn.WriteMessage(websocket.BinaryMessage, up); err != nil {
		fail("send uplink frame: %v", err)
	}

	// 透传段 (downlink): provider server frames arrive as Binary messages; the
	// terminal Text message is the signed session receipt.
	var down []byte
	var signed proof.SignedReceipt
	for {
		mt, payload, err := conn.ReadMessage()
		if err != nil {
			fail("read downlink/receipt: %v", err)
		}
		if mt == websocket.BinaryMessage {
			down = append(down, payload...)
			continue
		}
		// First Text past the ack is the terminal receipt.
		signed, err = tee.DecodeSessionReceipt(payload)
		if err != nil {
			fail("decode session receipt: %v", err)
		}
		break
	}

	ok := verifyReceipt(spec, up, down, *marker, signed)
	if !ok {
		os.Exit(1)
	}

	fmt.Printf("SESSION OK: provider=%s seq=%d requestbytes=%d responsebytes=%d frames=%d\n",
		spec.Provider, signed.Receipt.ProviderSeq, signed.Receipt.RequestBytes,
		signed.Receipt.ResponseBytes, len(down))
}

// buildSpec constructs the session JobSpec the Hub submits: a GET upgrade to the
// provider's WebSocket endpoint with Session set and an empty (zero-byte) body.
// The body hash commits to the digest of zero bytes, exactly as OpenSession
// requires.
func buildSpec(provider, host, path string) jobs.Spec {
	jobID := make([]byte, jobs.JobIDLength)
	_, _ = rand.Read(jobID)
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	bodyHash := jobs.HashBody(nil)

	return jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            jobID,
		Provider:         provider,
		Method:           "GET",
		Host:             host,
		Path:             path,
		Headers:          map[string]string{},
		BodyHash:         bodyHash[:],
		Nonce:            nonce,
		ExpiresAt:        time.Now().Add(time.Minute).Unix(),
		MaxResponseBytes: 1 << 20,
		Stream:           true,
		Session:          true,
	}
}

// verifyReceipt checks a signed session receipt against the bytes that actually
// moved and cryptographically verifies the signature. It prints each pass/fail.
func verifyReceipt(spec jobs.Spec, up, down []byte, marker string, signed proof.SignedReceipt) bool {
	rec := signed.Receipt
	pass := true
	check := func(name string, ok bool, detail string) {
		state := "  OK"
		if !ok {
			state = "  !! FAIL"
			pass = false
		}
		fmt.Printf("%s %-28s %s\n", state, name, detail)
	}

	if err := proof.Verify(signed, proof.VerifyOptions{AllowedPlatforms: []string{simulated.Platform}}); err != nil {
		check("signature", false, fmt.Sprintf("verify: %v", err))
	} else {
		check("signature", true, "verified against sim trust root")
	}

	specHash, _ := spec.Hash()
	check("spec binding", string(rec.JobSpecHash) == string(specHash[:]), fmt.Sprintf("matches submitted spec"))
	check("status 101", rec.StatusCode == 101, fmt.Sprintf("got %d", rec.StatusCode))
	check("uplink bytes", rec.RequestBytes == uint64(len(up)), fmt.Sprintf("receipt=%d moved=%d", rec.RequestBytes, len(up)))
	check("downlink bytes", rec.ResponseBytes == uint64(len(down)), fmt.Sprintf("receipt=%d moved=%d", rec.ResponseBytes, len(down)))

	wantHash := proof.HashResponseStream(spec.JobID, [][]byte{down})
	check("stream hash", sliceEq(rec.StreamHash, wantHash[:]), "recomputed over the relayed downlink")

	frames, ferr := parseServerFrames(down)
	if ferr != nil {
		check("frame parse", false, ferr.Error())
	} else {
		texts, hasClose := 0, false
		echoFound := false
		for _, f := range frames {
			switch f.opcode {
			case 0x1: // text
				texts++
				if !echoFound && contains(f.payload, []byte(marker)) {
					echoFound = true
				}
			case 0x8: // close
				hasClose = true
			}
		}
		check("frames", texts == 3 && hasClose, fmt.Sprintf("%d text + close frame, %d headers", texts, len(frames)))
		check("echo", echoFound, "uplink marker echoed by the provider (full-duplex)")
	}

	if rec.ProviderSeq < 1 {
		check("provider seq", false, "expected a monotonic provider sequence")
	} else {
		check("provider seq", true, fmt.Sprintf("seq=%d", rec.ProviderSeq))
	}
	return pass
}

// wsClientTextFrame builds a masked WebSocket client text frame. A WebSocket
// client must mask its frames; the TEE relays these bytes verbatim into the
// provider tunnel, so they must be exactly what the provider's frame parser
// expects.
func wsClientTextFrame(payload []byte) []byte {
	buf := make([]byte, 0, len(payload)+16)
	finOp := byte(0x80 | 0x1) // FIN + text
	var mask [4]byte
	_, _ = rand.Read(mask[:])

	n := len(payload)
	switch {
	case n < 126:
		buf = append(buf, finOp, 0x80|byte(n))
	case n < 1<<16:
		buf = append(buf, finOp, 0x80|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, finOp, 0x80|127,
			byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	buf = append(buf, mask[:]...)
	for i, b := range payload {
		buf = append(buf, b^mask[i%4])
	}
	return buf
}

// serverFrame is one parsed provider (server) frame.
type serverFrame struct {
	opcode  byte
	payload []byte
}

// parseServerFrames walks a server (unmasked) frame stream. It is lenient about
// continuation (0x0) and ignores data we do not need, rejecting only malformed
// lengths so a truncated transcript cannot read as a success.
func parseServerFrames(data []byte) ([]serverFrame, error) {
	var frames []serverFrame
	for i := 0; i < len(data); {
		if i+2 > len(data) {
			return nil, fmt.Errorf("truncated frame header at byte %d", i)
		}
		b0, b1 := data[i], data[i+1]
		opcode := b0 & 0x0f
		masked := b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		i += 2

		switch n {
		case 126:
			if i+2 > len(data) {
				return nil, fmt.Errorf("truncated frame length at byte %d", i)
			}
			n = uint64(data[i])<<8 | uint64(data[i+1])
			i += 2
		case 127:
			if i+8 > len(data) {
				return nil, fmt.Errorf("truncated frame length at byte %d", i)
			}
			n = 0
			for j := 0; j < 8; j++ {
				n = n<<8 | uint64(data[i+j])
			}
			i += 8
		}

		if masked {
			if i+4 > len(data) {
				return nil, fmt.Errorf("truncated mask key at byte %d", i)
			}
			key := data[i : i+4]
			i += 4
			if uint64(i)+n > uint64(len(data)) {
				return nil, fmt.Errorf("truncated masked payload at byte %d", i)
			}
			payload := make([]byte, n)
			for j := uint64(0); j < n; j++ {
				payload[j] = data[uint64(i)+j] ^ key[j%4]
			}
			frames = append(frames, serverFrame{opcode: opcode, payload: payload})
			i += int(n)
			continue
		}

		if uint64(i)+n > uint64(len(data)) {
			return nil, fmt.Errorf("truncated payload at byte %d", i)
		}
		frames = append(frames, serverFrame{opcode: opcode, payload: data[i : i+int(n)]})
		i += int(n)
	}
	return frames, nil
}

func contains(hay, needle []byte) bool {
	return len(needle) > 0 && len(hay) >= len(needle) && bytesIndexOf(hay, needle) >= 0
}

func bytesIndexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

func sliceEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "STREAM FAIL: "+format+"\n", args...)
	os.Exit(1)
}
