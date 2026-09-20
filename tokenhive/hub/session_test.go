package hub

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/mtls"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// TestSessionTunnelBindsTheReceiptToTheTLSConnection is the session half of the
// connection binding, over a real TLS handshake: the terminal receipt must be
// signed by the key the connection presented, and one from any other key is
// refused rather than handed on as if it accounted for the session. The receipt
// claims the key the simulated enclave's attested identity names, so the test
// also pins the invariant the digest rests on — that a receipt's KeyID is
// SHA-256 over the certificate's SubjectPublicKeyInfo — against a real
// certificate rather than against the helper that computes it.
func TestSessionTunnelBindsTheReceiptToTheTLSConnection(t *testing.T) {
	spec := testSpec(testProvider, "m")
	epoch, err := simulated.NewDeploymentEpoch([32]byte{})
	if err != nil {
		t.Fatalf("sim epoch: %v", err)
	}
	serverTLS := mtls.PlatformServerTLS(epoch)
	attested := epoch.Identity().KeyID
	other := sha256.Sum256([]byte("another enclave's key"))

	for _, tc := range []struct {
		name    string
		claimed []byte
		refused bool
	}{
		{"the certificate's own key", attested[:], false},
		{"another enclave's key", other[:], true},
	} {
		srv := tlsSessionServer(t, spec, tc.claimed, serverTLS)
		client := &HTTPTEE{
			SessionURL: "wss" + strings.TrimPrefix(srv.URL, "https") + "/v1/session",
			// The chain check is the dialer's business and is exercised against a
			// pinned certificate elsewhere; what is under test here is what the Hub
			// does with the receipt once the handshake has handed it the peer's key.
			Dialer: &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
		conn, err := client.OpenSession(context.Background(), spec)
		if err != nil {
			t.Fatalf("%s: open session: %v", tc.name, err)
		}
		_, rerr := conn.Read(make([]byte, 64))
		_ = conn.Close()

		if tc.refused {
			if !errors.Is(rerr, ErrReceiptNotBoundToConnection) {
				t.Errorf("%s: read = %v, want ErrReceiptNotBoundToConnection", tc.name, rerr)
			}
			continue
		}
		if rerr != io.EOF {
			t.Errorf("%s: read = %v, want EOF once the receipt arrived", tc.name, rerr)
		}
		if _, err := conn.Receipt(); err != nil {
			t.Errorf("%s: receipt refused: %v", tc.name, err)
		}
	}
}

// tlsSessionServer serves one session handshake over TLS and answers it the way
// the TEE does: an ack, then a terminal receipt claiming the key it was built
// with. claimed is fixed before the server starts, so the handler reads nothing
// the test writes afterwards.
func tlsSessionServer(t *testing.T, spec jobs.Spec, claimed []byte, serverTLS *tls.Config) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil { // the submitted job
			return
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(tee.SessionAck)); err != nil {
			return
		}
		signed := proof.SignedReceipt{Receipt: boundToSpec(spec, proof.Receipt{
			Version:     proof.VersionV1,
			Attestation: &proof.AttestationRef{KeyID: claimed},
		})}
		raw, err := canonical.Marshal(signed)
		if err != nil {
			return
		}
		payload, _ := json.Marshal(map[string]string{"receipt": base64.StdEncoding.EncodeToString(raw)})
		_ = conn.WriteMessage(websocket.TextMessage, payload)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// sessionTunnel is a full-duplex pipe: the Hub runs its Read and Write on two
// goroutines at once. A naive implementation serializes both behind one lock,
// so a downlink frame arriving while the uplink goroutine holds the lock can
// wedge the whole session. This drives a real WebSocket end-to-end, with the
// provider streaming down and the user streaming up concurrently, so a deadlock
// or a data race in the lock split surfaces immediately.

func TestSessionTunnelFullDuplexNoDeadlock(t *testing.T) {
	const downFrames = 200
	spec := testSpec(testProvider, "m")

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo protocol: for each uplink frame, echo one downlink frame back.
		// The Hub's reader therefore blocks waiting for a frame the Hub's own
		// writer must first send — the exact shape that deadlocks if Read and
		// Write share a single lock.
		for i := 0; i < downFrames; i++ {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, []byte("down")); err != nil {
				return
			}
		}
		signed := proof.SignedReceipt{Receipt: boundToSpec(spec, proof.Receipt{Version: proof.VersionV1})}
		raw, err := canonical.Marshal(signed)
		if err != nil {
			return
		}
		receiptJSON, _ := json.Marshal(map[string]string{
			"receipt": base64.StdEncoding.EncodeToString(raw),
		})
		_ = conn.WriteMessage(websocket.TextMessage, receiptJSON)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tun := &sessionTunnel{conn: conn, spec: testSpec(testProvider, "m")}

	// Upstream writer pushes frames while the downstream reader consumes them.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < downFrames; i++ {
			if _, err := tun.Write([]byte("up")); err != nil {
				// The provider closing mid-session makes later uplink writes
				// fail; in production that is the normal unwind, not a bug.
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		got := 0
		for {
			n, err := tun.Read(buf)
			got += n
			if err != nil {
				if err.Error() != "EOF" {
					t.Errorf("read: %v", err)
				}
				break
			}
		}
		if got == 0 {
			t.Errorf("read no downlink bytes")
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("session tunnel deadlocked under concurrent full-duplex traffic")
	}

	if _, err := tun.Receipt(); err != nil {
		t.Fatalf("receipt should be available after the session ended: %v", err)
	}
}
