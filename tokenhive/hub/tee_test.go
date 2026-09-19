package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// TestCredentialKeyCoalescesAConnectingFleet proves the two properties that
// matter when a TEE comes back and every agent reconnects at once: a wave of
// concurrent callers costs the TEE one round-trip, not one per agent, and a
// caller arriving afterwards still reads the TEE afresh.
//
// The second property is the one a TTL cache would break: the handler below
// rotates its key like a restarted TEE, and the later caller must see the new
// key immediately. Handing it the cached one would make every agent that
// reconnects inside the TTL window seal its token to a key the TEE can no
// longer open.
func TestCredentialKeyCoalescesAConnectingFleet(t *testing.T) {
	oldKey, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}
	newKey, err := tee.GenerateInboxKey()
	if err != nil {
		t.Fatalf("generate inbox key: %v", err)
	}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold every fetch open briefly. This widens the in-flight window so
		// the whole fleet is guaranteed to pile onto one request, which keeps
		// the assertion below deterministic rather than a scheduling race.
		time.Sleep(50 * time.Millisecond)
		if n := atomic.AddInt32(&hits, 1); n == 1 {
			_ = json.NewEncoder(w).Encode(oldKey.Public())
			return
		}
		// From the second fetch on, behave like a TEE that restarted: a fresh
		// inbox key, and the old one is dead.
		_ = json.NewEncoder(w).Encode(newKey.Public())
	}))
	defer srv.Close()

	client := &HTTPTEE{BaseURL: srv.URL, Client: srv.Client()}

	const fleet = 8
	got := make([]tee.InboxPublic, fleet)
	var wg sync.WaitGroup
	for i := 0; i < fleet; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := client.CredentialKey(context.Background())
			if err != nil {
				t.Errorf("credential key: %v", err)
				return
			}
			got[i] = key
		}(i)
	}
	wg.Wait()

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("%d concurrent callers cost %d TEE fetches, want 1", fleet, n)
	}
	for i, key := range got {
		if !sameKey(key, oldKey.Public()) {
			t.Fatalf("caller %d got an unexpected key", i)
		}
	}

	// A lone caller after the wave must re-read the TEE and see the rotated
	// key: there is no cached value to serve, so there is no staleness window.
	key, err := client.CredentialKey(context.Background())
	if err != nil {
		t.Fatalf("credential key after rotation: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("later caller did not re-read the TEE: hits = %d, want 2", n)
	}
	if !sameKey(key, newKey.Public()) {
		t.Fatal("later caller got the pre-rotation key: a restarted TEE would reject every envelope sealed to it")
	}
}

func sameKey(a, b tee.InboxPublic) bool {
	return a.KeyID == b.KeyID && bytes.Equal(a.PublicKey, b.PublicKey)
}

// TestReadSSEStopsWhenTheConsumerRefusesAChunk pins the contract that stops a
// stalled reader from turning into unbounded work on the Hub: a consumer that
// returns an error ends the exchange at that chunk. Draining the rest of the
// body anyway is what let a client that would not read keep the Hub pulling and
// buffering a response nobody was receiving.
func TestReadSSEStopsWhenTheConsumerRefusesAChunk(t *testing.T) {
	stream := strings.Join([]string{
		"event: start\ndata: {\"status\":200}\n\n",
		"data: one\n\n",
		"data: two\n\n",
	}, "")

	stop := errors.New("client is gone")
	var seen int
	_, err := readSSE(strings.NewReader(stream), func([]byte) error {
		seen++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("readSSE err = %v, want the consumer's own error", err)
	}
	if seen != 1 {
		t.Fatalf("consumer called %d times, want 1: the stream must end at the first refusal", seen)
	}
}
