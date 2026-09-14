package hub

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// These tests cover the Hub's business rules against a scripted TEE, with no
// network, no TEE, and no real credential. That is the point of putting the
// TEE behind one interface: the rules that change most often are testable at
// the cost of a function call.

const testProvider = "openai-sim"

func chunks(parts ...string) [][]byte {
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		out = append(out, []byte(part))
	}
	return out
}

func totalBytes(chunks [][]byte) uint64 {
	var n uint64
	for _, chunk := range chunks {
		n += uint64(len(chunk))
	}
	return n
}

// makeReceipt builds a receipt that passes the Hub's stream check, optionally
// mutated. The Hub only inspects a handful of fields, so the rest stay zero.
// The JobID is randomized per receipt — a real TEE signs each job under the
// JobID the Hub generated — so a script that returns the same receipt more
// than once does not accidentally replay one JobID into the settlement dedup.
func makeReceipt(seq uint64, stream [][]byte, mutate func(*proof.Receipt)) proof.SignedReceipt {
	jobID := make([]byte, proof.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		panic("makeReceipt: random job id: " + err.Error())
	}
	r := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         jobID,
		Provider:      testProvider,
		StatusCode:    200,
		Completion:    proof.CompletionComplete,
		ChunkCount:    uint64(len(stream)),
		ResponseBytes: totalBytes(stream),
		ProviderSeq:   seq,
	}
	if mutate != nil {
		mutate(&r)
	}
	r = ScriptReceipt(stream, r)
	return proof.SignedReceipt{Receipt: r}
}

func acceptAll(proof.SignedReceipt) error { return nil }

// ratesTable returns a Hub market table for a test, so a test can give two
// providers different prices and show the Hub follows the seller's card, not
// its own idea of what things cost. The Hub's price source is its own Rates
// table — pricing is a Hub-side commercial concern, not a TEE policy field.
func ratesTable(cards map[string]RateCard) map[string]RateCard {
	return cards
}

// testSpec frames a request job. Each call mints a fresh job id, because that
// id is the ledger's transaction id for the charge the job may become: two
// spec() calls are two orders, and a test that wants one order twice must
// reuse the spec it was handed.
func testSpec(provider, model string) jobs.Spec {
	jobID := make([]byte, jobs.JobIDLength)
	if _, err := rand.Read(jobID); err != nil {
		panic("testSpec: random job id: " + err.Error())
	}
	return jobs.Spec{
		Version:  jobs.VersionV1,
		JobID:    jobID,
		Provider: provider,
		Method:   "POST",
		Host:     "provider.test:443",
		Path:     "/v1/chat/completions",
		Stream:   true,
	}
}

func mustHub(t *testing.T, cfg Config) *Hub {
	t.Helper()
	if cfg.Rates == nil {
		cfg.Rates = ratesTable(map[string]RateCard{testProvider: {PerRequestMicros: 1_000_000}})
	}
	if cfg.Store == nil {
		cfg.Store = NewReceiptStore(t.TempDir())
	}
	if cfg.Verify == nil {
		cfg.Verify = acceptAll
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatalf("build hub: %v", err)
	}
	return h
}

// --- pricing ---------------------------------------------------------------

func TestPrice(t *testing.T) {
	card := RateCard{
		PerRequestMicros:   1_000_000,
		PerMegabyteMicros:  500_000,
		ModelPremiumMicros: map[string]uint64{"large": 250_000},
	}

	cases := []struct {
		name         string
		model        string
		relayedBytes uint64
		edit         func(*proof.Receipt)
		want         uint64
	}{
		{name: "complete 200 with empty body", want: 1_000_000},
		{name: "model premium applies", model: "large", want: 1_250_000},
		{name: "unlisted model pays no premium", model: "small", want: 1_000_000},
		{
			name:         "one byte bills a whole mebibyte",
			relayedBytes: 1,
			edit:         func(r *proof.Receipt) { r.ResponseBytes = 1 },
			want:         1_500_000,
		},
		{
			name:         "exactly one mebibyte bills one unit",
			relayedBytes: mebibyte,
			edit:         func(r *proof.Receipt) { r.ResponseBytes = mebibyte },
			want:         1_500_000,
		},
		{
			name:         "one byte over rounds up to two units",
			relayedBytes: mebibyte + 1,
			edit:         func(r *proof.Receipt) { r.ResponseBytes = mebibyte + 1 },
			want:         2_000_000,
		},
		{
			name: "request bytes bill input volume",
			edit: func(r *proof.Receipt) { r.RequestBytes = mebibyte },
			want: 1_500_000,
		},
		{
			name:         "input and output share one rounded unit",
			relayedBytes: 1,
			edit:         func(r *proof.Receipt) { r.RequestBytes = mebibyte - 1; r.ResponseBytes = 1 },
			want:         1_500_000,
		},
		{
			// The provider declined. The exchange happened and is attested,
			// but nothing was delivered, so nothing is owed.
			name: "provider 401 earns nothing",
			edit: func(r *proof.Receipt) { r.StatusCode = 401 },
			want: 0,
		},
		{
			name: "provider 429 earns nothing",
			edit: func(r *proof.Receipt) { r.StatusCode = 429 },
			want: 0,
		},
		{
			name: "server error earns nothing",
			edit: func(r *proof.Receipt) { r.StatusCode = 500 },
			want: 0,
		},
		{
			// Headers arrived, then the connection died before a byte was
			// relayed: from the buyer's side this is indistinguishable from a
			// failed exchange, so it earns nothing.
			name: "truncated with no delivered bytes earns nothing",
			edit: func(r *proof.Receipt) { r.Completion = proof.CompletionTruncated },
			want: 0,
		},
		{
			// The seller paid the upstream for the prompt and the partial
			// response, so the buyer pays for the delivered volume — but no
			// per-request fee: margin is earned only on completed work.
			name:         "truncated earns volume for delivered bytes",
			relayedBytes: 1,
			edit: func(r *proof.Receipt) {
				r.Completion = proof.CompletionTruncated
				r.ResponseBytes = 1
			},
			want: 500_000,
		},
		{
			name:         "truncated bills request volume too",
			relayedBytes: mebibyte,
			edit: func(r *proof.Receipt) {
				r.Completion = proof.CompletionTruncated
				r.RequestBytes = mebibyte
				r.ResponseBytes = mebibyte
			},
			want: 1_000_000,
		},
		{
			// The TEE counts everything the provider sent, including the bytes
			// past the cap that were never relayed; those are not billable.
			// The cap is not the delivered length: chunks are rejected whole,
			// so the relayed prefix can end anywhere below it.
			name:         "over-cap bytes are never billed",
			relayedBytes: mebibyte,
			edit:         func(r *proof.Receipt) { r.ResponseBytes = 2 * mebibyte },
			want:         1_500_000,
		},
		{
			name:         "truncated over-cap bills only what was relayed",
			relayedBytes: mebibyte,
			edit: func(r *proof.Receipt) {
				r.Completion = proof.CompletionTruncated
				r.ResponseBytes = 2 * mebibyte
			},
			want: 500_000,
		},
		{
			// The TEE rejects the whole chunk that crosses the cap, so a
			// response whose first read is already too large delivers nothing —
			// a 4 KiB cap with a 32 KiB first chunk bills zero, not 4 KiB.
			name: "truncated with attested bytes but nothing relayed bills nothing",
			edit: func(r *proof.Receipt) {
				r.Completion = proof.CompletionTruncated
				r.ResponseBytes = 32 * 1024
			},
			want: 0,
		},
		{
			name: "failed exchange earns nothing",
			edit: func(r *proof.Receipt) { r.Completion = proof.CompletionFailed },
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := proof.Receipt{
				StatusCode:    200,
				Completion:    proof.CompletionComplete,
				ResponseBytes: 0,
			}
			if tc.edit != nil {
				tc.edit(&r)
			}
			got, err := Price(card, tc.model, tc.relayedBytes, r)
			if err != nil {
				t.Fatalf("Price: %v", err)
			}
			if got != tc.want {
				t.Errorf("Price = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPriceOverflowIsRejectedNotWrapped(t *testing.T) {
	card := RateCard{
		PerRequestMicros:  MaxRateMicros,
		PerMegabyteMicros: MaxRateMicros,
	}
	receipt := proof.Receipt{
		StatusCode:    200,
		Completion:    proof.CompletionComplete,
		ResponseBytes: 1 << 60,
	}

	got, err := Price(card, "", 1<<60, receipt)
	if !errors.Is(err, ErrPriceOverflow) {
		t.Fatalf("Price error = %v, want ErrPriceOverflow", err)
	}
	// Wrapping would turn an enormous bill into a tiny one, which is the
	// failure mode worth refusing rather than surviving.
	if got != 0 {
		t.Errorf("Price = %d on overflow, want 0", got)
	}
}

func TestBillable(t *testing.T) {
	if !Billable(proof.Receipt{StatusCode: 200, Completion: proof.CompletionComplete}) {
		t.Error("200 complete should be billable")
	}
	if !Billable(proof.Receipt{StatusCode: 204, Completion: proof.CompletionComplete}) {
		t.Error("204 complete should be billable (2xx)")
	}
	if Billable(proof.Receipt{StatusCode: 200, Completion: proof.CompletionTruncated}) {
		t.Error("truncated should not be billable")
	}
}

// --- pricing authority -----------------------------------------------------

// TestHubChargesTheProvidersPrice is the regression test for pricing authority
// living with the provider. The Hub holds no price table; if someone adds one
// back, these two providers stop differing.
func TestHubChargesTheProvidersPrice(t *testing.T) {
	set := ratesTable(map[string]RateCard{
		"cheap": {PerRequestMicros: 100},
		"dear":  {PerRequestMicros: 900},
	})
	stream := chunks("hello")

	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, func(r *proof.Receipt) {
			r.Provider = spec.Provider
		})}, nil
	}}

	h := mustHub(t, Config{TEE: fake, Rates: set})

	cheap, err := h.Execute(context.Background(), "tenant", "m", testSpec("cheap", "m"), nil, nil)
	if err != nil {
		t.Fatalf("execute cheap: %v", err)
	}
	dear, err := h.Execute(context.Background(), "tenant", "m", testSpec("dear", "m"), nil, nil)
	if err != nil {
		t.Fatalf("execute dear: %v", err)
	}

	if cheap.Charged != 100 || dear.Charged != 900 {
		t.Errorf("charges = cheap %d / dear %d, want 100 / 900 — the Hub must price from the provider's card",
			cheap.Charged, dear.Charged)
	}
	snap := h.Ledger().Snapshot()
	if snap.Revenue != 1000 {
		t.Errorf("ledger revenue = %d, want 1000", snap.Revenue)
	}
}

func TestUnknownProviderIsRefusedBeforeDispatch(t *testing.T) {
	fake := &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) {
		t.Fatal("TEE must not be called for an unknown provider")
		return Result{}, nil
	}}
	h := mustHub(t, Config{TEE: fake})

	_, err := h.Execute(context.Background(), "tenant", "m", testSpec("nobody", "m"), nil, nil)
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("error = %v, want ErrUnknownProvider", err)
	}
	if fake.Calls() != 0 {
		t.Errorf("TEE called %d times, want 0", fake.Calls())
	}
}

// --- quota -----------------------------------------------------------------

func TestQuotaBlocksBeforeDispatch(t *testing.T) {
	quota, err := NewQuota(1, time.Minute)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Quota: quota})

	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("first request: %v", err)
	}

	_, err = h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second request error = %v, want ErrQuotaExceeded", err)
	}
	// A refused request must never reach the TEE. If it did, rate limiting
	// would consume ProviderSeq numbers and punch holes in the sequence —
	// indistinguishable from a Hub hiding executions.
	if fake.Calls() != 1 {
		t.Errorf("TEE calls = %d, want 1: quota must block before dispatch", fake.Calls())
	}
}

func TestQuotaIsPerTenant(t *testing.T) {
	quota, err := NewQuota(1, time.Minute)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Quota: quota})

	for _, tenant := range []string{"alice", "bob"} {
		if _, err := h.Execute(context.Background(), tenant, "m", testSpec(testProvider, "m"), nil, nil); err != nil {
			t.Fatalf("%s: %v", tenant, err)
		}
	}
	if fake.Calls() != 2 {
		t.Errorf("TEE calls = %d, want 2", fake.Calls())
	}
}

func TestQuotaWindowRollsOver(t *testing.T) {
	quota, err := NewQuota(1, time.Minute)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	now := time.Now()
	clock := func() time.Time { return now }

	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Quota: quota, Clock: clock})

	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	if quota.Remaining("tenant", now) != 0 {
		t.Errorf("remaining = %d, want 0", quota.Remaining("tenant", now))
	}

	now = now.Add(2 * time.Minute)
	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
		t.Fatalf("after window: %v", err)
	}
	if fake.Calls() != 2 {
		t.Errorf("TEE calls = %d, want 2", fake.Calls())
	}
}

func TestNewQuotaRejectsMeaninglessLimits(t *testing.T) {
	if _, err := NewQuota(0, time.Minute); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("limit 0 error = %v, want ErrInvalidQuota", err)
	}
	if _, err := NewQuota(5, 0); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("window 0 error = %v, want ErrInvalidQuota", err)
	}
}

// --- verification ----------------------------------------------------------

func TestUnverifiedReceiptIsNotCharged(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(1, stream, nil)}, nil
	}}
	h := mustHub(t, Config{
		TEE:    fake,
		Verify: func(proof.SignedReceipt) error { return errors.New("bad signature") },
	})

	_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
	if err == nil {
		t.Fatal("expected verification failure")
	}

	snap := h.Ledger().Snapshot()
	if snap.Verified != 0 || snap.Settled != 0 || snap.Revenue != 0 {
		t.Errorf("ledger after failed verification = %+v, want all zero", snap)
	}
	if snap.Dispatched != 1 {
		t.Errorf("dispatched = %d, want 1", snap.Dispatched)
	}
}

func TestStreamMismatchIsRejected(t *testing.T) {
	attested := chunks("what the TEE saw")
	delivered := chunks("what the Hub claims")
	fake := &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) {
		// The receipt commits to one transcript; the Hub hands back another.
		return Result{Chunks: delivered, Receipt: makeReceipt(1, attested, nil)}, nil
	}}
	h := mustHub(t, Config{TEE: fake})

	_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrStreamMismatch) {
		t.Fatalf("error = %v, want ErrStreamMismatch", err)
	}
	if h.Ledger().Snapshot().Revenue != 0 {
		t.Error("a receipt that does not describe the delivered bytes must not settle")
	}
}

// --- receipt store and gap detection ---------------------------------------

func TestStoreDetectsGaps(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")

	for _, seq := range []uint64{1, 2, 4, 5} {
		if err := store.Put(testProvider, makeReceipt(seq, stream, nil)); err != nil {
			t.Fatalf("put %d: %v", seq, err)
		}
	}

	report, err := store.Audit(testProvider, acceptAll)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if report.Verified != 4 || report.Total != 4 {
		t.Errorf("audit = verified %d of %d, want 4 of 4", report.Verified, report.Total)
	}
	if report.MaxSeq != 5 {
		t.Errorf("MaxSeq = %d, want 5", report.MaxSeq)
	}
	if len(report.Missing) != 1 || report.Missing[0] != 3 {
		t.Errorf("Missing = %v, want [3]", report.Missing)
	}
	if report.Complete() {
		t.Error("Complete() = true on a set with a hole")
	}
}

func TestStoreRefusesDuplicateSequence(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")

	if err := store.Put(testProvider, makeReceipt(7, stream, nil)); err != nil {
		t.Fatalf("put: %v", err)
	}
	err := store.Put(testProvider, makeReceipt(7, stream, nil))
	if !errors.Is(err, ErrDuplicateSeq) {
		t.Fatalf("second put error = %v, want ErrDuplicateSeq", err)
	}
}

func TestStoreCountsUnverifiableReceipts(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")

	for _, seq := range []uint64{1, 2, 3} {
		if err := store.Put(testProvider, makeReceipt(seq, stream, nil)); err != nil {
			t.Fatalf("put %d: %v", seq, err)
		}
	}

	report, err := store.Audit(testProvider, func(signed proof.SignedReceipt) error {
		if signed.Receipt.ProviderSeq == 2 {
			return errors.New("tampered")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if report.Verified != 2 || report.Invalid != 1 {
		t.Errorf("audit = verified %d invalid %d, want 2 and 1", report.Verified, report.Invalid)
	}
}

func TestAuditRequiresAVerifier(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	if _, err := store.Audit(testProvider, nil); !errors.Is(err, ErrNoVerifier) {
		t.Errorf("error = %v, want ErrNoVerifier", err)
	}
}

// TestWithholdingAReceiptLeavesADetectableGap is the whole ProviderSeq story in
// one test: a Hub that hides an execution still cannot hide the number.
func TestWithholdingAReceiptLeavesADetectableGap(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{
		TEE:      fake,
		Store:    store,
		Withhold: func(seq uint64) bool { return seq == 2 },
	})

	for i := 0; i < 3; i++ {
		if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err != nil {
			t.Fatalf("execute %d: %v", i, err)
		}
	}

	report, err := store.Audit(testProvider, acceptAll)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(report.Missing) != 1 || report.Missing[0] != 2 {
		t.Errorf("Missing = %v, want [2]: a withheld receipt must still leave a hole", report.Missing)
	}
	// The Hub charged for all three, which is exactly what the provider can
	// now prove happened without being shown the receipts.
	if snap := h.Ledger().Snapshot(); snap.Settled != 3 {
		t.Errorf("settled = %d, want 3", snap.Settled)
	}
}

// failStore is a Store whose Put always fails, for tests that need the Hub to
// lose the receipt right after the exchange verified.
type failStore struct{}

func (failStore) Put(string, proof.SignedReceipt) error { return errors.New("disk full") }

// TestStoreFailureBooksNothing locks the settle-then-store hazard from the
// money side: when the receipt cannot be stored, the ledger must record
// nothing. The receipt is the provider's audit record; a charge without it is
// money the provider can never reconcile. Before this ordering existed, a
// disk-full store charged the buyer, lost the receipt, and left the provider
// with a seq gap and no record of why.
func TestStoreFailureBooksNothing(t *testing.T) {
	stream := chunks("hello")
	fake := &ScriptedTEE{Reply: func(call int, _ jobs.Spec) (Result, error) {
		return Result{Chunks: stream, Receipt: makeReceipt(uint64(call), stream, nil)}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Store: failStore{}})

	if _, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil); err == nil {
		t.Fatal("expected the store failure to surface")
	}
	snap := h.Ledger().Snapshot()
	if snap.Settled != 0 || snap.Revenue != 0 {
		t.Errorf("settled = %d, revenue = %d, want 0: nothing books without a stored receipt", snap.Settled, snap.Revenue)
	}
}

// --- wiring ----------------------------------------------------------------

func TestNewRejectsIncompleteWiring(t *testing.T) {
	base := func() Config {
		return Config{
			TEE:    &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) { return Result{}, nil }},
			Rates:  ratesTable(map[string]RateCard{testProvider: {}}),
			Store:  NewReceiptStore(t.TempDir()),
			Verify: acceptAll,
		}
	}

	cases := []struct {
		name string
		want error
		edit func(*Config)
	}{
		{"no TEE", ErrNoTEE, func(c *Config) { c.TEE = nil }},
		{"no rates", ErrNoRates, func(c *Config) { c.Rates = nil }},
		{"no store", ErrNoStore, func(c *Config) { c.Store = nil }},
		{"no verifier", ErrNoVerifier, func(c *Config) { c.Verify = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.edit(&cfg)
			if _, err := New(cfg); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// --- the RPC seam ----------------------------------------------------------

// sseServer replays the wire format the real TEE writes, so the client is
// tested against the server's framing rather than a lookalike.
func sseServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != tee.ExecuteContentType {
			t.Errorf("content type = %q, want %q", r.Header.Get("Content-Type"), tee.ExecuteContentType)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		var req tee.ExecuteRequest
		if err := canonical.Unmarshal(raw, &req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Spec.Provider == "" {
			t.Error("request carried no provider")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
}

func TestHTTPTEERoundTrip(t *testing.T) {
	stream := chunks("hello ", "world")
	signed := makeReceipt(3, stream, nil)
	encoded, err := signed.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode receipt: %v", err)
	}
	server := sseServer(t, fmt.Sprintf("event: start\ndata: {\"status\":200,\"headers\":{\"content-type\":[\"text/event-stream\"]}}\n\n"+
		"data: hello \n\ndata: world\n\nevent: receipt\ndata: %s\n\n",
		base64.StdEncoding.EncodeToString(encoded)))
	defer server.Close()

	client := &HTTPTEE{URL: server.URL + "/v1/execute"}
	var (
		forwarded [][]byte
		started   bool
		startResp tee.Response
	)
	res, err := client.Execute(context.Background(), testSpec(testProvider, "m"), []byte("{}"),
		func(chunk []byte) error {
			if !started {
				t.Error("a chunk arrived before the response start")
			}
			forwarded = append(forwarded, chunk)
			return nil
		},
		func(resp tee.Response) {
			started = true
			startResp = resp
		})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.Chunks) != 2 || string(res.Chunks[0]) != "hello " || string(res.Chunks[1]) != "world" {
		t.Errorf("chunks = %q, want [hello  world]", res.Chunks)
	}
	if len(forwarded) != 2 {
		t.Errorf("forwarded %d chunks, want 2", len(forwarded))
	}
	if res.Receipt.Receipt.ProviderSeq != 3 {
		t.Errorf("ProviderSeq = %d, want 3", res.Receipt.Receipt.ProviderSeq)
	}
	// The start frame reached both the callback and the result, before the
	// body, carrying the status and the relayed headers.
	if !started {
		t.Fatal("response start was never reported")
	}
	if startResp.StatusCode != 200 {
		t.Errorf("start status = %d, want 200", startResp.StatusCode)
	}
	if got := startResp.Headers["content-type"]; len(got) != 1 || got[0] != "text/event-stream" {
		t.Errorf("start content-type = %v", got)
	}
	if res.Status != 200 || len(res.Headers["content-type"]) != 1 {
		t.Errorf("result status/headers = %d %v", res.Status, res.Headers)
	}
}

// startStubTEE is a scripted TEE whose response start is under the test's
// control — including a start that does NOT match the receipt, which is the
// one case ScriptedTEE cannot produce because it binds the receipt itself.
type startStubTEE struct {
	status  uint32
	headers map[string][]string
	receipt proof.Receipt
}

func (s *startStubTEE) Execute(_ context.Context, _ jobs.Spec, _ []byte, onChunk func([]byte) error, onStart ...func(tee.Response)) (Result, error) {
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](tee.Response{StatusCode: s.status, Headers: s.headers})
	}
	if onChunk != nil {
		_ = onChunk([]byte("ok"))
	}
	return Result{Chunks: [][]byte{[]byte("ok")}, Status: s.status, Headers: s.headers, Receipt: proof.SignedReceipt{Receipt: s.receipt}}, nil
}

func (s *startStubTEE) OpenSession(context.Context, jobs.Spec) (SessionConn, error) {
	return nil, ErrSessionUnsupported
}

// TestResponseStartIsBoundToTheReceipt covers the binding checks that make the
// start frame trustworthy: the Hub acts on the start immediately (that is the
// point of the protocol), but settles only when the signed receipt attests the
// same status and the same forwarded header set.
func TestResponseStartIsBoundToTheReceipt(t *testing.T) {
	stream := chunks("ok")
	hdr := map[string][]string{"content-type": {"text/event-stream"}}

	t.Run("matching start settles", func(t *testing.T) {
		r := makeReceipt(1, stream, func(r *proof.Receipt) { r.StatusCode = 401 })
		h := mustHub(t, Config{TEE: &startStubTEE{
			status:  401,
			headers: hdr,
			receipt: boundReceipt(r.Receipt, hdr),
		}})
		out, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		// The status the Hub committed is the attested one, and a 401 earns
		// the provider nothing.
		if out.StatusCode != 401 {
			t.Errorf("outcome status = %d, want 401", out.StatusCode)
		}
		if out.Charged != 0 || out.Buyer != 0 {
			t.Errorf("401 settled %d/%d, want nothing", out.Charged, out.Buyer)
		}
	})

	t.Run("status mismatch is refused", func(t *testing.T) {
		// The Hub showed the user a 401; the receipt says the upstream
		// answered 200. One of the two is a lie, and neither is settleable.
		r := makeReceipt(1, stream, nil) // StatusCode 200
		h := mustHub(t, Config{TEE: &startStubTEE{
			status:  401,
			headers: hdr,
			receipt: boundReceipt(r.Receipt, hdr),
		}})
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		if !errors.Is(err, ErrResponseStartMismatch) {
			t.Fatalf("error = %v, want ErrResponseStartMismatch", err)
		}
		if h.Ledger().Snapshot().Revenue != 0 {
			t.Error("a start that contradicts the receipt must not settle")
		}
	})

	t.Run("header hash mismatch is refused", func(t *testing.T) {
		r := makeReceipt(1, stream, nil)
		h := mustHub(t, Config{TEE: &startStubTEE{
			status:  200,
			headers: hdr,
			// The receipt attests a DIFFERENT header set than the one the Hub
			// was shown and relayed.
			receipt: boundReceipt(r.Receipt, map[string][]string{"retry-after": {"30"}}),
		}})
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		if !errors.Is(err, ErrResponseStartMismatch) {
			t.Fatalf("error = %v, want ErrResponseStartMismatch", err)
		}
	})

	t.Run("missing header hash is refused", func(t *testing.T) {
		// A start frame was shown but the receipt attests no header set at
		// all: the Hub cannot prove what it relayed, so it must not settle.
		r := makeReceipt(1, stream, nil)
		h := mustHub(t, Config{TEE: &startStubTEE{status: 200, headers: hdr, receipt: r.Receipt}})
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		if !errors.Is(err, ErrResponseStartMismatch) {
			t.Fatalf("error = %v, want ErrResponseStartMismatch", err)
		}
	})

	t.Run("attested start without an observed frame is refused", func(t *testing.T) {
		// The receipt proves a start existed — 401 plus a header hash — but
		// the Hub was shown no start frame at all. Settling it would let
		// chunks committed under a default 200 be covered by a receipt
		// attesting a real 401, so it must not pass the binding check either.
		r := makeReceipt(1, stream, func(r *proof.Receipt) { r.StatusCode = 401 })
		h := mustHub(t, Config{TEE: &startStubTEE{status: 0, headers: hdr, receipt: boundReceipt(r.Receipt, hdr)}})
		_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, nil)
		if !errors.Is(err, ErrResponseStartMismatch) {
			t.Fatalf("error = %v, want ErrResponseStartMismatch", err)
		}
	})
}

// boundReceipt attaches the response-start binding to a receipt, as the TEE
// does when it signs an exchange that produced a response.
func boundReceipt(r proof.Receipt, headers map[string][]string) proof.Receipt {
	h := tee.HashResponseHeaders(headers)
	r.ResponseHeadersHash = h[:]
	return r
}

// TestHTTPTEERoundTripsChunksByteForByte pins the framing's fidelity.
//
// The receipt's stream hash covers the chunks the TEE wrote, and the Hub
// checks it against the chunks it read. Every case here is something a naive
// SSE reader loses — leading space, trailing space, an embedded newline, an
// empty heartbeat — and losing any of them makes every receipt for that job
// unverifiable, which looks like a TEE bug and is actually a framing bug.
func TestHTTPTEERoundTripsChunksByteForByte(t *testing.T) {
	want := [][]byte{
		[]byte("  leading spaces"),
		[]byte("trailing spaces  "),
		[]byte("two\nlines"),
		{},
		{},
	}
	body := "data:   leading spaces\n\n" +
		"data: trailing spaces  \n\n" +
		"data: two\ndata: lines\n\n" +
		"data: \n\n" +
		"data: \n\n"

	server := sseServer(t, body)
	defer server.Close()

	res, err := (&HTTPTEE{URL: server.URL + "/v1/execute"}).
		Execute(context.Background(), testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrNoReceipt) {
		t.Fatalf("error = %v, want ErrNoReceipt for a stream with no receipt frame", err)
	}
	if len(res.Chunks) != len(want) {
		t.Fatalf("got %d chunks, want %d: %q", len(res.Chunks), len(want), res.Chunks)
	}
	for i := range want {
		if !bytes.Equal(res.Chunks[i], want[i]) {
			t.Errorf("chunk %d = %q, want %q", i, res.Chunks[i], want[i])
		}
	}
}

func TestHTTPTEERefusal(t *testing.T) {
	server := sseServer(t, "event: error\ndata: host not allowed by policy\n\n")
	defer server.Close()

	client := &HTTPTEE{URL: server.URL + "/v1/execute"}
	_, err := client.Execute(context.Background(), testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrTEERefused) {
		t.Fatalf("error = %v, want ErrTEERefused", err)
	}
}

func TestHTTPTEEMissingReceipt(t *testing.T) {
	server := sseServer(t, "data: hello\n\n")
	defer server.Close()

	client := &HTTPTEE{URL: server.URL + "/v1/execute"}
	res, err := client.Execute(context.Background(), testSpec(testProvider, "m"), nil, nil)
	if !errors.Is(err, ErrNoReceipt) {
		t.Fatalf("error = %v, want ErrNoReceipt", err)
	}
	// Chunks delivered before the stream died are still returned: the Hub got
	// bytes it may have passed on, and it needs to account for them.
	if len(res.Chunks) != 1 {
		t.Errorf("chunks = %q, want 1 chunk kept", res.Chunks)
	}
}

func TestHTTPTEERejectsEmptyURL(t *testing.T) {
	if _, err := (&HTTPTEE{}).Execute(context.Background(), testSpec(testProvider, "m"), nil, nil); err == nil {
		t.Error("expected an error for an empty URL")
	}
}

func TestScriptedTEEWithoutReplyFails(t *testing.T) {
	if _, err := (&ScriptedTEE{}).Execute(context.Background(), testSpec(testProvider, "m"), nil, nil); err == nil {
		t.Error("a scripted TEE with no Reply must fail loudly, not return nothing")
	}
}

// TestScriptedTEEForwardsBeforeFailing checks the stand-in behaves like the
// real TEE on a mid-flight failure: bytes already sent are still handed over.
func TestScriptedTEEForwardsBeforeFailing(t *testing.T) {
	stream := chunks("partial")
	fake := &ScriptedTEE{Reply: func(int, jobs.Spec) (Result, error) {
		return Result{Chunks: stream}, errors.New("connection reset")
	}}
	h := mustHub(t, Config{TEE: fake})

	var forwarded [][]byte
	_, err := h.Execute(context.Background(), "tenant", "m", testSpec(testProvider, "m"), nil, func(chunk []byte) error {
		forwarded = append(forwarded, chunk)
		return nil
	})
	if err == nil {
		t.Fatal("expected the transport error to surface")
	}
	if len(forwarded) != 1 {
		t.Errorf("forwarded %d chunks, want 1", len(forwarded))
	}
	if h.Ledger().Snapshot().Revenue != 0 {
		t.Error("a failed exchange must not be charged")
	}
}

// --- ledger ----------------------------------------------------------------

func TestLedgerSnapshotIsConsistent(t *testing.T) {
	ledger := NewLedger()
	ledger.NoteDispatch("a")
	ledger.NoteVerified("a")
	ledger.NoteSettled("a", 500)
	ledger.NoteDispatch("b")
	ledger.NoteVerified("b")
	ledger.NoteSettled("b", 0) // verified but earned nothing

	snap := ledger.Snapshot()
	if snap.Dispatched != 2 || snap.Verified != 2 || snap.Settled != 2 || snap.Revenue != 500 {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.ByProvider["a"].Revenue != 500 || snap.ByProvider["b"].Revenue != 0 {
		t.Errorf("per-provider = %+v", snap.ByProvider)
	}
}

func TestStoreListIsOrderedBySequence(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")
	for _, seq := range []uint64{3, 1, 2} {
		if err := store.Put(testProvider, makeReceipt(seq, stream, nil)); err != nil {
			t.Fatalf("put %d: %v", seq, err)
		}
	}
	receipts, err := store.List(testProvider)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(receipts) != 3 {
		t.Fatalf("listed %d receipts, want 3", len(receipts))
	}
	for i, want := range []uint64{1, 2, 3} {
		if receipts[i].Receipt.ProviderSeq != want {
			t.Errorf("receipt[%d].ProviderSeq = %d, want %d", i, receipts[i].Receipt.ProviderSeq, want)
		}
	}
}

func TestStoreRejectsTraversalInProviderName(t *testing.T) {
	store := NewReceiptStore(t.TempDir())
	stream := chunks("hello")
	for _, name := range []string{"../escape", "a/b", "", ".."} {
		if err := store.Put(name, makeReceipt(1, stream, nil)); err == nil {
			t.Errorf("provider name %q must be refused", name)
		}
	}
}
