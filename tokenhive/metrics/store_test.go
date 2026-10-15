package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// rec builds a record with the given job ID and one stage, so a test can tell
// records apart.
func rec(job string, ttfb time.Duration) tee.TimingRecord {
	return tee.TimingRecord{
		At:       time.Date(2026, 10, 15, 7, 0, 0, 0, time.UTC),
		JobID:    job,
		Provider: "openai",
		Host:     "chatgpt.com",
		Method:   "POST",
		Outcome:  tee.TimingComplete,
		Stages:   []tee.TimingStage{{Name: tee.StageTTFB, Dur: ttfb}},
	}
}

// TestStoreEvictsTheOldestAndCountsIt pins the ring: the newest records survive
// a full store, the sequence keeps climbing across evictions, and the count of
// what was lost is the one thing that tells a puller its answer is incomplete.
func TestStoreEvictsTheOldestAndCountsIt(t *testing.T) {
	store := NewStore("tokenhive-tee", 3)
	for _, job := range []string{"1", "2", "3", "4", "5"} {
		store.TimingRequest(rec(job, time.Second))
	}

	snap := store.snapshot()
	if snap.retained != 3 || snap.total != 5 || snap.dropped != 2 {
		t.Errorf("ring = %d retained / %d total / %d dropped, want 3 / 5 / 2", snap.retained, snap.total, snap.dropped)
	}
	var jobs []string
	for _, e := range snap.entries {
		jobs = append(jobs, e.rec.JobID)
	}
	if len(jobs) != 3 || jobs[0] != "3" || jobs[2] != "5" {
		t.Errorf("retained jobs = %v, want the newest three in order", jobs)
	}
	if snap.entries[0].seq >= snap.entries[2].seq {
		// A puller that kept the newest sequence it saw must never be handed an
		// old record again, so the numbers cannot be recycled by eviction.
		t.Errorf("sequences not increasing: %d..%d", snap.entries[0].seq, snap.entries[2].seq)
	}
}

// TestStoreKeepsTheLastAggregate pins that one pull returns both the detail and
// the shape of it, and that what is kept is a copy: the service re-uses its own
// aggregate value, so a store holding a reference would see it change under a
// reader.
func TestStoreKeepsTheLastAggregate(t *testing.T) {
	store := NewStore("tokenhive-tee", 4)
	agg := tee.TimingAggregate{
		Window:   30 * time.Second,
		Requests: 3,
		Stages:   []tee.TimingStat{{Name: tee.StageTTFB, P95: time.Second, Samples: 3}},
	}
	store.TimingAggregate(agg)
	agg.Stages[0].P95 = 99 * time.Second
	agg.Requests = 42

	snap := store.snapshot()
	if snap.aggregate == nil {
		t.Fatal("no aggregate retained")
	}
	if snap.aggregate.Requests != 3 || snap.aggregate.Stages[0].P95 != time.Second {
		t.Errorf("retained aggregate = %+v, want the values as they were reported", snap.aggregate)
	}
}

// TestNewStoreBoundsRetain pins both ends of the retain setting: zero means the
// default, and an absurd value is clamped rather than allocated.
func TestNewStoreBoundsRetain(t *testing.T) {
	if got := NewStore("s", 0).Retain(); got != DefaultRetain {
		t.Errorf("retain(0) = %d, want the default %d", got, DefaultRetain)
	}
	if got := NewStore("s", -5).Retain(); got != DefaultRetain {
		t.Errorf("retain(-5) = %d, want the default %d", got, DefaultRetain)
	}
	if got := NewStore("s", maxRetain+1).Retain(); got != maxRetain {
		t.Errorf("retain(over the cap) = %d, want %d", got, maxRetain)
	}
}

// TestStoreIsSafeForConcurrentUse is the one test that has to run with -race to
// mean anything. The store's real traffic is concurrent by construction: records
// arrive from every handler goroutine at once, plus a stall watcher per
// in-flight request, while an operator pulls the ring from its own connection.
func TestStoreIsSafeForConcurrentUse(t *testing.T) {
	store := NewStore("tokenhive-tee", 32)

	var wg sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				store.TimingRequest(rec("job", time.Millisecond))
				if i%16 == 0 {
					store.TimingAggregate(tee.TimingAggregate{Requests: i})
				}
			}
		}()
	}
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for _, e := range store.snapshot().entries {
					// Touch what a reader actually reads, so a race on the
					// record's own fields is not missed by only looking at the
					// ring's bookkeeping.
					_ = e.rec.Flat()
				}
			}
		}()
	}
	wg.Wait()

	snap := store.snapshot()
	if snap.total != 8*200 {
		t.Errorf("total = %d, want every concurrent write accounted for", snap.total)
	}
	if snap.retained != 32 || snap.dropped != 8*200-32 {
		t.Errorf("ring = %d retained / %d dropped, want a full ring of 32 and the rest dropped",
			snap.retained, snap.dropped)
	}
}

// pull drives one request through the registered route, which is the part a
// deployment actually uses.
func pull(t *testing.T, store *Store, method string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	NewHTTPServer(store, mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(method, "/timing", nil))
	return recorder
}

// TestServerServesPullableRecords pins the wire shape: one JSON object with the
// ring's state, the records in the same field spelling a log line uses, and the
// two fields only a stored record has.
func TestServerServesPullableRecords(t *testing.T) {
	store := NewStore("tokenhive-tee", 4)
	store.TimingRequest(rec("9f3a", 903*time.Millisecond))
	store.TimingRequest(tee.TimingRecord{
		At:      time.Date(2026, 10, 15, 7, 0, 1, 0, time.UTC),
		JobID:   "beef",
		Outcome: tee.TimingRunning,
		Stage:   tee.StageTLS,
		Waited:  30 * time.Second,
	})
	store.TimingAggregate(tee.TimingAggregate{Window: 30 * time.Second, Requests: 2})

	recorder := pull(t, store, http.MethodGet)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: what the endpoint serves is what the TEE has right now", got)
	}
	var out timingResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	if out.Service != "tokenhive-tee" || out.Served != 2 || out.Retained != 2 || out.Total != 2 || out.Dropped != 0 {
		t.Errorf("envelope = %+v, want 2 served / 2 retained / 2 total / 0 dropped of tokenhive-tee", out)
	}
	if len(out.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(out.Records))
	}
	for key, want := range map[string]any{
		"seq":      float64(1),
		"at":       "2026-10-15T07:00:00Z",
		"job":      "9f3a",
		"provider": "openai",
		"host":     "chatgpt.com",
		"outcome":  "complete",
		"ttfb_ms":  903.0,
	} {
		if got := out.Records[0][key]; got != want {
			t.Errorf("record[%s] = %v, want %v", key, got, want)
		}
	}

	// A stall is stored and served like anything else, in its own shape: the
	// stage it has not left, and none of the fields of a request that finished.
	stall := out.Records[1]
	if stall["stage"] != tee.StageTLS || stall["waited_ms"] != 30000.0 {
		t.Errorf("stall = %v, want the stage and how long it has been in it", stall)
	}
	if _, present := stall["outcome"]; present {
		t.Error("a stall has no outcome")
	}

	if out.Aggregate == nil || out.Aggregate["requests"] != float64(2) {
		t.Errorf("aggregate = %v, want the summary the TEE emitted", out.Aggregate)
	}

	// An empty store answers with an empty list rather than a null, so a puller
	// that has not missed anything reads the same shape either way.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(pull(t, NewStore("tokenhive-tee", 4), http.MethodGet).Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode empty pull: %v", err)
	}
	if string(raw["records"]) != "[]" {
		t.Errorf("empty pull records = %s, want []", raw["records"])
	}
}

// TestServerRejectsWrites pins the one refusal: the endpoint is a read, and
// answering a write would suggest otherwise.
func TestServerRejectsWrites(t *testing.T) {
	recorder := pull(t, NewStore("tokenhive-tee", 4), http.MethodPost)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", recorder.Code)
	}
	if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("Allow = %q, want GET", allow)
	}
}
