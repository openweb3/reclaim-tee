package tee

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// recordingSink captures what the service reports. It is safe for concurrent
// use because the stall watcher reports from its own goroutine.
type recordingSink struct {
	mu         sync.Mutex
	requests   []TimingRecord
	aggregates []TimingAggregate
}

func (s *recordingSink) TimingRequest(rec TimingRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, rec)
}

func (s *recordingSink) TimingAggregate(agg TimingAggregate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aggregates = append(s.aggregates, agg)
}

func (s *recordingSink) records() []TimingRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TimingRecord(nil), s.requests...)
}

func (s *recordingSink) summaries() []TimingAggregate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TimingAggregate(nil), s.aggregates...)
}

// waitFor polls until a matching record arrives. The stall path reports from a
// goroutine, so there is no event to select on and a poll is the honest shape.
func (s *recordingSink) waitFor(t *testing.T, match func(TimingRecord) bool) TimingRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, rec := range s.records() {
			if match(rec) {
				return rec
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("no matching record arrived within the deadline; got %d records", len(s.records()))
	return TimingRecord{}
}

// stagesOf lists a record's stage names, which is what most of these tests
// assert on: the names and their order are the measurement.
func stagesOf(rec TimingRecord) []string {
	names := make([]string, 0, len(rec.Stages))
	for _, stage := range rec.Stages {
		names = append(names, stage.Name)
	}
	return names
}

func statsOf(agg TimingAggregate) []string {
	names := make([]string, 0, len(agg.Stages))
	for _, stat := range agg.Stages {
		names = append(names, stat.Name)
	}
	return names
}

func sameNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// statOf returns one stage's stat, failing the test when it is absent.
func statOf(t *testing.T, agg TimingAggregate, name string) TimingStat {
	t.Helper()
	for _, stat := range agg.Stages {
		if stat.Name == name {
			return stat
		}
	}
	t.Fatalf("stage %q is absent from the aggregate %v", name, statsOf(agg))
	return TimingStat{}
}

// TestParseTimingLevel pins what a deployment may put in TEE_TIMING. The
// spelling is the operator's interface, so a typo has to be refused at startup
// rather than silently read as off, and whatever String prints has to be what
// the parser reads back.
func TestParseTimingLevel(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    TimingLevel
		wantErr bool
	}{
		{"", TimingOff, false},
		{" OFF ", TimingOff, false},
		{"summary", TimingSummary, false},
		{"Full", TimingFull, false},
		{"verbose", TimingOff, true},
	} {
		got, err := ParseTimingLevel(tc.in)
		if tc.wantErr != (err != nil) {
			t.Errorf("ParseTimingLevel(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseTimingLevel(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		if back, err := ParseTimingLevel(got.String()); err != nil || back != got {
			t.Errorf("ParseTimingLevel(%q) = %v, %v: a level must read back what it prints", got.String(), back, err)
		}
	}
}

// TestTimingsRecordsAChain pins the recorder's central properties: stages land
// in the order they were marked, Close closes the stage still open, and time
// spent in one stage twice is one entry carrying the total.
func TestTimingsRecordsAChain(t *testing.T) {
	jobID := []byte{0xde, 0xad, 0xbe, 0xef}
	tm := NewTimings()
	tm.Identify(jobID, "openai", "chatgpt.com", "POST", true)
	tm.SetCold()
	tm.Mark(StageRead)
	time.Sleep(5 * time.Millisecond)
	tm.Mark(StageGate)
	time.Sleep(10 * time.Millisecond)
	// A re-dial: the transport takes a second connection, so it pays to
	// acquire and to write twice. The record says so once, with the totals.
	tm.Mark(StageGate)
	time.Sleep(5 * time.Millisecond)
	tm.Mark(StageTTFB)
	time.Sleep(5 * time.Millisecond)

	tm.SetTraffic(4096, 7)
	rec := tm.Close(TimingComplete, nil)

	if got, want := stagesOf(rec), []string{StageRead, StageGate, StageTTFB}; !sameNames(got, want) {
		t.Fatalf("stages = %v, want %v", got, want)
	}
	if rec.Stages[1].Dur < 10*time.Millisecond {
		t.Errorf("%s duration = %v, want >= 10ms for a 10ms + 5ms pair of spans", StageGate, rec.Stages[1].Dur)
	}
	if rec.Stages[2].Dur < 5*time.Millisecond {
		t.Errorf("%s duration = %v, want >= 5ms: Close must close the open stage", StageTTFB, rec.Stages[2].Dur)
	}
	if rec.JobID != hex.EncodeToString(jobID) || rec.Provider != "openai" || rec.Host != "chatgpt.com" ||
		rec.Method != "POST" || !rec.Stream || !rec.Cold || rec.Bytes != 4096 || rec.Chunks != 7 {
		t.Errorf("record did not carry its identity and traffic: %+v", rec)
	}
	if rec.Outcome != TimingComplete || rec.Err != "" || rec.At.IsZero() {
		t.Errorf("record did not carry its outcome: %+v", rec)
	}
}

// TestTimingsIsFinalAfterClose pins the guard the stall watcher relies on: a
// record that has been reported can never change again, so a watcher that wakes
// late cannot describe a request that is over.
func TestTimingsIsFinalAfterClose(t *testing.T) {
	tm := NewTimings()
	tm.Mark(StageRead)
	tm.Close(TimingComplete, nil)

	tm.Mark(StageBody)
	tm.SetCold()
	tm.AddEgress(time.Hour)
	second := tm.Close(TimingFailed, errors.New("late"))

	if got, want := stagesOf(second), []string{StageRead}; !sameNames(got, want) {
		t.Errorf("stages after close = %v, want %v", got, want)
	}
	if second.Cold || second.Egress != 0 {
		t.Error("a write after Close changed the reported record")
	}
	if !tm.Closed() {
		t.Error("Closed() = false after Close")
	}
}

// TestTimingsStallNamesTheOpenStage is the whole point of a stall: not what
// finished, but what has not.
func TestTimingsStallNamesTheOpenStage(t *testing.T) {
	tm := NewTimings()
	tm.Mark(StageRead)
	tm.Mark(StageTLS)
	time.Sleep(5 * time.Millisecond)

	stage, waited := tm.Current()
	if stage != StageTLS || waited < 5*time.Millisecond {
		t.Errorf("Current() = %q/%v, want %s with >= 5ms", stage, waited, StageTLS)
	}

	stall := tm.Stall()
	if stall.Outcome != TimingRunning || stall.Stage != StageTLS || stall.Waited < 5*time.Millisecond {
		t.Errorf("stall = %+v, want a running record in %s", stall, StageTLS)
	}
	if got, want := stagesOf(stall), []string{StageRead}; !sameNames(got, want) {
		t.Errorf("stall stages = %v, want %v (the open one is not closed)", got, want)
	}
}

// TestTimingsAreNilSafe pins the property that lets every call site stay
// unconditional: an uninstrumented request carries a nil record and marks it
// anyway.
func TestTimingsAreNilSafe(t *testing.T) {
	var tm *Timings
	tm.Mark(StageRead)
	tm.Identify([]byte("job"), "p", "h", "POST", false)
	tm.SetCold()
	tm.SetTraffic(1, 2)
	tm.AddEgress(time.Second)

	if stage, waited := tm.Current(); stage != "" || waited != 0 {
		t.Errorf("Current() on a nil record = %q/%v, want empty", stage, waited)
	}
	if !tm.Closed() {
		t.Error("a nil record must read as closed, or a watcher would wait on it forever")
	}
	if got := tm.Stall(); got.Outcome != TimingRunning || got.Stage != "" {
		t.Errorf("Stall() on a nil record = %+v, want the zero record", got)
	}
	if got := tm.Close(TimingComplete, nil); got.Outcome != TimingRunning {
		t.Errorf("Close() on a nil record = %+v, want the zero record", got)
	}

	// And the same through the context, which is how every layer gets one.
	if TimingsFrom(WithTimings(context.Background(), nil)) != nil {
		t.Error("WithTimings(nil) must leave the context without a record")
	}
	if TimingsFrom(context.Background()) != nil {
		t.Error("a context that never carried a record must report none")
	}
}

// TestTimingReporterHonoursTheLevel pins the volume rule the console depends
// on: full forwards every request line, summary forwards none of them, and
// neither loses a stall — a stall is the one line that says a request is not
// finishing, and it must not be silenced by a level setting.
func TestTimingReporterHonoursTheLevel(t *testing.T) {
	for _, tc := range []struct {
		level     TimingLevel
		wantLines int
	}{
		{TimingSummary, 0},
		{TimingFull, 1},
	} {
		out := &recordingSink{}
		reporter := NewTimingReporter(tc.level, out, time.Minute)
		reporter.TimingRequest(TimingRecord{Outcome: TimingComplete, Stages: []TimingStage{{Name: StageTTFB, Dur: time.Second}}})
		if got := len(out.records()); got != tc.wantLines {
			t.Errorf("level %v forwarded %d request lines, want %d", tc.level, got, tc.wantLines)
		}

		reporter.TimingRequest(TimingRecord{Outcome: TimingRunning, Stage: StageTLS, Waited: time.Minute})
		if got := len(out.records()); got != tc.wantLines+1 {
			t.Errorf("level %v dropped a stall: %d lines, want %d", tc.level, got, tc.wantLines+1)
		}
	}
}

// TestTimingReporterSummarisesAWindow pins the aggregate: counts, per-stage
// percentiles, the ordering a reader parses by position, and the two silences
// that make the line worth trusting — an idle window says nothing, and a flushed
// window does not carry its samples into the next one.
func TestTimingReporterSummarisesAWindow(t *testing.T) {
	out := &recordingSink{}
	reporter := NewTimingReporter(TimingSummary, out, time.Minute)

	// Twenty records, one per millisecond of ttfb and read, so the percentiles
	// are known by construction rather than by recomputing them here.
	for i := 1; i <= 20; i++ {
		reporter.TimingRequest(TimingRecord{
			Outcome: TimingComplete,
			Cold:    i == 1,
			Stages: []TimingStage{
				{Name: StageTTFB, Dur: time.Duration(i) * time.Millisecond},
				{Name: StageRead, Dur: time.Duration(i) * time.Millisecond},
			},
		})
	}
	// A failed request and an unfinished one: the first counts as a failure,
	// the second is not a request that finished at all.
	reporter.TimingRequest(TimingRecord{Outcome: TimingFailed, Err: "boom"})
	reporter.TimingRequest(TimingRecord{Outcome: TimingRunning, Stage: StageBody})

	reporter.Flush()
	summaries := out.summaries()
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries, want 1", len(summaries))
	}
	agg := summaries[0]
	if agg.Requests != 21 || agg.Cold != 1 || agg.Failed != 1 {
		t.Errorf("window counts = %d/%d/%d, want 21 requests, 1 cold, 1 failed", agg.Requests, agg.Cold, agg.Failed)
	}
	if got, want := statsOf(agg), []string{StageRead, StageTTFB, timingSinkStage}; !sameNames(got, want) {
		t.Fatalf("window stages = %v, want %v: the request's stages in order, the sink's cost last", got, want)
	}
	ttfb := statOf(t, agg, StageTTFB)
	if ttfb.Samples != 20 || ttfb.P50 != 10*time.Millisecond || ttfb.P95 != 19*time.Millisecond {
		t.Errorf("ttfb stat = %+v, want 20 samples, p50 10ms, p95 19ms (nearest rank of 1..20ms)", ttfb)
	}
	// Only the stall reached the sink at this level, and its cost is reported
	// like any other name in the window: the aggregate has to say what the
	// instrumentation itself cost.
	if sink := statOf(t, agg, timingSinkStage); sink.Samples != 1 {
		t.Errorf("sink samples = %d, want 1 (the one line this level forwarded)", sink.Samples)
	}

	// An idle window is silent, and the window after a flush starts empty: a
	// cumulative p95 would describe a period nobody asked about.
	reporter.Flush()
	if got := len(out.summaries()); got != 1 {
		t.Errorf("a window with no requests emitted %d summaries, want 0", got-1)
	}
	reporter.TimingRequest(TimingRecord{Outcome: TimingComplete, Stages: []TimingStage{{Name: StageTTFB, Dur: time.Second}}})
	reporter.Flush()
	last := out.summaries()[1]
	if last.Requests != 1 || statOf(t, last, StageTTFB).Samples != 1 {
		t.Errorf("window after the flush = %+v, want exactly the one request that arrived", last)
	}
}

// sleepySink takes a measurable amount of time to accept a record, standing in
// for the serial console: a write that costs more than the work it describes is
// the failure mode the sink measurement exists to expose.
type sleepySink struct {
	recordingSink
	delay time.Duration
}

func (s *sleepySink) TimingRequest(rec TimingRecord) {
	time.Sleep(s.delay)
	s.recordingSink.TimingRequest(rec)
}

// TestTimingReporterMeasuresTheSinkCost pins the self-calibration: the summary
// says how long the instrumentation's own output took, so a reader can tell
// "this TEE is slow" from "this TEE's logging is slow".
func TestTimingReporterMeasuresTheSinkCost(t *testing.T) {
	out := &sleepySink{delay: 5 * time.Millisecond}
	reporter := NewTimingReporter(TimingFull, out, time.Minute)
	reporter.TimingRequest(TimingRecord{Outcome: TimingComplete, Stages: []TimingStage{{Name: StageTTFB, Dur: time.Second}}})
	reporter.Flush()

	summaries := out.summaries()
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries, want 1", len(summaries))
	}
	sink := statOf(t, summaries[0], timingSinkStage)
	if sink.Samples != 1 || sink.P95 < 5*time.Millisecond {
		t.Errorf("sink cost = %d samples / p95 %v, want the 5ms the sink slept", sink.Samples, sink.P95)
	}
}

// TestTimingSinksFansOut pins the two properties the process edge depends on
// when it feeds both the logger and the metrics store from one record: every
// destination sees the same value, and a nil entry is skipped rather than
// panicking on the request path.
func TestTimingSinksFansOut(t *testing.T) {
	first, second := &recordingSink{}, &recordingSink{}
	var sinks TimingSinks = TimingSinks{nil, first, second}

	sinks.TimingRequest(TimingRecord{JobID: "9f3a", Outcome: TimingComplete})
	sinks.TimingAggregate(TimingAggregate{Requests: 1})

	for i, sink := range []*recordingSink{first, second} {
		if got := sink.records(); len(got) != 1 || got[0].JobID != "9f3a" {
			t.Errorf("sink %d records = %+v, want the one record", i, got)
		}
		if got := sink.summaries(); len(got) != 1 || got[0].Requests != 1 {
			t.Errorf("sink %d summaries = %+v, want the one summary", i, got)
		}
	}
}

// TestNewServiceTimingWiring pins the two configuration rules: a level with
// nothing to send it to is refused rather than silently dropped, and an
// explicitly-off configuration is dropped so an uninstrumented TEE checks one
// nil pointer instead of a flag.
func TestNewServiceTimingWiring(t *testing.T) {
	build := func(timing *TimingConfig) (*Service, error) {
		doc := defaultPolicy()
		return NewService(Config{
			Policy:    &doc,
			Transport: &fakeTransport{},
			Signer:    proof.NewSigner(newTestEpoch(t)),
			Seq:       NewMemorySeqStore(),
			InboxKey:  newInbox(t),
			Timing:    timing,
		})
	}

	if _, err := build(&TimingConfig{Level: TimingFull}); !errors.Is(err, ErrNoTimingSink) {
		t.Errorf("NewService error = %v, want ErrNoTimingSink", err)
	}
	svc, err := build(&TimingConfig{Level: TimingOff, Sink: &recordingSink{}})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.timing != nil {
		t.Error("an off configuration was kept, so an uninstrumented TEE would still branch on it")
	}
}

// markingTransport stands in for the real transport: it marks the stages the
// network layer owns, so a test can prove that marks made in one layer land in
// the record another layer opened — which is the whole reason the record
// travels in the context instead of through a signature.
type markingTransport struct {
	// stages are marked back to back before the exchange begins, in order.
	stages []string
	// hold, when non-nil, keeps Do inside its last marked stage until closed.
	hold chan struct{}
	// err is returned after the chunks, for the failure path.
	err error

	chunks [][]byte
}

func (m *markingTransport) Do(ctx context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	tm := TimingsFrom(ctx)
	for _, name := range m.stages {
		tm.Mark(name)
	}
	if m.hold != nil {
		<-m.hold
	}
	resp := Response{StatusCode: 200}
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	for _, chunk := range m.chunks {
		if onChunk != nil {
			if err := onChunk(chunk); err != nil {
				return resp, err
			}
		}
	}
	return resp, m.err
}

// executeThroughServeExecute drives one real request through the handler and
// returns the record it reported, which is the only assertion that covers the
// whole path: a record opened by the handler, marked by the service, marked
// again by the transport, and reported when the response is written.
func executeThroughServeExecute(t *testing.T, env *testEnv, sink *recordingSink, payload []byte) (TimingRecord, jobs.Spec) {
	t.Helper()
	spec := env.spec(t, payload)
	body, err := ExecuteRequest{Spec: spec, Body: payload}.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode execute request: %v", err)
	}
	rec := httptest.NewRecorder()
	ServeExecute(env.service, rec, httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("execute status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	return sink.waitFor(t, func(r TimingRecord) bool { return r.Outcome != TimingRunning }), spec
}

// TestServiceRecordsTheWholeRequestChain pins the stage chain of a healthy
// request end to end: every stage the design names, in the order they happen,
// with the layers' marks interleaved the way the request really ran.
func TestServiceRecordsTheWholeRequestChain(t *testing.T) {
	sink := &recordingSink{}
	env := newTestEnv(t, func(cfg *Config) {
		cfg.Transport = &markingTransport{
			stages: []string{StageAcquire, StageWrite, StageTTFB, StageBody},
			chunks: [][]byte{[]byte("a"), []byte("bb")},
		}
		cfg.Timing = &TimingConfig{Level: TimingFull, Sink: sink}
	})

	rec, spec := executeThroughServeExecute(t, env, sink, []byte(`{"model":"m"}`))

	want := []string{
		StageRead, StageGate, StageCred, StageHash, StageSeq,
		StageAcquire, StageWrite, StageTTFB, StageBody, StageSign, StageEmit,
	}
	if got := stagesOf(rec); !sameNames(got, want) {
		t.Errorf("stage chain = %v, want %v", got, want)
	}
	if rec.Outcome != TimingComplete || rec.Err != "" {
		t.Errorf("outcome = %v (%q), want complete", rec.Outcome, rec.Err)
	}
	if rec.JobID != hex.EncodeToString(spec.JobID) {
		t.Errorf("job id = %q, want %q", rec.JobID, hex.EncodeToString(spec.JobID))
	}
	if rec.Provider != "openai" || rec.Host != "api.openai.com" || rec.Method != "POST" || !rec.Stream {
		t.Errorf("identity not carried: %+v", rec)
	}
	if rec.Bytes != 3 || rec.Chunks != 2 {
		t.Errorf("traffic = %d bytes / %d chunks, want 3 / 2", rec.Bytes, rec.Chunks)
	}
}

// TestServeExecuteReportsARefusedRequest pins that the reporting happens on the
// refusal paths too, and that a record from before the spec decoded has no job
// to name while still saying which stage it died in.
func TestServeExecuteReportsARefusedRequest(t *testing.T) {
	sink := &recordingSink{}
	env := newTestEnv(t, func(cfg *Config) {
		cfg.Timing = &TimingConfig{Level: TimingFull, Sink: sink}
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader([]byte("not-canonical-cbor")))
	ServeExecute(env.service, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	got := sink.waitFor(t, func(r TimingRecord) bool { return r.Outcome != TimingRunning })
	if got.Outcome != TimingFailed || got.Err == "" {
		t.Errorf("refused record = %+v, want a failure carrying its reason", got)
	}
	if got.JobID != "" {
		t.Errorf("job id = %q, want empty: the body never decoded", got.JobID)
	}
	if names := stagesOf(got); !sameNames(names, []string{StageRead}) {
		t.Errorf("stages = %v, want just the stage it died in", names)
	}
}

// TestStallWatcherReportsARequestThatIsNotMoving is the line the whole feature
// exists for: a request wedged somewhere says where, while it is still wedged,
// and the finished record still arrives afterwards.
func TestStallWatcherReportsARequestThatIsNotMoving(t *testing.T) {
	hold := make(chan struct{})
	sink := &recordingSink{}
	env := newTestEnv(t, func(cfg *Config) {
		cfg.Transport = &markingTransport{stages: []string{StageAcquire, StageTLS}, hold: hold}
		cfg.Timing = &TimingConfig{Level: TimingFull, Sink: sink, StallThreshold: 30 * time.Millisecond}
	})

	payload := []byte(`{"model":"m"}`)
	spec := env.spec(t, payload)
	body, err := ExecuteRequest{Spec: spec, Body: payload}.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode execute request: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ServeExecute(env.service, httptest.NewRecorder(),
			httptest.NewRequest(http.MethodPost, "/v1/execute", bytes.NewReader(body)))
	}()

	stall := sink.waitFor(t, func(r TimingRecord) bool { return r.Outcome == TimingRunning })
	if stall.Stage != StageTLS || stall.Waited < 30*time.Millisecond {
		t.Fatalf("stall = %s/%v, want %s held past the 30ms threshold", stall.Stage, stall.Waited, StageTLS)
	}
	if stall.JobID != hex.EncodeToString(spec.JobID) || stall.Provider != "openai" {
		t.Errorf("stall identity = %q/%q, want it attributable to the job", stall.JobID, stall.Provider)
	}

	// Let the request finish: the record still has to arrive, and the watcher
	// has to stop on its own.
	close(hold)
	<-done
	final := sink.waitFor(t, func(r TimingRecord) bool { return r.Outcome == TimingComplete })
	if names := stagesOf(final); !sameNames(names, []string{
		StageRead, StageGate, StageCred, StageHash, StageSeq, StageAcquire, StageTLS, StageSign, StageEmit,
	}) {
		t.Errorf("final stage chain = %v", names)
	}
}

// TestStallWatcherIsSilentWhenDisabled pins that a negative threshold means no
// watcher at all: a deployment that only wants the summary must not pay a
// goroutine per request for a report it turned off.
func TestStallWatcherIsSilentWhenDisabled(t *testing.T) {
	sink := &recordingSink{}
	env := newTestEnv(t, func(cfg *Config) {
		cfg.Timing = &TimingConfig{Level: TimingFull, Sink: sink, StallThreshold: -1}
	})

	tm := NewTimings()
	tm.Mark(StageTLS)
	stop := env.service.watchStall(tm)
	defer stop()

	// Several cadences, had a watcher been started for the threshold a negative
	// value would otherwise imply.
	time.Sleep(50 * time.Millisecond)
	if got := len(sink.records()); got != 0 {
		t.Errorf("a disabled watcher reported %d records", got)
	}
	if stop := env.service.watchStall(nil); stop == nil {
		t.Fatal("watchStall must always return a callable stop")
	}
}
