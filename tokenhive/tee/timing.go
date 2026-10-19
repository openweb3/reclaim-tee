package tee

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// This file is the TEE's instrumentation. It answers one question — where did
// this request's time go — and nothing else.
//
// Four properties decide its shape.
//
// One line per request. The enclave's always-available channel is the serial
// console, and on these instances it holds about 64 KiB that boot lines, kernel
// messages and handshake errors all compete for. So a request reports once, at
// the end, with every stage on that single line: two lines per request would
// halve how many the window can hold.
//
// Free when off. Nothing here allocates or reads a clock unless the service was
// configured with a level, and every method tolerates a nil receiver, so an
// instrumented and an uninstrumented call site are the same code. Turning the
// level off must not change what the TEE does, only what it says.
//
// Stage names are a log contract. They are exported constants because a reader
// greps for them and a dashboard sums them, so a name is never reused for a
// different interval.
//
// No logging library. The package takes a sink interface and imports nothing
// but the standard library, for the same reason it owns no network code: the
// parts of the system with security meaning stay reviewable on their own, and
// the choice of sink — console JSON, CloudWatch, a test spy — belongs to the
// process edge.

// TimingLevel is how much instrumentation a service produces.
type TimingLevel uint8

const (
	// TimingOff is the default. No recorder is allocated, no clock is read,
	// and the sink is never called.
	TimingOff TimingLevel = iota

	// TimingSummary emits one aggregate line per window and no per-request
	// lines. It is the level a TEE can run at indefinitely: a busy hour costs
	// about a hundred lines.
	TimingSummary

	// TimingFull adds one line per request on top of the summary. The serial
	// console holds roughly a hundred of them, so it is for a bounded run
	// unless the sink ships off the instance (on AWS the structured logger
	// does, whenever the instance carries an instance profile that can write
	// to CloudWatch — see shared/logger_cloudwatch_linux.go).
	TimingFull
)

// String returns the level's own spelling, which is also what ParseTimingLevel
// accepts, so a deployment and this package cannot disagree about the names.
func (l TimingLevel) String() string {
	switch l {
	case TimingOff:
		return "off"
	case TimingSummary:
		return "summary"
	case TimingFull:
		return "full"
	default:
		return fmt.Sprintf("TimingLevel(%d)", uint8(l))
	}
}

// ParseTimingLevel reads a level name. The empty string is off, because that is
// what an unset environment variable means.
func ParseTimingLevel(s string) (TimingLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return TimingOff, nil
	case "summary":
		return TimingSummary, nil
	case "full":
		return TimingFull, nil
	default:
		return TimingOff, fmt.Errorf("unknown timing level %q: want off, summary or full", s)
	}
}

// Stage names. Each is one interval on a request's own timeline, measured by
// the component that performs it: this package for the admission stages,
// transport for the network ones.
//
// The stages are a partition, not a hierarchy. Nothing nests, so their sum is
// the request's wall time and no millisecond is attributed twice — which is
// also why `egress` on the record is a field rather than a stage: it is time
// spent inside `body`, and a stage would double-count it.
const (
	// StageRead is the /v1/execute body being read from the Hub and decoded.
	// It is the first stage, and the one that covers a slow Hub↔TEE link.
	StageRead = "read"

	// StageGate is admission: the freshness refusals, the submitter check, the
	// spec and body binding, the policy decision, and the body-size cap.
	StageGate = "gate"

	// StageCred is the credential envelope opened and the provider's secret
	// merged into the outbound headers.
	StageCred = "cred"

	// StageHash is the job spec digest the receipt commits to.
	StageHash = "hash"

	// StageSeq is the provider sequence allocation: the one admission step
	// that writes to disk, and the only mutation before the wire.
	StageSeq = "seq"

	// StageAcquire is taking a connection — an idle one from the pool, or a
	// slot to open a new one. A request queued behind the per-host cap spends
	// its wait here.
	StageAcquire = "acquire"

	// StageDial is opening the relay stream a new provider connection rides,
	// which on the first request of a process also establishes the tunnel to
	// the Hub. Present only on a cold connection.
	StageDial = "dial"

	// StageTLS is the upstream TLS handshake. It terminates inside the TEE and
	// runs over the relayed stream, so its duration is the whole chain's
	// round trips, not just the provider's. Present only on a cold connection.
	StageTLS = "tls"

	// StageWrite is the request bytes going out.
	StageWrite = "write"

	// StageTTFB is the wait for the response headers. It is the provider's own
	// queueing and thinking time plus the relay chain, and none of it is ours.
	StageTTFB = "ttfb"

	// StageBody is the response body relayed to the caller, and the response
	// start frame that precedes the first chunk of it.
	StageBody = "body"

	// StageSign is the receipt built and signed. With evidence embedded it
	// covers canonicalising the evidence too, which is the larger part.
	StageSign = "sign"

	// StageEmit is the receipt frame encoded and written to the caller.
	StageEmit = "emit"
)

// timingStageOrder is the order the stages occur in on a complete request, and
// the order an aggregate reports them in. A warm request simply has no dial or
// tls entry, which is how a reader tells a pooled connection from a new one.
var timingStageOrder = []string{
	StageRead, StageGate, StageCred, StageHash, StageSeq,
	StageAcquire, StageDial, StageTLS, StageWrite, StageTTFB, StageBody,
	StageSign, StageEmit,
}

// TimingOutcome is how a request ended. It is the receipt's own completion
// state under names this package reads better, plus the one state a receipt can
// never name: a request that has not ended yet, which is what a stall reports.
//
// Sharing the type rather than mirroring it is what keeps a log line and the
// signed proof of the same request from ever disagreeing about whether it
// finished whole — there is one value, and both sides read it.
type TimingOutcome = proof.CompletionState

const (
	// TimingRunning is a request that has not ended: the record of a stall.
	TimingRunning = proof.CompletionUnspecified
	// TimingComplete is a response the provider finished.
	TimingComplete = proof.CompletionComplete
	// TimingTruncated is a response cut short, by the size cap or by the
	// provider dropping the connection.
	TimingTruncated = proof.CompletionTruncated
	// TimingFailed is a request that produced no usable response at all.
	TimingFailed = proof.CompletionFailed
)

// TimingStage is one measured interval.
type TimingStage struct {
	Name string
	Dur  time.Duration
}

// TimingRecord is one request's instrumentation.
//
// It is flat on purpose: a sink renders it as fields, a shipper stores them,
// and a query filters on them. A record that nested its stages would need a
// reader that knew the shape.
type TimingRecord struct {
	// At is when the record was reported: for a finished request, when it
	// ended, and for a stall, when it was described. The request began
	// At minus the sum of its stages.
	At time.Time

	// JobID is the spec's job ID in hex, and it is what ties this line to the
	// Hub's own lines for the same request. Empty on a record reported before
	// the body decoded, where there is no job to name yet.
	JobID    string
	Provider string
	Host     string
	Method   string
	Stream   bool

	// Outcome is how the request ended, or TimingRunning for a stall.
	Outcome TimingOutcome

	// Err is why it failed, when it did. A stall carries none: nothing has
	// failed yet, the request is simply not moving.
	Err string

	// Cold reports that the exchange opened a new provider connection, so its
	// cost includes dial and tls. False means it reused a pooled one.
	Cold bool

	// Bytes and Chunks are what the provider sent, counted exactly as the
	// receipt counts them.
	Bytes  uint64
	Chunks uint64

	// Egress is how long the request spent writing response frames to the
	// caller. It sits inside Body rather than beside it, and it is the only
	// number here that is the TEE's own cost during the relay.
	Egress time.Duration

	// Stages are the measured intervals in the order they first happened, one
	// entry per stage: a stage that time was spent in twice carries its total,
	// never two entries. See Timings.closeLocked.
	Stages []TimingStage

	// Stage and Waited are set on a stall record only: the stage the request
	// has not left, and how long it has been in it.
	Stage  string
	Waited time.Duration
}

// TimingStat is one stage's distribution over a window.
type TimingStat struct {
	Name    string
	P50     time.Duration
	P95     time.Duration
	Samples int
}

// TimingAggregate is one window of requests, summarised. Percentiles rather
// than a mean: request time is dominated by the provider's own thinking, so a
// distribution with one slow request in it is the normal case, not an outlier.
type TimingAggregate struct {
	// Window is how long the summary covers.
	Window time.Duration
	// Requests is how many finished in it. A stall is not counted: it is a
	// request that has not finished.
	Requests int
	// Cold is how many of them opened a new provider connection.
	Cold int
	// Failed is how many ended failed. Truncated responses are not failed —
	// the provider answered, just not to the end.
	Failed int
	// Stages carries one stat per name that had samples, in the order a request
	// goes through them, with the instrumentation's own cost last.
	//
	// That last one is not navel-gazing. The sink is where the serial console is
	// written, and a console write is the one thing here that can cost more than
	// the work it describes — an instrumented TEE whose report takes longer than
	// its requests would produce numbers that are true of a system nobody runs.
	// A "sink" that stays in the microseconds says the measurements are clean;
	// one that climbs into the milliseconds says to turn the level down before
	// believing anything else in the window.
	Stages []TimingStat
}

// TimingSink is where a service's instrumentation goes. The process edge
// implements it over the structured logger; the service only ever calls it.
//
// Two methods rather than one record type with a discriminator: a sink that
// rendered a summary as if it were a request would be a bug nobody notices
// until they read the numbers.
type TimingSink interface {
	TimingRequest(TimingRecord)
	TimingAggregate(TimingAggregate)
}

// TimingSinks fans one stream out to several sinks, in the order given.
//
// It exists because a TEE wants more than one destination at once and neither
// replaces the other: the structured logger is the durable channel (the serial
// console, or CloudWatch when the instance carries a profile), and the metrics
// store is the pullable one, which holds more detail than the console window
// ever could. Both are fed from the same record, so an operator comparing them
// is comparing two renderings of one measurement rather than two measurements.
type TimingSinks []TimingSink

// TimingSinks is itself a sink, so a fan-out can be nested and a caller never
// has to know how many destinations there are.
var _ TimingSink = TimingSinks(nil)

func (s TimingSinks) TimingRequest(rec TimingRecord) {
	for _, one := range s {
		if one != nil {
			one.TimingRequest(rec)
		}
	}
}

func (s TimingSinks) TimingAggregate(agg TimingAggregate) {
	for _, one := range s {
		if one != nil {
			one.TimingAggregate(agg)
		}
	}
}

// The reporter is a sink in both directions, so a drift here is a build
// failure rather than a line that silently stops appearing.
var _ TimingSink = (*TimingReporter)(nil)

// TimingField is one rendered field of a record: the name a reader greps for
// and the value they filter by.
type TimingField struct {
	Name  string
	Value any
}

// Millis renders a duration as milliseconds, which is the unit every field
// name in this file is suffixed with. Durations are not rendered as
// seconds-as-duration, where a two-millisecond signing step reads as 0.002.
func Millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// Flat renders a record as the ordered fields every consumer of it agrees on:
// the structured logger turns them into log fields, a metrics endpoint into
// JSON members. One spelling for both, which is the point — the name a query
// filters on is the name in either place.
func (rec TimingRecord) Flat() []TimingField {
	fields := []TimingField{
		{Name: "job", Value: rec.JobID},
		{Name: "provider", Value: rec.Provider},
		{Name: "host", Value: rec.Host},
		{Name: "method", Value: rec.Method},
		{Name: "stream", Value: rec.Stream},
		{Name: "cold", Value: rec.Cold},
	}

	// A stall is a different answer to a different question — which stage a
	// request has not left — so it does not carry the fields of a request that
	// finished. Its finished stages are deliberately absent too: the stage it
	// is stuck in is the story, and a reader of a stall line should not have to
	// work out which of the numbers is the interesting one.
	if rec.Outcome == TimingRunning {
		return append(fields,
			TimingField{Name: "stage", Value: rec.Stage},
			TimingField{Name: "waited_ms", Value: Millis(rec.Waited)},
		)
	}

	fields = append(fields,
		TimingField{Name: "outcome", Value: rec.Outcome.String()},
		TimingField{Name: "bytes", Value: rec.Bytes},
		TimingField{Name: "chunks", Value: rec.Chunks},
		TimingField{Name: "egress_ms", Value: Millis(rec.Egress)},
	)
	if rec.Err != "" {
		fields = append(fields, TimingField{Name: "error", Value: rec.Err})
	}
	for _, stage := range rec.Stages {
		fields = append(fields, TimingField{Name: stage.Name + "_ms", Value: Millis(stage.Dur)})
	}
	return fields
}

// Flat renders a summary as the ordered fields of a summary line: the counts
// first, then one p50/p95/sample triple per stage that had samples, then the
// instrumentation's own cost.
func (agg TimingAggregate) Flat() []TimingField {
	fields := []TimingField{
		{Name: "requests", Value: agg.Requests},
		{Name: "cold", Value: agg.Cold},
		{Name: "failed", Value: agg.Failed},
		{Name: "window", Value: agg.Window.String()},
	}
	for _, stat := range agg.Stages {
		fields = append(fields,
			TimingField{Name: stat.Name + "_p50_ms", Value: Millis(stat.P50)},
			TimingField{Name: stat.Name + "_p95_ms", Value: Millis(stat.P95)},
			TimingField{Name: stat.Name + "_n", Value: stat.Samples},
		)
	}
	return fields
}

// TimingConfig assembles a service's instrumentation. A nil Config.Timing is an
// uninstrumented service: nothing allocates, no clock is read, and every call
// site behaves exactly as it did before the instrumentation existed.
type TimingConfig struct {
	// Level is how much is recorded.
	Level TimingLevel

	// Sink receives what is recorded. Required whenever Level is not
	// TimingOff, and refused rather than defaulted — see ErrNoTimingSink.
	Sink TimingSink

	// StallThreshold is how long a request may sit in one stage before the
	// service reports it. Zero means DefaultStallThreshold, negative disables
	// the report.
	StallThreshold time.Duration
}

// DefaultStallThreshold is the stall report's default threshold. It is longer
// than a healthy request spends in any single stage (the provider's own
// thinking is charged to ttfb and body, and both can legitimately run for
// seconds) and far shorter than the exchange timeout, so a request that is
// actually wedged is reported several times before its own timeout kills it.
const DefaultStallThreshold = 30 * time.Second

// DefaultTimingWindow is the aggregate window when the caller names none.
const DefaultTimingWindow = 30 * time.Second

// timingsKey is the context key a record travels under. It is an unexported
// struct type so nothing outside can collide with it.
type timingsKey struct{}

// WithTimings carries a record through the call chain to the components that
// mark its stages.
//
// It travels in the context rather than in Request for one reason: the stages
// are marked by whoever does the work, and the work is spread across three
// layers — the HTTP handler reads the body, Service admits the job, transport
// performs the exchange. Threading a recorder through their signatures would
// change Service.Execute and Transport.Do, and Execute is called from every
// test there is; a per-request value is what contexts are for.
//
// A nil record leaves the context untouched, so an uninstrumented call allocates
// nothing.
func WithTimings(ctx context.Context, t *Timings) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, timingsKey{}, t)
}

// TimingsFrom returns the record carried by ctx, or nil when there is none.
// Every caller may mark a nil record: see Timings.
func TimingsFrom(ctx context.Context) *Timings {
	if t, ok := ctx.Value(timingsKey{}).(*Timings); ok {
		return t
	}
	return nil
}

// Timings is one request's record while it is still being written.
//
// It is a chain, not a tree: Mark closes the stage that was open and opens the
// next, so the stages land in the order they happened and their sum is the
// request's wall time. Nothing nests, which is why nothing here can double-count
// a millisecond.
//
// Every method tolerates a nil receiver, and that is the whole reason the
// instrumented and uninstrumented paths are one code path: a service that is not
// instrumented hands out nil, and the transport marks it without asking.
//
// It is safe for concurrent use. In the request path only the stall watcher
// runs beside the request's own goroutine, but the mutex is what lets the
// watcher read a record that is being written without the reader having to know
// how far along it is.
type Timings struct {
	mu sync.Mutex

	// identity, filled once the spec is in hand.
	jobID    string
	provider string
	host     string
	method   string
	stream   bool

	// The open stage, and the stages already closed.
	open     string
	openedAt time.Time
	closed   bool
	stages   []TimingStage

	// Fields the components that own them fill in as they learn them.
	cold   bool
	bytes  uint64
	chunks uint64
	egress time.Duration
}

// NewTimings starts a record. The caller owns it, hands it to the components
// that mark it (see WithTimings), and reports it from the Close return value.
func NewTimings() *Timings { return &Timings{} }

// Mark closes the open stage and opens name.
//
// The first Mark also starts the clock, so anything before it is unattributed.
// That is deliberate rather than incidental: a request whose body has not
// decoded yet has no job to attribute to, and the stall watcher can still say
// which stage such a request is sitting in.
func (t *Timings) Mark(name string) {
	if t == nil {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closeLocked(now)
	t.open, t.openedAt = name, now
}

// Identify names the request the record belongs to. It is called from the
// handler once the spec has been decoded, so a stall reported before that point
// carries no job ID.
//
// jobID is the spec's raw job ID; it is stored hex-encoded because that is how
// it appears in the Hub's own logs, which is what makes the two greppable
// together.
func (t *Timings) Identify(jobID []byte, provider, host, method string, stream bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.jobID = hex.EncodeToString(jobID)
	t.provider, t.host, t.method, t.stream = provider, host, method, stream
}

// SetCold marks that this request opened a new provider connection. Only the
// transport can know, and it is what makes the dial and tls stages in the record
// readable as "this request paid for a connection".
func (t *Timings) SetCold() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.cold = true
}

// SetTraffic records what the provider sent, as the receipt counts it.
func (t *Timings) SetTraffic(bytes, chunks uint64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.bytes, t.chunks = bytes, chunks
}

// AddEgress accumulates time spent writing response frames to the caller. It is
// called once per chunk of a streamed response, so it stays a lock and an add
// and nothing else — every other field here is written once.
//
// Every mutator respects Close, including this one, and the uniformity is the
// point: a reader should not have to work out which of them can still change a
// record that has already been reported. What a late write would change is a
// record nobody will read again — the reported one was copied out — so dropping
// it costs nothing and the invariant stays simple.
func (t *Timings) AddEgress(d time.Duration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.egress += d
}

// Current reports the open stage and how long it has been open, or "" when no
// stage is open.
func (t *Timings) Current() (string, time.Duration) {
	if t == nil {
		return "", 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.open == "" {
		return "", 0
	}
	return t.open, time.Since(t.openedAt)
}

// Closed reports whether the record has been finished. A watcher checks it
// before reporting, so a watcher that wakes after the request ended says
// nothing about a request that is over.
func (t *Timings) Closed() bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// Stall returns a record of the stage the request has not left. Its Stages are
// the stages that did finish: the open one is not among them, because nothing
// closed it.
//
// It reports false for a record that has closed, and that is not a courtesy:
// a watcher's check of Closed and its call to Stall are two moments, and the
// request can end between them. A snapshot taken across that gap would arrive
// *after* the record it belongs to, describing a finished request as one that
// is still running — the one shape of entry a reader of the pull cannot tell
// from the truth. Deciding it here, under the same lock Close takes, is what
// makes the two atomic.
func (t *Timings) Stall() (TimingRecord, bool) {
	if t == nil {
		return TimingRecord{}, false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return TimingRecord{}, false
	}
	rec := t.recordLocked(TimingRunning)
	rec.At = now
	rec.Stage, rec.Waited = t.open, now.Sub(t.openedAt)
	return rec, true
}

// Close ends the record and returns it, final.
//
// Nothing may mark a record afterwards, which is what keeps a watcher that
// fires after the request ended from printing a line about a request that is
// already over. A second Close returns the record again rather than appending
// the open stage twice.
func (t *Timings) Close(outcome TimingOutcome, err error) TimingRecord {
	if t == nil {
		return TimingRecord{}
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeLocked(now)
	t.closed = true
	rec := t.recordLocked(outcome)
	rec.At = now
	rec.Err = errString(err)
	return rec
}

// closeLocked closes the open stage, if any. Caller holds t.mu.
//
// A name that is already on the record has its time added to the entry it
// already has rather than getting a second one. The only way a name repeats is
// the transport re-dialling a connection a pooled socket lost, and one entry
// per stage is what keeps every consumer of a record from having to decide
// whether to sum the repeats or list them. The cost of a stage that happened
// twice is its total, which is the honest thing for a per-request line to say;
// the aggregate samples it once, like every other request.
func (t *Timings) closeLocked(now time.Time) {
	if t.open == "" {
		return
	}
	open, dur := t.open, now.Sub(t.openedAt)
	t.open = ""
	for i := range t.stages {
		if t.stages[i].Name == open {
			t.stages[i].Dur += dur
			return
		}
	}
	t.stages = append(t.stages, TimingStage{Name: open, Dur: dur})
}

// recordLocked snapshots the record. Caller holds t.mu.
//
// The stages are copied rather than aliased: the record outlives the recorder's
// last write by as long as a sink keeps it, and a background shipper may hold
// one across a re-arming of the same buffer.
func (t *Timings) recordLocked(outcome TimingOutcome) TimingRecord {
	rec := TimingRecord{
		JobID:    t.jobID,
		Provider: t.provider,
		Host:     t.host,
		Method:   t.method,
		Stream:   t.stream,
		Outcome:  outcome,
		Cold:     t.cold,
		Bytes:    t.bytes,
		Chunks:   t.chunks,
		Egress:   t.egress,
	}
	if len(t.stages) > 0 {
		rec.Stages = append([]TimingStage(nil), t.stages...)
	}
	return rec
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TimingReporter folds a stream of per-request records into a periodic summary
// and passes every record on to the sinks behind it.
//
// It forwards everything rather than filtering, because what an operator can
// pull and what a log receives are two different questions and the level answers
// only the second: the sink that writes lines is where "one line per request, or
// none" is enforced. Filtering here emptied the pullable store at exactly the
// level a long-running deployment is told to run at, and a store nothing feeds
// looks like a quiet TEE.
type TimingReporter struct {
	out    TimingSink
	window time.Duration

	mu     sync.Mutex
	stages map[string][]time.Duration
	cold   int
	failed int
	total  int
}

// timingSamplesPerStage bounds what one window keeps per stage. Beyond it the
// window is already describing a load nobody is reading by hand, and the cap is
// what keeps a reporter's memory flat under a burst.
const timingSamplesPerStage = 1024

// timingSinkStage is the one name in a summary that is not a stage of a
// request: how long the sink took to accept a record. It is measured and
// reported exactly like the others, because it is a per-record cost like the
// others, and the only thing that makes it special is that a reader has to
// know it describes the instrument rather than the system.
const timingSinkStage = "sink"

// timingAggregateOrder is what a summary reports and in what order: the stages
// of a request as they occur, then the instrumentation's own cost.
var timingAggregateOrder = slices.Concat(timingStageOrder, []string{timingSinkStage})

// NewTimingReporter wraps a sink with a periodic summary. A window of zero or
// less means DefaultTimingWindow.
func NewTimingReporter(out TimingSink, window time.Duration) *TimingReporter {
	if window <= 0 {
		window = DefaultTimingWindow
	}
	return &TimingReporter{
		out:    out,
		window: window,
		stages: make(map[string][]time.Duration, len(timingStageOrder)),
	}
}

// TimingRequest implements TimingSink.
func (r *TimingReporter) TimingRequest(rec TimingRecord) {
	// The sink's own cost is measured around the call rather than inside the
	// service, because what it costs is a property of where the record goes: a
	// store write is microseconds, a CloudWatch shipper queues it a little
	// later, and the serial console takes as long as the write takes.
	at := time.Now()
	r.out.TimingRequest(rec)
	// Folded in like any other sample, because that is what it is: what this
	// record cost to deliver, as opposed to what the request cost to serve.
	r.fold(timingSinkStage, time.Since(at))
	// A stall is not a request that finished, so it contributes no sample to
	// the window it arrives in.
	if rec.Outcome == TimingRunning {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	if rec.Cold {
		r.cold++
	}
	if rec.Outcome == TimingFailed {
		r.failed++
	}
	for _, st := range rec.Stages {
		r.foldLocked(st.Name, st.Dur)
	}
}

// fold adds one sample to the window.
func (r *TimingReporter) fold(name string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.foldLocked(name, d)
}

// foldLocked adds one sample to the window. Caller holds r.mu.
func (r *TimingReporter) foldLocked(name string, d time.Duration) {
	if len(r.stages[name]) >= timingSamplesPerStage {
		return
	}
	r.stages[name] = append(r.stages[name], d)
}

// TimingAggregate implements TimingSink as a pass-through, so a reporter is a
// sink in both directions and can be stacked without the summary losing its way
// out.
func (r *TimingReporter) TimingAggregate(agg TimingAggregate) { r.out.TimingAggregate(agg) }

// Run emits a summary every window until ctx is done. It is the caller's
// goroutine to start, and the caller's to stop: the TEE has no graceful
// shutdown, so a window in flight when the process is signalled is lost rather
// than flushed.
func (r *TimingReporter) Run(ctx context.Context) {
	ticker := time.NewTicker(r.window)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Flush()
		}
	}
}

// Flush emits the window that just closed and starts a new one.
//
// An idle window says nothing: a TEE with no traffic has no distribution worth
// a line, and the startup line already said the instrumentation is on. Silence
// from a busy TEE is the signal that matters, and it should be impossible to
// confuse with silence from an idle one.
func (r *TimingReporter) Flush() {
	r.mu.Lock()
	agg := TimingAggregate{
		Window:   r.window,
		Requests: r.total,
		Cold:     r.cold,
		Failed:   r.failed,
	}
	for _, name := range timingAggregateOrder {
		samples := r.stages[name]
		if len(samples) == 0 {
			continue
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		agg.Stages = append(agg.Stages, TimingStat{
			Name:    name,
			P50:     percentile(samples, 0.50),
			P95:     percentile(samples, 0.95),
			Samples: len(samples),
		})
	}
	r.stages = make(map[string][]time.Duration, len(timingAggregateOrder))
	r.total, r.cold, r.failed = 0, 0, 0
	r.mu.Unlock()

	if agg.Requests == 0 {
		return
	}
	r.out.TimingAggregate(agg)
}

// percentile returns the nearest-rank percentile of an ascending sample. It is
// nearest-rank rather than interpolated because the samples are latencies: the
// answer a reader wants is "a request this slow happened", and that is one of
// the samples, not a number between two of them.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}
