package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// newTimingTestSink returns a sink whose lines can be read back as JSON. The
// fields are the contract a log query is written against, so they are asserted
// rather than eyeballed.
func newTimingTestSink(t *testing.T, level tee.TimingLevel) (timingSink, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		MessageKey:  "message",
		LevelKey:    "level",
		TimeKey:     "", // left out: the record's shape is what is under test
		EncodeLevel: zapcore.LowercaseLevelEncoder,
	})
	logger := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel))
	return timingSink{log: logger, level: level}, &buf
}

// decodeLine parses the single JSON line the sink wrote.
func decodeLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("decode timing line %q: %v", buf.String(), err)
	}
	return line
}

// TestTimingSinkRendersARequest pins the field names and their units. A reader
// greps these and a dashboard sums them, so a rename is a breaking change and
// belongs in a test rather than in a changelog.
func TestTimingSinkRendersARequest(t *testing.T) {
	sink, buf := newTimingTestSink(t, tee.TimingFull)
	sink.TimingRequest(tee.TimingRecord{
		JobID:    "9f3a",
		Provider: "openai",
		Host:     "chatgpt.com",
		Method:   "POST",
		Stream:   true,
		Outcome:  tee.TimingComplete,
		Cold:     true,
		Bytes:    18342,
		Chunks:   57,
		Egress:   8200 * time.Microsecond,
		Stages: []tee.TimingStage{
			{Name: tee.StageRead, Dur: 400 * time.Microsecond},
			{Name: tee.StageTTFB, Dur: 903*time.Millisecond + 100*time.Microsecond},
			{Name: tee.StageSign, Dur: 2100 * time.Microsecond},
		},
	})

	line := decodeLine(t, buf)
	if line["level"] != "info" || line["message"] != "tee.request" {
		t.Errorf("line = %v, want an info tee.request", line)
	}
	for key, want := range map[string]any{
		"job":      "9f3a",
		"provider": "openai",
		"host":     "chatgpt.com",
		"method":   "POST",
		"stream":   true,
		"cold":     true,
		"outcome":  "complete",
		"bytes":    float64(18342),
		"chunks":   float64(57),
	} {
		if got := line[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
	if got := line["read_ms"]; got != 0.4 {
		t.Errorf("read_ms = %v, want 0.4", got)
	}
	if got := line["ttfb_ms"]; got != 903.1 {
		t.Errorf("ttfb_ms = %v, want 903.1", got)
	}
	if got := line["sign_ms"]; got != 2.1 {
		t.Errorf("sign_ms = %v, want 2.1", got)
	}
	if got := line["egress_ms"]; got != 8.2 {
		t.Errorf("egress_ms = %v, want 8.2", got)
	}
	if _, present := line["error"]; present {
		t.Errorf("a healthy request must not carry an error field: %v", line)
	}
}

// TestTimingSinkRendersAStall pins the line the feature exists for: which stage
// a request has not left, at warn level, with none of the stage fields a
// finished request carries.
func TestTimingSinkRendersAStall(t *testing.T) {
	// Summary, deliberately: a stalled request is written at every level, and
	// this is the test that would fail if that stopped being true.
	sink, buf := newTimingTestSink(t, tee.TimingSummary)
	sink.TimingRequest(tee.TimingRecord{
		JobID:    "9f3a",
		Provider: "openai",
		Host:     "chatgpt.com",
		Outcome:  tee.TimingRunning,
		Stage:    tee.StageTLS,
		Waited:   30*time.Second + 500*time.Millisecond,
		Stages:   []tee.TimingStage{{Name: tee.StageAcquire, Dur: time.Millisecond}},
	})

	line := decodeLine(t, buf)
	if line["level"] != "warn" || line["message"] != "tee.request.stalled" {
		t.Errorf("line = %v, want a warn tee.request.stalled", line)
	}
	if line["stage"] != tee.StageTLS {
		t.Errorf("stage = %v, want %s", line["stage"], tee.StageTLS)
	}
	if got := line["waited_ms"]; got != 30500.0 {
		t.Errorf("waited_ms = %v, want 30500", got)
	}
	if _, present := line["acquire_ms"]; present {
		t.Error("a stall must not report finished stages: the stage it is stuck in is the story")
	}
	if _, present := line["outcome"]; present {
		t.Error("a stall is not an outcome")
	}
}

// TestTimingSinkHonoursTheLevel pins where the volume rule lives, now that the
// reporter no longer filters: the level decides what reaches a log. A request
// line is what full adds, a stall is written either way, and the answer has
// nothing to do with the store an operator pulls from.
func TestTimingSinkHonoursTheLevel(t *testing.T) {
	request := tee.TimingRecord{Outcome: tee.TimingComplete, Stages: []tee.TimingStage{{Name: tee.StageTTFB, Dur: time.Second}}}
	stall := tee.TimingRecord{Outcome: tee.TimingRunning, Stage: tee.StageTLS, Waited: time.Minute}

	sink, buf := newTimingTestSink(t, tee.TimingSummary)
	sink.TimingRequest(request)
	if buf.Len() != 0 {
		t.Errorf("summary wrote a request line: %q", buf.String())
	}
	sink.TimingRequest(stall)
	if line := decodeLine(t, buf); line["message"] != "tee.request.stalled" {
		t.Errorf("summary dropped a stall: %v", line)
	}

	sink, buf = newTimingTestSink(t, tee.TimingFull)
	sink.TimingRequest(request)
	if line := decodeLine(t, buf); line["message"] != "tee.request" {
		t.Errorf("full wrote %v, want the request line the level adds", line)
	}
}

// TestTimingSinkRendersASummary pins the aggregate's shape: counts, then one
// p50/p95/sample triple per stage that had samples, and the instrumentation's
// own cost last.
func TestTimingSinkRendersASummary(t *testing.T) {
	sink, buf := newTimingTestSink(t, tee.TimingSummary)
	sink.TimingAggregate(tee.TimingAggregate{
		Window:   30 * time.Second,
		Requests: 12,
		Cold:     4,
		Failed:   1,
		Stages: []tee.TimingStat{
			{Name: tee.StageTTFB, P50: 900 * time.Millisecond, P95: 4200 * time.Millisecond, Samples: 12},
			{Name: tee.StageSign, P50: 2 * time.Millisecond, P95: 3 * time.Millisecond, Samples: 12},
			// The instrumentation's own cost is the last name in the window and
			// is rendered like the rest of them: it is a per-record cost too.
			{Name: "sink", P50: 200 * time.Microsecond, P95: 250 * time.Microsecond, Samples: 12},
		},
	})

	line := decodeLine(t, buf)
	if line["message"] != "tee.timing.summary" {
		t.Errorf("message = %v, want tee.timing.summary", line["message"])
	}
	for key, want := range map[string]any{
		"window":      "30s",
		"requests":    float64(12),
		"cold":        float64(4),
		"failed":      float64(1),
		"ttfb_p50_ms": 900.0,
		"ttfb_p95_ms": 4200.0,
		"ttfb_n":      float64(12),
		"sign_p50_ms": 2.0,
		"sign_p95_ms": 3.0,
		"sign_n":      float64(12),
		"sink_p50_ms": 0.2,
		"sink_p95_ms": 0.25,
		"sink_n":      float64(12),
	} {
		if got := line[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
}
