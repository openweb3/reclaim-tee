package tee

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
)

// TestExecuteRefusesAReplayedJob pins the guard to the service: a spec carries
// no submitter signature, so its bytes are a valid job for as long as its own
// window lasts. Refusing the second submission is what keeps a job lifted off
// the wire from spending the provider's quota and sequence numbers twice.
func TestExecuteRefusesAReplayedJob(t *testing.T) {
	env := newTestEnv(t)
	body := []byte(`{"model":"gpt-4o"}`)
	spec := env.spec(t, body)

	if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if _, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil); !errors.Is(err, ErrJobReplayed) {
		t.Fatalf("replay = %v, want %v", err, ErrJobReplayed)
	}

	// The same request under a new job ID is a new job: it is the ID that is
	// spent, not the bytes.
	fresh := env.spec(t, body)
	if _, err := env.service.Execute(context.Background(), Job{Spec: fresh, Body: body}, nil); err != nil {
		t.Fatalf("fresh job ID: %v", err)
	}
}

// TestReplayGuardForgetsAnAgedOutJobID checks the table's window rather than the
// service around it: an entry is retained until the spec's own expiry, and after
// that the ID may be used again — by which time the spec naming it is expired
// too, so nothing replayable is left behind.
func TestReplayGuardForgetsAnAgedOutJobID(t *testing.T) {
	guard := newReplayGuard()
	id := []byte("0123456789abcdef")
	expiry := baseTime.Add(time.Minute)

	if !guard.spend(id, baseTime, expiry) {
		t.Fatal("first spend refused")
	}
	if guard.spend(id, baseTime.Add(time.Second), expiry) {
		t.Fatal("second spend admitted a replayed job ID")
	}
	if !guard.spend(id, expiry.Add(time.Second), expiry.Add(time.Minute)) {
		t.Fatal("an ID past its window stayed spent forever")
	}
}

// TestReplayGuardRejectsOnlyTheJobIDShapeItCannotName keeps the guard from
// standing in front of jobs the surrounding checks are responsible for: a spec
// whose ID has the wrong length is refused by jobs.Spec.Validate, not here.
func TestReplayGuardRejectsOnlyTheJobIDShapeItCannotName(t *testing.T) {
	guard := newReplayGuard()
	short := make([]byte, jobs.JobIDLength-1)
	if !guard.spend(short, baseTime, baseTime.Add(time.Minute)) {
		t.Fatal("a job ID the guard cannot name was refused here")
	}
}
