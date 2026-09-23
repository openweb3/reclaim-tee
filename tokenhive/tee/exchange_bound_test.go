package tee

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// The signing deadline used to bound an exchange as well as gate its admission:
// Execute installed it on the exchange's context, so an answer still streaming
// when the deadline arrived was cut in half. What those tests pinned has moved.
// These pin the replacement — the deadline is not imposed on a running exchange
// at all, an exchange that outlives the epoch it was admitted under is signed by
// the epoch that replaced it, and the refusal survives only for the case the
// handoff cannot fix.
//
// boundTransport deliberately has no "wait for the context to end" mode any
// more: with no bound of its own, an exchange waiting on one would wait forever.
// It records what the service did to the context and never blocks on it.

// boundTransport records the deadline the service puts on each exchange. There
// is no longer meant to be one, which is exactly what the tests assert.
type boundTransport struct {
	mu        sync.Mutex
	requests  []Request
	budgets   []time.Duration
	hasBudget []bool

	// chunks are delivered before the exchange considers ending.
	chunks [][]byte

	// onCall runs once at the start of each exchange, before any chunk. Tests
	// use it to move a borrowed clock past the pinned epoch's deadline and to
	// publish a rotated signer — an exchange outliving its epoch while a
	// rotation lands underneath it.
	onCall func()
}

func (b *boundTransport) Do(ctx context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	deadline, bounded := ctx.Deadline()
	var budget time.Duration
	if bounded {
		budget = time.Until(deadline)
	}

	b.mu.Lock()
	b.requests = append(b.requests, req)
	b.budgets = append(b.budgets, budget)
	b.hasBudget = append(b.hasBudget, bounded)
	chunks := b.chunks
	onCall := b.onCall
	b.mu.Unlock()

	if onCall != nil {
		onCall()
	}

	resp := Response{StatusCode: 200}
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	for _, chunk := range chunks {
		if onChunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

func (b *boundTransport) sent(t *testing.T) []Request {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.requests) == 0 {
		t.Fatal("transport was never called")
	}
	return append([]Request(nil), b.requests...)
}

// imposedDeadline reports whether the exchange ran under any deadline at all.
// After the signing deadline stopped being imposed on the exchange, a true here
// can only come from the caller.
func (b *boundTransport) imposedDeadline(t *testing.T) bool {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.hasBudget) == 0 {
		t.Fatal("transport was never called")
	}
	return b.hasBudget[len(b.hasBudget)-1]
}

// budget returns the time left on the exchange's context as the transport saw
// it. The service derives its own room from its own clock while
// context.WithTimeout measures from the wall clock, so an absolute instant is
// not comparable across a pinned test clock; the remaining duration is.
func (b *boundTransport) budget(t *testing.T) time.Duration {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.budgets) == 0 {
		t.Fatal("transport was never called")
	}
	if !b.hasBudget[len(b.hasBudget)-1] {
		t.Fatal("the exchange was given no deadline")
	}
	return b.budgets[len(b.budgets)-1]
}

func withTransport(tr Transport) envOption { return func(c *Config) { c.Transport = tr } }

func withRequestTimeout(d time.Duration) envOption { return func(c *Config) { c.RequestTimeout = d } }

func withClock(now func() time.Time) envOption { return func(c *Config) { c.Clock = now } }

// withSignerCell makes the service follow a cell a test can rotate mid-exchange,
// the way the refresh loop does.
func withSignerCell(cell *atomic.Pointer[proof.Signer]) envOption {
	return func(c *Config) { c.SignerCell = cell }
}

// shiftableClock is a clock a test can move forward, for modelling an exchange
// that outlives the deadline its epoch carried.
type shiftableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *shiftableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *shiftableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestExchangeIsGivenNoDeadlineOfItsOwn pins what the service stopped doing. The
// signing deadline used to be installed on the exchange's context, and that is
// what cut long answers in half at the deadline: bytes already relayed to the
// buyer, no receipt, settled by nothing. The room is still measured — admission
// refuses an exchange with none (see TestRefusesWhenThereIsNoRoomToSign) — but it
// is no longer imposed, so the only deadline the transport may see is one the
// caller set. An exchange's length is bounded by RequestTimeout instead, which
// the transport applies from the request.
func TestExchangeIsGivenNoDeadlineOfItsOwn(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	epoch := epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))
	env := newTestEnv(t,
		withSigner(epoch),
		withTransport(transport),
		withRequestTimeout(90*time.Second),
	)
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("Execute with a fresh epoch = %v, want success", err)
	}

	if transport.imposedDeadline(t) {
		t.Fatal("the service put a deadline of its own on the exchange; cutting an exchange mid-flight is what left relayed bytes unsettleable")
	}
	if request := transport.sent(t)[0]; request.Timeout != 90*time.Second {
		t.Fatalf("request carried Timeout %s, want the service's own 90s — the bound on the exchange's length", request.Timeout)
	}
	if string(result.Receipt.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("an exchange that never left its epoch did not sign under the epoch it was admitted on")
	}
}

// TestExchangeOutlivingItsEpochIsSignedByTheLiveOne is the handoff, and the
// whole point of it: an exchange admitted before the deadline can still be
// running when the deadline passes, and the old code refused the signature at
// that point. That refusal settled nothing — the answer had been delivered, the
// provider had been paid upstream, and the receipt that would have priced it did
// not exist. The signature moves to whatever the process serves now instead.
//
// The rotated epoch is a different key from the pinned one, and the receipt
// naming it is what proves the handoff happened rather than the pin surviving on
// a technicality.
func TestExchangeOutlivingItsEpochIsSignedByTheLiveOne(t *testing.T) {
	clock := &shiftableClock{now: baseTime}
	cell := &atomic.Pointer[proof.Signer]{}

	// Two seconds of leaf beyond the signing margin, less the handoff, is room
	// for an exchange that is admitted and then outlives it. A real NitroTPM leaf
	// is second-granularity, so this is as short as the window can be made
	// without a fake clock.
	pinned := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+2*time.Second))
	rotated := epochWithNitroLeaf(t, baseTime.Add(3*time.Hour))

	transport := &boundTransport{
		chunks: [][]byte{[]byte("event: a\n\n")},
		// The rotation lands while the provider is streaming: the cell moves to
		// the newer key and the clock passes the pinned epoch's deadline.
		onCall: func() {
			cell.Store(proof.NewSigner(rotated))
			clock.Advance(10 * time.Second)
		},
	}
	env := newTestEnv(t,
		withSigner(pinned),
		withSignerCell(cell),
		withTransport(transport),
		withClock(clock.Now),
	)
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if err != nil {
		t.Fatalf("Execute that outlived its epoch = %v, want a receipt under the rotated key", err)
	}
	if result == nil {
		t.Fatal("Execute returned no result for an exchange that ran to completion")
	}
	got := result.Receipt.Receipt.Attestation.KeyID
	if string(got) == string(pinned.identity.KeyID[:]) {
		t.Fatal("receipt still names the pinned epoch, which was past its signing deadline when the exchange ended")
	}
	if string(got) != string(rotated.identity.KeyID[:]) {
		t.Fatalf("receipt names key %x, want the rotated epoch %x", got, rotated.identity.KeyID[:])
	}
	// A handoff that produced an empty or truncated receipt would settle as
	// little as no receipt did: the bytes were relayed and the provider was paid.
	if result.Truncated || result.Receipt.Receipt.Completion != proof.CompletionComplete {
		t.Fatalf("completion = %q truncated = %t, want the delivered response attested as complete",
			result.Receipt.Receipt.Completion, result.Truncated)
	}
	if result.Receipt.Receipt.StatusCode != 200 || result.ResponseBytes == 0 {
		t.Fatalf("receipt attests status %d and %d bytes, want the response that arrived",
			result.Receipt.Receipt.StatusCode, result.ResponseBytes)
	}
}

// TestExchangeIsRefusedWhenNoFresherEpochExists is the fail-closed half that
// survives the handoff. With nothing newer to sign under, a signature would be a
// receipt every verifier refuses — evidence that looks real and is settled like
// evidence until somebody checks the leaf. The exchange is abandoned instead.
//
// This is the only refusal that arrives after provider work has been done, and
// after the handoff it is reached for one reason only: the rotation itself has
// failed, so the live signer is the pinned one and it is stale too.
func TestExchangeIsRefusedWhenNoFresherEpochExists(t *testing.T) {
	clock := &shiftableClock{now: baseTime}
	transport := &boundTransport{
		chunks: [][]byte{[]byte("event: a\n\n")},
		// The exchange runs past the signer's deadline with no rotation behind
		// it: it returns a complete response, having advanced the clock beyond
		// the instant the receipt may still be signed at.
		onCall: func() { clock.Advance(10 * time.Second) },
	}
	epoch := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+3*time.Second))
	env := newTestEnv(t, withSigner(epoch), withTransport(transport), withClock(clock.Now))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("Execute that outlived the deadline with no rotation = %v, want %v", err, ErrAttestationStale)
	}
	if result != nil {
		t.Fatal("a receipt was returned for an exchange with no fresh evidence to sign under")
	}
	if len(transport.sent(t)) != 1 {
		t.Fatal("the exchange did not reach the provider, so this test is not exercising the fail-safe")
	}
}

// stallTransport delivers a prefix and then holds the exchange open until the
// caller's context ends: a provider stream still in progress. It is the
// exchange counterpart of blockingSessionConn — the difference between an
// exchange the provider finished and one the TEE cut is visible only in whether
// a receipt exists and what it says.
type stallTransport struct {
	prefix [][]byte
}

func (b *stallTransport) Do(ctx context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	resp := Response{StatusCode: 200}
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	for _, chunk := range b.prefix {
		if onChunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return resp, err
		}
	}
	<-ctx.Done()
	return resp, ctx.Err()
}

// liveSpec builds a spec valid at the wall clock for tests that run on it:
// the default helper pins expiry to baseTime, which ValidateAt with time.Now
// would refuse before the exchange even reaches the transport.
func liveSpec(t *testing.T, env *testEnv, body []byte) jobs.Spec {
	t.Helper()
	spec := env.spec(t, body)
	spec.ExpiresAt = time.Now().Add(5 * time.Minute).Unix()
	return spec
}

func livePolicy() envOption {
	return withPolicy(func(p *policy.Policy) {
		p.IssuedAt = time.Now().Add(-time.Hour).Unix()
		p.ExpiresAt = time.Now().Add(time.Hour).Unix()
	})
}

// TestExchangeCutWhenNoFresherEpochKeepsItBillable is the stop-loss: a provider
// stream still running when the live signer's budget runs out with no rotation
// behind it must end as a truncated receipt for the bytes that did arrive —
// relayed, paid for upstream, priceable — not as the fail-closed refusal that
// settles nothing. The cancel lands signingHandoff before the deadline, so the
// receipt is signed under evidence verifiers still accept.
//
// It runs on the wall clock like the session deadline tests: the deadline is a
// real instant and a pinned one would never arrive.
func TestExchangeCutWhenNoFresherEpochKeepsItBillable(t *testing.T) {
	transport := &stallTransport{prefix: [][]byte{[]byte("event: a\n\n")}}
	epoch := epochWithNitroLeaf(t, time.Now().Add(rootShared.SNPSigningMargin+3*time.Second))
	env := newTestEnv(t,
		withSigner(epoch),
		withTransport(transport),
		withClock(time.Now),
		livePolicy(),
	)
	body := []byte(`{"model":"m"}`)
	spec := liveSpec(t, env, body)

	start := time.Now()
	result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("stalled exchange with no rotation = %v, want a truncated receipt", err)
	}
	if result == nil {
		t.Fatal("no result for an exchange cut while the provider was streaming")
	}
	if !result.Truncated || result.Receipt.Receipt.Completion != proof.CompletionTruncated {
		t.Fatalf("completion = %q truncated = %t, want the delivered prefix attested as truncated",
			result.Receipt.Receipt.Completion, result.Truncated)
	}
	if string(result.Receipt.Receipt.Attestation.KeyID) != string(epoch.identity.KeyID[:]) {
		t.Fatal("cut receipt is not signed under the epoch it was cut for")
	}
	if result.ResponseBytes == 0 {
		t.Fatal("cut receipt attests zero bytes, want the delivered prefix")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("exchange ran %s, want the stop-loss near the ~2s budget", elapsed)
	}
}

// TestExchangeCutFollowsTheRotation is the other half: a rotation landing
// mid-exchange moves the deadline out, so the watcher must re-arm instead of
// firing. The exchange runs past its opening epoch's deadline and is signed by
// the live key, complete rather than truncated.
func TestExchangeCutFollowsTheRotation(t *testing.T) {
	cell := &atomic.Pointer[proof.Signer]{}
	opening := epochWithNitroLeaf(t, time.Now().Add(rootShared.SNPSigningMargin+3*time.Second))
	cell.Store(proof.NewSigner(opening))
	transport := &stallTransport{prefix: [][]byte{[]byte("event: a\n\n")}}
	// Provider ends the stream on its own terms, past the opening deadline.
	done := make(chan struct{})
	wrapped := &rotatingStallTransport{stall: transport, done: done}
	env := newTestEnv(t,
		withSigner(opening),
		withSignerCell(cell),
		withTransport(wrapped),
		withClock(time.Now),
		livePolicy(),
	)
	body := []byte(`{"model":"m"}`)
	spec := liveSpec(t, env, body)

	type outcome struct {
		result *Result
		err    error
	}
	out := make(chan outcome, 1)
	go func() {
		result, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
		out <- outcome{result, err}
	}()

	// Rotation lands well before the opening budget runs out; the provider ends
	// past the instant the opening epoch alone would have cut.
	time.Sleep(500 * time.Millisecond)
	rotated := epochWithNitroLeaf(t, time.Now().Add(3*time.Hour))
	cell.Store(proof.NewSigner(rotated))
	time.Sleep(3 * time.Second)
	close(done)

	select {
	case got := <-out:
		if got.err != nil {
			t.Fatalf("exchange with a mid-flight rotation = %v, want success", got.err)
		}
		if got.result == nil {
			t.Fatal("no result for an exchange a rotation carried past its opening deadline")
		}
		if got.result.Truncated || got.result.Receipt.Receipt.Completion != proof.CompletionComplete {
			t.Fatalf("completion = %q truncated = %t, want complete: the cut should have re-armed",
				got.result.Receipt.Receipt.Completion, got.result.Truncated)
		}
		if string(got.result.Receipt.Receipt.Attestation.KeyID) != string(rotated.identity.KeyID[:]) {
			t.Fatal("receipt does not name the rotated epoch")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("exchange did not finish after the provider ended it")
	}
}

// rotatingStallTransport is a stallTransport whose hold can be released by the
// test closing done, modelling a provider that ends its stream on its own.
type rotatingStallTransport struct {
	stall *stallTransport
	done  chan struct{}
}

func (b *rotatingStallTransport) Do(ctx context.Context, req Request, onChunk func([]byte) error, onStart ...StartFunc) (Response, error) {
	resp := Response{StatusCode: 200}
	if len(onStart) > 0 && onStart[0] != nil {
		onStart[0](resp)
	}
	for _, chunk := range b.stall.prefix {
		if onChunk == nil {
			continue
		}
		if err := onChunk(chunk); err != nil {
			return resp, err
		}
	}
	select {
	case <-b.done:
		return resp, nil
	case <-ctx.Done():
		return resp, ctx.Err()
	}
}

// TestRefusesWhenThereIsNoRoomToSign: with less than signingHandoff left before
// the deadline, no exchange started now could finish and still be signed inside
// the margin. It is refused the way a stale epoch is — before a sequence number
// or a credential is spent — rather than started into a run it could never
// attest. This is the surviving half of the old bound: the deadline is no longer
// imposed on an exchange that is running, but an exchange that cannot be signed
// at all from the outset still never starts.
func TestRefusesWhenThereIsNoRoomToSign(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	// One second of leaf beyond the margin is exactly signingHandoff, leaving an
	// exchange no room at all.
	epoch := epochWithNitroLeaf(t, baseTime.Add(rootShared.SNPSigningMargin+time.Second))
	env := newTestEnv(t, withSigner(epoch), withTransport(transport))
	body := []byte(`{"model":"m"}`)
	spec := env.spec(t, body)

	start := time.Now()
	_, err := env.service.Execute(context.Background(), Job{Spec: spec, Body: body}, nil)
	if !errors.Is(err, ErrAttestationStale) {
		t.Fatalf("Execute with no room before the deadline = %v, want %v", err, ErrAttestationStale)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the refusal took %s, want an immediate one rather than an exchange that ran and then failed", elapsed)
	}
	if len(transport.requests) != 0 {
		t.Fatal("a job with no room to be signed reached the provider transport")
	}
	if seq, err := env.service.seq.Next([]byte("openai")); err != nil || seq != 1 {
		t.Fatalf("refused job consumed sequence (next = %d, err = %v), want the series untouched", seq, err)
	}
}

// TestUntrackedEvidenceLeavesTheContextAlone: evidence with no readable NitroTPM
// leaf carries no deadline to measure against, so such a signer is never stale
// and nothing is refused or cut. The simulation and the harness both run on
// evidence like this, and a gate that invented a deadline would look like an
// outage against every pinned test clock.
//
// The second half is the general rule the exchange bound used to violate: a
// deadline the caller set belongs to the caller and passes through untouched.
func TestUntrackedEvidenceLeavesTheContextAlone(t *testing.T) {
	transport := &boundTransport{chunks: [][]byte{[]byte("event: a\n\n")}}
	env := newTestEnv(t, withTransport(transport))
	body := []byte(`{"model":"m"}`)

	if _, err := env.service.Execute(context.Background(), Job{Spec: env.spec(t, body), Body: body}, nil); err != nil {
		t.Fatalf("Execute on untracked evidence = %v, want success", err)
	}
	if bounded := transport.hasBudget[0]; bounded {
		t.Fatal("an unreadable leaf produced a deadline out of nothing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := env.service.Execute(ctx, Job{Spec: env.spec(t, body), Body: body}, nil); err != nil {
		t.Fatalf("Execute under a caller's deadline = %v, want success", err)
	}
	if got := transport.budget(t); got > 30*time.Second || got < 25*time.Second {
		t.Fatalf("exchange had %s left of the caller's own 30s deadline", got)
	}
}
