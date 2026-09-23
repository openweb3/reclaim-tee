// Package tee is the execution core of a TokenHive enclave: it takes a job,
// decides whether the provider's policy permits it, performs the request with
// the shared credential, and returns a signed receipt describing what happened.
//
// The package owns no network code. Outbound HTTP lives behind the Transport
// interface so that the parts of the system with security meaning — ordering
// of checks, credential isolation, response attestation — can be reasoned
// about and tested without a socket.
//
// # The order of checks
//
// Execute runs its checks in a fixed order, and the order is the design:
//
//  0. epoch freshness — the signer must name evidence still outside its
//     signing margin (see Config.SignerCell)
//  1. submitter identity (optional, see Config.SubmitterVerifier)
//  2. spec structure and expiry
//  3. body binding — the body must hash to the spec's committed digest
//  4. policy authorisation
//  5. body size against the policy cap
//  6. credential resolution
//  7. sequence allocation (see Config.Seq)
//
// Steps 2 and 3 establish that the job is internally consistent; only then is
// it meaningful to ask whether it is permitted. Authorising a request whose
// body does not match its own description would spend a credential on a
// question nobody asked.
//
// Step 7 is last because it is the only step that mutates state. Every check
// that can refuse a job runs first, so a refused job never consumes a sequence
// number and never leaves a hole in the provider's series.
//
// # When a receipt exists
//
// A receipt is produced if and only if the request was actually put on the
// wire. Jobs refused earlier — malformed, unauthorised, or lacking a
// credential — return an error and no receipt, because there is nothing to
// attest to and handing out a signature would only say "an enclave saw this",
// which helps nobody.
//
// Once a request is sent, every outcome is signed, including failure. A
// receipt that says CompletionFailed is the proof the Hub needs in order not
// to charge for a response that never arrived; without it, a dropped stream
// and a successful one would be indistinguishable to the verifier.
package tee

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/policy"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Configuration errors, all of which mean the service was built wrong rather
// than that a job was bad.
var (
	ErrNoPolicy        = errors.New("no policy configured")
	ErrNoInboxKey      = errors.New("no inbox key configured")
	ErrNoSigner        = errors.New("no receipt signer configured")
	ErrCredentialClash = errors.New("job already sets the header the credential occupies")
	ErrBodyTooLarge    = errors.New("request body exceeds the policy limit")
	ErrNoCredential    = errors.New("job carries no credential")
)

// ErrBodyMismatch means the supplied request body does not hash to the digest
// committed in the spec.
//
// This is not an authorisation failure. The job may be perfectly permissible;
// it is simply not the job it claims to be. It is the guard against two
// concurrent executions having their payloads crossed, and against a body
// truncated in transit being sent under a spec that described the whole thing.
var ErrBodyMismatch = errors.New("request body does not match the hash committed in the job spec")

// ErrNoSessionSupport means the configured transport can run request/response
// exchanges but not streaming sessions. It is a wiring mismatch surfaced lazily
// when a session is requested, because a request/response-only transport is
// legitimate and a Hub may simply never need streaming.
var ErrNoSessionSupport = errors.New("transport does not support streaming sessions")

// ErrSessionBody means a streaming session job carried a request body. A
// session is opened by a handshake, not a payload: it commits to an empty body,
// and the body hash must be the digest of zero bytes.
var ErrSessionBody = errors.New("streaming session must carry an empty body")

// ErrAttestationStale is a refusal: the receipt signer the service would use
// names an epoch whose evidence is inside its signing margin, so any receipt it
// produced would reach a verifier with too little validity left on the evidence
// it cites. The caller should retry once the platform has published a fresh
// epoch.
//
// It is returned in two places and they do not cost the same. Before a job
// starts it costs nothing at all: no sequence number is allocated, no
// credential is opened, nothing is put on the wire, and the job never happened.
// After an exchange has ended it is the fail-safe at the end of perform — the
// receipt about to be signed would be refused by every verifier, so it is not
// signed — and there the provider work has already been done and will not be
// settled, because a receipt is what settlement is made of. The exchange bound
// in perform exists to keep that second case from ever being reached.
var ErrAttestationStale = errors.New("attested epoch inside its signing margin; rotation has not published")

// Job is a request to execute: the spec plus the body it commits to.
//
// The body travels alongside the spec rather than inside it because the spec
// is hashed and cited in receipts while the body may be large and is only ever
// needed at execution time. Spec.BodyHash is what ties them together.
type Job struct {
	Spec jobs.Spec
	Body []byte
}

// Result is the outcome of an executed job.
//
// Receipt is always present when Execute returns a result, including when it
// also returns an error: a job that failed mid-flight still has something to
// prove.
type Result struct {
	// Receipt is the signed execution proof. Verify it with proof.Verify.
	Receipt proof.SignedReceipt

	// StatusCode is what the provider returned. Zero when the exchange never
	// produced a response.
	StatusCode uint32

	// ChunkCount and ResponseBytes describe what was received. They are also
	// inside the signed receipt; they are surfaced here for callers that relay
	// the body and want to cross-check their own counters.
	ChunkCount    uint64
	ResponseBytes uint64

	// StreamHash is the response digest. Also inside the receipt.
	StreamHash [32]byte

	// Truncated reports that the response was cut short, either by the size
	// cap or by the connection dropping.
	Truncated bool

	// PolicyHash names the policy revision that authorised the job.
	PolicyHash []byte

	// ProviderSeq is this execution's place in the provider's series. Also
	// inside the signed receipt; surfaced here so a server can log it without
	// decoding the receipt it just emitted.
	ProviderSeq uint64
}

// Config assembles a Service.
//
// Every field but Clock, RequestTimeout and SubmitterVerifier is mandatory. A
// service that cannot authorise, execute, or attest must not be constructible —
// the failure should surface at wiring time, not on the first job.
type Config struct {
	// Policy is the deployment whitelist: the only thing that decides whether
	// a job may spend a provider's credential, and the same document every
	// provider agent egresses under.
	Policy *policy.Policy

	// Transport performs the outbound request.
	Transport Transport

	// Signer issues execution receipts from an attested key.
	Signer *proof.Signer

	// SignerCell, when non-nil, tracks the process's current receipt signer
	// across epoch rotations. The service signs with the signer it holds at
	// sign time rather than the startup one, so a streaming session that
	// outlives a rotation still finishes with a receipt under fresh evidence.
	// The rotation loop stores each adopted signer here; services built
	// without one keep signing with their own Signer. The cell is an
	// atomic.Pointer[proof.Signer] so readers never block a rotation.
	SignerCell *atomic.Pointer[proof.Signer]

	// Seq assigns the per-provider monotonic sequence number signed into every
	// receipt. Mandatory, and deliberately not defaulted: see ErrNoSeqStore.
	Seq SeqStore

	// Clock is the service's time source. Defaults to time.Now. Injected
	// because receipt timestamps are part of what gets signed, and tests need
	// to pin them.
	Clock func() time.Time

	// RequestTimeout bounds a single provider exchange. Zero means no
	// service-level deadline beyond the caller's context.
	RequestTimeout time.Duration

	// SubmitterVerifier, when set, is consulted before anything else. It
	// answers "may this caller submit jobs at all".
	//
	// It is deliberately a bare function and deliberately optional. Transport
	// level mutual TLS is the intended first deployment, since it identifies
	// the Hub without introducing a key registry; this hook is where an
	// application-level scheme (a Hub signature over the spec) can be added
	// later without changing the shape of Execute.
	SubmitterVerifier func(ctx context.Context, spec jobs.Spec) error

	// InboxKey decrypts the credential envelope carried on every job. The TEE
	// stores no access token: each job brings its provider's token sealed to
	// this key, and the private half of InboxKey is the only way to open it.
	// Mandatory — a service that cannot decrypt its jobs' credentials cannot
	// execute them.
	InboxKey *InboxKey
}

// Service executes jobs inside the enclave. It is safe for concurrent use.
type Service struct {
	policy          policy.Policy
	transport       Transport
	signer          *proof.Signer
	signerCell      *atomic.Pointer[proof.Signer]
	seq             SeqStore
	clock           func() time.Time
	requestTimeout  time.Duration
	submitterVerify func(ctx context.Context, spec jobs.Spec) error
	inbox           *InboxKey
}

// NewService validates a configuration and returns a ready service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Policy == nil {
		return nil, ErrNoPolicy
	}
	if cfg.InboxKey == nil {
		return nil, ErrNoInboxKey
	}
	if cfg.Transport == nil {
		return nil, ErrNoTransport
	}
	if cfg.Signer == nil {
		return nil, ErrNoSigner
	}
	if cfg.Seq == nil {
		return nil, ErrNoSeqStore
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		policy:          *cfg.Policy,
		transport:       cfg.Transport,
		signer:          cfg.Signer,
		signerCell:      cfg.SignerCell,
		seq:             cfg.Seq,
		clock:           clock,
		requestTimeout:  cfg.RequestTimeout,
		submitterVerify: cfg.SubmitterVerifier,
		inbox:           cfg.InboxKey,
	}, nil
}

// activeSigner is the signer receipts are issued with right now: the rotation
// loop's current one when this service follows it, else the startup one.
func (s *Service) activeSigner() *proof.Signer {
	if s.signerCell != nil {
		if signer := s.signerCell.Load(); signer != nil {
			return signer
		}
	}
	return s.signer
}

// signingHandoff is the room an exchange leaves between its own end and the
// signing deadline it has to fit inside.
//
// The deadline is what a receipt must be signed before; the exchange is what
// has to happen first. Cutting the exchange exactly at the deadline would
// therefore leave nothing in which to sign, and the receipt would land outside
// the margin the whole mechanism exists to respect. The work in between —
// hashing the transcript, building the receipt, one signature — takes
// microseconds, so this is not a budget being spent but a floor against a
// stalled scheduler or a coarse clock. A job that arrives with less room than
// this is refused outright: no exchange started then could finish and still be
// signed inside the margin, and refusing before the provider is touched beats
// executing work whose receipt could never be issued.
const signingHandoff = time.Second

// signingDeadline reports when this signer must stop signing — SNPSigningMargin
// before its epoch's NitroTPM leaf expires — and whether the epoch carried a
// readable leaf at all.
//
// The flag is not decoration. Evidence without a leaf (simulated epochs, test
// fakes) has no TEE-side expiry: the fallback TTL in snpLeafDeadline is a
// refresh-scheduling aid, not a verdict on serving, and comparing it against an
// injected test clock would mistake every pinned clock for an outage. tracked
// = false is what keeps both the refusal in Execute and the deadline the session
// watcher cuts on from inventing a deadline that does not exist.
func signingDeadline(signer *proof.Signer) (time.Time, bool) {
	if signer == nil {
		return time.Time{}, false
	}
	epoch := signer.Epoch()
	if epoch == nil {
		return time.Time{}, false
	}
	return rootShared.SNPSigningDeadline(epoch.Identity().Evidence)
}

// signingBudget is how much room is left under signer before it must stop
// signing, less signingHandoff: the time until its epoch's NitroTPM leaf reaches
// SNPSigningMargin, less the sliver in which a receipt is hashed, built and
// signed. bounded is false for an epoch with no readable leaf, in which case
// there is no deadline to measure against and the caller's own context is the
// only bound — the same rule signerStaleAt applies to refusing.
//
// A budget at or below zero is not "run very briefly", it is "cannot be done":
// an exchange admitted now would have to end before it started. Admission
// refuses on exactly that. The budget is deliberately not imposed on the
// exchange as a context deadline any more — an exchange cut mid-flight produced
// no receipt at all, so bytes already relayed to the buyer settled nothing. The
// length of an exchange is bounded by its own RequestTimeout instead, and the
// key it finally signs under is chosen at the end (see perform).
//
// The one exception is the stop-loss below: while the exchange runs, a watcher
// tracks the live signer's budget and cancels the exchange when that budget
// runs out with no fresher epoch behind it (see watchExchangeBudget). On a
// healthy platform a rotation lands first, the watcher re-arms on the new
// budget and never fires; only a platform that stopped reissuing still cuts,
// and then into a truncated receipt that stays billable instead of a refusal
// that settles nothing.
func (s *Service) signingBudget(signer *proof.Signer) (budget time.Duration, bounded bool) {
	deadline, tracked := signingDeadline(signer)
	if !tracked {
		return 0, false
	}
	return deadline.Sub(s.clock()) - signingHandoff, true
}

// watchExchangeBudget cancels the running exchange when the live signer runs
// out of room with no fresher epoch to hand the signature to.
//
// It is the exchange counterpart of watchSigningDeadline, with one deliberate
// asymmetry: a healthy rotation must not cut. So unlike a plain context
// deadline, it re-reads the live signer every time it wakes. A rotation that
// lands mid-exchange publishes an epoch expiring later, the budget moves out,
// and the watcher re-arms instead of firing — the exchange runs on and is
// signed by the live key at the end (see perform). Only when the wake finds
// the same stale signer — the platform stopped reissuing — does it cancel,
// turning an exchange that could never be signed into a truncated one that
// still can: the cancel lands signingHandoff before the deadline, so the
// receipt the pump then signs is under evidence verifiers still accept.
//
// Evidence with no readable leaf carries no deadline (tracked=false), so the
// watcher waits the exchange out, exactly as Execute's admission does.
func (s *Service) watchExchangeBudget(stop <-chan struct{}, parent context.Context, cancel context.CancelFunc) {
	for {
		budget, bounded := s.signingBudget(s.activeSigner())
		if !bounded {
			select {
			case <-stop:
				return
			case <-parent.Done():
				return
			}
		}
		if budget <= 0 {
			cancel()
			return
		}
		timer := time.NewTimer(budget)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-parent.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// watchSigningDeadline closes the returned channel when a session has to stop
// relaying for its terminal receipt to still be signed — the live signer is
// within signingHandoff of its signing deadline — and stops watching when stop
// is closed. The caller owns stop and must close it when the session is over.
//
// A session is deliberately unbounded (SessionIdleTimeout is a watchdog against
// a peer that vanished, not a duration cap), so it can outlive the epoch it
// opened under. An exchange does not need cutting for that: it can be signed
// under the epoch that replaced the one it started with (see perform). A session
// cannot be fixed that way, because its end is decided by the provider — it
// lasts exactly as long as the upstream stream does — so a session still
// relaying when even the live signer has run out of room can end only one way,
// and it is not a receipt: the bytes were relayed, the provider was paid for
// them upstream, and nothing can be settled. Cutting first turns that into a
// truncated receipt for the bytes that did arrive, which is a receipt the Hub
// can price.
//
// The cut is therefore the stop-loss for a rotation that has failed, not part of
// a healthy one. The watcher reads the live signer every time it wakes instead
// of latching the one the session opened under, and that is not a detail: a
// rotation landing mid-session publishes an epoch that expires later, so the
// deadline moves out, and a session that could have run to its natural end under
// fresh evidence must not be cut for having opened under an older one. Waking on
// the budget the old signer left and re-arming is how that is expressed — which
// is also why waking early costs nothing and needs no lock. With the refresh
// cadence aiming inside the platform's reissue window (see snpRotationLead) the
// live signer is already the newer one by the time the old one's deadline
// arrives, so on a healthy platform this never fires at all.
//
// Evidence with no readable leaf carries no deadline at all — the same
// tracked=false that keeps Execute from inventing a bound for the simulation —
// so such a signer is never stale and there is nothing here to cut for. The
// watcher waits the session out instead.
func (s *Service) watchSigningDeadline(stop <-chan struct{}) <-chan struct{} {
	cutoff := make(chan struct{})
	go func() {
		for {
			budget, bounded := s.signingBudget(s.activeSigner())
			if !bounded {
				<-stop
				return
			}
			if budget <= 0 {
				close(cutoff)
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(budget):
			}
		}
	}()
	return cutoff
}

// signerStaleAt reports whether signing with signer at now would produce a
// receipt no verifier accepts: its epoch carries a short-lived NitroTPM leaf
// that has passed SNPSigningMargin. The bound is deliberately narrower than
// admission — a handshake only has to be valid when it happens, while a receipt
// has to stay valid for a verifier that reads it later — so in the last minutes
// of a leaf this refuses work while the listener keeps accepting connections.
func signerStaleAt(signer *proof.Signer, now time.Time) bool {
	deadline, tracked := signingDeadline(signer)
	if !tracked {
		// A signer with no epoch is unusable, and one with untracked evidence
		// has no TEE-side expiry to compare against; only the former is stale.
		return signer == nil || signer.Epoch() == nil
	}
	return !now.Before(deadline)
}

// Execute runs one job and returns its signed receipt.
//
// onChunk receives response bytes as they arrive and may be nil. Returning an
// error from it stops the exchange; the receipt still describes everything
// received up to that point, marked truncated.
//
// onStart, when given, receives the response start — the upstream status code
// and the allowlisted response headers — exactly once, before the first chunk.
// It is how the Hub learns that a stream is a 200 before it relays the first
// byte, or that it is a 401/429 before it shows the user an error. The
// receipt binds this start regardless of whether a callback is supplied.
//
// An error is returned only for refusals and for a receipt that cannot be
// issued at all. Once the request is sent, the outcome normally arrives as a
// Result whose Receipt.Completion reports what happened, and the error is nil
// even when the exchange failed.
//
// The exception is ErrAttestationStale from the end of an exchange: the epoch
// went past its signing deadline while the provider was being called and the
// process has published no newer one since. An exchange that simply outlived its
// epoch is not refused — the signature moves to whatever the process serves now
// (see perform), because those two epochs are the same measured enclave. So this
// refusal means the rotation itself has failed. It is not signed, and the Result
// is nil with it — an event with nothing to prove is better than evidence that
// fails when it is checked. Every other error means the job never reached the
// provider.
//
// That inversion is deliberate. The receipt is worth most exactly when the
// exchange went wrong: it is the evidence that lets a Hub avoid charging for a
// response that never arrived, or prove a provider cut a stream short. Handing
// back a non-nil error in that case would invite the usual
// `if err != nil { return }` and take the evidence with it. The invariant is
// therefore that error is non-nil if and only if Result is nil.
func (s *Service) Execute(ctx context.Context, job Job, onChunk ChunkFunc, onStart ...StartFunc) (*Result, error) {
	now := s.clock()
	signer := s.activeSigner()

	// Freshness before everything: a stale epoch can attest nothing, so the
	// job is refused before it can spend provider work or a sequence number.
	if signerStaleAt(signer, now) {
		return nil, ErrAttestationStale
	}

	// Room to finish, refused in the same place and for the same reason. An
	// exchange admitted with less than signingHandoff left before the deadline
	// could not produce a signable receipt at all, and refusing here rather than
	// inside the exchange also keeps the provider's series whole: a sequence
	// number spent on a job that never runs is a gap the provider cannot tell
	// from a hidden execution.
	//
	// It refuses the admission, not the exchange's own length. The deadline used
	// to be imposed on the running exchange as a context bound as well, and that
	// was the wrong half to keep: an exchange cut mid-flight produced no receipt
	// at all, so every byte it had already relayed to the buyer settled nothing —
	// relayed, paid for upstream, unbillable. An exchange that outlives its epoch
	// is now signed by the epoch that replaced it (see perform), and its length
	// is bounded by its own RequestTimeout, which the transport applies.
	if budget, bounded := s.signingBudget(signer); bounded && budget <= 0 {
		return nil, ErrAttestationStale
	}

	if s.submitterVerify != nil {
		if err := s.submitterVerify(ctx, job.Spec); err != nil {
			return nil, fmt.Errorf("submitter rejected: %w", err)
		}
	}

	// Structure and freshness first: an unusable spec is not worth authorising.
	if err := job.Spec.ValidateAt(now); err != nil {
		return nil, err
	}

	// The body must be the body the spec describes. This is what catches two
	// concurrent jobs having their payloads crossed, or a truncated body
	// arriving under another job's authorisation.
	if !job.Spec.MatchesBody(job.Body) {
		return nil, ErrBodyMismatch
	}

	decision, err := s.policy.AuthorizeAt(job.Spec, now)
	if err != nil {
		return nil, err
	}

	if uint64(len(job.Body)) > decision.MaxBodyBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d",
			ErrBodyTooLarge, len(job.Body), decision.MaxBodyBytes)
	}

	headers, err := s.injectCredential(job.Spec)
	if err != nil {
		return nil, err
	}

	specHash, err := job.Spec.Hash()
	if err != nil {
		return nil, err
	}

	// The last thing before the wire, and the only thing here that mutates
	// state. A failure to allocate is a refusal, not a receipt: better to
	// decline a job than to execute one whose place in the provider's series
	// cannot be recorded.
	//
	// The allocation is conservative in the other direction too. If the
	// exchange happens but signing then fails, the number is spent with no
	// receipt to show for it, and the provider sees a gap where nothing was
	// hidden. That is the right way round — a gap invites a question, while a
	// number reused after a crash would let a hidden receipt pass as accounted
	// for.
	seq, err := s.seq.Next([]byte(job.Spec.Provider))
	if err != nil {
		return nil, fmt.Errorf("allocate provider sequence: %w", err)
	}

	request := Request{
		Method:           job.Spec.Method,
		Provider:         job.Spec.Provider,
		Host:             job.Spec.Host,
		Path:             job.Spec.Path,
		Query:            job.Spec.Query,
		Headers:          headers,
		Body:             job.Body,
		Stream:           job.Spec.Stream,
		MaxResponseBytes: decision.MaxResponseBytes,
		Timeout:          s.requestTimeout,
	}

	// Stop-loss for a rotation that failed, invisible on a healthy platform.
	// The watcher cancels the exchange only when the live signer's budget runs
	// out with no fresher epoch behind it; a rotation landing first re-arms it
	// and the exchange runs on to be signed by the live key. It is started
	// after the sequence number is spent so a cancel that races admission
	// cannot spend a number on work that never reaches the wire, and it uses a
	// cancel without a deadline so the transport sees no deadline of its own
	// (see TestExchangeIsGivenNoDeadlineOfItsOwn).
	exchangeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	if _, bounded := s.signingBudget(signer); bounded {
		go s.watchExchangeBudget(done, exchangeCtx, cancel)
	}

	return s.perform(exchangeCtx, request, job.Spec, specHash, decision, seq, onChunk, onStart)
}

// injectCredential decrypts the credential envelope carried on the job and
// merges the provider's secret into the caller's headers, returning the exact
// header set to put on the wire.
//
// The secret (token and its header/scheme shape) arrives on the job itself,
// sealed to this service's inbox key by the provider's agent and relayed
// verbatim by the Hub. The TEE stores nothing: the private half of InboxKey is
// the only thing in the system that can reopen the envelope. A job with no
// credential is refused — a schedulable provider always carries one, so an
// empty envelope means the Hub sidestepped registration. A secret that declares
// no header is one whose upstream needs no authentication: nothing is injected.
func (s *Service) injectCredential(spec jobs.Spec) (map[string]string, error) {
	headers := make(map[string]string, len(spec.Headers)+1)
	for name, value := range spec.Headers {
		headers[name] = value
	}

	if len(spec.Credential) == 0 {
		return nil, fmt.Errorf("%w: provider %q", ErrNoCredential, spec.Provider)
	}
	env, err := DecodeEnvelope(spec.Credential)
	if err != nil {
		return nil, err
	}
	secret, declared, err := s.inbox.Open(env)
	if err != nil {
		return nil, err
	}
	if declared != spec.Provider {
		return nil, fmt.Errorf("credential envelope is bound to provider %q, not %q", declared, spec.Provider)
	}
	if err := secret.Validate(); err != nil {
		return nil, err
	}
	if secret.Header == "" {
		// The registered secret declares no authentication header: this
		// provider's upstream needs none, so nothing is injected.
		return headers, nil
	}

	// The job must not already occupy the header the credential goes in.
	// jobs.Validate rejects the reserved headers, so reaching here means that
	// check was bypassed — refuse rather than silently overwrite, which would
	// turn a guard into a no-op and leave no trace.
	if headerSet(headers, secret.Header) {
		return nil, fmt.Errorf("%w: %q", ErrCredentialClash, secret.Header)
	}

	name, value, err := secret.Render()
	if err != nil {
		return nil, err
	}
	headers[name] = value
	return headers, nil
}

// perform sends the request, digests the response as it arrives, and signs the
// receipt. It is the only path that produces a receipt, which is why it is
// separated from the checks above: everything before it can refuse a job
// outright, everything inside it has already committed to executing. The one
// refusal it can still produce is the fail-safe at the signature, and it now
// fires only when the process has no fresher key to hand the signature to at
// all — an epoch that went past its signing deadline while the exchange ran and
// no rotation to replace it. The alternative it refuses is a receipt no verifier
// accepts, and the alternative to refusing it is settled by nobody.
func (s *Service) perform(
	ctx context.Context,
	request Request,
	spec jobs.Spec,
	specHash [32]byte,
	decision policy.Decision,
	seq uint64,
	onChunk ChunkFunc,
	onStart []StartFunc,
) (*Result, error) {
	hasher := proof.NewStreamingHasher(spec.JobID)
	truncated := false

	// The signer this exchange starts under is the one its receipt should name.
	// A receipt is held to the attested key of the connection that carried it,
	// and that connection presented the epoch current when the request arrived,
	// so naming it keeps the pair a verifier can check consistent. That is the
	// state to prefer whenever the exchange can stay inside its epoch, and this
	// is where the preference is expressed.
	//
	// It is a preference, not a guarantee. The exchange can outlive the epoch it
	// started under, and the alternative to naming a newer key is no receipt at
	// all: bytes already relayed to the buyer, paid for upstream, settled by
	// nothing. So when the pinned key has run out of room the signature moves to
	// whatever the process serves now — see the handoff at the end of this
	// function. The two keys belong to the same measured enclave, which is what
	// the Hub pins: it compares neither half to the other half, and no part of it
	// could, since the verifier it is handed is `func(proof.SignedReceipt) error`
	// and sees no connection. What that gives up is the connection↔receipt
	// pairing for exactly those exchanges that cross a rotation, and it is
	// written up in docs/cert-lifetime-audit.md §19.
	//
	// The pinned signer is also what admission measured its room against, and a
	// rotation landing in between can only replace it with a leaf that expires
	// later — so the room admission granted stays conservative either way.
	signer := s.activeSigner()

	// The response start: filter the upstream headers to the relay allowlist,
	// hash them for the receipt, and (when the caller wants it) report them
	// before the first chunk moves. The hash is computed before the callback
	// so a callback that panics or errors cannot desynchronise the receipt
	// from what the Hub was shown. A zero status means the transport never
	// produced a response (e.g. a failed handshake): there is no start to
	// report, and nothing to attest.
	var started bool
	var headerHash []byte
	start := func(resp Response) {
		if started || resp.StatusCode == 0 {
			return
		}
		started = true
		resp.Headers = ForwardResponseHeaders(resp.Headers)
		h := HashResponseHeaders(resp.Headers)
		headerHash = h[:]
		if len(onStart) > 0 && onStart[0] != nil {
			onStart[0](resp)
		}
	}
	// Total bytes/chunks the provider actually sent, counted even past the
	// cap. The StreamHash below covers only what was relayed (so the Hub can
	// verify the prefix it forwarded), while these totals honestly record how
	// much arrived — a provider cannot later claim it sent less than it did.
	var totalBytes, totalChunks uint64

	// Digest before relaying. If the relay fails — the Hub hung up, the
	// consumer is gone — the receipt still owes the verifier an honest account
	// of what the provider actually sent. Relaying first would let a consumer
	// error silently shrink the attested transcript.
	relay := func(chunk []byte) error {
		totalBytes += uint64(len(chunk))
		totalChunks++
		// Enforce the cap before the bytes enter the hash. If we hashed first
		// and checked after, the over-cap chunk would be counted in the
		// StreamHash but never relayed, so the receipt's hash could never
		// agree with the bytes the Hub actually forwarded — every truncated
		// response would then fail the Hub's stream check. Stopping first
		// keeps the hash equal to the relayed prefix; the overflow lives in
		// ResponseBytes/ChunkCount instead.
		if hasher.BytesWritten()+uint64(len(chunk)) > request.MaxResponseBytes {
			truncated = true
			return ErrResponseBodyTooLarge
		}
		if err := hasher.WriteChunk(chunk); err != nil {
			return err
		}
		if onChunk == nil {
			return nil
		}
		if err := onChunk(chunk); err != nil {
			// The provider stream is fine; the consumer stopped taking it.
			// The response is partial from the caller's point of view even
			// though the exchange itself completed.
			truncated = true
			return err
		}
		return nil
	}

	startedAt := s.clock().Unix()
	response, err := s.transport.Do(ctx, request, relay, start)
	finishedAt := s.clock().Unix()

	completion := proof.CompletionComplete
	switch {
	case err != nil && !started && hasher.BytesWritten() == 0:
		completion = proof.CompletionFailed
	case err != nil, truncated:
		completion = proof.CompletionTruncated
	}

	// A status is trustworthy only once the response actually began, and
	// `started` — not the byte count — is the marker of a begun response: the
	// transport fires start the moment it parses the headers, before any body
	// byte. An error after that (headers arrived, body dropped) is a truncated
	// response with a real status, which the receipt must keep attesting:
	// clearing it would contradict the start the Hub was already shown, and
	// the Hub would reject every such exchange. Only when the start never
	// fired is there truly no status to attest.
	statusCode := response.StatusCode
	if err != nil && !started {
		statusCode = 0
	}

	streamHash := hasher.Sum()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         spec.JobID,
		JobSpecHash:   specHash[:],
		Provider:      spec.Provider,
		Method:        spec.Method,
		Host:          spec.Host,
		Path:          spec.Path,
		StatusCode:    statusCode,
		StreamHash:    streamHash[:],
		ChunkCount:    totalChunks,
		ResponseBytes: totalBytes,
		Completion:    completion,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		PolicyHash:    decision.PolicyHash,

		// The request side of the exchange. The size was already computed to
		// check it against the policy cap; signing it costs nothing and is the
		// only attested record of how much was sent, since the body itself
		// appears in the receipt only as a hash.
		RequestBytes: uint64(len(request.Body)),

		// Where this execution sits in the provider's series. A provider
		// holding a receipt numbered N knows it was used at least N times,
		// which is what turns a pile of individually-valid receipts into a
		// ledger whose completeness can be checked.
		ProviderSeq: seq,

		// The response start the Hub was shown. Present exactly when the
		// exchange produced a response, which is also exactly when the Hub can
		// hold this receipt against the status and headers it relayed.
		ResponseHeadersHash: headerHash,
	}

	// Freshness is checked again here, at the point of no return, and not only
	// before the exchange — but the answer is a handoff rather than a refusal.
	// Signing with an epoch past its deadline would produce a receipt every
	// verifier refuses, which is worse than no receipt, because it looks like
	// evidence and is settled like evidence until someone checks the leaf.
	// Refusing it outright was the other half of that choice, and it is the half
	// that no longer holds: a refusal here arrives after the provider has been
	// paid and after the bytes reached the buyer, so the exchange settles nothing
	// at all.
	//
	// So the signature moves to whatever the process serves now. A rotation is
	// the ordinary reason the pin went stale, and a rotation only ever installs
	// an epoch whose evidence expires later, so the handoff normally signs under
	// evidence with hours left on it. Both epochs are the same measured
	// application; what the pair loses is described where the pin is taken.
	//
	// The refusal survives for the case the handoff cannot fix: no rotation has
	// landed, so the live signer is the pinned one and it is stale too. That is a
	// platform that stopped reissuing, and there is genuinely nothing left to
	// sign with — the same fail-closed outcome as before, now reached only when
	// the rotation itself has failed rather than whenever an exchange happens to
	// straddle one.
	signing := signer
	if signerStaleAt(signing, s.clock()) {
		signing = s.activeSigner()
	}
	if signerStaleAt(signing, s.clock()) {
		return nil, ErrAttestationStale
	}
	signed, err := signing.Sign(receipt)
	if err != nil {
		return nil, fmt.Errorf("sign receipt: %w", err)
	}

	result := &Result{
		Receipt:       signed,
		StatusCode:    statusCode,
		ChunkCount:    totalChunks,
		ResponseBytes: totalBytes,
		StreamHash:    streamHash,
		// Derived from the completion state rather than tracked separately:
		// a result that says truncated while reporting a complete receipt, or
		// the reverse, would leave the caller guessing which to believe. The
		// relay's own flag is folded in to cover a transport that swallows a
		// consumer error and returns success anyway.
		Truncated:   truncated || completion == proof.CompletionTruncated,
		PolicyHash:  decision.PolicyHash,
		ProviderSeq: seq,
	}
	return result, nil
}

// headerSet reports whether a header map already contains name, ignoring case.
func headerSet(headers map[string]string, name string) bool {
	for existing := range headers {
		if strings.EqualFold(existing, name) {
			return true
		}
	}
	return false
}

// Session is a metered, attested transparent tunnel to a provider, opened by
// Service.OpenSession. It runs the same refusal checks a normal execution does,
// then turns the transport's session connection into a byte pipe whose every
// byte is counted (uplink → RequestBytes, downlink → ResponseBytes) and whose
// downlink plaintext is streamed into the receipt digest. Frame and payload
// semantics are never touched here — the caller owns them, which is the whole
// point of the design: the TEE only moves, counts, and digests bytes.
type Session struct {
	svc      *Service
	spec     jobs.Spec
	specHash [32]byte
	decision policy.Decision
	seq      uint64
	conn     SessionConn

	hasher  *proof.StreamingHasher
	started int64

	// downLimit is the session's downlink cap, taken from Spec.MaxResponseBytes.
	// Zero means no cap. Read enforces it so that the receipt digests exactly
	// the bytes the caller received — see Read.
	downLimit uint64

	mu             sync.Mutex
	requestBytes   uint64
	responseBytes  uint64
	chunkCount     uint64
	finishedAt     int64
	truncated      bool
	receiptEmitted bool
	cachedRes      *Result
	cachedErr      error
}

// OpenSession establishes a streaming session to the provider. It runs the same
// refusal checks as Execute — submitter, spec structure and expiry, body
// binding, policy authorisation, credential resolution, sequence allocation —
// then performs the Upgrade handshake and returns a Session the caller drives
// with Read/Write and finishes with Receipt.
//
// A session job must carry an empty body and set Spec.Session. The body hash
// binding still applies: the writer commits to a hash of zero bytes, which is
// how a session and a stray request are told apart even before the transport
// sees them.
func (s *Service) OpenSession(ctx context.Context, job Job) (*Session, error) {
	now := s.clock()
	signer := s.activeSigner()

	// Same freshness refusal as Execute, before the sequence or the provider
	// handshake is spent.
	if signerStaleAt(signer, now) {
		return nil, ErrAttestationStale
	}

	// And the same refusal of an admission with no room left to sign behind it.
	// A session is not held to the exchange's rule — it is signed by whatever
	// the process serves when it ends, so a rotation landing mid-session is
	// fine — but its terminal receipt still has to be signed, and the opening
	// handshake sits between here and the relay loop that watches the deadline:
	// a provider connect is not bounded by the signing budget the way an
	// exchange's own work is, so a session admitted into the last signingHandoff
	// can spend a sequence number and a provider session and then have no room
	// left to sign the receipt that would have paid for them. Refusing here is
	// the trade Execute already makes, in the same place and for the same
	// reason.
	if budget, bounded := s.signingBudget(signer); bounded && budget <= 0 {
		return nil, ErrAttestationStale
	}

	if s.submitterVerify != nil {
		if err := s.submitterVerify(ctx, job.Spec); err != nil {
			return nil, fmt.Errorf("submitter rejected: %w", err)
		}
	}
	if err := job.Spec.ValidateAt(now); err != nil {
		return nil, err
	}
	if !job.Spec.MatchesBody(job.Body) {
		return nil, ErrBodyMismatch
	}
	if len(job.Body) != 0 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrSessionBody, len(job.Body))
	}
	if !job.Spec.Session {
		return nil, fmt.Errorf("%w: Spec.Session is false", ErrSessionBody)
	}

	decision, err := s.policy.AuthorizeAt(job.Spec, now)
	if err != nil {
		return nil, err
	}
	headers, err := s.injectCredential(job.Spec)
	if err != nil {
		return nil, err
	}
	specHash, err := job.Spec.Hash()
	if err != nil {
		return nil, err
	}
	seq, err := s.seq.Next([]byte(job.Spec.Provider))
	if err != nil {
		return nil, fmt.Errorf("allocate provider sequence: %w", err)
	}

	opener, ok := s.transport.(SessionOpener)
	if !ok {
		return nil, ErrNoSessionSupport
	}

	// A session is a GET handshake with no body; the transport adds the
	// Upgrade headers itself. Spec.MaxResponseBytes is applied to the tunnel's
	// downlink (see Session.Read): a session is bounded by bytes rather than by
	// a body, and the Hub bounds its own relay with the same number, so the two
	// cut at the same point and the receipt stays reconcilable with what the Hub
	// moved. The policy's own MaxResponseBytes is not folded in here — it caps a
	// job's response and the caller has already stated the session's bound in
	// the spec, which the policy authorised on the way in.
	request := Request{
		Method:   job.Spec.Method,
		Provider: job.Spec.Provider,
		Host:     job.Spec.Host,
		Path:     job.Spec.Path,
		Query:    job.Spec.Query,
		Headers:  headers,
		Stream:   true,
		Timeout:  s.requestTimeout,
	}
	conn, err := opener.OpenSession(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}

	return &Session{
		svc:       s,
		spec:      job.Spec,
		specHash:  specHash,
		decision:  decision,
		seq:       seq,
		conn:      conn,
		hasher:    proof.NewStreamingHasher(job.Spec.JobID),
		started:   now.Unix(),
		downLimit: job.Spec.MaxResponseBytes,
	}, nil
}

// Write sends bytes uplink to the provider and counts them toward RequestBytes
// in the eventual receipt.
func (s *Session) Write(p []byte) (int, error) {
	n, err := s.conn.Write(p)
	if n > 0 {
		s.mu.Lock()
		s.requestBytes += uint64(n)
		s.mu.Unlock()
	}
	return n, err
}

// Read receives downlink bytes from the provider, counts them toward
// ResponseBytes, and digests them into the receipt's StreamHash. The bytes are
// opaque — frame interpretation is entirely the caller's.
//
// The session's downlink cap (Spec.MaxResponseBytes) is enforced here, and it is
// enforced by not delivering the offending bytes rather than by delivering them
// and trimming the count afterwards. Everything the caller is handed is
// therefore exactly what the digest covers, so the receipt reconciles with the
// relayed transcript byte for byte. That is load-bearing for billing: the Hub
// bounds its own relay with the same number, and a TEE that had digested a byte
// it never delivered would leave no prefix of its receipt matching what the Hub
// actually moved — which is precisely why a capped session used to settle
// nothing. Reaching the cap marks the session truncated, so it prices for the
// bytes that were delivered and no more.
func (s *Session) Read(p []byte) (int, error) {
	s.mu.Lock()
	limit := s.downLimit
	used := s.responseBytes
	s.mu.Unlock()

	if limit > 0 && used >= limit {
		// The bound is already spent. End the relay without reading, so the
		// provider is never drained past what the receipt accounts for.
		s.markTruncated()
		return 0, io.EOF
	}

	n, err := s.conn.Read(p)
	if n > 0 {
		if limit > 0 && used+uint64(n) > limit {
			// The cap lands inside this read: hand over only the bytes up to
			// it and drop the rest. The dropped bytes are never hashed, so they
			// are not in the receipt either.
			n = int(limit - used)
		}
		_ = s.hasher.WriteChunk(p[:n])
		s.mu.Lock()
		s.responseBytes += uint64(n)
		s.chunkCount++
		if limit > 0 && s.responseBytes >= limit {
			s.truncated = true
		}
		s.mu.Unlock()
	}
	// A provider that drops the socket mid-session — anything but a clean EOF —
	// leaves the transcript partial, and the receipt must say so. This includes
	// a read that returns zero bytes with a non-EOF error (e.g. an RST): the
	// session was still open when the wire vanished, so it is truncated, not
	// complete. The flag is checked even when n == 0 for exactly that case.
	if err != nil && !errors.Is(err, io.EOF) {
		s.markTruncated()
	}
	return n, err
}

// markTruncated records that the session's transcript is partial, so Receipt
// signs it as CompletionTruncated rather than CompletionComplete.
func (s *Session) markTruncated() {
	s.mu.Lock()
	s.truncated = true
	s.mu.Unlock()
}

// Close tears down the underlying provider connection. Pending Reads on the
// same Session return once the socket is closed.
func (s *Session) Close() error { return s.conn.Close() }

// Receipt signs the session's execution receipt. It is idempotent: the first
// call signs, and later calls return the same result. Call it once the session
// is over. The receipt carries StatusCode 101 (the successful upgrade),
// RequestBytes equal to the uplink total, and ResponseBytes/ChunkCount/
// StreamHash describing the downlink — the same response-digest contract a
// normal execution receipt uses.
func (s *Session) Receipt() (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.receiptEmitted {
		return s.cachedRes, s.cachedErr
	}
	s.finishedAt = s.svc.clock().Unix()

	completion := proof.CompletionComplete
	if s.truncated {
		completion = proof.CompletionTruncated
	}
	streamHash := s.hasher.Sum()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         s.spec.JobID,
		JobSpecHash:   s.specHash[:],
		Provider:      s.spec.Provider,
		Method:        s.spec.Method,
		Host:          s.spec.Host,
		Path:          s.spec.Path,
		StatusCode:    101,
		StreamHash:    streamHash[:],
		ChunkCount:    s.chunkCount,
		ResponseBytes: s.responseBytes,
		Completion:    completion,
		StartedAt:     s.started,
		FinishedAt:    s.finishedAt,
		PolicyHash:    s.decision.PolicyHash,
		RequestBytes:  s.requestBytes,
		ProviderSeq:   s.seq,
	}
	// The session may have outlived the rotation it opened under: sign with
	// whatever the process serves now, so a long session still finishes under
	// fresh evidence instead of the expired key it started with.
	//
	// This refusal is the fail-safe, not the mechanism. A session served over
	// /v1/session stops relaying at the live signer's deadline whatever the
	// provider is doing — relaySession cuts the tunnel while there is still
	// room to sign, which turns an unattestable session into a truncated and
	// priceable one (see watchSigningDeadline) — so arriving here means the cut
	// did not happen: a caller driving a Session directly, or a deadline that
	// passed between the cut and this line. An explicit error is still better
	// than a receipt no verifier would accept.
	signer := s.svc.activeSigner()
	if signerStaleAt(signer, s.svc.clock()) {
		return nil, ErrAttestationStale
	}
	signed, err := signer.Sign(receipt)
	result := &Result{
		Receipt:       signed,
		StatusCode:    101,
		ChunkCount:    s.chunkCount,
		ResponseBytes: s.responseBytes,
		StreamHash:    streamHash,
		Truncated:     completion == proof.CompletionTruncated,
		PolicyHash:    s.decision.PolicyHash,
		ProviderSeq:   s.seq,
	}
	s.receiptEmitted = true
	s.cachedRes = result
	s.cachedErr = err
	return result, err
}
