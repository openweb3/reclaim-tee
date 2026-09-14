package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Session errors.
var (
	// ErrNoReceiptForSession means the tunnel ended without a terminal receipt,
	// so there is nothing to settle against.
	ErrNoReceiptForSession = errors.New("session ended without a receipt")
	// ErrSessionStreamMismatch means the session receipt attests bytes other
	// than the ones the Hub actually relayed. For the downlink that is exact
	// (the stream hash binds the receipt to the relayed bytes); for the uplink
	// it fires only when the receipt attests MORE uplink than the Hub counted
	// — the direction that indicates a receipt the Hub could not have relayed.
	// A receipt attesting fewer uplink bytes than the Hub counted is the
	// teardown tail, not a lie, and does not forfeit the session (see
	// relaySession).
	ErrSessionStreamMismatch = errors.New("session receipt attests different bytes than the Hub relayed")
	// ErrSessionLimitExceeded means the Hub's downlink backstop fired: the TEE
	// relayed past the bound the two agreed on through Spec.MaxResponseBytes.
	//
	// It is a fault, not a normal bound. A session's cap travels on its spec and
	// is enforced by the TEE, which digests exactly what it delivers; the Hub's
	// sessionMaxDownBytes is aligned to that number (see boundSession), so the
	// TEE always cuts first and the receipt reconciles with what the Hub
	// relayed. This error therefore means the TEE broke its own attested bound:
	// it forwarded bytes the Hub never moved, so its digest no longer covers a
	// transcript the Hub can produce — and since the response digest is a plain
	// hash rather than a prefix-verifiable one, no prefix of it can be checked
	// either. Nothing is settled, because there is nothing to settle *against*:
	// a buyer must not be charged on a number no receipt supports. A TEE that
	// honours its cap never produces this.
	ErrSessionLimitExceeded = errors.New("the TEE relayed past the session's agreed downlink bound")
)

// upGrant is how long relaySession waits for an in-flight uplink to finish
// before counting it, once the session has ended. Long enough for a buffered
// user link to drain in tests, short enough that a silent-but-connected user
// cannot hold a session open through a count that is already settled.
const upGrant = 250 * time.Millisecond

// RealtimeLink is the user side of a streaming session. The Hub only moves
// bytes: Read yields the user's frames to forward uplink, Write delivers the
// provider's downlink frames back. Frame semantics belong to the caller (the
// user's protocol), never to the Hub or the TEE.
type RealtimeLink interface {
	io.Reader
	io.Writer
}

// SessionOutcome is the settled result of a streaming session.
type SessionOutcome struct {
	Receipt       proof.SignedReceipt
	Provider      string
	UplinkBytes   uint64
	DownlinkBytes uint64
	Charged       uint64
	Commission    uint64
	Buyer         uint64
	Stored        bool
}

// OpenSessionForModel selects the cheapest provider serving a model and opens a
// streaming session to it through the TEE. Provider selection happens before a
// single byte reaches the user, so a provider whose open fails can give way to
// the next-cheapest candidate, exactly as ExecuteForModel does for requests.
//
// build frames the session spec for one provider (host, path, Session flag);
// the caller supplies it once because that framing is identical across
// providers. The built spec's downlink cap is then tightened to the Hub's own
// session bound (see boundSession) — the two must be the same number for a
// capped session to reconcile.
//
// The tenant's in-flight share is taken here and travels with the returned
// connection, because a session does not finish when this call returns: it runs
// until the connection closes, holding a provider connection the whole time. A
// caller must close it, or the slot — and the pool slot behind it — is held
// until the process exits.
func (h *Hub) OpenSessionForModel(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	conn, spec, _, err := h.openSession(ctx, tenant, model, "", build)
	return conn, spec, err
}

// OpenSessionForProvider opens a streaming session to a named provider pinned
// source, with no fallback. It mirrors ExecuteForProvider for the session path:
// the buyer who asks for a specific AI source by name gets exactly that source,
// never a substitute. The named provider must be a current server of the model,
// otherwise the open is refused before a byte moves.
func (h *Hub) OpenSessionForProvider(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	conn, spec, _, err := h.openSession(ctx, tenant, model, provider, build)
	return conn, spec, err
}

// openSession opens a session either for the cheapest server of a model
// (provider empty) or pinned to one named provider. It admits the tenant and,
// on a failed open, returns the reserved share so a failed open never holds a
// running job. The returned spend carries the session's in-flight slot and
// money hold; it travels on the connection (see newFlightConn) and is
// consumed by settle or by Close, whichever comes first.
func (h *Hub) openSession(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, *jobSpend, error) {

	// The job id is minted here, before the provider is even chosen, because
	// it names the ledger order the admission opens: the hold has to be
	// recorded against something the settlement can quote, and the open may
	// fall back through several providers before one answers.
	jobID, err := newJobID()
	if err != nil {
		return nil, jobs.Spec{}, nil, err
	}
	spend, err := h.beginJob(tenant, jobID)
	if err != nil {
		return nil, jobs.Spec{}, nil, err
	}
	conn, spec, err := h.openSessionFor(ctx, model, provider, jobID, build)
	if err != nil {
		// Nothing came up, so the share this admission reserved goes straight
		// back: a failed open is not a running job and must not hold one.
		spend.release()
		return nil, jobs.Spec{}, nil, err
	}
	return newFlightConn(conn, spend), spec, spend, nil
}

// openSessionFor opens the session itself, without admitting the tenant.
// It is split out so admission happens once, above, and so the slot it reserves
// is still in hand when the caller decides whether the session came up.
func (h *Hub) openSessionFor(ctx context.Context, model, provider string, jobID []byte,
	build func(provider string) (jobs.Spec, error)) (SessionConn, jobs.Spec, error) {

	var providers []string
	if provider != "" {
		if !h.providerServes(provider, model) {
			return nil, jobs.Spec{}, fmt.Errorf("%w: model %q from provider %q", ErrNoProviderForModel, model, provider)
		}
		providers = []string{provider}
	} else {
		providers = h.providersForModel(model)
		if len(providers) == 0 {
			return nil, jobs.Spec{}, h.supplyError(model)
		}
	}
	for _, p := range providers {
		spec, berr := build(p)
		if berr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("build session spec for %q: %w", p, berr)
		}
		// The Hub owns the job's identity: the held order, the receipt the TEE
		// signs and the charge that follows all name this one value.
		spec.JobID = jobID
		spec = h.boundSession(spec)
		spec, aerr := h.attachCredential(spec)
		if aerr != nil {
			return nil, jobs.Spec{}, fmt.Errorf("attach credential for %q: %w", p, aerr)
		}
		attemptCtx, cancel := h.attemptContext(ctx)
		conn, oerr := h.tee.OpenSession(attemptCtx, spec)
		cancel()
		if oerr != nil {
			continue
		}
		return conn, spec, nil
	}
	return nil, jobs.Spec{}, fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
}

// boundSession returns spec with its downlink cap tightened to the Hub's own
// session bound, so the TEE stops relaying exactly where the Hub would.
//
// The two numbers must agree or a capped session cannot be reconciled. The TEE
// enforces Spec.MaxResponseBytes on the downlink and digests exactly what it
// delivers (tee.Session.Read); the Hub enforces its own sessionMaxDownBytes and
// digests exactly what it relays. If the Hub's bound were the tighter of the
// two it would cut the tunnel first, its digest would cover a prefix the TEE's
// does not, and — since the response digest is a plain hash rather than a
// prefix-verifiable one — nothing the TEE signs could be matched against what
// the Hub moved. Aligning them means the TEE always cuts first, its receipt
// covers exactly the relayed bytes, and the session settles for what it
// delivered.
//
// The Hub only ever tightens, never widens: widening the caller's cap could
// raise it above the provider policy's own limit, which the TEE refuses
// outright (policy.AuthorizeAt). A zero Hub bound means "no bound of mine", so
// the caller's cap stands alone, exactly as before.
func (h *Hub) boundSession(spec jobs.Spec) jobs.Spec {
	if h.sessionMaxDownBytes == 0 {
		return spec
	}
	if spec.MaxResponseBytes == 0 || h.sessionMaxDownBytes < spec.MaxResponseBytes {
		spec.MaxResponseBytes = h.sessionMaxDownBytes
	}
	return spec
}

// RunRealtime drives a streaming session end to end: select the cheapest
// provider for model, open the tunnel through the TEE, relay the user's frames,
// and settle the terminal receipt. It returns the settled outcome together with
// the relay error (if the session was cut short by a bound or a transport
// failure).
//
// The Hub applies its own session bounds here — a wall-clock timeout, an
// uplink byte bound, a downlink byte backstop, and a downlink-stall watchdog.
// The wall-clock, uplink and stall bounds are the Hub's because the TEE applies
// none of them to a session: it is a transparent relay, and keeping unbounded
// consumption out of the account book is the Hub's job. The downlink bound is
// the exception — it travels on the session spec and is enforced by the TEE, so
// that the byte count in the receipt is one the Hub can actually reconcile (see
// boundSession); the Hub's own copy is only a backstop for a TEE that breaks
// that contract.
func (h *Hub) RunRealtime(ctx context.Context, tenant, model string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	return h.runRealtime(ctx, tenant, model, "", build, link)
}

// RunRealtimeForProvider drives a streaming session pinned to one named
// provider, with no fallback. It is the session counterpart of
// ExecuteForProvider (and of the route's optional "provider" field): the buyer
// gets exactly the source they asked for. An open that cannot find the named
// provider serving the model is refused before a byte moves.
func (h *Hub) RunRealtimeForProvider(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	return h.runRealtime(ctx, tenant, model, provider, build, link)
}

// runRealtime drives a streaming session end to end: select the cheapest
// provider for model (or the pinned provider), open the tunnel through the TEE,
// relay the user's frames, and settle the terminal receipt. It returns the
// settled outcome together with the relay error (if the session was cut short
// by a bound or a transport failure).
func (h *Hub) runRealtime(ctx context.Context, tenant, model, provider string,
	build func(provider string) (jobs.Spec, error), link RealtimeLink) (SessionOutcome, error) {

	var (
		conn  SessionConn
		spec  jobs.Spec
		spend *jobSpend
		err   error
	)
	conn, spec, spend, err = h.openSession(ctx, tenant, model, provider, build)
	if err != nil {
		return SessionOutcome{}, err
	}
	defer conn.Close()

	h.ledger.NoteDispatch(spec.Provider)

	if h.sessionTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.sessionTimeout)
		defer cancel()
	}
	// Any expiry (wall-clock timeout or the caller's cancellation) must unwedge
	// the relay loops, which are otherwise blocked on the tunnel: closing the
	// tunnel aborts the downlink read so we can return and settle.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	up, down, downHash, relErr := relaySession(ctx, conn, link, spec.JobID,
		h.sessionMaxUpBytes, h.sessionMaxDownBytes, h.sessionIdle)

	if errors.Is(relErr, ErrSessionLimitExceeded) {
		// The Hub's backstop answered: the TEE relayed past the bound its own
		// spec declared, so the tunnel is already torn down and its digest
		// covers bytes this Hub never moved. Settle nothing — no receipt can be
		// reconciled against the relayed transcript (see
		// ErrSessionLimitExceeded) — and report the frame that cut it.
		return SessionOutcome{Provider: spec.Provider, UplinkBytes: up, DownlinkBytes: down}, relErr
	}

	receipt, rerr := conn.Receipt()
	if rerr != nil {
		return SessionOutcome{}, fmt.Errorf("%w: %v", ErrNoReceiptForSession, rerr)
	}
	if err := h.verify(receipt); err != nil {
		return SessionOutcome{}, fmt.Errorf("verify session receipt: %w", err)
	}
	h.ledger.NoteVerified(spec.Provider)

	rec := receipt.Receipt
	if rec.StatusCode != 101 {
		return SessionOutcome{}, fmt.Errorf("session receipt status %d, want 101", rec.StatusCode)
	}
	// The uplink comparison is deliberately one-sided. The Hub counts uplink
	// when it reads it from the user, and a session can end while the user's
	// final bytes are still in flight: the Hub may count bytes the closed
	// tunnel never delivered, so its count is an upper bound on what the TEE
	// can attest. An exact equality would forfeit a settled session over that
	// teardown tail. Only a receipt attesting MORE uplink than the Hub ever
	// relayed is a contradiction worth refusing — and the receipt stays the
	// billing record either way, so the buyer pays exactly what the TEE
	// attested was delivered. The downlink side is exact (the stream hash
	// already binds it), so its count stays an equality.
	if rec.RequestBytes > up || rec.ResponseBytes != down || !streamHashEq(rec.StreamHash, downHash[:]) {
		return SessionOutcome{}, ErrSessionStreamMismatch
	}

	card, ok := h.card(spec.Provider)
	if !ok {
		return SessionOutcome{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}
	// Sessions are never capped by the TEE, so the receipt's ResponseBytes is
	// exactly what was relayed — and the mismatch check above bound it to the
	// Hub's own relayed count. Pass the relayed count so pricing needs no cap
	// special case.
	charged, err := Price(card, model, down, rec)
	if err != nil {
		return SessionOutcome{}, fmt.Errorf("price session: %w", err)
	}
	commission, err := h.commission.CommissionOn(charged)
	if err != nil {
		return SessionOutcome{}, err
	}
	buyer, ok := addChecked(charged, commission)
	if !ok {
		return SessionOutcome{}, fmt.Errorf("%w: charged %d plus commission %d", ErrPriceOverflow, charged, commission)
	}
	outcome := SessionOutcome{
		Receipt:       receipt,
		Provider:      spec.Provider,
		UplinkBytes:   up,
		DownlinkBytes: down,
		Charged:       charged,
		Commission:    commission,
		Buyer:         buyer,
	}
	if h.maxJob > 0 && buyer > h.maxJob {
		// Same policy as the request path: the exchange really happened, so
		// the receipt is kept for the provider's audit, but a session priced
		// above the Hub's per-job ceiling settles nothing.
		if serr := h.store.Put(spec.Provider, receipt); serr != nil {
			return outcome, fmt.Errorf("store session receipt: %w", serr)
		}
		outcome.Stored = true
		return outcome, fmt.Errorf("%w: buyer %d exceeds %d", ErrJobPriceExceeded, buyer, h.maxJob)
	}
	if err := h.store.Put(spec.Provider, receipt); err != nil {
		// Same rule as the request path: the receipt is not durable, so the
		// ledger records no money. The caller still gets the priced outcome
		// to report what would have been charged.
		return outcome, fmt.Errorf("store session receipt: %w", err)
	}
	// Store first, then settle: the provider's audit record is durable before
	// money books. The settlement is one transaction, and a ledger that cannot
	// commit marks itself broken (refusing new jobs) rather than pretend the
	// charge landed: the session was delivered either way, and the order id is
	// what makes retrying the charge safe.
	outcome.Stored = true
	if !h.claimSettlement(spec.JobID) {
		return outcome, fmt.Errorf("%w: job %x", ErrDuplicateSettlement, spec.JobID)
	}
	if err := spend.settle(spec.Provider, buyer, charged, commission); err != nil {
		return outcome, err
	}
	h.ledger.NoteSettled(spec.Provider, charged)
	h.ledger.NoteCommission(spec.Provider, commission)
	return outcome, relErr
}

// relaySession copies the provider's downlink to the user (hashing and capping
// it) on one goroutine and the user's uplink to the provider on another. The
// session ends when the provider closes (downlink hits io.EOF after the receipt
// has been flushed through the tunnel), the user closes, or a bound fires.
//
// maxUp and maxDown are the Hub's own byte bounds; zero means no bound. The
// uplink bound is enforced by simply not reading further from the user, which
// ends the session normally: nothing was truncated on the provider's side, so
// the receipt still reconciles and the session still settles for what crossed.
// The downlink bound is different — it is a backstop, not the operative cap; a
// healthy session is cut by the TEE at the same number and settles for the
// bytes it delivered. See ErrSessionLimitExceeded.
//
// relaySession returns as soon as the downlink side resolves (or the session
// times out), because that is when the receipt has been produced. The uplink
// goroutine is left to unwind when the caller closes the user connection, which
// is the only thing that can unblock a read on a live user socket.
func relaySession(ctx context.Context, tunnel SessionConn, link RealtimeLink, jobID []byte,
	maxUp, maxDown uint64, idle time.Duration) (up, down uint64, downHash [32]byte, relErr error) {

	hasher := proof.NewStreamingHasher(jobID)

	// Downlink-stall watchdog: if the provider streams nothing for `idle`, tear
	// the tunnel down so the receipt (or io.EOF) surfaces and we stop waiting.
	var idleTimer *time.Timer
	if idle > 0 {
		idleTimer = time.AfterFunc(idle, func() { _ = tunnel.Close() })
		defer idleTimer.Stop()
	}

	var downCount uint64
	downDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := tunnel.Read(buf)
			if n > 0 {
				if maxDown > 0 && downCount+uint64(n) > maxDown {
					downDone <- ErrSessionLimitExceeded
					return
				}
				downCount += uint64(n)
				_ = hasher.WriteChunk(buf[:n])
				if _, werr := link.Write(buf[:n]); werr != nil {
					downDone <- werr
					return
				}
				if idleTimer != nil {
					idleTimer.Reset(idle)
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					downDone <- nil
				} else {
					downDone <- rerr
				}
				return
			}
		}
	}()

	var upCount atomic.Uint64
	upGone := make(chan struct{})
	go func() {
		defer close(upGone)
		buf := make([]byte, 32*1024)
		for {
			n, rerr := link.Read(buf)
			if n > 0 {
				if maxUp > 0 && upCount.Load()+uint64(n) > maxUp {
					// The user is uploading more than the Hub will relay into
					// the provider's tunnel. Stop reading and end the session:
					// the provider's own tunnel sees a clean close, so nothing
					// is truncated mid-frame and the receipt still reconciles.
					break
				}
				upCount.Add(uint64(n))
				if _, werr := tunnel.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		// User side finished: stop the provider-side read so the session can end.
		_ = tunnel.Close()
	}()

	// drainUplink lets an in-flight uplink finish so the count is as settled as
	// it can be before it is compared against the receipt's RequestBytes —
	// otherwise a receipt that is perfectly honest races the last write. The
	// count can still grow after the drain (a user socket the goroutine is
	// blocked reading), which is why the comparison in RunRealtime accepts a
	// receipt attesting no more than the Hub counted: the Hub's count is an
	// upper bound on what the TEE could have received, and a receipt inside
	// that bound is the attested billing record. It returns immediately if
	// the goroutine is already gone, and is bounded because with a live user
	// socket the goroutine can only be unwound by the caller closing the
	// connection, which happens after we return.
	drainUplink := func() {
		timer := time.NewTimer(upGrant)
		defer timer.Stop()
		select {
		case <-upGone:
		case <-timer.C:
		}
	}

	select {
	case <-ctx.Done():
		_ = tunnel.Close()
		<-downDone
		drainUplink()
		return upCount.Load(), downCount, hasher.Sum(), ctx.Err()
	case downErr := <-downDone:
		// The provider closed (or a bound fired); the receipt may already have
		// been read. Close the relay so any uplink still being handed to the
		// tunnel unwinds, then settle the uplink count.
		_ = tunnel.Close()
		drainUplink()
		if downErr != nil {
			return upCount.Load(), downCount, hasher.Sum(), downErr
		}
		return upCount.Load(), downCount, hasher.Sum(), nil
	}
}

func streamHashEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
