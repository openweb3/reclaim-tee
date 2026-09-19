// Package hub is the business side of TokenHive: everything that needs
// semantics rather than bytes.
//
// The TEE answers one question — did this exchange really happen, with exactly
// these bytes? It does not know what a model is, what a token costs, or who
// owes whom. This package answers those.
//
// The split is what makes Hub logic cheap to develop. Everything here sits on
// the far side of a single RPC, so it can be built and tested against an
// in-memory stand-in without a TEE, a network, or a real credential — which is
// the point, because pricing and quota are the parts most likely to change.
package hub

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// Wiring errors. These are construction mistakes, not runtime conditions, and
// they fire on the first call rather than the first job.
var (
	ErrNoTEE      = errors.New("hub has no TEE to dispatch to")
	ErrNoRates    = errors.New("hub has no rate table")
	ErrNoStore    = errors.New("hub has no receipt store")
	ErrNoVerifier = errors.New("hub has no receipt verifier")
)

// Execution errors.
var (
	// ErrUnknownProvider means the Hub was asked to use a provider it has no
	// rate for. Rates are the market registry: a seller that has not published
	// a price is a provider the Hub cannot dispatch to.
	ErrUnknownProvider = errors.New("no rate published for provider")
	// ErrQuotaExceeded means the tenant was refused before dispatch.
	ErrQuotaExceeded = errors.New("tenant quota exhausted")
	// ErrBudgetExceeded means the tenant's cumulative spend has reached the
	// ceiling the Hub holds for it. Like the quota it is refused before
	// dispatch, so the provider is never asked to spend a credential on a job
	// the buyer cannot pay for.
	ErrBudgetExceeded = errors.New("tenant budget exhausted")
	// ErrStreamMismatch means the receipt attests bytes other than the ones
	// the Hub forwarded. Either the Hub is lying about what it delivered or
	// the TEE is not describing the same exchange; neither is settleable.
	ErrStreamMismatch = errors.New("receipt attests different bytes than the Hub forwarded")
	// ErrJobPriceExceeded means a job priced above the Hub's per-job ceiling.
	// It is a Hub policy refusal, not a provider fault: the exchange happened
	// and its receipt is kept (so the execution is not hidden from the
	// provider), but no money moves, because the Hub will not bill a buyer for
	// a job it did not bound. Retrying another provider cannot help — the
	// ceiling is what it is.
	ErrJobPriceExceeded = errors.New("job priced above the hub's per-job ceiling")
	// ErrResponseStartMismatch means the response-start frame the Hub acted
	// on — the status it showed the user and the headers it relayed — is not
	// the exchange the receipt attests. Like ErrStreamMismatch it is a
	// contradiction between what the Hub did and what the TEE signed, so
	// nothing is settled against it.
	ErrResponseStartMismatch = errors.New("response start does not match the receipt")
	// ErrDuplicateSettlement means a receipt for a job this Hub already settled
	// was presented again. One JobID settles exactly once; a repeat is either a
	// broken caller or a double-charge attempt, and neither books a second time.
	ErrDuplicateSettlement = errors.New("job already settled")
)

// Config assembles a Hub.
type Config struct {
	// TEE is the execution seam. Required.
	TEE TEE

	// Rates is the market price list, keyed by provider. Prices are seller
	// reported commercial data maintained by the Hub — deliberately NOT part
	// of the Provider Policy, which is now a Hub-predefined whitelist loaded
	// into TEE deployment config. Required: without it the Hub cannot know
	// what a provider charges or even which providers are on the market.
	Rates map[string]RateCard

	// Store persists the receipts a provider is entitled to audit. Required:
	// a Hub that keeps no receipts removes the provider's only means of
	// noticing an execution that was hidden from it.
	Store Store

	// Verify checks a receipt's signature and attestation. Required, and
	// injected rather than hard-wired to proof.Verify so that the trust roots
	// — which attestation platforms are acceptable — stay the caller's call.
	Verify func(proof.SignedReceipt) error

	// Ledger accumulates charges. Created if nil: it holds no durable state,
	// so defaulting it cannot silently weaken any guarantee.
	Ledger *Ledger

	// Quota bounds what one tenant may consume. Nil means unlimited, which is
	// a deliberate opt-out rather than a default: a control that exists to
	// stop a credential being drained should not be on unless asked for.
	Quota *Quota

	// Budgets caps each tenant's cumulative spend, keyed by tenant, in the same
	// micro-units as a rate card. A tenant absent from the map has no ceiling —
	// the deliberate opt-out described on Quota — and is never tracked, so the
	// table is bounded by what is provisioned here.
	//
	// It is the cumulative counterpart of MaxJobMicros: that bounds one job,
	// this bounds the sum. Without it a seller whose card prices just under the
	// per-job ceiling can bill a buyer indefinitely.
	Budgets map[string]uint64

	// Commission sets the fixed fraction the Hub takes over every settled
	// charge, in basis points. 100 is 1%, 1000 is 10%, zero means the Hub takes
	// no commission.
	//
	// Pricing authority on the seller side is unchanged: the ledger keeps the
	// provider's revenue unchanged, and the commission is tracked as a
	// separate total. The provider always earns exactly what its rate card says.
	Commission uint64

	// MaxJobMicros caps what a single job may bill the buyer, in the same
	// integer micro-units as a rate card. Zero (the default) means no ceiling,
	// which is the deliberate opt-out described on Quota — a control that
	// exists to stop a hostile seller's rate card from draining a buyer should
	// not be on unless asked for.
	//
	// It is the buyer-side counterpart of the seller-side RateCard: the card
	// says what a seller may charge, the ceiling says what the Hub will pass on.
	// Without it a seller's volume rate is bounded only by MaxRateMicros, which
	// is large enough that a hidden per-megabyte price can still produce a
	// crippling bill. A job that prices above the ceiling is refused at
	// settlement: its receipt is stored (the execution is never invisible) but
	// nothing is charged or paid (see ErrJobPriceExceeded).
	MaxJobMicros uint64

	// MaxInflightPerTenant caps how many jobs one tenant may run at the same
	// time. Zero (the default) means no cap, the deliberate opt-out described
	// on Quota; the hub binary ships a default so a deployment is fair unless
	// it opts out.
	//
	// It is the fairness control for a shared provider, and the only layer that
	// can enforce one: the TEE pools provider connections per (provider, host)
	// and never learns which tenant a job belongs to (the tenant is not in the
	// JobSpec, so it is not attested). Without a cap, one tenant can hold every
	// slot a shared provider has — a streaming session does so for its whole
	// life — and leave the market's other buyers queueing behind it.
	//
	// The cap is on concurrency, not on rate: a tenant may run any number of
	// jobs over time, just not more than its share at one instant. Requests and
	// sessions share the one count, because they draw on the same pool.
	MaxInflightPerTenant int

	// Clock returns the current time. Defaults to time.Now.
	Clock func() time.Time

	// AttemptTimeout bounds one dispatch to a provider, including the time the
	// TEE spends on it. Zero (the default) means the caller's context is the
	// only bound. The TEE already bounds a single exchange (its request
	// timeout), which is what stops a deliberately slow provider from holding a
	// job open forever; this is the Hub-side backstop for a TEE that stops
	// answering for any other reason. It must be set longer than the TEE's own
	// bound, or the Hub would cut exchanges the TEE would have completed — and
	// therefore bill a truncation the provider did not cause.
	AttemptTimeout time.Duration

	// Withhold, if set, suppresses the receipt carrying a given ProviderSeq
	// from the store. It exists so a test can play a Hub that hides an
	// execution and check that gap detection still catches it. A Hub that
	// wants to be trusted leaves it nil.
	Withhold func(seq uint64) bool

	// SessionTimeout bounds a streaming session's wall-clock lifetime; zero
	// means no time bound. SessionMaxDownBytes caps the bytes relayed downlink;
	// zero means no byte bound. SessionMaxUpBytes caps the bytes relayed
	// uplink; zero means no byte bound. SessionIdle is the downlink-stall
	// watchdog — if the provider streams nothing for this long the session is
	// torn down; zero disables the stall watchdog. These four are the Hub's own
	// bounds: the TEE deliberately applies none to a session (it is a
	// transparent relay), so unbounded consumption stays on the Hub's side of
	// the wire.
	SessionTimeout      time.Duration
	SessionMaxDownBytes uint64
	SessionMaxUpBytes   uint64
	SessionIdle         time.Duration

	// AgentKeys is the per-provider key map a Provider Agent must present to
	// dial in through the reverse-tunnel gate (AgentProviderHeader + AgentKeyHeader).
	// A dial-in must name a provider and present exactly the key registered for
	// it, which is what binds a tunnel to a provider: no seller can come online
	// as another without their key, displace their tunnel, or collect the
	// revenue routed to that name. Empty disables agent registration — the
	// deliberate stance for a Hub that only runs against scripted stand-ins.
	AgentKeys map[string][]byte

	// AdmitAgent, when set, is consulted with a registering agent before it
	// becomes schedulable. It is where the deployment's whitelist gets to
	// refuse a seller: a provider agent declares what it charges and which
	// models it serves, never what the enclave will accept, so admission is a
	// question the operator's policy answers, not the agent's.
	//
	// Nil admits every authenticated agent — the stance for a Hub whose
	// whitelist lives entirely in the TEE, where a job would be refused instead.
	AdmitAgent func(AgentRegister) error

	// RelaySecret is the key the TEE must present to dial the TeeRelay
	// endpoint (RelayKeyHeader). The relay bridges any stream into any online
	// agent's tunnel, so an unauthenticated one is an open egress proxy
	// through every seller's connection. Nil leaves it open — the deliberate
	// stance for a Hub whose TEE is only reachable by the operator.
	RelaySecret []byte

	// Credentials is the TEE's credential plane (see CredentialService): its
	// only job is to publish the TEE's inbox public key, which provider agents
	// fetch (through the Hub) to encrypt their tokens to. Required to host
	// agents or to publish a key at all.
	Credentials CredentialService

	// CredentialStore persists the envelopes provider agents register on
	// dial-in: the token sealed to the TEE's inbox key, never the plaintext.
	// The Hub attaches the stored envelope to every job it dispatches to that
	// provider (see Execute), so the TEE can decrypt it per request. Defaults
	// to an in-memory store when nil; a resident Hub passes a file-backed store
	// so envelopes survive restarts.
	CredentialStore CredentialStore
}

// Hub turns a job into a settled charge and an auditable receipt.
type Hub struct {
	tee        TEE
	rates      map[string]RateCard
	store      Store
	verify     func(proof.SignedReceipt) error
	ledger     *Ledger
	quota      *Quota
	budget     *Budget
	flight     *flightLimiter
	commission CommissionRate
	maxJob     uint64
	clock      func() time.Time
	withhold   func(uint64) bool

	attemptTimeout time.Duration

	sessionTimeout      time.Duration
	sessionMaxDownBytes uint64
	sessionMaxUpBytes   uint64
	sessionIdle         time.Duration

	agents          *agentRegistry
	admit           func(AgentRegister) error
	agentKeys       map[string][]byte
	relaySecret     []byte
	credentials     CredentialService
	credentialStore CredentialStore

	settledMu sync.Mutex
	settled   map[string]struct{}
}

// New builds a Hub, refusing to construct one that would settle incorrectly.
func New(cfg Config) (*Hub, error) {
	if cfg.TEE == nil {
		return nil, ErrNoTEE
	}
	if cfg.Rates == nil {
		return nil, ErrNoRates
	}
	if cfg.Store == nil {
		return nil, ErrNoStore
	}
	if cfg.Verify == nil {
		return nil, ErrNoVerifier
	}
	ledger := cfg.Ledger
	if ledger == nil {
		ledger = NewLedger()
	}
	var budget *Budget
	if len(cfg.Budgets) > 0 {
		// A budget that no per-job ceiling backs cannot hold: admission is
		// check-then-record, so concurrent jobs overshoot by in-flight x the
		// largest single charge, and without MaxJobMicros that charge is whatever
		// the seller's card asks for.
		if cfg.MaxJobMicros == 0 {
			return nil, fmt.Errorf("%w: budgets need a per-job ceiling to bound their overshoot", ErrInvalidBudget)
		}
		built, err := NewBudget(cfg.Budgets)
		if err != nil {
			return nil, err
		}
		budget = built
	}
	// A nil limiter admits everything, so an unconfigured Hub carries no
	// per-tenant bookkeeping at all.
	var flight *flightLimiter
	if cfg.MaxInflightPerTenant > 0 {
		flight = newFlightLimiter(cfg.MaxInflightPerTenant, MaxFlightTenants)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	credentialStore := cfg.CredentialStore
	if credentialStore == nil {
		credentialStore = NewMemoryCredentialStore()
	}
	return &Hub{
		tee:        cfg.TEE,
		rates:      cfg.Rates,
		store:      cfg.Store,
		verify:     cfg.Verify,
		ledger:     ledger,
		quota:      cfg.Quota,
		budget:     budget,
		flight:     flight,
		commission: CommissionRate{BasisPoints: cfg.Commission},
		maxJob:     cfg.MaxJobMicros,
		clock:      clock,
		withhold:   cfg.Withhold,

		attemptTimeout: cfg.AttemptTimeout,

		sessionTimeout:      cfg.SessionTimeout,
		sessionMaxDownBytes: cfg.SessionMaxDownBytes,
		sessionMaxUpBytes:   cfg.SessionMaxUpBytes,
		sessionIdle:         cfg.SessionIdle,

		agents:          newAgentRegistry(),
		agentKeys:       cfg.AgentKeys,
		admit:           cfg.AdmitAgent,
		relaySecret:     cfg.RelaySecret,
		credentials:     cfg.Credentials,
		credentialStore: credentialStore,

		settled: make(map[string]struct{}),
	}, nil
}

// Ledger returns the Hub's ledger, so a caller can read what it owes.
func (h *Hub) Ledger() *Ledger { return h.ledger }

// CredentialKey returns the TEE's inbox public key, so provider agents can
// encrypt their tokens to the TEE that will actually hold them. The Hub is
// only a relay: it fetches the key on demand from its credential plane and
// hands it back untouched.
func (h *Hub) CredentialKey(ctx context.Context) (tee.InboxPublic, error) {
	if h.credentials == nil {
		return tee.InboxPublic{}, ErrNoCredentialService
	}
	return h.credentials.CredentialKey(ctx)
}

// RegisterCredential seals a provider's token to the TEE's inbox key and stores
// the envelope where the dispatcher will attach it to every job for that
// provider. It is how a one-shot Hub that talks to the TEE directly (with no
// dialing agent) delivers the seller's token: the Hub stores ciphertext only,
// exactly as it would for an agent registration, and never sees the plaintext.
func (h *Hub) RegisterCredential(ctx context.Context, provider string, secret tee.Secret) error {
	pub, err := h.CredentialKey(ctx)
	if err != nil {
		return err
	}
	env, err := tee.EncryptCredential(pub, provider, secret)
	if err != nil {
		return err
	}
	return h.credentialStore.Put(provider, env)
}

// attachCredential binds the provider's registered envelope onto a job before
// it is dispatched, so the TEE can decrypt the token inside. The envelope is
// whatever the provider's agent last registered (stored as ciphertext by the
// Hub); a provider with none on record dispatches without one and relies on
// the TEE to refuse gracefully.
func (h *Hub) attachCredential(spec jobs.Spec) (jobs.Spec, error) {
	env, ok := h.credentialStore.Get(spec.Provider)
	if !ok {
		return spec, nil
	}
	enc, err := env.EncodeCanonical()
	if err != nil {
		return spec, fmt.Errorf("canonical-encode credential for %q: %w", spec.Provider, err)
	}
	spec.Credential = enc
	return spec, nil
}

// card returns the effective price card the Hub quotes for a provider: the live
// agent's self-reported card when an agent is online for that provider, and the
// platform default otherwise. Settling against the same accessor keeps what the
// scheduler picked and what the ledger bills from drifting apart.
func (h *Hub) card(provider string) (RateCard, bool) {
	if a, ok := h.agents.conn(provider); ok {
		return a.price, true
	}
	card, ok := h.rates[provider]
	return card, ok
}

// admitTenant applies the Hub's pre-dispatch controls for a tenant: the
// cumulative budget, then the request quota.
//
// The budget is checked first on purpose. It is the money gate, and a tenant
// whose budget is exhausted must not also burn a rate-limit slot — the request
// is going to be refused either way, and consuming the slot would push the
// tenant's next (affordable) request out of its window. Both checks run before
// dispatch, so a refused request never consumes a ProviderSeq.
func (h *Hub) admitTenant(tenant string) error {
	if h.budget != nil && !h.budget.Allow(tenant) {
		return fmt.Errorf("%w: tenant %q", ErrBudgetExceeded, tenant)
	}
	if h.quota != nil && !h.quota.Allow(tenant, h.clock()) {
		return fmt.Errorf("%w: tenant %q", ErrQuotaExceeded, tenant)
	}
	return nil
}

// chargeTenant records a settled bill against the tenant's budget. It is called
// exactly where the ledger settles, never where the Hub merely priced a job it
// refused to bill: a refusal moves no money and must not consume budget.
func (h *Hub) chargeTenant(tenant string, micros uint64) {
	if h.budget != nil {
		h.budget.Record(tenant, micros)
	}
}

// attemptContext derives the per-attempt context from the caller's, bounding
// one dispatch with the Hub's attempt window. A zero window leaves the
// caller's context untouched and returns a no-op cancel, so callers can always
// defer it.
func (h *Hub) attemptContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.attemptTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, h.attemptTimeout)
}

// Outcome is what one request through the Hub produced.
type Outcome struct {
	// Receipt is the verified receipt. Zero if the job never reached the TEE.
	Receipt proof.SignedReceipt
	// Chunks are the response bytes the Hub forwarded to its caller.
	Chunks [][]byte
	// StatusCode is the upstream status the Hub committed its response with.
	// Zero when the exchange never produced a response.
	StatusCode uint32
	// Charged is what the provider earned, in the micro-units of its own rate
	// card. Zero for anything the provider did not complete.
	Charged uint64
	// Commission is the Hub's cut on the charge, in the same micro-units. Zero
	// when there is no commission or nothing was earned.
	Commission uint64
	// Buyer is what the buyer is billed: Charged plus Commission.
	Buyer uint64
	// Stored reports whether the receipt reached the provider's audit store.
	Stored bool
}

// Execute runs one job: check budget and quota, dispatch, verify, price,
// settle, store.
//
// model is the Hub's own pricing key, deliberately out-of-band from the job
// spec: the TEE only establishes and holds the provider connection, so it
// neither reads nor attests a model, and the spec stays a pure "what HTTP
// request to perform". The Hub selects and prices providers from the model it
// resolved locally.
//
// The ordering is load-bearing in three places. Budget and quota are checked
// before dispatch, so a refused request never consumes a ProviderSeq — if it
// did, ordinary rate limiting would punch holes in the provider's sequence and
// be indistinguishable from the Hub hiding executions. The receipt is verified
// before anything is charged, so a forged receipt cannot move money. And the
// receipt is stored before the ledger settles, so money books only when the
// provider's audit record is durable: a store failure means the exchange did
// not happen as far as the books are concerned, and the buyer is not charged
// for an answer whose receipt was never kept (a retry is a fresh purchase, not
// a double charge).
func (h *Hub) Execute(ctx context.Context, tenant, model string, spec jobs.Spec, body []byte,
	onChunk func([]byte) error, onStart ...func(tee.Response)) (Outcome, error) {
	release, err := h.beginJob(tenant)
	if err != nil {
		return Outcome{}, err
	}
	defer release()

	card, ok := h.card(spec.Provider)
	if !ok {
		return Outcome{}, fmt.Errorf("%w: %q", ErrUnknownProvider, spec.Provider)
	}

	// Bind the provider's registered credential envelope onto the job so the
	// TEE can authenticate the upstream request. This happens per dispatch,
	// from the store, so the Hub never holds the token itself — only the
	// ciphertext an agent registered.
	spec, err = h.attachCredential(spec)
	if err != nil {
		return Outcome{}, err
	}

	h.ledger.NoteDispatch(spec.Provider)

	// Bound this one dispatch (see AttemptTimeout). Each attempt gets a fresh
	// window, so a slow provider that eats the whole window does not also
	// consume the fallback's.
	ctx, cancel := h.attemptContext(ctx)
	defer cancel()

	res, err := h.tee.Execute(ctx, spec, body, onChunk, onStart...)
	// Everything from here on reports on the same exchange, so the outcome is
	// built once and each refusal fills in what it knows: what the caller was
	// shown, and the receipt if one arrived.
	outcome := Outcome{Chunks: res.Chunks, StatusCode: res.Status}
	if err != nil {
		return outcome, err
	}

	if err := h.verify(res.Receipt); err != nil {
		return outcome, fmt.Errorf("verify receipt: %w", err)
	}
	h.ledger.NoteVerified(spec.Provider)

	if !res.Receipt.Receipt.MatchesStream(res.Chunks) {
		return outcome, ErrStreamMismatch
	}

	// The response start the Hub acted on must be the exchange the receipt
	// attests: the status it committed to its caller and the headers it
	// relayed are part of what the provider gets billed against, so they must
	// be provable. The check binds in both directions (see receiptMatchesStart):
	// a start frame whose receipt contradicts it is refused, and so is a
	// receipt that attests a start — a non-empty ResponseHeadersHash — when no
	// frame was observed, since body chunks committed under a default 200
	// would then settle against a receipt attesting a real 401.
	if !receiptMatchesStart(res.Receipt.Receipt, res.Status, res.Headers) {
		return outcome, ErrResponseStartMismatch
	}

	// Price by the bytes actually relayed, not by the job's cap: the TEE
	// rejects whole chunks that cross MaxResponseBytes, so the delivered
	// prefix can end far below the cap (or at zero), while the receipt's
	// ResponseBytes counts everything the provider sent. The chunk stream was
	// just verified against the receipt's hash, so its length is attested by
	// construction.
	var relayed uint64
	for _, chunk := range res.Chunks {
		relayed += uint64(len(chunk))
	}
	amt, err := h.price(card, model, relayed, res.Receipt.Receipt)
	if err != nil {
		return outcome, err
	}
	outcome.Receipt = res.Receipt
	outcome.Charged = amt.provider
	outcome.Commission = amt.commission
	outcome.Buyer = amt.buyer
	outcome.Stored, err = h.book(tenant, spec.Provider, res.Receipt, amt,
		h.withhold != nil && h.withhold(res.Receipt.Receipt.ProviderSeq))
	return outcome, err
}

// maxSettledJobs caps the in-memory dedup table. Beyond it the table is reset
// and the dedup window restarts: JobIDs are generated by the Hub, so a repeated
// settlement across a reset is no more plausible than a colliding JobID.
const maxSettledJobs = 1 << 18

// claimSettlement records that a job's receipt is being settled, returning
// false when the same JobID was already settled by this Hub. It is the
// defensive half of "one JobID settles exactly once": the TEE signs each job
// once, so a second settlement of the same JobID is a broken caller or a
// double-charge attempt, and the Hub refuses to book it twice.
func (h *Hub) claimSettlement(jobID []byte) bool {
	h.settledMu.Lock()
	defer h.settledMu.Unlock()
	if _, dup := h.settled[string(jobID)]; dup {
		return false
	}
	if len(h.settled) >= maxSettledJobs {
		h.settled = make(map[string]struct{})
	}
	h.settled[string(jobID)] = struct{}{}
	return true
}

// receiptMatchesStart reports whether a receipt attests the response start the
// Hub acted on: the same status, and a ResponseHeadersHash over exactly the
// header set the Hub was shown. The digest is recomputed here, from the start
// frame the Hub parsed, and compared against the signed value — a TEE that
// relayed one start and signed another would be caught the same way a forged
// stream is caught by MatchesStream.
//
// A receipt without a ResponseHeadersHash attests no start, so it binds
// nothing: it is compatible exactly with an exchange that produced no start
// either (status zero — the legacy pre-start shape). Once a start was shown
// the Hub must be able to prove what it relayed, and once a receipt attests a
// start the Hub must have observed the frame it describes.
func receiptMatchesStart(r proof.Receipt, status uint32, headers map[string][]string) bool {
	if len(r.ResponseHeadersHash) == 0 {
		return status == 0
	}
	if r.StatusCode != status {
		return false
	}
	h := tee.HashResponseHeaders(headers)
	return streamHashEq(h[:], r.ResponseHeadersHash)
}
