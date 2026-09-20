package hub

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// ErrNoProviderForModel means no provider on the market can serve the
// requested model. That is a supply problem, not a failure path worth hiding
// behind a provider-specific error.
var ErrNoProviderForModel = errors.New("no provider serves this model")

// ErrNoProvidersOnline means a Hub that hosts an agent gate has no agent
// holding a tunnel at all: the entire supply is down, not the model unknown.
// It is the honest answer when every listing dropped (agents are tested to
// take their listing down the moment their control stream closes), and it
// lets the HTTP layer answer 503 instead of a 404 that would read "this model
// never existed".
var ErrNoProvidersOnline = errors.New("no provider is online")

// supplyError picks the honest description for an empty candidate list. With
// an agent gate configured but not a single agent online, the whole market is
// down — a temporary condition, not a nonexistent model. Otherwise the model
// is simply not served by anything the Hub knows.
func (h *Hub) supplyError(model string) error {
	if h.agentsEnabled() && len(h.agents.onlineProviders()) == 0 {
		return fmt.Errorf("%w: model %q", ErrNoProvidersOnline, model)
	}
	return fmt.Errorf("%w: model %q", ErrNoProviderForModel, model)
}

// providersForModel returns the providers the Hub can route a model to, ordered
// by their effective book price for it (ascending), with ties broken by provider
// name so the order is a pure function of supply and price.
//
// The Hub only routes new work to a provider whose agent is online right now —
// a provider nobody currently egresses for cannot carry traffic, so it is not a
// candidate. A Hub that does not host agent registration at all (no agent
// secret configured: the embedded business tests driving a scripted TEE)
// schedules over the static market table instead, where every listed provider
// is treated as supply.
//
// The distinction matters on disconnect: an agent that goes offline takes its
// listing with it, and its provider stops being a candidate at any price — not
// even the platform default. Falling back to the market table whenever no agent
// happened to be online would keep routing jobs to a tunnel nobody is holding.
//
// An agent may additionally declare which models its upstream can serve (see
// AgentRegister.Models). That declaration is a soft capability hint, not a
// gate: an agent that declared nothing serves any model and stays a candidate;
// an agent that declared a list the requested model is not in is skipped, since
// sending it the job would only buy an upstream refusal. When the model is in
// no online agent's list at all, the request is refused with
// ErrNoProviderForModel rather than fired at every provider hoping one answers.
//
// The effective book price is per-request plus any per-model surcharge plus a
// floor of one mebibyte of the volume rate, taken from the agent's own card
// when it declared one and the platform default otherwise. Volume pricing is
// deliberately left out of the *forecast* — the Hub cannot know how large a
// response will be before it runs the job, so an order that depended on the
// final size would be non-deterministic. The floor is not a forecast: billing
// rounds volume up to whole mebibytes, so the smallest non-empty exchange
// already bills one unit of the volume rate. Folding that floor in is what
// keeps a seller from hiding its cost behind a zero per-request price (see
// bookPrice).
//
// An unlisted model pays no premium under a rate card, so every candidate is
// still priced. The card's numbers, not the Hub's opinion, decide the order.
func (h *Hub) providersForModel(model string) []string {
	var providers []string
	if !h.agentsEnabled() {
		// No agent gate on this Hub: the market table is the supply.
		providers = make([]string, 0, len(h.rates))
		for provider := range h.rates {
			providers = append(providers, provider)
		}
	} else {
		// Supply is the agents holding a tunnel open right now that can serve
		// this model (an agent that declared no models serves everything).
		online := h.agents.onlineProviders()
		providers = make([]string, 0, len(online))
		for _, provider := range online {
			if conn, ok := h.agents.conn(provider); ok && conn.serves(model) {
				providers = append(providers, provider)
			}
		}
	}
	// Price every candidate once, dropping any whose floor book price already
	// exceeds the Hub's per-job ceiling: no job within the ceiling can be
	// settled against it, so dispatching to it would only buy a refusal at
	// settlement.
	priced := make(map[string]uint64, len(providers))
	kept := make([]string, 0, len(providers))
	for _, provider := range providers {
		price, ok := h.bookPrice(provider, model)
		if !ok {
			// No card at all: unpriceable, so it sorts last and is only ever
			// reached after every priced candidate (Execute then refuses it as
			// an unknown provider).
			price = ^uint64(0)
		} else if h.maxJob > 0 && price > h.maxJob {
			continue
		}
		priced[provider] = price
		kept = append(kept, provider)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		pi, pj := priced[kept[i]], priced[kept[j]]
		if pi != pj {
			return pi < pj
		}
		return kept[i] < kept[j]
	})
	return kept
}

// bookPrice returns a provider's per-job book price for a model: the
// per-request rate, plus any model surcharge, plus one mebibyte of the volume
// rate. ok is false when the provider has no card at all.
//
// The volume floor is deliberate and load-bearing. A scheduler keyed on the
// per-request rate alone can be gamed: a seller advertises a zero (or trivial)
// per-request price, hides an enormous per-megabyte rate behind it, wins every
// auction on the headline number, and only then does the buyer discover the
// bill. Billing rounds volume up to whole mebibytes, so the smallest non-empty
// exchange already bills one unit of the volume rate; folding exactly that
// floor into the book price puts the volume rate back into the number the
// scheduler orders by and the number the buyer is shown. A card that charges a
// lot per megabyte then looks expensive where the choice is made. It is a
// floor, not a forecast — the charge itself still comes from Price over the
// bytes actually delivered — so it can only ever make a provider look *more*
// expensive than a real tiny job would be, never less. Understating a price is
// the vulnerability; overstating it is merely conservative.
//
// It is the single price source for both the scheduler's candidate order and
// the buyer-facing directory, so the price a buyer sees is the price the
// scheduler would dispatch on.
func (h *Hub) bookPrice(provider, model string) (uint64, bool) {
	card, ok := h.card(provider)
	if !ok {
		return 0, false
	}
	book, ok := addChecked(card.PerRequestMicros, card.Premium(model))
	if !ok {
		return 0, false
	}
	return addChecked(book, card.PerMegabyteMicros)
}

// ModelQuote is one row of the buyer-facing model directory: a model an online
// agent declared it can serve, priced at the lowest per-request book price
// among its current candidates.
type ModelQuote struct {
	// Model is the model ID (as declared by the serving agents).
	Model string `json:"model"`
	// Provider is the cheapest candidate currently serving the model.
	Provider string `json:"provider"`
	// PriceMicros is that provider's book price for the model: the per-request
	// rate, plus any model surcharge, plus one mebibyte of the volume rate. The
	// volume term is the minimum a non-empty exchange bills, so the number is
	// never smaller than what the cheapest possible job would cost — see
	// bookPrice.
	PriceMicros uint64 `json:"price_micros"`
}

// ModelDirectory lists every model an online agent has declared it can serve,
// each with the lowest price a buyer would currently pay for it. It is the
// market's answer to "what can I buy, and what does it cost" — computed
// entirely from the Hub's in-memory supply, with no probe of any provider.
//
// A Hub without an agent gate has no declarations to list, so it returns
// nothing regardless of its market table.
func (h *Hub) ModelDirectory() []ModelQuote {
	return h.SearchModels("")
}

// MarketQuotes returns the expanded buyer-facing market view: every model every
// online agent declares, each with the price its provider charges. Unlike the
// model-aggregated SearchModels directory, the same model served by two
// providers appears as two rows — the source matters to a buyer who wants to
// pick not just the cheapest but the *provider* of a model, or to survey what a
// particular source offers.
//
// provider, when non-empty, narrows the view to one provider; model, when
// non-empty, narrows it by a case-insensitive substring of the model ID. Both
// may be set: one provider's quote for a matching model family. Rows are sorted
// by provider then model, so the view is a pure function of supply.
func (h *Hub) MarketQuotes(provider, model string) []ModelQuote {
	if !h.agentsEnabled() {
		return nil
	}
	model = strings.ToLower(model)
	var quotes []ModelQuote
	for _, p := range h.agents.onlineProviders() {
		if provider != "" && p != provider {
			continue
		}
		conn, ok := h.agents.conn(p)
		if !ok {
			continue
		}
		for _, m := range conn.models {
			if m == "" || (model != "" && !strings.Contains(strings.ToLower(m), model)) {
				continue
			}
			price, ok := h.bookPrice(p, m)
			if !ok {
				continue
			}
			quotes = append(quotes, ModelQuote{Model: m, Provider: p, PriceMicros: price})
		}
	}
	sort.Slice(quotes, func(i, j int) bool {
		if quotes[i].Provider != quotes[j].Provider {
			return quotes[i].Provider < quotes[j].Provider
		}
		return quotes[i].Model < quotes[j].Model
	})
	return quotes
}

// SearchModels filters the model directory by name: a case-insensitive
// substring match, so a buyer can search by an exact model ID ("gpt-4o") or by
// a prefix or fragment ("deepseek" matches both "deepseek-pro" and
// "deepseek-flash"). An empty query returns the whole directory.
//
// This is the model-aggregated view: each model appears once, at the lowest
// price any source charges for it. A buyer who wants to see every source of a
// model or every model of one source uses MarketQuotes instead.
func (h *Hub) SearchModels(query string) []ModelQuote {
	seen := make(map[string]struct{})
	for _, p := range h.agents.onlineProviders() {
		conn, ok := h.agents.conn(p)
		if !ok {
			continue
		}
		for _, m := range conn.models {
			if m != "" {
				seen[m] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}

	query = strings.ToLower(query)
	quotes := make([]ModelQuote, 0, len(seen))
	for model := range seen {
		if query != "" && !strings.Contains(strings.ToLower(model), query) {
			continue
		}
		candidates := h.providersForModel(model)
		if len(candidates) == 0 {
			continue
		}
		cheapest := candidates[0]
		price, _ := h.bookPrice(cheapest, model)
		quotes = append(quotes, ModelQuote{
			Model:       model,
			Provider:    cheapest,
			PriceMicros: price,
		})
	}
	sort.Slice(quotes, func(i, j int) bool { return quotes[i].Model < quotes[j].Model })
	return quotes
}

// ExecuteForModel runs a job for a model, dispatching to the cheapest provider
// that can serve it and falling back to the next cheapest on failure.
//
// A provider counts as serving the model when the job completes billably — a
// completed 2xx receipt. A cheaper provider that errors (refused, transport
// failure, provider fault, or a non-billable receipt) hands the job to the next
// candidate. If none serves the model billably, the outcome of the last attempt
// is returned: the Hub still has to be able to show what it received, and the
// receipt store records every attempt so no credential use is ever invisible.
//
// Fallback stops the moment the response is committed to a provider — either
// its response start has been relayed (the caller has already written that
// provider's status and headers), its first body byte has, or the attempt
// earned anything at all. Once the user has seen content from provider A,
// switching to provider B would splice two providers' transcripts into one
// response — a stream no client could parse and no receipt would cover — and
// switching after a positively priced attempt would bill the buyer twice for
// one answer. A provider that fails after committing is therefore final: its
// (truncated) outcome is returned as-is, and the caller reports what it got
// rather than silently switching horses mid-response.
//
// build produces the job spec for a given provider: the Hub decides who to ask,
// but the caller supplies how to phrase the ask (host, headers, body binding)
// once, since that framing is identical across providers.
func (h *Hub) ExecuteForModel(ctx context.Context, tenant, model string, body []byte,
	build func(provider string) (jobs.Spec, error), onChunk func([]byte) error, onStart ...func(tee.Response)) (Outcome, error) {

	providers, err := h.candidatesForModel(model, "")
	if err != nil {
		return Outcome{}, err
	}
	return h.executeForProviders(ctx, tenant, model, providers, body, build, onChunk, onStart...)
}

// candidatesForModel resolves who may serve a job for a model: every current
// server, cheapest floor first, or the single named source when the buyer pinned
// one. A pinned request is never substituted — the buyer asked for that source,
// and routing it elsewhere would silently override the choice — so a pin is
// resolved or refused.
//
// It is the one place either plane decides who is a candidate, so a request and
// a streaming session dispatch from the same supply under the same rules.
func (h *Hub) candidatesForModel(model, provider string) ([]string, error) {
	if provider != "" {
		if !h.providerServes(provider, model) {
			return nil, fmt.Errorf("%w: model %q from provider %q", ErrNoProviderForModel, model, provider)
		}
		return []string{provider}, nil
	}
	providers := h.providersForModel(model)
	if len(providers) == 0 {
		return nil, h.supplyError(model)
	}
	return providers, nil
}

// ExecuteForProvider runs a job for a model pinned to one named source, with no
// fallback to another provider. It answers the buyer who asks for a specific
// AI source by name — through a route's optional "provider" field — and must be
// honored exactly: routing a pinned job to a different provider would silently
// override the buyer's choice of source.
//
// The named provider must be a current server of the model; otherwise the job
// is refused before dispatch (ErrNoProviderForModel), never fired elsewhere. A
// provider that fails after committing is final, exactly as in ExecuteForModel:
// splicing in a second provider's bytes would corrupt the reply and double-bill.
func (h *Hub) ExecuteForProvider(ctx context.Context, tenant, model, provider string, body []byte,
	build func(provider string) (jobs.Spec, error), onChunk func([]byte) error, onStart ...func(tee.Response)) (Outcome, error) {

	providers, err := h.candidatesForModel(model, provider)
	if err != nil {
		return Outcome{}, err
	}
	return h.executeForProviders(ctx, tenant, model, providers, body, build, onChunk, onStart...)
}

// executeForProviders is the shared workhorse behind ExecuteForModel and
// ExecuteForProvider: run a job against an explicit, price-ordered candidate
// list, falling back down it for a model-based dispatch (the list holds every
// server, cheapest first. For a provider-pinned dispatch the list holds the one
// named source, so the fallback loop is exactly "try it once".
func (h *Hub) executeForProviders(ctx context.Context, tenant, model string, providers []string, body []byte,
	build func(provider string) (jobs.Spec, error), onChunk func([]byte) error, onStart ...func(tee.Response)) (Outcome, error) {

	var (
		last    Outcome
		err     error
		ran     bool
		relayed bool
	)
	// Count the bytes that reached the user. The relayed flag is what tells the
	// fallback loop that the response is already committed to a provider.
	relay := onChunk
	if relay != nil {
		relay = func(chunk []byte) error {
			if len(chunk) > 0 {
				relayed = true
			}
			return onChunk(chunk)
		}
	}
	// A relayed response start commits the exchange exactly as a body byte
	// does: the caller has already written that provider's status and headers
	// by the time onStart returns, so falling back would splice the next
	// provider's bytes under the first provider's response. A provider whose
	// start was shown but whose body never came is therefore committed to.
	start := onStart
	if len(start) > 0 && start[0] != nil {
		cb := start[0]
		start = []func(tee.Response){func(resp tee.Response) {
			relayed = true
			cb(resp)
		}}
	}

	for _, provider := range providers {
		spec, berr := build(provider)
		if berr != nil {
			return Outcome{}, fmt.Errorf("build spec for %q: %w", provider, berr)
		}
		ran = true
		last, err = h.Execute(ctx, tenant, model, spec, body, relay, start...)
		if err != nil {
			if relayed {
				// This provider's start or bytes already reached the user. There
				// is no honest way to continue with another provider: return the
				// attempt's outcome as final.
				return last, err
			}
			if errors.Is(err, ErrJobPriceExceeded) {
				// The Hub's own per-job ceiling refused the price. Candidates
				// are tried cheapest floor-first and the ceiling is a property
				// of the Hub, not of a provider, so a more expensive candidate
				// cannot help — the refusal is final.
				return last, err
			}
			continue
		}
		if Billable(last.Receipt.Receipt) {
			return last, nil
		}
		// Completed but not billable. A truncated attempt that delivered bytes
		// still priced above zero and was settled inside Execute; paying the
		// next provider too would bill the buyer twice, so any positively
		// priced outcome is final. This matters when the caller passed no
		// callbacks — with callbacks, the relayed check below catches it.
		if last.Charged > 0 {
			return last, nil
		}
		// Nothing was paid and nothing reached the user — a provider that
		// declined or errored. Try the next candidate.
		if relayed {
			return last, nil
		}
	}
	if !ran {
		return Outcome{}, h.supplyError(model)
	}
	return last, err
}

// providerServes reports whether a named provider is a current server of a
// model: with an agent gate, the provider must hold an online tunnel that
// declares the model (or declares nothing, which serves anything); without one,
// it must be listed on the market table. It is the pinned counterpart of the
// candidate list providersForModel builds.
func (h *Hub) providerServes(provider, model string) bool {
	if !h.agentsEnabled() {
		_, ok := h.rates[provider]
		return ok
	}
	conn, ok := h.agents.conn(provider)
	return ok && conn.serves(model)
}
