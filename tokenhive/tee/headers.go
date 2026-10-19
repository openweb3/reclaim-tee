// Response-header policy for the Hub↔TEE seam.
//
// The TEE forwards a small, fixed allowlist of upstream response headers to the
// Hub in the start frame (see rpc.go), and the signed receipt binds exactly
// that forwarded set (proof.Receipt.ResponseHeadersHash). Two things follow
// from the list being the contract:
//
//   - The Hub may act on a header only if the TEE relayed it, and the receipt
//     proves the relayed set — a header that is not on this list is invisible
//     to the Hub and cannot be passed through or acted on.
//   - The list is deliberately short. Every entry is a header a buyer-facing
//     Hub legitimately needs to shape the response (content type, retry
//     timing, credential health) and that cannot leak anything the seller did
//     not already expose to its own clients. Anything else stays inside the
//     TEE.
package tee

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
)

// AllowedResponseHeaders is the set of upstream response header names (matched
// case-insensitively) the TEE relays to the Hub. The set is exact: no
// wildcards, no open-ended families, so what the receipt can attest is always
// precisely what the Hub can be shown.
var AllowedResponseHeaders = map[string]struct{}{
	// Content-Type is what lets the Hub tell a streaming SSE success from a
	// JSON error body before the first byte is relayed.
	"content-type": {},
	// Cache-Control governs whether an intermediary may buffer the stream.
	"cache-control": {},
	// Retry-After is the standard signal on a 429/503: the Hub needs it to
	// apply its rate-limit rules and to pass a retry hint to the buyer.
	"retry-after": {},
	// WWW-Authenticate on a 401 tells the Hub the credential really is the
	// problem (vs. an application-level refusal), which is what triggers
	// credential-invalid handling.
	"www-authenticate": {},
	// Request IDs let the buyer and the Hub correlate with the provider's own
	// diagnostics. OpenAI uses x-request-id; Anthropic uses request-id.
	"x-request-id": {},
	"request-id":   {},
	// OpenAI's processing metadata.
	"openai-organization":  {},
	"openai-processing-ms": {},
	"openai-version":       {},
	// Rate-limit state, OpenAI shape.
	"x-ratelimit-limit-requests":     {},
	"x-ratelimit-remaining-requests": {},
	"x-ratelimit-reset-requests":     {},
	"x-ratelimit-limit-tokens":       {},
	"x-ratelimit-remaining-tokens":   {},
	"x-ratelimit-reset-tokens":       {},
	// Rate-limit state, Anthropic shape.
	"anthropic-ratelimit-requests-limit":          {},
	"anthropic-ratelimit-requests-remaining":      {},
	"anthropic-ratelimit-requests-reset":          {},
	"anthropic-ratelimit-input-tokens-limit":      {},
	"anthropic-ratelimit-input-tokens-remaining":  {},
	"anthropic-ratelimit-input-tokens-reset":      {},
	"anthropic-ratelimit-output-tokens-limit":     {},
	"anthropic-ratelimit-output-tokens-remaining": {},
	"anthropic-ratelimit-output-tokens-reset":     {},
	// The ChatGPT subscription endpoint's request IDs, the ones its operators
	// ask for: x-request-id is not what chatgpt.com sends.
	"x-oai-request-id": {},
	"cf-ray":           {},
	// What the Codex client reads off a subscription response, so a buyer's
	// Codex behaves as it does signed in to the subscription. The quota and
	// credit headers that endpoint also sends describe the seller's account,
	// not the buyer's, and stay inside the TEE.
	//
	// x-codex-turn-state is a sticky-routing token Codex echoes on the next
	// request of the turn.
	"x-codex-turn-state": {},
	// x-models-etag tells Codex its model catalog changed and to refresh it.
	"x-models-etag": {},
	// x-reasoning-included says the response already counts reasoning, which
	// Codex uses to account its context and decide when to compact.
	"x-reasoning-included": {},
	// openai-model names the model that actually served the request, so Codex
	// can warn when it differs from the one asked for.
	"openai-model": {},
	// The safety-buffering pair tells Codex the response is being held back
	// for review, and which faster model it may suggest instead.
	"x-codex-safety-buffering-enabled":      {},
	"x-codex-safety-buffering-faster-model": {},
}

// ForwardResponseHeaders filters a transport's full upstream header set down
// to the allowlist. The returned map is a copy, so the transport's own map is
// never mutated. Names keep their original casing (net/http canonicalises
// them); the digest in HashResponseHeaders normalises case.
//
// Content-Length is deliberately absent from the allowlist: the Hub may
// truncate or extend a stream ([DONE] terminators, error frames), so a
// forwarded Content-Length would lie about the bytes the buyer actually
// receives.
func ForwardResponseHeaders(src map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for name, values := range src {
		if _, ok := AllowedResponseHeaders[strings.ToLower(name)]; !ok {
			continue
		}
		out[name] = values
	}
	return out
}

// HashResponseHeaders digests a forwarded header set for the receipt: sha256
// over the canonical JSON of the set with names lowercased and sorted. Both
// sides of the seam compute it the same way — the TEE when signing the
// receipt, the Hub when checking that the start frame it acted on is the
// exchange the receipt attests.
//
// JSON is the canonical form here (not CBOR): it sorts map keys and preserves
// value order, and it is exactly the encoding the start frame carries on the
// wire, so the Hub can hash the frame it parsed.
func HashResponseHeaders(h map[string][]string) [32]byte {
	norm := make(map[string][]string, len(h))
	for name, values := range h {
		norm[strings.ToLower(name)] = values
	}
	// encoding/json sorts map keys deterministically and cannot fail on
	// strings; the digest is therefore a pure function of the header set.
	encoded, _ := json.Marshal(norm)
	return sha256.Sum256(encoded)
}
