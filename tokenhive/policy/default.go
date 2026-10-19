package policy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
)

// The validity window stamped on the shipped whitelist. It is deliberately not
// in the document: a date is not a rule, and both values are load-bearing in
// ways a per-deployment file should not be able to get wrong.
//
// NoExpiry is the ExpiresAt. The deployment whitelist is scaffolding every
// seller onboards against, not a rotating per-seller grant, so its window is
// left effectively open: a lapsed whitelist would turn every seller
// unserviceable the moment the clock crossed it, and nothing would say so until
// a job was refused. Replacing it is a redeploy, not a runtime event; the
// calendar simply never forces one. MaxInt64 seconds since the epoch is ~292
// billion years, and ValidateAt only requires ExpiresAt > IssuedAt, so this
// never trips ErrPolicyExpired.
//
// NoIssueDate is the IssuedAt. A constant rather than the build clock, because
// these bytes are measured: a document that changed on every build would move
// SNP_APP_HASH with no code change and leave the artifact irreproducible. The
// field only needs to be a positive instant before the (open) expiry, and 1
// says exactly what is true — no issue date applies. Regenerating the whitelist
// is therefore a no-op until the document itself changes, which is what lets a
// build re-emit it every time instead of freezing a stale copy.
const (
	NoIssueDate = int64(1)
	NoExpiry    = int64(math.MaxInt64)
)

// defaultWhitelist is the deployment whitelist this build ships: the document
// in whitelist.json, next to this file.
//
// It is embedded rather than read from disk so that every path that needs it —
// -emit-policy-dir, the simulation's fixture writer — works from any working
// directory and cannot pick up a different file by accident. The document's
// bytes are what the attestation covers, so the only way to change what a
// deployment enforces is to change this file and rebuild, which is the point.
//
//go:embed whitelist.json
var defaultWhitelist []byte

// Default returns the deployment whitelist this build ships: the document in
// whitelist.json, plus the open-ended validity window above.
//
// The document carries the rules — which hosts the enclave may reach, which
// request families on them, and the bounds a job must stay inside. Hosts name
// the upstreams the deployment is willing to reach: the two AI vendors' API
// endpoints, the ChatGPT subscription endpoint a logged-in account speaks to,
// and the mock host the simulation runs every shape behind. Its paths mirror
// the Hub's user-facing routes: the OpenAI chat completions endpoint, the
// OpenAI Responses endpoint, the Anthropic messages endpoint, the ChatGPT
// subscription endpoint and the Codex model catalog beside it, and the
// streaming-session endpoint. In a real
// deployment those live on api.openai.com, api.anthropic.com and chatgpt.com;
// the simulation serves every shape from one mock host, so one whitelist covers
// them all.
//
// The window is stamped here rather than written into the document, because it
// is policy about every whitelist this codebase ships, not something a
// deployment chooses.
//
// Unknown keys are an error. A misspelled field would otherwise be dropped in
// silence, and the deployment would enforce less than its own file says it
// does — the one failure a whitelist must not have.
func Default() (Policy, error) {
	return fromDocument(defaultWhitelist)
}

// fromDocument parses a whitelist document and stamps the validity window on
// it. Split out from Default so a test can drive it with a modified document
// rather than with the shipped one.
func fromDocument(doc []byte) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse whitelist document: %w", err)
	}

	p.IssuedAt, p.ExpiresAt = NoIssueDate, NoExpiry

	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("whitelist document: %w", err)
	}
	return p, nil
}
