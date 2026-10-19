package policy

import (
	"bytes"
	"encoding/json"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"testing"
	"time"
)

// TestDefaultWhitelistIsTheDocument pins that the shipped whitelist is the file
// in this package and nothing else: the rules come from whitelist.json, and the
// validity window — the one part of a policy that is not a rule — is stamped by
// the loader rather than written into the document.
func TestDefaultWhitelistIsTheDocument(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if p.Version != VersionV1 {
		t.Errorf("version = %d, want %d", p.Version, VersionV1)
	}
	if len(p.Hosts) == 0 || len(p.Rules) == 0 {
		t.Fatalf("the shipped document describes no reachable upstream: %d hosts, %d rules", len(p.Hosts), len(p.Rules))
	}
	if p.IssuedAt != NoIssueDate || p.ExpiresAt != NoExpiry {
		t.Errorf("window = (%d, %d), want (%d, %d)", p.IssuedAt, p.ExpiresAt, NoIssueDate, NoExpiry)
	}

	// The document must not carry the window. A file that set its own IssuedAt
	// would move SNP_APP_HASH on every edit — including edits that changed
	// nothing — and one that set a finite ExpiresAt would start refusing every
	// job one day, with the file still looking correct.
	var raw Policy
	if err := json.Unmarshal(defaultWhitelist, &raw); err != nil {
		t.Fatalf("whitelist.json: %v", err)
	}
	if raw.IssuedAt != 0 || raw.ExpiresAt != 0 {
		t.Errorf("whitelist.json carries a validity window (%d, %d); the loader stamps it",
			raw.IssuedAt, raw.ExpiresAt)
	}
}

// TestWhitelistDocumentRejectsUnknownKeys pins the one failure a whitelist must
// not have: a misspelled key dropping a rule in silence, leaving the deployment
// enforcing less than its own file says it does.
func TestWhitelistDocumentRejectsUnknownKeys(t *testing.T) {
	docs := []string{
		// "allow_streamd": the rule is not the one the file describes.
		`{"version":1,"hosts":["api.openai.com"],"rules":[{"methods":["POST"],"path":"/v1/responses","allow_streamd":true}],"limits":{}}`,
		// "host" instead of "hosts": the whitelist would admit nobody.
		`{"version":1,"host":"api.openai.com","hosts":["api.openai.com"],"rules":[{"methods":["POST"],"path":"/v1/responses"}],"limits":{}}`,
	}
	for _, doc := range docs {
		if _, err := fromDocument([]byte(doc)); err == nil {
			t.Errorf("a document with an unknown key was accepted:\n%s", doc)
		}
	}
}

// TestWhitelistDocumentSetsEveryField pins that every field of a policy has a
// configuration key and that the key reaches the field. A field the document
// cannot set is a rule a deployment cannot state; a key that misses its field
// is a rule the deployment states and does not get, which is why this compares
// the canonical encoding rather than a handful of fields.
func TestWhitelistDocumentSetsEveryField(t *testing.T) {
	const doc = `{
	  "version": 1,
	  "hosts": ["api.openai.com", "chatgpt.com"],
	  "rules": [
	    {"methods": ["POST"], "path": "/v1/responses", "allow_stream": true, "query_keys": ["fault"]},
	    {"methods": ["GET"], "path": "/v1/realtime", "allow_stream": true, "allow_any_query": true}
	  ],
	  "limits": {"max_response_bytes": 2048, "max_body_bytes": 1024, "allowed_headers": ["Content-Type"]}
	}`

	got, err := fromDocument([]byte(doc))
	if err != nil {
		t.Fatalf("fromDocument: %v", err)
	}
	want := Policy{
		Version: VersionV1,
		Hosts:   []string{"api.openai.com", "chatgpt.com"},
		Rules: []Rule{
			{Methods: []string{"POST"}, Path: "/v1/responses", AllowStream: true, QueryKeys: []string{"fault"}},
			{Methods: []string{"GET"}, Path: "/v1/realtime", AllowStream: true, AllowAnyQuery: true},
		},
		Limits:    Limits{MaxResponseBytes: 2048, MaxBodyBytes: 1024, AllowedHeaders: []string{"Content-Type"}},
		IssuedAt:  NoIssueDate,
		ExpiresAt: NoExpiry,
	}

	gotEnc, err := got.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode got: %v", err)
	}
	wantEnc, err := want.EncodeCanonical()
	if err != nil {
		t.Fatalf("encode want: %v", err)
	}
	if !bytes.Equal(gotEnc, wantEnc) {
		t.Fatalf("the document did not map onto the policy it describes:\ngot  %+v\nwant %+v", got, want)
	}
}

// TestDefaultWhitelistIsReproducible pins that the shipped whitelist is a
// function of its document alone. Its bytes are measured, so a document that
// changed on every load would move SNP_APP_HASH with no change to the file,
// leaving the attestation unreproducible and the image unverifiable — the shape
// of bug that a build-clock IssuedAt would reintroduce.
func TestDefaultWhitelistIsReproducible(t *testing.T) {
	first, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	second, err := Default()
	if err != nil {
		t.Fatalf("Default again: %v", err)
	}

	firstHash, err := first.Hash()
	if err != nil {
		t.Fatalf("hash first: %v", err)
	}
	secondHash, err := second.Hash()
	if err != nil {
		t.Fatalf("hash second: %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("the shipped whitelist is not reproducible: %x vs %x", firstHash, secondHash)
	}
}

// TestDefaultWhitelistAdmitsTheCodexModelCatalog pins the one GET the
// subscription endpoint answers outside inference: the model catalog for a
// Codex release, asked for by client_version and nothing else.
func TestDefaultWhitelistAdmitsTheCodexModelCatalog(t *testing.T) {
	p, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	now := time.Now()
	spec := jobs.Spec{
		Version:          jobs.VersionV1,
		JobID:            make([]byte, jobs.JobIDLength),
		Provider:         "openai",
		Method:           "GET",
		Host:             "chatgpt.com:443",
		Path:             "/backend-api/codex/models",
		Query:            "client_version=0.163.0",
		Headers:          map[string]string{"accept": "application/json", "chatgpt-account-id": "account", "originator": "codex_cli_rs", "user-agent": "codex_cli_rs/0.163.0"},
		BodyHash:         bodyHash(""),
		Nonce:            make([]byte, jobs.MinNonceLength),
		ExpiresAt:        now.Unix() + 60,
		MaxResponseBytes: 1 << 20,
	}
	if _, err := p.AuthorizeAt(spec, now); err != nil {
		t.Fatalf("the Codex model catalog was refused: %v", err)
	}
	spec.Query = "client_version=0.163.0&limit=1"
	if _, err := p.AuthorizeAt(spec, now); err == nil {
		t.Fatal("a catalog query with an unlisted key was admitted")
	}
	spec.Query, spec.Stream = "client_version=0.163.0", true
	if _, err := p.AuthorizeAt(spec, now); err == nil {
		t.Fatal("the catalog was admitted as a stream")
	}
}
