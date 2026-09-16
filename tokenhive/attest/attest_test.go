package attest

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	sevsnpverify "github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/sevsnp/verify"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform/simulated"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// makeSigner returns a signer bound to a fresh simulated epoch, plus the epoch's
// public identity for populating an evidence cache.
func makeSigner(t *testing.T, bound [32]byte) (*proof.Signer, platform.Identity) {
	t.Helper()
	var e platform.Epoch
	var err error
	if bound != [32]byte{} {
		e, err = simulated.NewDeploymentEpoch(bound)
	} else {
		e, err = simulated.NewEpoch()
	}
	if err != nil {
		t.Fatalf("new epoch: %v", err)
	}
	return proof.NewSigner(e), e.Identity()
}

// makeReceipt signs a minimal-but-structurally-valid receipt so the signature
// and structural checks in Check run against a real receipt.
func makeReceipt(t *testing.T, signer interface {
	Sign(receipt proof.Receipt) (proof.SignedReceipt, error)
}) proof.SignedReceipt {
	t.Helper()
	jobID := make([]byte, proof.JobIDLength)
	_, _ = rand.Read(jobID)
	specHash := make([]byte, proof.JobSpecHashLength)
	streamHash := make([]byte, proof.StreamHashLength)
	now := time.Now().Unix()
	receipt := proof.Receipt{
		Version:       proof.VersionV1,
		JobID:         jobID,
		JobSpecHash:   specHash,
		Provider:      "openai-sim",
		Method:        "POST",
		Host:          "127.0.0.1:18080",
		Path:          "/v1/chat/completions",
		StatusCode:    200,
		StreamHash:    streamHash,
		ChunkCount:    1,
		ResponseBytes: 0,
		Completion:    proof.CompletionComplete,
		StartedAt:     now,
		FinishedAt:    now,
		RequestBytes:  0,
		ProviderSeq:   1,
	}
	signed, err := signer.Sign(receipt)
	if err != nil {
		t.Fatalf("sign receipt: %v", err)
	}
	return signed
}

func defaultConfig(t *testing.T, fetcher Fetcher, policyHash [32]byte) *Verifier {
	t.Helper()
	cfg := Config{
		AllowedPlatforms: []string{simulated.Platform},
		ByPlatform:       map[string]platform.EvidenceVerifier{simulated.Platform: simulated.Verifier{}},
		Fetcher:          fetcher,
		PolicySetHash:    policyHash,
	}
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return v
}

func TestAllowlistRefusesDisallowedPlatform(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	// A trust root that accepts only the real AWS SEV-SNP platform must refuse
	// a simulated receipt, even though the simulated verifier is registered.
	v, err := New(Config{
		AllowedPlatforms: []string{platform.PlatformAWSSEVSNP},
		ByPlatform: map[string]platform.EvidenceVerifier{
			simulated.Platform:         simulated.Verifier{},
			platform.PlatformAWSSEVSNP: sevsnpverify.Verifier{},
		},
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.Check(signed); !errors.Is(err, proof.ErrPlatformNotAllowed) {
		t.Fatalf("Check = %v, want ErrPlatformNotAllowed", err)
	}
}

func TestNewRejectsEmptyAllowlist(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted an empty AllowedPlatforms")
	}
}

func TestNewRejectsAllowedPlatformWithoutVerifier(t *testing.T) {
	_, err := New(Config{
		AllowedPlatforms: []string{"aws-sev-snp"},
		ByPlatform:       map[string]platform.EvidenceVerifier{},
	})
	if err == nil {
		t.Fatal("New accepted an allowed platform with no verifier")
	}
}

func TestInlineEvidenceVerifies(t *testing.T) {
	// IncludeEvidence=true signs a self-contained receipt; with no Fetcher the
	// verifier must demand inline evidence and accept the sim trust root.
	signer, _ := makeSigner(t, [32]byte{})
	signer.IncludeEvidence = true
	signed := makeReceipt(t, signer)

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); err != nil {
		t.Fatalf("Check(tampered) = %v, want nil", err)
	}
}

func TestInlineEvidenceTamperedFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signer.IncludeEvidence = true
	signed := makeReceipt(t, signer)
	// Flip one byte in the receipt body — signature must no longer verify.
	signed.Receipt.ResponseBytes++

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); err == nil {
		t.Fatal("Check accepted a tampered receipt")
	}
}

func TestHashOnlyReceiptResolvesViaCache(t *testing.T) {
	signer, identity := makeSigner(t, [32]byte{})
	// A small, hash-only receipt (IncludeEvidence=false is the Signer default).
	signed := makeReceipt(t, signer)
	if len(signed.Receipt.Attestation.Evidence) != 0 {
		t.Fatal("expected a hash-only receipt")
	}

	// The verifier's cache is populated with the TEE identity it saw online.
	cache := &Cache{}
	cache.Put(identity)

	v := defaultConfig(t, cache, [32]byte{})
	if err := v.Check(signed); err != nil {
		t.Fatalf("Check(hash-only) = %v, want nil", err)
	}
}

func TestHashOnlyReceiptWithoutFetcherFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	v := defaultConfig(t, nil, [32]byte{})
	if err := v.Check(signed); !errors.Is(err, proof.ErrEvidenceRequired) {
		t.Fatalf("Check = %v, want ErrEvidenceRequired", err)
	}
}

func TestCacheKeyedByPlatformAndAppAndHash(t *testing.T) {
	cache := &Cache{}
	cache.Put(platform.Identity{
		Platform:      simulated.Platform,
		ApplicationID: simulated.ApplicationID,
		Evidence:      []byte("evidence-bytes"),
		EvidenceHash:  sha256Of([]byte("evidence-bytes")),
	})
	got, err := cache.Fetch(context.Background(), platform.Identity{
		Platform:      simulated.Platform,
		ApplicationID: simulated.ApplicationID,
		EvidenceHash:  sha256Of([]byte("evidence-bytes")),
	})
	if err != nil {
		t.Fatalf("Fetch = %v", err)
	}
	if string(got) != "evidence-bytes" {
		t.Fatalf("Fetch = %q, want evidence-bytes", got)
	}
	// A different application ID must miss.
	if _, err := cache.Fetch(context.Background(), platform.Identity{
		Platform:      simulated.Platform,
		ApplicationID: "other-app",
		EvidenceHash:  sha256Of([]byte("evidence-bytes")),
	}); err == nil {
		t.Fatal("Fetch hit for a different application ID")
	}
}

func TestWrongEvidenceFromFetcherFails(t *testing.T) {
	signer, _ := makeSigner(t, [32]byte{})
	signed := makeReceipt(t, signer)

	// A fetcher that returns bytes whose hash does not match the receipt's
	// EvidenceHash must be refused by the simulated platform's evidence check.
	v := defaultConfig(t, FuncFetcher(func(ctx context.Context, id platform.Identity) ([]byte, error) {
		return []byte("wrong-evidence"), nil
	}), [32]byte{})
	if err := v.Check(signed); err == nil {
		t.Fatal("Check accepted evidence with a hash mismatch")
	}
}

func TestDeploymentBindingEnforced(t *testing.T) {
	policyHash := sha256Of([]byte("deployment-policy-set"))

	cfg := Config{
		AllowedPlatforms: []string{simulated.Platform},
		ByPlatform:       map[string]platform.EvidenceVerifier{simulated.Platform: simulated.Verifier{}},
		PolicySetHash:    policyHash,
	}
	deployVer, err := New(cfg)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// Enclave configured with the expected policy set: binds cleanly.
	boundSigner, _ := makeSigner(t, policyHash)
	boundSigner.IncludeEvidence = true // self-contained, no Fetcher dependency
	if err := deployVer.Check(makeReceipt(t, boundSigner)); err != nil {
		t.Fatalf("Check(deployment-bound, matching) = %v, want nil", err)
	}

	// Same enclave image but an epoch never bound to a policy set must be
	// refused, because its evidence cannot show the required configuration.
	looseSigner, _ := makeSigner(t, [32]byte{})
	looseSigner.IncludeEvidence = true
	if err := deployVer.Check(makeReceipt(t, looseSigner)); err == nil {
		t.Fatal("Check accepted an unbound receipt against a deployment-bound verifier")
	}
}

func sha256Of(b []byte) [32]byte { return sha256Sum(b) }
