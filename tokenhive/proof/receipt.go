// Package proof defines the TokenHive execution receipt: the signed statement a
// TEE emits after running a job, binding what was requested to what actually
// came back from the provider.
//
// A receipt is only meaningful together with an attestation. The signature
// proves an attested key produced it; the attestation proves that key never
// existed outside the enclave that ran the job. Verifiers must check both.
package proof

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

const (
	// VersionV1 is the only receipt version the verifier accepts.
	VersionV1 = 1

	// ReceiptSigningDomain separates receipt signatures from every other
	// signature the TokenHive stack produces.
	ReceiptSigningDomain = "TokenHive.ExecutionReceipt.v1"

	JobIDLength          = 16
	JobSpecHashLength    = 32
	StreamHashLength     = 32
	EvidenceHashLength   = 32
	PolicyHashLength     = 32
	MaxApplicationIDSize = 256
)

// CompletionState tells the verifier whether the response is whole.
//
// A truncated or failed response is still worth signing: the receipt then
// attests that the provider stopped early, which is exactly what the Hub needs
// in order to avoid charging for a complete response.
type CompletionState uint8

const (
	// CompletionUnspecified is the zero value and is never valid on the wire.
	CompletionUnspecified CompletionState = 0
	// CompletionComplete means the provider closed the stream normally.
	CompletionComplete CompletionState = 1
	// CompletionTruncated means the response hit MaxResponseBytes or the
	// provider dropped the connection mid-stream.
	CompletionTruncated CompletionState = 2
	// CompletionFailed means the request never produced a usable response.
	CompletionFailed CompletionState = 3
)

// Valid reports whether the state is one this version defines. The zero value
// is rejected so that a partially decoded receipt cannot pass validation.
func (c CompletionState) Valid() bool {
	switch c {
	case CompletionComplete, CompletionTruncated, CompletionFailed:
		return true
	default:
		return false
	}
}

func (c CompletionState) String() string {
	switch c {
	case CompletionComplete:
		return "complete"
	case CompletionTruncated:
		return "truncated"
	case CompletionFailed:
		return "failed"
	default:
		return fmt.Sprintf("CompletionState(%d)", uint8(c))
	}
}

// Receipt validation errors.
var (
	ErrUnsupportedVersion  = errors.New("unsupported receipt version")
	ErrInvalidJobID        = errors.New("invalid job ID")
	ErrInvalidJobSpecHash  = errors.New("invalid job spec hash")
	ErrInvalidStreamHash   = errors.New("invalid response stream hash")
	ErrInvalidHeaderHash   = errors.New("invalid response headers hash")
	ErrInvalidModel        = errors.New("invalid model")
	ErrInvalidPolicyHash   = errors.New("invalid policy hash")
	ErrInvalidCompletion   = errors.New("invalid completion state")
	ErrInvalidTimeRange    = errors.New("invalid time range")
	ErrMissingAttestation  = errors.New("receipt has no attestation reference")
	ErrInvalidAttestation  = errors.New("invalid attestation reference")
	ErrPlatformNotAllowed  = errors.New("attestation platform is not allowed")
	ErrEvidenceRequired    = errors.New("attestation evidence is required")
	ErrAttestationMismatch = errors.New("attestation does not match the signing key")
	ErrReceiptTooOld       = errors.New("receipt is older than the allowed window")
	ErrNoEpoch             = errors.New("no attested epoch available for signing")
)

// AttestationRef carries just enough of a remote attestation for a verifier to
// identify which enclave image signed a receipt.
//
// Evidence is optional and usually omitted: a full SEV-SNP report is several
// kilobytes, and the roadmap caps a receipt at 2KB. When it is absent the
// verifier is expected to resolve EvidenceHash against its own attestation
// cache, keyed by the platform and application ID.
type AttestationRef struct {
	Platform        string `cbor:"1,keyasint"`
	AttestationType string `cbor:"2,keyasint"`
	ApplicationID   string `cbor:"3,keyasint"`
	KeyID           []byte `cbor:"4,keyasint"`
	PublicKeyDER    []byte `cbor:"5,keyasint"`
	EvidenceHash    []byte `cbor:"6,keyasint"`
	Evidence        []byte `cbor:"7,keyasint,omitempty"`
}

// Receipt is the unsigned body of an execution proof.
type Receipt struct {
	Version       uint32          `cbor:"1,keyasint"`
	JobID         []byte          `cbor:"2,keyasint"`
	JobSpecHash   []byte          `cbor:"3,keyasint"`
	Provider      string          `cbor:"4,keyasint"`
	Method        string          `cbor:"5,keyasint"`
	Host          string          `cbor:"6,keyasint"`
	Path          string          `cbor:"7,keyasint"`
	StatusCode    uint32          `cbor:"8,keyasint"`
	StreamHash    []byte          `cbor:"9,keyasint"`
	ChunkCount    uint64          `cbor:"10,keyasint"`
	ResponseBytes uint64          `cbor:"11,keyasint"`
	Completion    CompletionState `cbor:"12,keyasint"`
	StartedAt     int64           `cbor:"13,keyasint"`
	FinishedAt    int64           `cbor:"14,keyasint"`
	Attestation   *AttestationRef `cbor:"15,keyasint,omitempty"`

	// PolicyHash identifies the whitelist the TEE enforced when it ran the job.
	// Without it a receipt proves an enclave produced a response but not what
	// that enclave was permitted to do, which is the half of the guarantee the
	// provider actually cares about: the point of running the job in an enclave
	// is that the whitelist could not be talked out of.
	//
	// Mandatory. A TEE is configured with a policy before it serves anything,
	// so a receipt that names none is not a weaker proof, it is an unexplained
	// one — and a verifier that pins the deployment's whitelist would otherwise
	// have nothing to compare against.
	PolicyHash []byte `cbor:"16,keyasint"`

	// RequestBytes is the size of the request body the TEE actually sent to the
	// provider. The TEE already computes len(body) to enforce MaxResponseBytes,
	// so attesting it costs nothing and closes the input-side metering gap:
	// until v1 the request body size was never proven.
	RequestBytes uint64 `cbor:"17,keyasint,omitempty"`

	// ProviderSeq is a per-provider monotonic sequence number the TEE signs
	// into every receipt. A receipt proves one execution was genuine; the
	// sequence proves the set of receipts a provider holds is complete. A
	// provider holding receipts 2 and 4 knows it was used at least four times
	// and can demand the missing record. It is the only piece of TEE state and
	// must survive restarts (sealed in production, a file store in simulation).
	ProviderSeq uint64 `cbor:"18,keyasint,omitempty"`

	// ResponseHeadersHash is the digest of the response headers the TEE
	// forwarded in the start frame (see tee.ForwardResponseHeaders and
	// tee.HashResponseHeaders). It binds the response start the Hub acted on —
	// the status it showed the user and the headers it relayed — to this
	// receipt, exactly as StreamHash binds the body. Optional: an exchange
	// that never produced a response (CompletionFailed, no start frame) has
	// nothing to attest, so it stays empty.
	ResponseHeadersHash []byte `cbor:"19,keyasint,omitempty"`

	// Model is the model the Hub declared for this job, which is the key its
	// rate card prices the premium on. The TEE cannot verify a model — it does
	// not know one vendor's model list from another's — so this is an attestation
	// of what was asked, not a claim that the request carried it: the signed
	// statement is "the Hub routed and priced this exchange as this model",
	// which is exactly what a provider needs to reconcile the receipt against
	// its own upstream bill, and which a Hub that under-declared cannot later
	// disown. Optional: a deployment that does not price by model omits it.
	Model string `cbor:"20,keyasint,omitempty"`
}

// SignedReceipt is a receipt together with the TEE's signature over it.
type SignedReceipt struct {
	Receipt   Receipt            `cbor:"1,keyasint"`
	Signature platform.Signature `cbor:"2,keyasint"`
}

// EncodeCanonical returns the deterministic CBOR encoding of the receipt body.
// This is the exact byte string the TEE signs.
func (r Receipt) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(r)
}

// Validate checks structural correctness, including the attestation reference,
// without checking any signature.
func (r Receipt) Validate() error {
	if r.Version != VersionV1 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, r.Version)
	}
	if len(r.JobID) != JobIDLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidJobID, len(r.JobID), JobIDLength)
	}
	if len(r.JobSpecHash) != JobSpecHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidJobSpecHash, len(r.JobSpecHash), JobSpecHashLength)
	}
	if len(r.StreamHash) != StreamHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidStreamHash, len(r.StreamHash), StreamHashLength)
	}
	if len(r.ResponseHeadersHash) != 0 && len(r.ResponseHeadersHash) != StreamHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidHeaderHash, len(r.ResponseHeadersHash), StreamHashLength)
	}
	// The bound is jobs', not a copy of it: the receipt and the spec it
	// describes have to agree on what a model identifier may look like, and two
	// constants that agree by convention eventually do not.
	if len(r.Model) > jobs.MaxModelLength {
		return fmt.Errorf("%w: %q exceeds %d bytes", ErrInvalidModel, r.Model, jobs.MaxModelLength)
	}
	for _, ch := range r.Model {
		if ch <= ' ' || ch == '\x7f' {
			return fmt.Errorf("%w: %q contains a control character", ErrInvalidModel, r.Model)
		}
	}
	if len(r.PolicyHash) != PolicyHashLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidPolicyHash, len(r.PolicyHash), PolicyHashLength)
	}
	if !r.Completion.Valid() {
		return fmt.Errorf("%w: %d", ErrInvalidCompletion, uint8(r.Completion))
	}
	if r.StartedAt <= 0 || r.FinishedAt < r.StartedAt {
		return fmt.Errorf("%w: started %d, finished %d", ErrInvalidTimeRange, r.StartedAt, r.FinishedAt)
	}
	return validateAttestation(r.Attestation)
}

func validateAttestation(ref *AttestationRef) error {
	if ref == nil {
		return ErrMissingAttestation
	}
	if ref.Platform == "" {
		return fmt.Errorf("%w: empty platform", ErrInvalidAttestation)
	}
	if ref.AttestationType == "" {
		return fmt.Errorf("%w: empty attestation type", ErrInvalidAttestation)
	}
	if ref.ApplicationID == "" || len(ref.ApplicationID) > MaxApplicationIDSize {
		return fmt.Errorf("%w: invalid application ID", ErrInvalidAttestation)
	}
	if len(ref.KeyID) != sha256.Size {
		return fmt.Errorf("%w: key ID length %d, want %d", ErrInvalidAttestation, len(ref.KeyID), sha256.Size)
	}
	if len(ref.PublicKeyDER) == 0 {
		return fmt.Errorf("%w: empty public key", ErrInvalidAttestation)
	}
	if len(ref.EvidenceHash) != EvidenceHashLength {
		return fmt.Errorf("%w: evidence hash length %d, want %d",
			ErrInvalidAttestation, len(ref.EvidenceHash), EvidenceHashLength)
	}
	if computed := sha256.Sum256(ref.PublicKeyDER); subtle.ConstantTimeCompare(computed[:], ref.KeyID) != 1 {
		return fmt.Errorf("%w: key ID does not match the public key", ErrInvalidAttestation)
	}
	return nil
}

// Identity reconstructs the signing identity from the attestation reference so
// that signature verification reuses the platform verification path.
func (r Receipt) Identity() (platform.Identity, error) {
	if err := validateAttestation(r.Attestation); err != nil {
		return platform.Identity{}, err
	}

	var keyID, evidenceHash [32]byte
	copy(keyID[:], r.Attestation.KeyID)
	copy(evidenceHash[:], r.Attestation.EvidenceHash)

	return platform.Identity{
		Platform:        r.Attestation.Platform,
		AttestationType: r.Attestation.AttestationType,
		ApplicationID:   r.Attestation.ApplicationID,
		Evidence:        r.Attestation.Evidence,
		EvidenceHash:    evidenceHash,
		PublicKeyDER:    r.Attestation.PublicKeyDER,
		KeyID:           keyID,
	}, nil
}

// EncodeCanonical returns the deterministic CBOR encoding of a signed receipt,
// suitable for transport or storage.
func (s SignedReceipt) EncodeCanonical() ([]byte, error) {
	return canonical.Marshal(s)
}

// Signer produces receipts using an attested key epoch.
//
// The signer deliberately has no fallback to an unattested key: a receipt that
// cannot name the enclave that produced it is worth nothing.
type Signer struct {
	epoch platform.Epoch

	// IncludeEvidence embeds the full attestation report in every receipt,
	// making each one self-contained. It costs several kilobytes per receipt,
	// so it is off by default and verifiers are expected to resolve
	// EvidenceHash from a shared attestation cache instead.
	IncludeEvidence bool
}

// NewSigner binds a signer to one attested epoch. When the platform rotates its
// epoch key, callers must construct a new signer so that receipts carry the
// matching attestation.
func NewSigner(epoch platform.Epoch) *Signer {
	return &Signer{epoch: epoch}
}

// Epoch returns the attested epoch this signer signs for. The service layer
// uses it to refuse work once the epoch's evidence has passed its freshness
// margin, instead of executing jobs whose receipts no verifier would accept.
func (s *Signer) Epoch() platform.Epoch {
	if s == nil {
		return nil
	}
	return s.epoch
}

// Sign validates and signs a receipt, filling in the attestation reference from
// the signer's epoch. Any attestation the caller pre-populated is overwritten:
// the reference must describe the key that actually signs.
func (s *Signer) Sign(receipt Receipt) (SignedReceipt, error) {
	var empty SignedReceipt

	if s == nil || s.epoch == nil {
		return empty, ErrNoEpoch
	}

	identity := s.epoch.Identity()
	evidenceHash := identity.EvidenceHash
	receipt.Attestation = &AttestationRef{
		Platform:        identity.Platform,
		AttestationType: identity.AttestationType,
		ApplicationID:   identity.ApplicationID,
		KeyID:           identity.KeyID[:],
		PublicKeyDER:    identity.PublicKeyDER,
		EvidenceHash:    evidenceHash[:],
	}
	if s.IncludeEvidence {
		receipt.Attestation.Evidence = identity.Evidence
	}

	if err := receipt.Validate(); err != nil {
		return empty, err
	}

	encoded, err := receipt.EncodeCanonical()
	if err != nil {
		return empty, err
	}
	signature, err := s.epoch.Sign(ReceiptSigningDomain, encoded)
	if err != nil {
		return empty, fmt.Errorf("sign receipt: %w", err)
	}

	return SignedReceipt{Receipt: receipt, Signature: signature}, nil
}

// VerifyOptions constrains what a verifier is willing to accept.
type VerifyOptions struct {
	// Now is the verifier's clock. Zero means time.Now().
	Now time.Time
	// AllowedPlatforms restricts which attestation platforms are trusted. Empty
	// means no restriction beyond a well-formed platform string.
	AllowedPlatforms []string
	// RequireEvidence rejects receipts that omit inline attestation evidence.
	// Verifiers without an attestation cache must set this.
	RequireEvidence bool
	// MaxAge rejects receipts finished longer ago than this. Zero disables the
	// check, which is appropriate only for offline archival verification.
	MaxAge time.Duration
}

// Verify checks a signed receipt: structure, policy constraints, and the
// signature against the attested key named in the receipt.
//
// Verify does not itself validate the attestation evidence. Resolving that
// evidence to a trusted measurement is the caller's responsibility — it is the
// step that turns "an enclave signed this" into "the enclave I trust signed
// this", and it depends on the verifier's own trust roots.
func Verify(signed SignedReceipt, opts VerifyOptions) error {
	if err := signed.Receipt.Validate(); err != nil {
		return err
	}
	if opts.RequireEvidence && len(signed.Receipt.Attestation.Evidence) == 0 {
		return ErrEvidenceRequired
	}
	if len(opts.AllowedPlatforms) > 0 && !containsString(opts.AllowedPlatforms, signed.Receipt.Attestation.Platform) {
		return fmt.Errorf("%w: %q", ErrPlatformNotAllowed, signed.Receipt.Attestation.Platform)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if opts.MaxAge > 0 {
		finished := time.Unix(signed.Receipt.FinishedAt, 0)
		if now.Sub(finished) > opts.MaxAge {
			return fmt.Errorf("%w: finished %v, now %v", ErrReceiptTooOld, finished, now)
		}
	}

	identity, err := signed.Receipt.Identity()
	if err != nil {
		return err
	}
	// The signature must have been made by the key the receipt names. Without
	// this check a receipt could name a genuine enclave while carrying a
	// signature from an unrelated key.
	if subtle.ConstantTimeCompare(signed.Signature.KeyID[:], identity.KeyID[:]) != 1 {
		return fmt.Errorf("%w: signature key ID %x, receipt key ID %x",
			ErrAttestationMismatch, signed.Signature.KeyID, identity.KeyID)
	}

	encoded, err := signed.Receipt.EncodeCanonical()
	if err != nil {
		return err
	}
	return platform.VerifySignature(identity, ReceiptSigningDomain, encoded, signed.Signature)
}

// DecodeAndVerify decodes a canonical-CBOR signed receipt and verifies it.
// Decoding enforces canonical form, so a receipt whose bytes were rewritten
// into a non-canonical but equivalent encoding is rejected rather than
// accepted under a different hash.
func DecodeAndVerify(data []byte, opts VerifyOptions) (SignedReceipt, error) {
	var signed SignedReceipt
	if err := canonical.Unmarshal(data, &signed); err != nil {
		return SignedReceipt{}, err
	}
	if err := Verify(signed, opts); err != nil {
		return SignedReceipt{}, err
	}
	return signed, nil
}

// MatchesStream reports whether the receipt's stream hash matches the digest of
// the supplied transcript.
func (r Receipt) MatchesStream(chunks [][]byte) bool {
	if len(r.StreamHash) != StreamHashLength {
		return false
	}
	computed := HashResponseStream(r.JobID, chunks)
	return subtle.ConstantTimeCompare(computed[:], r.StreamHash) == 1
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
