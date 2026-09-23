//go:build !mobile

// Package sevsnp adapts Reclaim's RA-TLS and combined AWS SEV-SNP evidence for
// the platform-neutral TokenHive trusted runtime.
package sevsnp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// Config controls the identity emitted by the AWS SEV-SNP adapter.
type Config struct {
	Role   string
	Logger *shared.Logger
}

// Adapter keeps admission, evidence, and signing on a verified RA-TLS epoch.
//
// Admission is derived from the epoch itself — what it is serving and whether
// that epoch's evidence is still within its own validity — rather than from a
// flag a refresh flips. A rotation therefore never interrupts service: it swaps
// one verified epoch for the next in a single assignment, and the epoch it
// replaces stays admissible until its own NitroTPM leaf expires, which is
// exactly the point at which a verifier would stop accepting it.
type Adapter struct {
	manager ratlsManager
	baseTLS *tls.Config

	refreshGate chan struct{}
	mu          sync.RWMutex
	current     *epoch
}

// NewAWS initializes and self-verifies an AWS SEV-SNP RA-TLS epoch. It refuses
// to fall back to local development or another cloud platform.
func NewAWS(ctx context.Context, config Config) (*Adapter, error) {
	deps := dependencies{
		isSEVSNP:     shared.IsSEVSNPMode,
		isAWS:        shared.IsAWSSEVSNP,
		validateMode: shared.ValidateSNPAttestationType,
		newRATLSManager: func(ctx context.Context, role string, logger *shared.Logger) (ratlsManager, error) {
			manager, err := shared.NewRATLSManager(ctx, role, nil)
			if err != nil {
				return nil, err
			}
			return &sharedManager{manager: manager, logger: logger}, nil
		},
	}
	return newAWS(ctx, config, deps)
}

type dependencies struct {
	isSEVSNP        func() bool
	isAWS           func() bool
	validateMode    func() error
	newRATLSManager func(context.Context, string, *shared.Logger) (ratlsManager, error)
}

func newAWS(ctx context.Context, config Config, deps dependencies) (*Adapter, error) {
	config.Role = strings.TrimSpace(config.Role)
	if config.Role == "" || len(config.Role) > 64 {
		return nil, fmt.Errorf("SEV-SNP role must contain between 1 and 64 bytes")
	}
	if err := deps.validateMode(); err != nil {
		return nil, fmt.Errorf("validate SEV-SNP attestation mode: %w", err)
	}
	if !deps.isSEVSNP() {
		return nil, errors.New("AWS SEV-SNP adapter requires /dev/sev-guest")
	}
	if !deps.isAWS() {
		return nil, errors.New("AWS SEV-SNP adapter requires an Amazon EC2 guest")
	}
	if config.Logger == nil {
		config.Logger = shared.NewNopLogger()
	}

	manager, err := deps.newRATLSManager(ctx, config.Role, config.Logger)
	if err != nil {
		return nil, fmt.Errorf("initialize RA-TLS manager: %w", err)
	}
	baseTLS := manager.ServerTLSConfig()
	if baseTLS == nil {
		return nil, errors.New("RA-TLS manager did not provide a server TLS configuration")
	}

	adapter := &Adapter{
		manager:     manager,
		baseTLS:     baseTLS.Clone(),
		refreshGate: make(chan struct{}, 1),
	}
	initial, err := buildEpoch(manager.Snapshot())
	if err != nil {
		return nil, fmt.Errorf("verify initial AWS SEV-SNP epoch: %w", err)
	}
	adapter.current = initial
	return adapter, nil
}

// Healthy reports whether new trusted work and TLS handshakes may be admitted.
// It is true exactly while the adapter holds an epoch whose evidence is still
// inside the validity of its own NitroTPM leaf, so a failed rotation shows up
// here only once the evidence has actually expired — not when it is merely
// older than the schedule wanted, which is a state the listener can keep
// serving without any verifier objecting.
func (a *Adapter) Healthy() bool {
	if a == nil {
		return false
	}
	return a.admitted() != nil
}

// admitted returns the epoch the adapter is serving, or nil when it holds none
// or the one it holds has run out of validity.
func (a *Adapter) admitted() *epoch {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.served()
}

// served is admitted's body, for callers already holding a.mu.
func (a *Adapter) served() *epoch {
	if a.current == nil || !a.current.admissible() {
		return nil
	}
	return a.current
}

// ServerTLSConfig returns an RA-TLS server configuration whose certificate
// admission fails closed once the served epoch's NitroTPM leaf has expired —
// never merely because a rotation is in progress. Handshakes are admitted for
// exactly as long as a verifier would accept the certificate presented, which
// is what keeps a rotation that has not yet found newer evidence from becoming
// an outage of its own.
func (a *Adapter) ServerTLSConfig() *tls.Config {
	config := a.baseTLS.Clone()
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		served := a.admitted()
		if served == nil {
			return nil, platform.ErrNotReady
		}
		certificate := served.snapshot.Certificate()
		if certificate == nil {
			return nil, platform.ErrNotReady
		}
		return certificate, nil
	}
	return config
}

// Snapshot returns the last fully verified immutable epoch.
func (a *Adapter) Snapshot(ctx context.Context) (platform.Epoch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	served := a.served()
	if served == nil {
		return nil, platform.ErrNotReady
	}
	return served, nil
}

// Refresh rotates the RA-TLS key and evidence and publishes the new epoch if it
// moves admission further out. The epoch being replaced keeps serving until
// then, because its own evidence is still valid — the rotation is scheduled with
// room to spare — so refusing new handshakes for the duration of an attestation
// call would drop traffic to prove nothing.
//
// Publishing only newer evidence matters routinely, not just in principle: AWS
// reissues the NitroTPM leaf only in the last minutes of its life, so a rotation
// that lands earlier regenerates the key and is handed back the certificate
// already in service. Installing that would swap evidence that still has hours
// of validity for evidence that expires at the very same instant, and would
// retire every live connection to do it. The epoch stays, and the tick returns
// nil: it is a rotation the platform declined, not a failure, and the epoch it
// declined to replace is still being served.
//
// A rotation that fails leaves the previous epoch in place and admits from it
// until its own evidence expires; the failure reads as a rotation that did not
// happen. A rotation that succeeds swaps the epoch, and admission follows the
// new one automatically, with no window in between for a reader to glimpse a
// half-rotated state.
func (a *Adapter) Refresh(ctx context.Context) error {
	select {
	case a.refreshGate <- struct{}{}:
		defer func() { <-a.refreshGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.manager.Refresh(ctx); err != nil {
		return fmt.Errorf("refresh AWS SEV-SNP RA-TLS epoch: %w", err)
	}
	next, err := buildEpoch(a.manager.Snapshot())
	if err != nil {
		return fmt.Errorf("verify refreshed AWS SEV-SNP epoch: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !next.supersedes(a.current) {
		return nil
	}
	a.current = next
	return nil
}

type epoch struct {
	identity platform.Identity
	snapshot ratlsSnapshot
	// admissibleUntil is when this epoch stops being presentable: the NitroTPM
	// leaf's own NotAfter, which is the instant a verifier stops accepting it.
	// Reading it once here keeps admission from re-parsing the attestation on
	// every handshake. Signing has its own, earlier deadline (the shared
	// SNPSigningDeadline the service applies), because a receipt outlives the
	// handshake that carried it while a certificate does not.
	admissibleUntil time.Time
}

// admissible reports whether the epoch's evidence may still be presented. It is
// the adapter's whole admission rule: an epoch is served exactly while its own
// evidence is valid, so no mutable flag can disagree with what the listener
// presents.
func (e *epoch) admissible() bool { return time.Now().Before(e.admissibleUntil) }

// supersedes reports whether e moves admission further out than previous, which
// is the condition for replacing it. The comparison is on the deadline rather
// than on "a rotation happened", so evidence that expires no later than the
// evidence already in service can never displace it — a refresh must buy the
// listener time, and one that does not is a rotation the platform declined.
func (e *epoch) supersedes(previous *epoch) bool {
	return previous == nil || e.admissibleUntil.After(previous.admissibleUntil)
}

func buildEpoch(snapshot ratlsSnapshot) (*epoch, error) {
	if snapshot == nil || snapshot.Certificate() == nil {
		return nil, errors.New("RA-TLS snapshot has no certificate")
	}
	publicKeyDER, err := snapshot.PublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("read RA-TLS public key: %w", err)
	}
	computedKeyID := sha256.Sum256(publicKeyDER)
	keyID := snapshot.SPKIHash()
	if computedKeyID != keyID {
		return nil, errors.New("RA-TLS snapshot public key does not match SPKI hash")
	}
	applicationID, attestationType, encodedEvidence, err := snapshot.Evidence()
	if err != nil {
		return nil, fmt.Errorf("extract verified evidence: %w", err)
	}
	if applicationID == "" {
		return nil, errors.New("verified evidence has no application identity")
	}
	if attestationType != shared.AttestationTypeSEVSNP && attestationType != shared.AttestationTypeSecureBoot {
		return nil, fmt.Errorf("unexpected attestation type %q", attestationType)
	}
	evidence, err := base64.StdEncoding.DecodeString(string(encodedEvidence))
	if err != nil {
		return nil, fmt.Errorf("decode verified SEV-SNP evidence: %w", err)
	}
	if len(evidence) == 0 {
		return nil, errors.New("verified SEV-SNP evidence is empty")
	}

	identity := platform.Identity{
		Platform:        platform.PlatformAWSSEVSNP,
		AttestationType: attestationType,
		ApplicationID:   applicationID,
		Evidence:        evidence,
		EvidenceHash:    sha256.Sum256(evidence),
		PublicKeyDER:    append([]byte(nil), publicKeyDER...),
		KeyID:           keyID,
	}
	// The deadline is the leaf's own NotAfter, or the fixed fallback for
	// evidence that carries no readable leaf; the flag is not needed here
	// because admission uses the value either way.
	deadline, _ := shared.SNPAdmissionDeadline(evidence)
	return &epoch{
		identity:        identity,
		snapshot:        snapshot,
		admissibleUntil: deadline,
	}, nil
}

func (e *epoch) Identity() platform.Identity {
	return platform.CloneIdentity(e.identity)
}

func (e *epoch) Sign(domain string, payload []byte) (platform.Signature, error) {
	digest, err := platform.SigningDigest(domain, payload)
	if err != nil {
		return platform.Signature{}, err
	}
	value, err := e.snapshot.SignDigest(digest)
	if err != nil {
		return platform.Signature{}, fmt.Errorf("sign with attested epoch key: %w", err)
	}
	return platform.Signature{
		Algorithm: platform.SignatureAlgorithmECDSAP256SHA256ASN1,
		KeyID:     e.identity.KeyID,
		Value:     value,
	}, nil
}

type ratlsManager interface {
	ServerTLSConfig() *tls.Config
	Snapshot() ratlsSnapshot
	Refresh(context.Context) error
}

type ratlsSnapshot interface {
	Certificate() *tls.Certificate
	PublicKeyDER() ([]byte, error)
	SPKIHash() [32]byte
	SignDigest([32]byte) ([]byte, error)
	Evidence() (applicationID, attestationType string, encodedEvidence []byte, err error)
}

type sharedManager struct {
	manager *shared.RATLSManager
	logger  *shared.Logger
}

func (m *sharedManager) ServerTLSConfig() *tls.Config      { return m.manager.ServerTLSConfig() }
func (m *sharedManager) Refresh(ctx context.Context) error { return m.manager.Refresh(ctx) }
func (m *sharedManager) Snapshot() ratlsSnapshot {
	return &sharedSnapshot{snapshot: m.manager.Snapshot(), logger: m.logger}
}

type sharedSnapshot struct {
	snapshot shared.RATLSSnapshot
	logger   *shared.Logger
}

func (s *sharedSnapshot) Certificate() *tls.Certificate { return s.snapshot.Certificate() }
func (s *sharedSnapshot) PublicKeyDER() ([]byte, error) { return s.snapshot.PublicKeyDER() }
func (s *sharedSnapshot) SPKIHash() [32]byte            { return s.snapshot.SPKIHash() }
func (s *sharedSnapshot) SignDigest(digest [32]byte) ([]byte, error) {
	return s.snapshot.SignRegistration(digest)
}
func (s *sharedSnapshot) Evidence() (string, string, []byte, error) {
	return shared.ExtractIdentityFromRATLS(s.snapshot, s.logger)
}

var _ platform.Epoch = (*epoch)(nil)
