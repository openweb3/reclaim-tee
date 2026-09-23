package main

import (
	"context"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// generateAttestationDoc produces a fresh GCP attestation token bound to
// the supplied nonces, against the launcher socket on the host.
func (t *TEET) generateAttestationDoc(ctx context.Context, nonces ...string) ([]byte, error) {
	doc, err := t.generateAttestationDocRaw(ctx, nonces...)
	if err != nil {
		t.attestHealth.RecordFailure(err)
		return nil, err
	}
	t.attestHealth.RecordSuccess()
	return doc, nil
}

func (t *TEET) generateAttestationDocRaw(ctx context.Context, nonces ...string) ([]byte, error) {
	if t.genAttestationDocFn != nil {
		return t.genAttestationDocFn(ctx, nonces...)
	}
	if shared.IsSEVSNPMode() {
		return shared.GenerateSEVSNPNonceAttestation(nonces)
	}
	return shared.GenerateGCPAttestation(ctx, nonces...)
}

// attestationReportType labels the app-layer attestation by platform so the
// peer verifier picks the right validation path.
func attestationReportType() string {
	if shared.IsSEVSNPMode() {
		return shared.CurrentSNPAttestationType()
	}
	return "gcp"
}

func (t *TEET) refreshAttestation() error {
	if t.ratls == nil {
		return nil
	}

	// Rotate the signing keypair on every refresh (forward secrecy), mirroring
	// TEE_K. The fresh attestation binds this new key's ETH address, and the
	// bundle path snapshots {signingKeyPair, cachedAttestation} together.
	newKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		return fmt.Errorf("rotate signing key: %v", err)
	}
	ethAddress := newKeyPair.GetEthAddress()

	// Bind to the current keypair's SPKI hash. The RA-TLS key also rotates on
	// refresh; ratls.Refresh runs immediately before this callback, so
	// SPKIHash() already reflects the new key.
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_t_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_t") + fmt.Sprintf("%x", spkiHash[:])

	raw, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}
	reportType := attestationReportType()
	if shared.IsSEVSNPMode() {
		reportType, raw, err = shared.ClientCompatibleSNPAttestation(reportType, raw)
		if err != nil {
			return fmt.Errorf("build client-compatible SNP attestation: %v", err)
		}
	}

	attestationReport := &teeproto.AttestationReport{Type: reportType, Report: raw}
	// Publish the new signing key + its attestation atomically.
	t.attestationMutex.Lock()
	t.signingKeyPair = newKeyPair
	t.cachedAttestation = attestationReport
	// Expiry tracks the real NitroTPM leaf (AWS), minus the shared signing
	// margin, so the cached attestation is regenerated before it expires rather
	// than at a fixed guess; falls back to the cache TTL for GCP/CS. A cache
	// miss regenerates, so this self-heals if AWS shortens the leaf.
	t.attestationExpiry, _ = shared.SNPSigningDeadline(raw)
	t.attestationMutex.Unlock()
	t.logger.Debug("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)))
	return nil
}

// nextRATLSRefresh is the adaptive cadence passed to RunRATLSRefresh: for
// SEV-SNP, refresh when the cached attestation is due to go stale (the
// NitroTPM leaf expiry minus margin), clamped to a floor (avoid churn) and the
// RATLSRefreshIntervalSNP ceiling. Returns 0 for CS so the fixed cadence applies.
func (t *TEET) nextRATLSRefresh() time.Duration {
	if !shared.IsSEVSNPMode() {
		return 0
	}
	t.attestationMutex.RLock()
	exp := t.attestationExpiry
	t.attestationMutex.RUnlock()
	d := max(min(time.Until(exp), shared.RATLSRefreshIntervalSNP), 10*time.Minute)
	return d
}

// getCachedAttestation returns the cached attestation if valid, otherwise
// generates a new one. Concurrent cache-miss callers are coalesced via
// singleflight so only ONE launcher-socket call fires; all waiters share
// the result.
func (t *TEET) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	if t.ratls == nil {
		return nil, nil
	}
	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()
	if cached != nil && time.Now().Before(expiry) {
		t.logger.Debug("Using cached attestation",
			zap.String("session_id", sessionID),
			zap.String("type", cached.Type))
		return cached, nil
	}

	t.logger.Warn("Cached attestation expired or missing, coalescing refresh",
		zap.String("session_id", sessionID))
	val, err, _ := t.attestationSF.Do("refresh", func() (any, error) {
		// Re-check inside the singleflight in case another caller just
		// finished refreshing while we were waiting at the door.
		t.attestationMutex.RLock()
		cached := t.cachedAttestation
		expiry := t.attestationExpiry
		t.attestationMutex.RUnlock()
		if cached != nil && time.Now().Before(expiry) {
			return cached, nil
		}
		if err := t.refreshAttestation(); err != nil {
			return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
		}
		t.attestationMutex.RLock()
		result := t.cachedAttestation
		t.attestationMutex.RUnlock()
		return result, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*teeproto.AttestationReport), nil
}

// signingEpoch returns a consistent snapshot of {signing keypair, attestation}
// for building a bundle. The keypair rotates on every attestation refresh, so
// the two MUST be read together under one lock — otherwise a bundle could be
// signed by a key from one epoch while carrying an attestation from another.
// It first ensures the attestation is fresh (refreshing+rotating if stale).
func (t *TEET) signingEpoch(sessionID string) (*shared.SigningKeyPair, *teeproto.AttestationReport, error) {
	if t.ratls != nil {
		if _, err := t.getCachedAttestation(sessionID); err != nil {
			return nil, nil, err
		}
	}
	t.attestationMutex.RLock()
	defer t.attestationMutex.RUnlock()
	return t.signingKeyPair, t.cachedAttestation, nil
}

// generateAttestationForTEEK generates attestation with cert hash for mutual auth
func (t *TEET) generateAttestationForTEEK() (*teeproto.AttestationReport, error) {
	// Standalone (local-dev) mode: peer won't run a real attestation verifier.
	if t.ratls == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// SPKI binding — see refreshAttestation comment for rationale.
	spkiHash := t.ratls.SPKIHash()
	userData := shared.SPKINoncePrefix("tee_t") + fmt.Sprintf("%x", spkiHash[:])

	t.logger.Debug("Generating attestation for TEE_K (SPKI-bound)")

	attestationDoc, err := t.generateAttestationDoc(context.Background(), userData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	attestationType := attestationReportType()

	t.logger.Debug("Generated attestation for TEE_K",
		zap.String("type", attestationType))

	return &teeproto.AttestationReport{
		Type:   attestationType,
		Report: attestationDoc,
	}, nil
}

// verifyTEEKAttestation verifies TEE_K's attestation request. Symmetric to
// TEE_K's verifyTEETAttestation: validates the JWT signature, then confirms
// the eat_nonce array carries a `tee_k_cert_hash:<sha256(peer cert)>` entry
// — binding the inner attestation to the TLS cert TEE_K presented during
// the mTLS handshake.
//
// TEE_K's attestation carries TWO nonces (tee_k_public_key:<eth-addr> and
// tee_k_cert_hash:<hash>), so we look up by prefix rather than reading
// nonce[0].
//
// peerCert is the raw DER of TEE_K's client cert (PeerCertificates[0] of
// the TLS connection underlying this control WebSocket). Pass nil in
// standalone mode; the function will branch into the standalone path.
func (t *TEET) verifyTEEKAttestation(req *teeproto.TEEKAttestationRequest, peerCert []byte) error {
	if req == nil {
		return fmt.Errorf("malformed TEE_K attestation request: missing request")
	}
	attestation := req.AttestationReport
	if attestation == nil {
		return fmt.Errorf("malformed TEE_K attestation request: missing report")
	}

	// Standalone (local-dev) mode
	if attestation.Type == "standalone" {
		if t.ratls == nil && string(attestation.Report) == "standalone" {
			t.logger.Debug("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone but in router mode")
	}
	if attestation.Type != shared.AttestationTypeSEVSNP &&
		attestation.Type != shared.AttestationTypeSecureBoot &&
		attestation.Type != "gcp" {
		return fmt.Errorf("unsupported attestation type: %s", attestation.Type)
	}

	// Router mode
	if t.ratls == nil {
		return fmt.Errorf("mode mismatch: received GCP attestation but in standalone mode")
	}

	if len(peerCert) == 0 {
		return fmt.Errorf("no peer TLS certificate available for SPKI binding")
	}

	expectedSPKI, err := shared.SPKIHashFromCertDER(peerCert)
	if err != nil {
		return fmt.Errorf("compute TEE_K SPKI hash: %w", err)
	}
	expectedSPKIHex := fmt.Sprintf("%x", expectedSPKI[:])

	// SNP: the attestation binds a presentable nonce list; verify the generation
	// named by the protocol type, then bind the result to the mTLS peer SPKI.
	if attestation.Type == shared.AttestationTypeSEVSNP || attestation.Type == shared.AttestationTypeSecureBoot {
		nonces, _, err := shared.VerifyPeerSNPNonceAttestation(attestation.Type, attestation.Report)
		if err != nil {
			return fmt.Errorf("validate TEE_K %s attestation: %w", attestation.Type, err)
		}
		gotHex, err := shared.FindNonceInList(nonces, shared.SPKINoncePrefix("tee_k"))
		if err != nil {
			return fmt.Errorf("find tee_k_spki_hash nonce: %w", err)
		}
		if gotHex != expectedSPKIHex {
			return fmt.Errorf("TEE_K SPKI mismatch: attestation says %q, peer cert SPKI hashes to %q", gotHex, expectedSPKIHex)
		}
		t.logger.Debug("TEE_K SNP attestation verified", zap.String("type", attestation.Type))
		return nil
	}

	// RA-TLS already verified peer image_digest at the TLS handshake.
	// Bind the attestation to TEE_K's TLS keypair via the SPKI nonce —
	// stable across cert refreshes, unlike a full cert-DER hash.
	attestor, err := shared.NewGoogleAttestor()
	if err != nil {
		return fmt.Errorf("build attestor: %w", err)
	}
	if err := attestor.Validate(attestation.Report, t.logger); err != nil {
		return fmt.Errorf("validate TEE_K attestation JWT: %w", err)
	}

	gotHex, err := shared.FindNonceValue(attestation.Report, shared.SPKINoncePrefix("tee_k"))
	if err != nil {
		return fmt.Errorf("find tee_k_spki_hash nonce: %w", err)
	}
	if gotHex != expectedSPKIHex {
		return fmt.Errorf("TEE_K SPKI mismatch: attestation says %q, peer cert SPKI hashes to %q", gotHex, expectedSPKIHex)
	}

	t.logger.Debug("TEE_K SPKI hash verified")
	return nil
}
