package main

import (
	"context"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// generateAttestationDoc produces a fresh GCP attestation token bound to
// the supplied nonces, against the launcher socket on the host.
func (t *TEEK) generateAttestationDoc(ctx context.Context, nonces ...string) ([]byte, error) {
	doc, err := t.generateAttestationDocRaw(ctx, nonces...)
	if err != nil {
		t.attestHealth.RecordFailure(err)
		return nil, err
	}
	t.attestHealth.RecordSuccess()
	return doc, nil
}

func (t *TEEK) generateAttestationDocRaw(ctx context.Context, nonces ...string) ([]byte, error) {
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

// refreshAttestation generates a new attestation and caches it
func (t *TEEK) refreshAttestation() error {
	// Skip in standalone mode (no RA-TLS — no attestation primitives).
	if t.ratls == nil {
		return nil
	}

	// Rotate the signing keypair on every refresh (forward secrecy): a key
	// extracted via a TEE compromise is only useful until the next refresh.
	// The fresh attestation below binds this new key's ETH address, and the
	// bundle path snapshots {signingKeyPair, cachedAttestation} together, so a
	// bundle is always signed by the key its embedded attestation vouches for.
	newKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		return fmt.Errorf("rotate signing key: %v", err)
	}
	ethAddress := newKeyPair.GetEthAddress()

	// Bind the attestation to the current TLS keypair's SPKI hash. The RA-TLS
	// key also rotates on refresh; ratls.Refresh runs immediately before this
	// callback, so SPKIHash() already reflects the new key.
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_k") + fmt.Sprintf("%x", spkiHash[:])

	attestationDoc, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}
	reportType := attestationReportType()
	if shared.IsSEVSNPMode() {
		reportType, attestationDoc, err = shared.ClientCompatibleSNPAttestation(reportType, attestationDoc)
		if err != nil {
			return fmt.Errorf("build client-compatible SNP attestation: %v", err)
		}
	}

	// Create structured report
	attestationReport := &teeproto.AttestationReport{
		Type:   reportType,
		Report: attestationDoc,
	}

	// Publish the new signing key + its attestation atomically so no bundle
	// observes a key from one epoch with an attestation from another.
	t.attestationMutex.Lock()
	t.signingKeyPair = newKeyPair
	t.cachedAttestation = attestationReport
	// Expiry tracks the real NitroTPM leaf (AWS), minus the shared signing
	// margin, so the cached attestation is regenerated before it expires rather
	// than at a fixed guess; falls back to the cache TTL for GCP/CS. A cache
	// miss regenerates, so this self-heals if AWS shortens the leaf.
	t.attestationExpiry, _ = shared.SNPSigningDeadline(attestationDoc)
	t.attestationMutex.Unlock()

	t.logger.Debug("Cached new attestation")

	return nil
}

// nextRATLSRefresh is the adaptive cadence passed to RunRATLSRefresh: for
// SEV-SNP, refresh when the cached attestation is due to go stale (the
// NitroTPM leaf expiry minus margin), clamped to a floor (avoid churn) and the
// RATLSRefreshIntervalSNP ceiling. Returns 0 for CS so the fixed cadence applies.
func (t *TEEK) nextRATLSRefresh() time.Duration {
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
// singleflight so only ONE launcher-socket call fires per miss; all
// waiters share that one result.
func (t *TEEK) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	// Skip in standalone mode
	if t.ratls == nil {
		return nil, nil
	}

	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()

	// Fast path — cache hit.
	if cached != nil && time.Now().Before(expiry) {
		t.logger.WithSession(sessionID).Debug("Using cached attestation",
			zap.String("type", cached.Type))
		return cached, nil
	}

	// Cache miss. Use singleflight so N concurrent miss-callers fire only
	// one refresh. The "refresh" key is constant — there's only one global
	// per-TEE attestation cache.
	t.logger.WithSession(sessionID).Warn("Cached attestation expired or missing, coalescing refresh")
	val, err, _ := t.attestationSF.Do("refresh", func() (any, error) {
		// Re-check inside the singleflight — another caller may have just
		// completed the refresh while we were waiting at the door.
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
func (t *TEEK) signingEpoch(sessionID string) (*shared.SigningKeyPair, *teeproto.AttestationReport, error) {
	if t.ratls != nil {
		if _, err := t.getCachedAttestation(sessionID); err != nil {
			return nil, nil, err
		}
	}
	t.attestationMutex.RLock()
	defer t.attestationMutex.RUnlock()
	return t.signingKeyPair, t.cachedAttestation, nil
}

// generateAttestationForTEET generates attestation for mutual auth with TEE_T
func (t *TEEK) generateAttestationForTEET() (*teeproto.AttestationReport, error) {
	// Standalone (local-dev) mode: TEE_T won't run a real attestation
	// verifier — exchange a sentinel value so both sides know not to expect
	// a real GCP token.
	if t.ratls == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// Router mode: generate attestation with eth address and SPKI hash.
	// Read the signing key under the lock since it rotates on refresh.
	t.attestationMutex.RLock()
	ethAddress := t.signingKeyPair.GetEthAddress()
	t.attestationMutex.RUnlock()
	spkiHash := t.ratls.SPKIHash()

	publicKeyNonce := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())
	spkiHashNonce := shared.SPKINoncePrefix("tee_k") + fmt.Sprintf("%x", spkiHash[:])

	attestationDoc, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, spkiHashNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	return &teeproto.AttestationReport{
		Type:   attestationReportType(),
		Report: attestationDoc,
	}, nil
}

// verifyTEETAttestation verifies TEE_T's attestation response
func (t *TEEK) verifyTEETAttestation(msgBytes []byte, tlsCert []byte) error {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}
	attestation, err := teetAttestationReportFromEnvelope(&env)
	if err != nil {
		return err
	}

	// Standalone (local-dev) mode
	if attestation.Type == "standalone" {
		if t.ratls == nil && string(attestation.Report) == "standalone" {
			t.logger.Debug("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone but in router mode")
	}

	// Router mode
	if t.ratls == nil {
		return fmt.Errorf("mode mismatch: received GCP attestation but in standalone mode")
	}

	expectedSPKI, err := shared.SPKIHashFromCertDER(tlsCert)
	if err != nil {
		return fmt.Errorf("compute TEE_T SPKI hash: %w", err)
	}
	expectedSPKIHex := fmt.Sprintf("%x", expectedSPKI[:])

	// SNP: the attestation binds a presentable nonce list; verify the generation
	// named by the protocol type, then bind the result to the mTLS peer SPKI.
	if attestation.Type == shared.AttestationTypeSEVSNP || attestation.Type == shared.AttestationTypeSecureBoot {
		nonces, _, err := shared.VerifyPeerSNPNonceAttestation(attestation.Type, attestation.Report)
		if err != nil {
			return fmt.Errorf("validate TEE_T %s attestation: %w", attestation.Type, err)
		}
		gotHex, err := shared.FindNonceInList(nonces, shared.SPKINoncePrefix("tee_t"))
		if err != nil {
			return fmt.Errorf("find tee_t_spki_hash nonce: %w", err)
		}
		if gotHex != expectedSPKIHex {
			t.logger.Error("SPKI hash mismatch", zap.String("expected", expectedSPKIHex), zap.String("got", gotHex))
			return fmt.Errorf("TEE_T SPKI hash mismatch")
		}
		t.logger.Debug("TEE_T SNP attestation verified", zap.String("type", attestation.Type))
		return nil
	}

	// Verify the SPKI hash in the attestation against TEE_T's TLS keypair.
	// Binding to SPKI (not the full cert DER) means the check is stable
	// across cert refreshes — the keypair is invariant.
	if attestation.Type != "gcp" {
		return fmt.Errorf("unsupported attestation type: %s", attestation.Type)
	}
	attestor, err := shared.NewGoogleAttestor()
	if err != nil {
		return fmt.Errorf("build attestor: %w", err)
	}
	if err := attestor.Validate(attestation.Report, t.logger); err != nil {
		return fmt.Errorf("validate TEE_T attestation: %w", err)
	}

	gotHex, err := shared.FindNonceValue(attestation.Report, shared.SPKINoncePrefix("tee_t"))
	if err != nil {
		return fmt.Errorf("find tee_t_spki_hash nonce: %w", err)
	}
	if gotHex != expectedSPKIHex {
		t.logger.Error("SPKI hash mismatch", zap.String("expected", expectedSPKIHex), zap.String("got", gotHex))
		return fmt.Errorf("TEE_T SPKI hash mismatch")
	}

	t.logger.Debug("TEE_T SPKI hash verified")
	return nil
}

func teetAttestationReportFromEnvelope(env *teeproto.Envelope) (*teeproto.AttestationReport, error) {
	if env == nil {
		return nil, fmt.Errorf("malformed TEE_T attestation response: missing envelope")
	}

	// Check for error message
	if errMsg, ok := env.Payload.(*teeproto.Envelope_Error); ok {
		if errMsg == nil || errMsg.Error == nil {
			return nil, fmt.Errorf("malformed TEE_T attestation error: missing error data")
		}
		return nil, fmt.Errorf("TEE_T rejected attestation: %s", errMsg.Error.Message)
	}

	resp, ok := env.Payload.(*teeproto.Envelope_TeetAttestation)
	if !ok {
		return nil, fmt.Errorf("unexpected message type: %T", env.Payload)
	}

	if resp == nil || resp.TeetAttestation == nil {
		return nil, fmt.Errorf("malformed TEE_T attestation response: missing response")
	}
	attestation := resp.TeetAttestation.AttestationReport
	if attestation == nil {
		return nil, fmt.Errorf("malformed TEE_T attestation response: missing report")
	}
	return attestation, nil
}
