//go:build !mobile

package shared

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// HeartbeatTarget is satisfied by both TEEK and TEET via small accessor
// methods. The router heartbeat goroutine reads through this interface so
// the loop body lives in shared/ rather than being duplicated per side.
//
// PairID returns "" when the side does not yet know its pair_id (TEE_T at
// boot, before TEE_K's TEEKPairAssignment envelope arrives); RunHeartbeats
// skips ticks in that state.
type HeartbeatTarget interface {
	PairID() string
	Router() *RouterClient
	ControlHealthy() bool
	OTReady() bool
	ActiveSessions() int
}

// RouterHeartbeatInterval is the cadence each side reports liveness +
// observation state to the router. Matches the router's 3-missed-in-15s
// "dead" threshold.
const RouterHeartbeatInterval = 5 * time.Second

// InitialRegisterRetryWindow bounds how long startRouterMode keeps
// retrying /register before giving up. A transient router 5xx or a
// stale source-IP check during router redeploy shouldn't cost a boot
// cycle. Exhausting it is fatal and reboots the guest (FatalBootReset).
// 2 minutes covers a Cloud Run revision swap plus a bit of slack.
const InitialRegisterRetryWindow = 2 * time.Minute

// RATLSRefreshInterval is how often each side regenerates its RA-TLS
// cert. GCP Confidential Space attestations expire in ~5 minutes;
// refreshing every 4 keeps new handshakes validating cleanly.
const RATLSRefreshInterval = 4 * time.Minute

// SEV-SNP attestations are bounded by cert validity (AWS NitroTPM leaf), not a
// short TTL, and regenerating them is CPU-heavy. This is now a CEILING: the
// actual cadence is driven by the real leaf NotAfter, rotating when that
// evidence's signing deadline comes due. The ceiling caps churn when the leaf is
// long-lived; a shorter-than-expected leaf rotates sooner.
const RATLSRefreshIntervalSNP = 2 * time.Hour

// SNPSigningMargin is how long before the NitroTPM leaf's NotAfter a TEE stops
// signing receipts under that leaf's evidence: a receipt issued now still has
// this much validity left, so a verifier checking evidence against its own clock
// is not handed a leaf that expires while the receipt is in flight.
//
// It bounds signing, NOT admission. A verifier accepts the leaf until its
// NotAfter and no later, so a TEE that stops presenting the leaf any earlier
// refuses handshakes that would have verified — and since AWS reissues the leaf
// only in the last minutes of its life, a rotation that lands earlier is simply
// handed back the certificate it already holds. A margin wider than that reissue
// window is therefore not a safety net; it is an interval in which every
// handshake is refused and no rotation can succeed. Admission runs to the leaf's
// own NotAfter (SNPAdmissionDeadline), and this margin stays well inside it.
const SNPSigningMargin = 5 * time.Minute

// ratlsRefreshInterval picks the cert-refresh cadence for the active TEE mode.
func ratlsRefreshInterval() time.Duration {
	if IsSEVSNPMode() {
		return RATLSRefreshIntervalSNP
	}

	return RATLSRefreshInterval
}

// AttestationCacheTTL is how long a TEE may serve a cached attestation before
// regenerating. Kept above the refresh cadence so the periodic postRefresh
// (not a lazy cache-miss) drives regeneration.
func AttestationCacheTTL() time.Duration {
	if IsSEVSNPMode() {
		return RATLSRefreshIntervalSNP + 10*time.Minute
	}

	return 5 * time.Minute
}

// SNPAdmissionDeadline returns when a TEE must stop presenting this attestation:
// the NitroTPM leaf's own NotAfter.
//
// That is the exact instant a verifier stops accepting the leaf — the Hub's
// chain check and a receipt verifier's both compare it against their own clock
// and nothing else — so a TEE that stops earlier is not being conservative, it
// is refusing handshakes that would have verified. The flag reports whether the
// deadline came from the attestation's own leaf (AWS) rather than the fallback
// below, which is how a caller tells a real expiry from the guess it silently
// degrades to.
func SNPAdmissionDeadline(attestation []byte) (time.Time, bool) {
	return snpLeafDeadline(attestation, 0)
}

// SNPSigningDeadline returns when a TEE must stop signing receipts under this
// attestation: SNPSigningMargin before the leaf's NotAfter. A rotation schedule
// aims at that instant, because it is the last moment a receipt can be issued
// under this evidence: one issued later would cite evidence that expires inside
// the margin its verifier requires.
func SNPSigningDeadline(attestation []byte) (time.Time, bool) {
	return snpLeafDeadline(attestation, SNPSigningMargin)
}

// snpLeafDeadline reads the NitroTPM leaf's NotAfter out of an AWS combined
// attestation and steps back by margin. Evidence with no readable leaf (GCP
// Confidential Space, the simulation) has no TEE-side expiry to read: callers
// get now + AttestationCacheTTL() — enough to schedule a rotation, and never a
// verdict on serving, which is what tracked=false tells them.
func snpLeafDeadline(attestation []byte, margin time.Duration) (time.Time, bool) {
	if notAfter, ok := SNPNitroLeafNotAfter(attestation); ok {
		return notAfter.Add(-margin), true
	}
	return time.Now().Add(AttestationCacheTTL()), false
}

// RunHeartbeats fires a heartbeat to the router every `interval` until
// ctx is cancelled. On ErrRouterNotFound (router lost our pair_id, e.g.
// after a restart in single-replica mode), it calls onLost to re-register;
// other errors are logged but don't abort the loop.
func RunHeartbeats(
	ctx context.Context,
	target HeartbeatTarget,
	role string,
	logger *Logger,
	onLost func(context.Context) error,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pid := target.PairID()
			if pid == "" {
				continue
			}
			req := HeartbeatRequest{
				PairID:         pid,
				Role:           role,
				ControlHealthy: target.ControlHealthy(),
				OTReady:        target.OTReady(),
				ActiveSessions: target.ActiveSessions(),
			}
			_, err := target.Router().Heartbeat(ctx, req)
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering",
					zap.String("pair_id", pid))
				if regErr := onLost(ctx); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
}

// RegisterWithRetry calls the supplied register fn with exponential
// backoff up to InitialRegisterRetryWindow. Use at boot so a transient
// router error (5xx, a stale source-IP check during router redeploy,
// etc.) doesn't cost a boot cycle. Returns the last error only if the
// window is exhausted; callers treat that as fatal.
func RegisterWithRetry(ctx context.Context, register func(context.Context) error, logger *Logger) error {
	deadline := time.Now().Add(InitialRegisterRetryWindow)
	backoff := 1 * time.Second
	var lastErr error
	for {
		err := register(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if time.Now().Add(backoff).After(deadline) {
			return fmt.Errorf("register retry window exhausted: %w", lastErr)
		}
		logger.Warn("register failed, retrying", zap.Duration("backoff", backoff), zap.Error(err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 15*time.Second {
			backoff = 15 * time.Second
		}
	}
}

// RATLSRefresher is the rotation surface RunRATLSRefresh drives. *RATLSManager
// is the direct implementation; a platform adapter whose Refresh also
// re-verifies the rotated epoch before publishing it satisfies this too, so
// both callers share one cadence and one failure policy.
type RATLSRefresher interface {
	Refresh(context.Context) error
}

// RunRATLSRefresh rotates the RA-TLS cert on a fixed interval until ctx
// is cancelled. Errors are logged; the loop continues so a transient
// launcher-socket failure doesn't kill the goroutine.
//
// postRefresh runs synchronously after each successful cert rotation,
// inside the same tick. TEEs use it to regenerate any per-session
// attestation cache that binds to the cert hash — keeping the cert and
// the cached attestation atomically in sync from any consumer's point
// of view (no window where the cert is new but the cached attestation
// still references the old hash). Pass nil if not needed.
// nextInterval, when non-nil, is consulted after each refresh to pick the delay
// until the next one — letting SEV-SNP track the actual NitroTPM leaf expiry
// (rotate when the evidence's signing deadline comes due, SNPSigningDeadline)
// instead of a fixed cadence. A nil callback (or a non-positive return) falls
// back to the fixed ratlsRefreshInterval().
//
// skipInitial suppresses the one priming call postRefresh otherwise gets before
// the loop starts. Callers whose postRefresh populates state that a reader
// depends on from the first request (the TEEs' per-session attestation cache)
// must not skip it. A caller whose postRefresh is instead a full publish of an
// epoch it has already published during startup should: the priming call would
// rewrite every artifact and rebuild the signer for a state that is already in
// place, once per boot.
func RunRATLSRefresh(ctx context.Context, ratls RATLSRefresher, postRefresh func() error, nextInterval func() time.Duration, health *AttestationHealth, logger *Logger, skipInitial bool) {
	// Run postRefresh once immediately so the per-session attestation
	// cache is populated before the server starts accepting traffic.
	// Without this, the cache sits empty for the first RATLSRefreshInterval
	// (4 minutes) after every TEE boot — and any request arriving in that
	// window triggers a lazy fallback to GenerateGCPAttestation. Under
	// concurrent load that's N simultaneous calls to the launcher socket,
	// which can't keep up and starts timing out. NewRATLSManager already
	// generated the initial cert; we just need to prime the cached
	// per-session attestation here.
	if postRefresh != nil && !skipInitial {
		if err := postRefresh(); err != nil {
			logger.Error("RA-TLS initial post-refresh failed", zap.Error(err))
		}
	}

	for {
		d := ratlsRefreshInterval()
		if nextInterval != nil {
			if n := nextInterval(); n > 0 {
				d = n
			}
		}
		// Emit as strings: the GCP logging core doesn't serialize zap.Duration
		// or zap.Time (they render as null / {} in jsonPayload).
		nextAt := time.Now().Add(d)
		logger.Info("next RA-TLS attestation refresh scheduled",
			zap.String("in", d.Round(time.Second).String()),
			zap.String("at", nextAt.UTC().Format(time.RFC3339)))
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := ratls.Refresh(ctx); err != nil {
				logger.Error("RA-TLS refresh failed", zap.Error(err))
				// The cert path hits the device directly (not via generateAttestationDoc);
				// feed the watchdog here too — the path that goes silent on a wedge.
				health.RecordFailure(err)
				continue
			}
			// A rotation that succeeded clears the failure streak. RecordFailure
			// increments it and nothing else in this loop decrements it, so without
			// this a single transient failure keeps the TEE reporting unhealthy for
			// the life of the process (or until the self-reset it triggers).
			health.RecordSuccess()
			if postRefresh != nil {
				if err := postRefresh(); err != nil {
					logger.Error("RA-TLS post-refresh hook failed", zap.Error(err))
					continue
				}
			}
			logger.Debug("RA-TLS attestation refreshed")
		}
	}
}

// ExtractIdentityFromRATLS reads the in-flight RA-TLS cert and pulls the
// attestation JWT + container image digest out of it. The same JWT goes
// into the router registration body; the digest is the router's
// allowlist key.
func ExtractIdentityFromRATLS(snap RATLSSnapshot, logger *Logger) (imageDigest, attestationType string, attestation []byte, err error) {
	cert := snap.Certificate()
	if cert == nil || cert.Leaf == nil {
		return "", "", nil, errors.New("RA-TLS manager has no current cert")
	}
	leaf := cert.Leaf
	// SNP evidence takes precedence when present. The report is binary, so it
	// travels base64-encoded in the JSON register body; the router decodes it.
	// A Secure Boot .3 marker upgrades the legacy-compatible .2 evidence before
	// registration, so the router records the correct internal generation.
	snpType, report, rerr := snpAttestationFromCert(leaf)
	if rerr != nil {
		return "", "", nil, rerr
	}
	if report != nil {
		spki, serr := snap.PublicKeyDER()
		if serr != nil {
			return "", "", nil, fmt.Errorf("marshal SPKI: %w", serr)
		}
		var app string
		var verr error
		if snpType == AttestationTypeSecureBoot {
			app, _, verr = VerifyCombinedSecureBootAttestation(report, spki)
		} else {
			app, _, verr = VerifyCombinedSEVSNPAttestation(report, spki)
		}
		if verr != nil {
			return "", "", nil, fmt.Errorf("verify %s attestation: %w", snpType, verr)
		}
		enc := base64.StdEncoding.EncodeToString(report)
		return app, snpType, []byte(enc), nil
	}
	attestation, err = ExtractAttestationFromCert(leaf)
	if err != nil {
		return "", "", nil, fmt.Errorf("extract attestation: %w", err)
	}
	imageDigest, err = ExtractImageDigestFromGCPAttestation(attestation, logger)
	if err != nil {
		return "", "", nil, fmt.Errorf("extract image digest: %w", err)
	}
	return imageDigest, AttestationTypeCS, attestation, nil
}

// LoadOPRFShare reads (or creates) this side's persistent MPC OPRF key
// share from GCP Secret Manager. role is "tee_k" or "tee_t"; deploymentKey
// is the per-deployment discriminator (e.g. "tk.reclaimprotocol.org") that
// disambiguates the secret name. Requires GOOGLE_PROJECT_ID, GOOGLE_KMS_
// LOCATION, GOOGLE_KMS_KEYRING, GOOGLE_KMS_KEY to be set.
func LoadOPRFShare(role, deploymentKey string, logger *Logger) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// On AWS SEV-SNP the share lives in AWS Secrets Manager (same secret name,
	// seeded from the GCP-exported share); GCP keeps using Secret Manager + KMS.
	if IsAWSSEVSNP() {
		store, err := NewAWSSecretStore(ctx, GetEnvOrDefault("AWS_OPRF_KMS_KEY_ID", ""))
		if err != nil {
			return nil, fmt.Errorf("new aws secret store: %w", err)
		}
		share, err := store.LoadOrCreateOPRFShare(ctx, role, deploymentKey)
		if err != nil {
			return nil, fmt.Errorf("LoadOrCreateOPRFShare (aws): %w", err)
		}
		if logger != nil {
			logger.Info("Loaded OPRF share from AWS Secrets Manager",
				zap.String("role", role),
				zap.String("deployment_key", deploymentKey))
		}
		return share, nil
	}

	required := []struct {
		name, value string
	}{
		{"GOOGLE_PROJECT_ID", GetEnvOrDefault("GOOGLE_PROJECT_ID", "")},
		{"GOOGLE_KMS_LOCATION", GetEnvOrDefault("GOOGLE_KMS_LOCATION", "")},
		{"GOOGLE_KMS_KEYRING", GetEnvOrDefault("GOOGLE_KMS_KEYRING", "")},
		{"GOOGLE_KMS_KEY", GetEnvOrDefault("GOOGLE_KMS_KEY", "")},
	}
	for _, r := range required {
		if r.value == "" {
			return nil, fmt.Errorf("%s required when KMS_ENCLAVE_DOMAIN_KEY is set", r.name)
		}
	}

	store, err := NewSecretStore(ctx, required[0].value, required[1].value, required[2].value, required[3].value)
	if err != nil {
		return nil, fmt.Errorf("new secret store: %w", err)
	}
	share, err := store.LoadOrCreateOPRFShare(ctx, role, deploymentKey)
	if err != nil {
		return nil, fmt.Errorf("LoadOrCreateOPRFShare: %w", err)
	}
	if logger != nil {
		logger.Info("Loaded OPRF share from Secret Manager",
			zap.String("role", role),
			zap.String("deployment_key", deploymentKey))
	}
	return share, nil
}
