// RA-TLS epoch refresh for the TokenHive TEE.
//
// The Hub↔TEE channel is mutual TLS, and the TEE's half of it is an attested
// RA-TLS certificate: on AWS SEV-SNP the leaf carries a NitroTPM attestation
// whose chain is signed by AWS and is only valid for hours. A TEE that boots
// once and runs for weeks would therefore hand the Hub a certificate whose
// evidence has expired — the Hub's chain check, and the receipt verifier's, are
// both date-checked, so the deployment would go dark on a schedule.
//
// The rotation itself lives behind the platform adapter (sevsnp.Adapter.Refresh
// rotates the key and re-verifies the resulting epoch in one step). What is
// assembled here is the TEE-specific half: which parts of this process follow
// the rotated epoch, when the next rotation is due, and what has to be durable
// before a rotated key is allowed to sign.
package main

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	rootShared "github.com/reclaimprotocol/reclaim-tee/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// epochRefresher is the rotation surface of a platform whose attested epoch
// expires. The AWS SEV-SNP adapter implements it: one Refresh rotates the
// RA-TLS key and re-verifies the resulting epoch before publishing it, so this
// process never signs with a key the platform has not attested to. A nil
// refresher means the epoch is fixed for the process lifetime — the simulation,
// whose software evidence does not expire.
type epochRefresher interface {
	Refresh(context.Context) error
	Snapshot(context.Context) (platform.Epoch, error)
}

// epochAssembly is what buildEpoch assembles for the selected platform: the
// epoch that signs receipts now, the RA-TLS listener configuration presenting
// the matching key, and — where that evidence expires — the adapter that
// rotates both.
type epochAssembly struct {
	Epoch     platform.Epoch
	ServerTLS *tls.Config
	Refresher epochRefresher
}

// snpReissueWindow is how long before the NitroTPM leaf's own NotAfter AWS is
// willing to hand out a newer one: ~9m48s, constant across the nine cycles
// measured off a live deployment (±1s). Outside it a rotation is not refused —
// it regenerates the RA-TLS key and is handed back the certificate already in
// service, which the adapter declines to install (see sevsnp.Adapter.Refresh).
//
// Both constants below are derived from it, so it is written down once here
// rather than repeated as prose in each of their comments.
const snpReissueWindow = 9*time.Minute + 48*time.Second

// minRefreshFloor bounds how soon the adaptive cadence may fire again. It earns
// its keep once a rotation has failed for long enough that the epoch still being
// served is inside its signing margin: the TEE then refuses work while the
// listener keeps admitting handshakes, and only a rotation clears that state, so
// the retry cannot wait out the two-hour ceiling.
//
// It also has to be shorter than snpReissueWindow. A floor wider than the window
// can step over all of it: one retry lands before the reissue point and the next
// lands after the epoch's own deadline, so the rotation scheduled to keep
// evidence fresh misses it every cycle. That is what a 10m floor did to a 30m
// margin. tee_k/tee_t keep their own 10m floor and are not affected: their
// listener always presents the manager's current certificate, so a rotation that
// misses the reissue window costs them nothing.
const minRefreshFloor = 2 * time.Minute

// snpRotationLead is how far before the leaf's own NotAfter the adaptive cadence
// aims a rotation. It is deliberately wider than SNPSigningMargin rather than
// equal to it.
//
// Aiming at the signing deadline reads well and is wrong. That deadline is the
// last instant a receipt can be signed under this evidence, and the platform
// only reissues inside snpReissueWindow, so a rotation scheduled *for* the
// deadline cannot have landed before it: every cycle then contains an interval,
// as long as the attestation round trip, in which the epoch still being served
// is past its deadline — new work refused, in-flight exchanges cut, sessions
// ended — however healthy the platform is. Aiming a lead inside the reissue
// window puts the rotation before the deadline instead, so the signer that
// reaches the deadline is already the newer one and the interval never opens.
// The deadline is not narrowed by this; it stops being reached at all.
//
// The lead has to sit inside snpReissueWindow with room to spare, not on its
// edge, because the window is a mean over nine cycles at second granularity: the
// first attempt is placed ~48s inside it. minRefreshFloor then produces retries
// at 2m that stay inside the window and before the signing deadline, which is
// what carries a rotation that fails the first time — two attempts land before
// the deadline, and the ones after it are still inside the window. A lead wider
// than the window is the failure this exists to prevent: the first attempt is
// handed back the leaf already in service, and the retry grid can step over the
// whole window.
const snpRotationLead = 9 * time.Minute

// serviceRuntime is the mutable half of this process. A receipt names the
// attested key that signed it, so a rotation has to reach the service that
// signs. Everything else the service holds — the whitelist, the transport, the
// sequence store, the credential inbox key — is fixed for the process lifetime,
// so a rotation rebuilds the service around a fresh signer rather than
// restructuring any of it. Service is immutable once NewService returns, which
// is what makes publishing the new one a pointer assignment.
type serviceRuntime struct {
	template tee.Config
	logger   *rootShared.Logger

	// conns is the listener's half of a rotation. The signer moves to the new
	// epoch's key; a connection that already presented the previous epoch's
	// certificate cannot follow it, so it is retired instead.
	conns *epochConnections

	mu      sync.RWMutex
	current *tee.Service
	// adopted is the attested key current signs with. A refresh tick compares
	// the epoch the platform serves against it to tell a rotation to install
	// from the same evidence coming back: on AWS the NitroTPM leaf is reissued
	// only in the last minutes of its life, so a tick that lands earlier asks,
	// gets what is already in service, and has nothing to publish.
	adopted [32]byte
}

// newServiceRuntime builds the runtime for the epoch the process boots on. That
// epoch is published and adopted exactly the way every later rotation publishes
// and adopts, so startup is the first epoch rather than a second code path.
func newServiceRuntime(template tee.Config, epoch platform.Epoch, logger *rootShared.Logger) (*serviceRuntime, error) {
	r := &serviceRuntime{template: template, logger: logger, conns: newEpochConnections()}
	if err := r.publish(epoch); err != nil {
		return nil, err
	}
	return r, r.adopt(epoch)
}

// publish makes an epoch observable outside this process: the evidence a
// hash-only receipt resolves, then the identity an auditor reads. The RA-TLS
// leaf is deliberately NOT published — a rotating epoch presents a new one
// every rotation, which no pin can name (the fixed sim epoch publishes its
// leaf once from main instead).
func (r *serviceRuntime) publish(epoch platform.Epoch) error {
	identity := epoch.Identity()
	// Only the hash-only receipt form needs the store: an inline receipt carries
	// its evidence, so a stored copy is a file nothing resolves.
	if !r.template.Signer.IncludeEvidence {
		if err := shared.RecordTEEEvidence(identity); err != nil {
			return err
		}
	}
	// The identity is the file that describes the *signer*, so it goes last:
	// written any earlier it would name a key the receipts do not yet carry.
	if err := shared.WriteTEEIdentity(identity); err != nil {
		r.logger.Warn("ratls: publish tee identity: " + err.Error())
	}
	return nil
}

// get returns the service signing receipts right now. Handlers go through it on
// every request, so a rotation reaches them without a restart or a reconnect.
func (r *serviceRuntime) get() *tee.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// serving reports whether the runtime is already signing with the epoch whose
// attested key is keyID.
func (r *serviceRuntime) serving(keyID [32]byte) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adopted == keyID
}

// adopt binds the runtime to an epoch: it builds the service that signs with
// that epoch's key and publishes it. Receipts signed from here on name the key
// the TEE presents on its TLS listener, which is the pairing a verifier checks
// when it resolves a receipt's attestation reference.
//
// The adopted signer is also stored in the template's live cell before the
// service pointer swaps, so sessions opened under the previous epoch finish
// with the fresh key instead of the expired one they started with. Either
// order is safe — both epochs are fresh during a healthy rotation — but the
// cell first means no new request can observe the new service while still
// signing with the old key.
func (r *serviceRuntime) adopt(epoch platform.Epoch) error {
	// The template's signer is the startup one and is never rebound, so its
	// options are this process's receipt-form configuration. A rotated key must
	// not change the receipt form, so they carry over to the new signer.
	identity := epoch.Identity()
	signer := proof.NewSigner(epoch)
	signer.IncludeEvidence = r.template.Signer.IncludeEvidence

	template := r.template
	template.Signer = signer
	next, err := tee.NewService(template)
	if err != nil {
		return err
	}
	if template.SignerCell != nil {
		template.SignerCell.Store(signer)
	}
	r.mu.Lock()
	r.current = next
	r.adopted = identity.KeyID
	r.mu.Unlock()
	// Last, and only once the new service is the one handlers will reach: a
	// connection retired before the swap could be replaced by one that still
	// gets answered by the previous epoch, which is the state this is removing.
	r.conns.rotate()
	return nil
}

// runEpochRefresh keeps the attested epoch inside its evidence's validity for as
// long as the process runs, using the shared SEV-SNP cadence: rotate a rotation
// lead before the NitroTPM leaf's NotAfter (snpRotationLead, which places it
// inside the window in which AWS will reissue rather than at the signing
// deadline the reissue necessarily misses), capped at RATLSRefreshIntervalSNP so
// a long-lived leaf does not cause churn, and floored at minRefreshFloor.
//
// The credential inbox key is deliberately untouched here. It is generated once
// at startup and never persisted, so a restart — not a rotation — is what makes
// agents re-register; keeping the two independent is what lets a TEE rotate its
// evidence without invalidating the envelopes providers sealed to it.
func runEpochRefresh(ctx context.Context, refresher epochRefresher, runtime *serviceRuntime, logger *rootShared.Logger) {
	// published remembers whether the last rotation reached the service. The loop
	// asks for the next delay right after a failure, and a Refresh that succeeded
	// leaves the adapter healthy — so without this memory a publication that
	// never landed would wait out the two-hour ceiling while the listener already
	// serves the new key and receipts are still signed by the previous epoch,
	// whose evidence is about to age out.
	published := true
	publish := func() error {
		err := publishEpoch(ctx, refresher, runtime)
		published = err == nil
		return err
	}
	next := func() time.Duration { return nextRefreshDelay(ctx, refresher, published, logger) }
	// The health tracker is intentionally nil: AttestationHealth exists to
	// self-reset a guest whose attestation device has wedged, and this process
	// has no recovery path to drive. A refresh that keeps failing is logged by
	// the loop and shows up as the Hub losing its TLS peer.
	// skipInitial: publish is a full publish, not a cache-priming hook, and this
	// process has already published its startup epoch — main writes the identity
	// and the evidence, then builds the signer. Letting the
	// loop prime it again would rewrite all of that and rebuild the signer on
	// every boot, for a state that is already in place.
	rootShared.RunRATLSRefresh(ctx, refresher, publish, next, nil, logger, true)
}

// publishEpoch makes one rotated epoch the epoch this process serves: what the
// outside world can see about it, then the signer. Publishing precedes signing,
// so the process never signs with an epoch whose evidence never landed — the
// one half a verifier cannot work around. Whichever half fails, the previous
// service keeps signing while its evidence is still outside its signing margin,
// so the failure reads as a rotation that did not happen; inside the margin the
// service refuses new work outright (ErrAttestationStale) rather than signing
// receipts no verifier would accept.
//
// An epoch the runtime already serves is not published again. The platform can
// hand back what it already gave — AWS reissues its NitroTPM leaf only in the
// last minutes of the leaf's life, and the adapter declines to install anything
// it is not newer — and re-adopting it would rewrite the identity and evidence
// for unchanged evidence and retire every live connection to do it. Returning
// early there is also what keeps a publication that failed the first time
// retryable: that epoch differs from the one in service, so the next tick
// installs it.
func publishEpoch(ctx context.Context, refresher epochRefresher, runtime *serviceRuntime) error {
	snapshot, err := refresher.Snapshot(ctx)
	if err != nil {
		return err
	}
	if runtime.serving(snapshot.Identity().KeyID) {
		return nil
	}
	if err := runtime.publish(snapshot); err != nil {
		return err
	}
	return runtime.adopt(snapshot)
}

// nextRefreshDelay picks how long to wait before the next rotation. It reads the
// deadline out of the evidence the TEE is currently presenting, so the cadence
// tracks whatever TTL AWS actually issues rather than a hardcoded guess, and
// clamps the result between the two published bounds: RATLSRefreshIntervalSNP
// caps churn when the leaf is long-lived, and minRefreshFloor keeps a failed
// rotation from waiting out the full ceiling before it retries.
//
// It aims at snpRotationLead before the leaf's own NotAfter — the admission
// deadline, not the signing one — because that is where the platform's reissue
// window is. Aiming at the signing deadline is the mistake this avoids: a
// rotation cannot land there any earlier than the deadline itself, so the old
// epoch is still the live one when the deadline arrives and the deployment has
// a scheduled interval per cycle in which it refuses work, cuts exchanges and
// ends sessions. See snpRotationLead for the full reasoning.
//
// published says whether the last rotation completed. When it did not — the
// refresh succeeded but the epoch never reached the service — the floor applies
// however fresh the evidence looks, because the listener has already rotated and
// the mismatch has to be corrected promptly rather than at the ceiling.
func nextRefreshDelay(ctx context.Context, refresher epochRefresher, published bool, logger *rootShared.Logger) time.Duration {
	if !published {
		return minRefreshFloor
	}
	snapshot, err := refresher.Snapshot(ctx)
	if err != nil {
		// The adapter admits nothing until a rotation succeeds, which is what
		// happens once the epoch it is serving runs out of validity.
		return minRefreshFloor
	}
	admission, tracked := rootShared.SNPAdmissionDeadline(snapshot.Identity().Evidence)
	if !tracked {
		// The adaptive half of the cadence reads the NitroTPM leaf's NotAfter.
		// When that read fails the loop silently falls back to the two-hour
		// ceiling, which for a three-hour AWS leaf sits only thirty minutes
		// inside expiry — no longer adaptive, just short enough to look fine.
		// Say so, because there is no other trace of it until evidence goes stale.
		logger.Warn("evidence carries no readable NitroTPM leaf expiry; refresh cadence falls back to the fixed two-hour ceiling")
	}
	return max(min(time.Until(admission.Add(-snpRotationLead)), rootShared.RATLSRefreshIntervalSNP), minRefreshFloor)
}
