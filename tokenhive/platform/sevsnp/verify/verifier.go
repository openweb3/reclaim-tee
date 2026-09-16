package verify

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/shared/attestverify"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// Verifier implements platform.EvidenceVerifier for AWS SEV-SNP confidential
// VMs. It validates a combined attestation (AMD SEV-SNP report + NitroTPM
// document) through Reclaim's shared verifier, which uses go-sev-guest with the
// embedded AMD root CA bundle (offline, no KDS dependency).
//
// The production evidence path is exercised against real hardware; the trust
// root here is the operator's pinned expected application identity, which must
// name the exact measured enclave image ("snp-app:<sha256 hex>").
type Verifier struct {
	// ExpectedApp is the attested application identity the deployment trusts,
	// formatted "snp-app:<sha256 hex>". Empty disables the assertion, which is
	// appropriate only for development or when the caller binds the image
	// identity separately.
	ExpectedApp string
}

// Platform reports the AWS SEV-SNP platform string.
func (v Verifier) Platform() string { return platform.PlatformAWSSEVSNP }

// CheckEvidence validates inline AWS SEV-SNP attestation evidence: the chip and
// NitroTPM signature chain, the policy and TCB guards, the caller binding, and
// the expected measured image.
func (v Verifier) CheckEvidence(id platform.Identity) error {
	if id.Platform != platform.PlatformAWSSEVSNP {
		return fmt.Errorf("expected platform %q, got %q", platform.PlatformAWSSEVSNP, id.Platform)
	}
	if len(id.Evidence) == 0 {
		return errors.New("aws sev-snp attestation has no evidence")
	}
	if sum := sha256.Sum256(id.Evidence); sum != id.EvidenceHash {
		return errors.New("aws sev-snp evidence hash mismatch")
	}
	// verifyCombined binds the SPKI into the report and proves the NitroTPM
	// document, the AMD policy/TCB, and the cross-cloud measured application
	// identity in one pass. Secure Boot evidence carries a distinct wire tag
	// (the R-signed loader sets SNP_ATTESTATION_TYPE=secure-boot), so dispatch
	// it to the event-log verifier that also proves the R-only boot policy;
	// plain SEV2 evidence goes through the legacy tag.
	var app string
	var err error
	if attestverify.IsSecureBootAttestation(id.Evidence) {
		app, _, err = attestverify.VerifyCombinedSecureBootAttestation(id.Evidence, id.PublicKeyDER)
	} else {
		app, _, err = attestverify.VerifyCombinedSEVSNPAttestation(id.Evidence, id.PublicKeyDER)
	}
	if err != nil {
		return fmt.Errorf("verify aws sev-snp evidence: %w", err)
	}
	if v.ExpectedApp != "" && app != v.ExpectedApp {
		return fmt.Errorf("%w: attested application %q, expected %q",
			proof.ErrAttestationMismatch, app, v.ExpectedApp)
	}
	return nil
}

// CheckEvidenceForDeployment refuses deployment-bound verification. The
// deployment's policy files are loaded at runtime from outside the measured
// bundle, so this verifier cannot attest the supplied digest: accepting any
// evidence here would let two deployments with different policies pass the
// same hardware check. Callers that need the binding must pin the policy
// digest where the platform can prove it.
func (v Verifier) CheckEvidenceForDeployment(id platform.Identity, _ [32]byte) error {
	return errors.New("aws sev-snp evidence cannot attest the deployment policy set: policy files are loaded at runtime, outside the measured bundle")
}
