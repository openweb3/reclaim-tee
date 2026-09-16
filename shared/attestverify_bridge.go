package shared

import (
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared/attestverify"
)

// The attestation verification cluster moved to shared/attestverify so that a
// verifier can be imported without this package's cloud clients: reading a
// SEV-SNP report needs go-sev-guest and go-eventlog, not KMS, Secret Manager
// or CloudWatch, and Go links a package as a whole. These names stay here so
// every existing caller keeps compiling and reading the same way.

type SecureBootResult = attestverify.SecureBootResult

const (
	SEVSNPAppPrefix  = attestverify.SEVSNPAppPrefix
	SEVSNPBasePrefix = attestverify.SEVSNPBasePrefix
)

func ValidateSNPAttestationType() error { return attestverify.ValidateSNPAttestationType() }

const (
	snpAttestationTypeEnv = attestverify.SNPAttestationTypeEnv

	snpAttestTagGCP = attestverify.SNPAttestTagGCP
	snpAttestTagAWS = attestverify.SNPAttestTagAWS

	snpAttestTagSecureBootGCP = attestverify.SNPAttestTagSecureBootGCP
	snpAttestTagSecureBootAWS = attestverify.SNPAttestTagSecureBootAWS
)

func spkiSha256(spkiDER []byte) [32]byte { return attestverify.SPKISHA256(spkiDER) }

func secureBootAttestationEnabled() bool { return attestverify.SecureBootAttestationEnabled() }

func CurrentSNPAttestationType() string { return attestverify.CurrentSNPAttestationType() }

func IsSecureBootAttestation(att []byte) bool { return attestverify.IsSecureBootAttestation(att) }

func LegacyCompatibleSNPAttestation(att []byte) ([]byte, error) {
	return attestverify.LegacyCompatibleSNPAttestation(att)
}

func ClientCompatibleSNPAttestation(attestationType string, att []byte) (string, []byte, error) {
	return attestverify.ClientCompatibleSNPAttestation(attestationType, att)
}

func SecureBootAttestationFromCompatibleWire(att []byte) ([]byte, error) {
	return attestverify.SecureBootAttestationFromCompatibleWire(att)
}

func VerifyCompatibleSecureBootNonceAttestation(att []byte) ([]string, string, *SecureBootResult, error) {
	return attestverify.VerifyCompatibleSecureBootNonceAttestation(att)
}

func VerifyCombinedSecureBootAttestation(att, spkiDER []byte) (string, *SecureBootResult, error) {
	return attestverify.VerifyCombinedSecureBootAttestation(att, spkiDER)
}

func VerifyCombinedSecureBootNonceAttestation(att []byte) ([]string, string, *SecureBootResult, error) {
	return attestverify.VerifyCombinedSecureBootNonceAttestation(att)
}

func VerifyTypedSNPNonceAttestation(attestationType string, att []byte) ([]string, string, error) {
	return attestverify.VerifyTypedSNPNonceAttestation(attestationType, att)
}

func VerifyPeerSNPNonceAttestation(attestationType string, att []byte) ([]string, string, error) {
	return attestverify.VerifyPeerSNPNonceAttestation(attestationType, att)
}

func VerifyCombinedSEVSNPAttestation(att, spkiDER []byte) (string, string, error) {
	return attestverify.VerifyCombinedSEVSNPAttestation(att, spkiDER)
}

func VerifyCombinedSEVSNPNonceAttestation(att []byte) ([]string, string, string, error) {
	return attestverify.VerifyCombinedSEVSNPNonceAttestation(att)
}

func VerifyCombinedGCPAttestation(att, spkiDER []byte) (string, string, error) {
	return attestverify.VerifyCombinedGCPAttestation(att, spkiDER)
}

func VerifyCombinedAWSAttestation(att, spkiDER []byte) (string, string, error) {
	return attestverify.VerifyCombinedAWSAttestation(att, spkiDER)
}

func SNPNitroLeafNotAfter(attestation []byte) (time.Time, bool) {
	return attestverify.SNPNitroLeafNotAfter(attestation)
}
