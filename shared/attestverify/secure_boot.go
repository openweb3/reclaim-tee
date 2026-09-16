package attestverify

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

const (
	secureBootEventLogPath = "/run/reclaim-secure-boot-eventlog"
	maxSecureBootEventLog  = 1 << 20
)

// The deployment release-signing public key is the stable cross-cloud trust
// root. Certificates in UEFI db may be reissued without changing this key.
//
//go:embed secure_boot_release_pub.pem
var secureBootReleasePublicKeyPEM []byte

// SecureBootResult describes the event-log proof layered on top of the current
// combined SEV2 attestation.
type SecureBootResult struct {
	EventLogBytes          int
	VerifiedEvents         int
	PostSeparatorUses      int
	ReleasePublicKeySHA256 string
}

type secureBootAuthorityPolicy struct {
	enabled                bool
	permittedKeys          int
	permittedHashes        int
	releaseDBEntries       int
	releaseDBXEntries      int
	preAuthorities         int
	postAuthorities        int
	releasePostAuthorities int
}

// IsSecureBootAttestation reports whether att uses one of the distinct Secure
// Boot wire tags. Old SEV2 verifiers reject these tags instead of silently
// accepting evidence whose additional policy they do not understand.
func IsSecureBootAttestation(att []byte) bool {
	return len(att) != 0 && (att[0] == snpAttestTagSecureBootGCP || att[0] == snpAttestTagSecureBootAWS)
}

// LegacyCompatibleSNPAttestation changes only the wire tag of a Secure Boot
// envelope. The provider evidence and event log stay intact. This lets old
// clients run their SEV2 prerequisite while updated verifiers use the signed
// payload generation marker to require the additional Secure Boot checks.
func LegacyCompatibleSNPAttestation(att []byte) ([]byte, error) {
	if len(att) == 0 {
		return nil, fmt.Errorf("empty SNP attestation")
	}
	out := append([]byte(nil), att...)
	switch out[0] {
	case snpAttestTagGCP, snpAttestTagAWS:
		return out, nil
	case snpAttestTagSecureBootGCP:
		out[0] = snpAttestTagGCP
	case snpAttestTagSecureBootAWS:
		out[0] = snpAttestTagAWS
	default:
		return nil, fmt.Errorf("unknown SNP attestation tag 0x%02x", out[0])
	}
	return out, nil
}

// ClientCompatibleSNPAttestation returns the report type and bytes exposed to
// clients. Secure Boot evidence uses the legacy SEV-SNP outer type and tag;
// its generation is asserted separately inside the signed TEE output body.
func ClientCompatibleSNPAttestation(attestationType string, att []byte) (string, []byte, error) {
	switch attestationType {
	case AttestationTypeSEVSNP:
		if IsSecureBootAttestation(att) {
			return "", nil, fmt.Errorf("SEV-SNP client report carries a Secure Boot tag")
		}
		wire, err := LegacyCompatibleSNPAttestation(att)
		return AttestationTypeSEVSNP, wire, err
	case AttestationTypeSecureBoot:
		wire, err := LegacyCompatibleSNPAttestation(att)
		return AttestationTypeSEVSNP, wire, err
	default:
		return "", nil, fmt.Errorf("unsupported SNP attestation type: %s", attestationType)
	}
}

// SecureBootAttestationFromCompatibleWire restores the Secure Boot tag on a
// legacy-compatible envelope. Callers must invoke this only when an
// authenticated protocol value requires Secure Boot; the legacy tag alone is
// intentionally not a generation signal.
func SecureBootAttestationFromCompatibleWire(att []byte) ([]byte, error) {
	if len(att) == 0 {
		return nil, fmt.Errorf("empty SNP attestation")
	}
	out := append([]byte(nil), att...)
	switch out[0] {
	case snpAttestTagSecureBootGCP, snpAttestTagSecureBootAWS:
		return out, nil
	case snpAttestTagGCP:
		out[0] = snpAttestTagSecureBootGCP
	case snpAttestTagAWS:
		out[0] = snpAttestTagSecureBootAWS
	default:
		return nil, fmt.Errorf("unknown SNP attestation tag 0x%02x", out[0])
	}
	return out, nil
}

// VerifyCompatibleSecureBootNonceAttestation verifies Secure Boot evidence
// carried under either the new tag or the legacy-compatible tag. The caller is
// responsible for authenticating the Secure Boot generation marker first or
// verifying the signature that covers it immediately afterward.
func VerifyCompatibleSecureBootNonceAttestation(att []byte) (nonces []string, app string, result *SecureBootResult, err error) {
	secure, err := SecureBootAttestationFromCompatibleWire(att)
	if err != nil {
		return nil, "", nil, err
	}
	return VerifyCombinedSecureBootNonceAttestation(secure)
}

// VerifyCombinedSecureBootAttestation verifies the existing SPKI-bound SEV2
// proof first, then replays the raw firmware event log against provider-quoted
// PCR 4/7/11 values and requires an R-only Secure Boot policy.
func VerifyCombinedSecureBootAttestation(att, spkiDER []byte) (app string, result *SecureBootResult, err error) {
	env, app, _, result, err := verifyCombinedSecureBoot(att, spkiDER)
	if err != nil {
		return "", nil, err
	}
	if len(env.Nonces) != 0 {
		return "", nil, fmt.Errorf("SPKI-bound Secure Boot attestation unexpectedly carries nonces")
	}
	return app, result, nil
}

// VerifyCombinedSecureBootNonceAttestation verifies the claim-path Secure Boot
// evidence and returns the hardware-bound presentable nonces and app identity.
func VerifyCombinedSecureBootNonceAttestation(att []byte) (nonces []string, app string, result *SecureBootResult, err error) {
	if len(att) < 1 {
		return nil, "", nil, fmt.Errorf("empty Secure Boot attestation")
	}
	var peek combinedEnvelope
	if e := cbor.Unmarshal(att[1:], &peek); e != nil {
		return nil, "", nil, fmt.Errorf("decode Secure Boot envelope: %w", e)
	}
	if len(peek.Nonces) == 0 {
		return nil, "", nil, fmt.Errorf("Secure Boot nonce attestation carries no nonces")
	}
	_, app, _, result, err = verifyCombinedSecureBoot(att, snpNonceCommitment(peek.Nonces))
	if err != nil {
		return nil, "", nil, err
	}
	return peek.Nonces, app, result, nil
}

// VerifyTypedSNPNonceAttestation dispatches an app-layer claim proof by its
// protocol type. Keep this dispatch shared by TEE_K and TEE_T so a new SNP
// generation cannot be enabled for one peer-verification direction only.
func VerifyTypedSNPNonceAttestation(attestationType string, att []byte) (nonces []string, app string, err error) {
	switch attestationType {
	case AttestationTypeSEVSNP:
		if IsSecureBootAttestation(att) {
			return nil, "", fmt.Errorf("attestation type %q carries Secure Boot evidence", attestationType)
		}
		nonces, app, _, err = VerifyCombinedSEVSNPNonceAttestation(att)
		return nonces, app, err
	case AttestationTypeSecureBoot:
		if !IsSecureBootAttestation(att) {
			return nil, "", fmt.Errorf("attestation type %q does not carry Secure Boot evidence", attestationType)
		}
		nonces, app, _, err = VerifyCombinedSecureBootNonceAttestation(att)
		return nonces, app, err
	default:
		return nil, "", fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}

// VerifyPeerSNPNonceAttestation additionally requires the control peer to use
// the local TEE generation. Client-facing certificates deliberately use the
// legacy-compatible tag, so the control attestation is the generation boundary
// that prevents a Secure Boot half from pairing with an SEV2 half.
func VerifyPeerSNPNonceAttestation(attestationType string, att []byte) (nonces []string, app string, err error) {
	want := CurrentSNPAttestationType()
	if attestationType != want {
		return nil, "", fmt.Errorf("peer attestation generation %q does not match local %q mode", attestationType, want)
	}
	return VerifyTypedSNPNonceAttestation(attestationType, att)
}

// verifyCombinedSecureBoot preserves the current SEV2 verifier as the first
// gate by translating only the new tag to its legacy cloud tag. It then obtains
// the PCR values from the already-authenticated provider evidence and verifies
// the new event-log policy.
func verifyCombinedSecureBoot(att, bound []byte) (env combinedEnvelope, app, base string, result *SecureBootResult, err error) {
	legacyTag, bank, err := secureBootLegacyTagAndBank(att)
	if err != nil {
		return env, "", "", nil, err
	}
	legacy := append([]byte{legacyTag}, att[1:]...)
	env, app, base, err = verifyCombined(legacy, bound)
	if err != nil {
		return env, "", "", nil, fmt.Errorf("SEV2 prerequisite: %w", err)
	}

	var eventLog []byte
	var pcrs map[uint32][]byte
	switch att[0] {
	case snpAttestTagSecureBootGCP:
		var tpmAtt tpmpb.Attestation
		if err := proto.Unmarshal(env.TPM, &tpmAtt); err != nil {
			return env, "", "", nil, fmt.Errorf("unmarshal GCP TPM attestation: %w", err)
		}
		akCert, err := x509.ParseCertificate(tpmAtt.GetAkCert())
		if err != nil {
			return env, "", "", nil, fmt.Errorf("parse GCP AK certificate: %w", err)
		}
		nonce := sha256.Sum256(bound)
		pcrs, err = verifiedPCRValues(&tpmAtt, akCert.PublicKey, nonce[:])
		if err != nil {
			return env, "", "", nil, err
		}
		eventLog = tpmAtt.GetEventLog()
	case snpAttestTagSecureBootAWS:
		_, pcrs, _, err = verifyNitroTPMDocument(env.NitroTPM)
		if err != nil {
			return env, "", "", nil, err
		}
		eventLog = env.EventLog
	}

	result, err = verifyReleaseSecureBootEventLog(eventLog, pcrs, bank)
	if err != nil {
		return env, "", "", nil, err
	}
	return env, app, base, result, nil
}

func secureBootLegacyTagAndBank(att []byte) (byte, crypto.Hash, error) {
	if len(att) < 1 {
		return 0, 0, fmt.Errorf("empty Secure Boot attestation")
	}
	switch att[0] {
	case snpAttestTagSecureBootGCP:
		return snpAttestTagGCP, crypto.SHA256, nil
	case snpAttestTagSecureBootAWS:
		return snpAttestTagAWS, crypto.SHA384, nil
	default:
		return 0, 0, fmt.Errorf("unknown Secure Boot attestation tag 0x%02x", att[0])
	}
}

func verifyReleaseSecureBootEventLog(raw []byte, pcrs map[uint32][]byte, bank crypto.Hash) (*SecureBootResult, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("Secure Boot attestation carries no event log")
	}
	if len(raw) > maxSecureBootEventLog {
		return nil, fmt.Errorf("Secure Boot event log is %d bytes; maximum is %d", len(raw), maxSecureBootEventLog)
	}

	mrs := make([]register.MR, 0, 3)
	for _, index := range []int{4, 7, 11} {
		digest := pcrs[uint32(index)]
		if len(digest) != bank.Size() {
			return nil, fmt.Errorf("provider quote missing %s PCR %d", bank, index)
		}
		mrs = append(mrs, register.PCR{Index: index, Digest: digest, DigestAlg: bank})
	}
	events, err := tcg.ParseAndReplay(raw, mrs, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		return nil, fmt.Errorf("Secure Boot event-log replay: %w", err)
	}
	state, err := extract.ParseSecurebootStateLegacy(events)
	if err != nil {
		return nil, fmt.Errorf("Secure Boot state: %w", err)
	}

	releaseSPKI, err := releasePublicKeySPKI()
	if err != nil {
		return nil, err
	}
	dbMatches, err := countCertificatesWithSPKI(state.PermittedKeys, releaseSPKI)
	if err != nil {
		return nil, err
	}
	dbxMatches, err := countCertificatesWithSPKI(state.ForbiddenKeys, releaseSPKI)
	if err != nil {
		return nil, err
	}
	postMatches, err := countCertificatesWithSPKI(state.PostSeparatorAuthority, releaseSPKI)
	if err != nil {
		return nil, err
	}

	policy := secureBootAuthorityPolicy{
		enabled:                state.Enabled,
		permittedKeys:          len(state.PermittedKeys),
		permittedHashes:        len(state.PermittedHashes),
		releaseDBEntries:       dbMatches,
		releaseDBXEntries:      dbxMatches,
		preAuthorities:         len(state.PreSeparatorAuthority),
		postAuthorities:        len(state.PostSeparatorAuthority),
		releasePostAuthorities: postMatches,
	}
	if !secureBootAuthorityPolicyOK(policy) {
		return nil, fmt.Errorf("event log does not prove an R-only post-separator Secure Boot policy")
	}

	fingerprint := sha256.Sum256(releaseSPKI)
	return &SecureBootResult{
		EventLogBytes:          len(raw),
		VerifiedEvents:         len(events),
		PostSeparatorUses:      postMatches,
		ReleasePublicKeySHA256: fmt.Sprintf("%x", fingerprint[:]),
	}, nil
}

func secureBootAuthorityPolicyOK(policy secureBootAuthorityPolicy) bool {
	return policy.enabled &&
		policy.permittedKeys == 1 &&
		policy.permittedHashes == 0 &&
		policy.releaseDBEntries == 1 &&
		policy.releaseDBXEntries == 0 &&
		policy.preAuthorities == 0 &&
		policy.postAuthorities > 0 &&
		policy.releasePostAuthorities == policy.postAuthorities
}

func releasePublicKeySPKI() ([]byte, error) {
	block, _ := pem.Decode(secureBootReleasePublicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("embedded Secure Boot release public key is invalid PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse embedded Secure Boot release public key: %w", err)
	}
	return block.Bytes, nil
}

func countCertificatesWithSPKI(certs []x509.Certificate, trustedSPKI []byte) (int, error) {
	count := 0
	for i := range certs {
		spki, err := x509.MarshalPKIXPublicKey(certs[i].PublicKey)
		if err != nil {
			return 0, fmt.Errorf("marshal Secure Boot certificate public key: %w", err)
		}
		if bytes.Equal(spki, trustedSPKI) {
			count++
		}
	}
	return count, nil
}
