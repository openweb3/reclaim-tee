package attestverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"
)

// Tags prefixing the SEV-SNP cert-extension payload so the verifier can dispatch
// per cloud (GCP carries a go-tpm-tools Attestation proto; AWS carries a CBOR
// envelope of the NitroTPM document + the SEV report).
const (
	snpAttestTagGCP           = SNPAttestTagGCP
	snpAttestTagAWS           = SNPAttestTagAWS
	snpAttestTagSecureBootGCP = SNPAttestTagSecureBootGCP
	snpAttestTagSecureBootAWS = SNPAttestTagSecureBootAWS
)

// AWS Nitro Enclaves root CA (pinned trust anchor for the NitroTPM attestation
// document's cabundle). NitroTPM uses the same Nitro Attestation PKI as Enclaves.
//
//go:embed aws_nitro_root.pem
var awsNitroRootPEM []byte

// combinedEnvelope is the CBOR cert-extension payload (after the 1-byte cloud
// tag) for both clouds. AppHash = sha256(app bundle), the cross-cloud payload
// identity; the verifier proves it against PCR 8. TPM is the go-tpm-tools
// Attestation proto (GCP); NitroTPM + SEV are the AWS evidence.
type combinedEnvelope struct {
	AppHash  []byte `cbor:"app"`
	TPM      []byte `cbor:"tpm,omitempty"`
	NitroTPM []byte `cbor:"nitrotpm,omitempty"`
	SEV      []byte `cbor:"sev,omitempty"`
	// EventLog is the uncompressed raw TCG firmware event log on AWS. GCP
	// carries the same bytes in the standard go-tpm-tools Attestation.event_log
	// field. The Secure Boot verifier requires it; legacy SEV2 readers ignore it.
	EventLog []byte `cbor:"eventlog,omitempty"`
	// SEV2 is the same-guest AWS proof. Its report_data commits to the exact
	// signed NitroTPM document, AppHash, and caller binding. SEV remains present
	// for clients released before SEV2, but current verifiers require SEV2.
	SEV2 []byte `cbor:"sev2,omitempty"`
	// Nonces, when present, are the presentable claims the attestation binds
	// (e.g. the signing-key + SPKI nonces), the SEV-SNP analogue of a CS JWT
	// eat_nonce. The hardware binding then commits snpNonceCommitment(Nonces)
	// rather than a raw SPKI. Empty for the RA-TLS cert-extension attestation,
	// which binds the SPKI directly.
	Nonces []string `cbor:"nonces,omitempty"`
}

const awsCombinedV2Domain = "reclaim/aws-combined-attestation/v2\x00"

// awsCombinedV2ReportData binds the AMD report to the exact NitroTPM evidence,
// rather than only to caller-controlled data that another guest can replay.
// Length-prefix every variable field so the transcript has one encoding.
func awsCombinedV2ReportData(bound, appHash, nitroTPM []byte) [sha512.Size]byte {
	h := sha512.New()
	h.Write([]byte(awsCombinedV2Domain))
	var n [8]byte
	for _, field := range [][]byte{bound, appHash, nitroTPM} {
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var out [sha512.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// snpNonceCommitment is the length-prefixed hash of the presentable nonce list.
// Producer and verifier compute it identically; binding it in report_data (which
// the AMD/vTPM key signs) is what makes the carried Nonces unforgeable.
func snpNonceCommitment(nonces []string) []byte {
	h := sha256.New()
	var n8 [8]byte
	for _, n := range nonces {
		binary.BigEndian.PutUint64(n8[:], uint64(len(n)))
		h.Write(n8[:])
		h.Write([]byte(n))
	}
	return h.Sum(nil)
}

// Identity prefixes: the cross-cloud app/payload hash (surfaced in the signed
// claim, like a CS image_digest) and the per-cloud base UKI hash (PCR 11,
// pinned against known values).
const (
	SEVSNPAppPrefix  = "snp-app:"
	SEVSNPBasePrefix = "snp-base:"
)

// VerifyCombinedSEVSNPAttestation dispatches a tagged SEV-SNP attestation to the
// per-cloud verifier and returns (app, base) code identities: app =
// snp-app:<sha256(bundle)> (cross-cloud), base = snp-base:<PCR11> (per-cloud).
func VerifyCombinedSEVSNPAttestation(att, spkiDER []byte) (app, base string, err error) {
	env, app, base, err := verifyCombined(att, spkiDER)
	if err != nil {
		return "", "", err
	}
	// Domain separation: an SPKI-bound attestation (RA-TLS cert / register) must
	// not carry a presentable nonce list — that is the app-layer claim variant.
	if len(env.Nonces) != 0 {
		return "", "", fmt.Errorf("SPKI-bound attestation unexpectedly carries nonces")
	}
	return app, base, nil
}

// VerifyCombinedSEVSNPNonceAttestation verifies the app-layer claim variant: the
// hardware binds snpNonceCommitment(env.Nonces), so the returned nonces are
// AMD/vTPM-attested and presentable (the SEV-SNP analogue of reading a CS JWT
// eat_nonce). Returns the nonce list plus the (app, base) code identities.
func VerifyCombinedSEVSNPNonceAttestation(att []byte) (nonces []string, app, base string, err error) {
	if len(att) < 1 {
		return nil, "", "", fmt.Errorf("empty SEV-SNP attestation")
	}
	var peek combinedEnvelope
	if e := cbor.Unmarshal(att[1:], &peek); e != nil {
		return nil, "", "", fmt.Errorf("decode SEV-SNP envelope: %w", e)
	}
	if len(peek.Nonces) == 0 {
		return nil, "", "", fmt.Errorf("nonce attestation carries no nonces")
	}
	_, app, base, err = verifyCombined(att, snpNonceCommitment(peek.Nonces))
	if err != nil {
		return nil, "", "", err
	}
	return peek.Nonces, app, base, nil
}

// VerifyCombinedGCPAttestation and VerifyCombinedAWSAttestation verify a
// tag-less per-cloud envelope bound to spkiDER. Thin wrappers retained for
// hardware fixtures and the nitroprobe tool; production dispatches via
// VerifyCombinedSEVSNPAttestation.
func VerifyCombinedGCPAttestation(attBytes, spkiDER []byte) (app, base string, err error) {
	var env combinedEnvelope
	if e := cbor.Unmarshal(attBytes, &env); e != nil {
		return "", "", fmt.Errorf("decode GCP envelope: %w", e)
	}
	return verifyCombinedGCP(env, spkiDER)
}

func VerifyCombinedAWSAttestation(attBytes, spkiDER []byte) (app, base string, err error) {
	var env combinedEnvelope
	if e := cbor.Unmarshal(attBytes, &env); e != nil {
		return "", "", fmt.Errorf("decode AWS envelope: %w", e)
	}
	return verifyCombinedAWS(env, spkiDER)
}

// verifyCombined decodes the tagged envelope and runs the per-cloud verifier
// against the given bound blob (raw SPKI for the cert path, the nonce
// commitment for the claim path). It returns the decoded envelope so callers
// can apply path-specific checks (e.g. Nonces presence).
func verifyCombined(att, bound []byte) (env combinedEnvelope, app, base string, err error) {
	if len(att) < 1 {
		return env, "", "", fmt.Errorf("empty SEV-SNP attestation")
	}
	if e := cbor.Unmarshal(att[1:], &env); e != nil {
		return env, "", "", fmt.Errorf("decode SEV-SNP envelope: %w", e)
	}
	switch att[0] {
	case snpAttestTagGCP:
		app, base, err = verifyCombinedGCP(env, bound)
	case snpAttestTagAWS:
		app, base, err = verifyCombinedAWS(env, bound)
	default:
		err = fmt.Errorf("unknown SEV-SNP attestation tag 0x%02x", att[0])
	}
	return env, app, base, err
}

// expectedPCR8 is the PCR 8 value the loader produces for appHash in bank alg:
// it extends PCR 8 (pristine 0) once with alg(appHash), so
// PCR8 = alg(0^algSize || alg(appHash)). Lets the verifier prove a single
// cross-cloud appHash against the per-cloud, per-bank PCR 8.
func expectedPCR8(appHash []byte, newHash func() hash.Hash) []byte {
	inner := newHash()
	inner.Write(appHash)
	id := inner.Sum(nil)
	outer := newHash()
	outer.Write(make([]byte, len(id)))
	outer.Write(id)
	return outer.Sum(nil)
}

// appBaseIdentity formats the (app, base) identity strings from the proven
// appHash and the attested PCR 11.
func appBaseIdentity(appHash, pcr11 []byte) (string, string) {
	return SEVSNPAppPrefix + hex.EncodeToString(appHash), SEVSNPBasePrefix + hex.EncodeToString(pcr11)
}

// verifyCombinedAWS verifies the NitroTPM code identity and the AMD policy.
// SEV2 binds the exact signed NitroTPM document, AppHash, and caller value. The
// legacy report remains in the envelope for old readers; current readers ignore
// it and require the same-guest SEV2 proof.
func verifyCombinedAWS(env combinedEnvelope, bound []byte) (app, base string, err error) {
	if len(env.SEV2) == 0 {
		return "", "", fmt.Errorf("AWS combined attestation has no same-guest v2 proof")
	}
	bind := sha512.Sum512(bound)

	// (1) NitroTPM document: COSE_Sign1 -> Nitro root, user_data binding.
	_, pcrs, userData, err := verifyNitroTPMDocument(env.NitroTPM)
	if err != nil {
		return "", "", err
	}
	if subtle.ConstantTimeCompare(userData, bind[:]) != 1 {
		return "", "", fmt.Errorf("NitroTPM user_data does not bind the SPKI")
	}

	// (2) Verify the same-guest report. Producers still carry the legacy report
	// for old clients, but it is not part of the current verifier's trust path.
	v2 := awsCombinedV2ReportData(bound, env.AppHash, env.NitroTPM)
	if err := verifyAWSSEVBinding(env.SEV2, v2[:], "v2"); err != nil {
		return "", "", err
	}

	// (3) Prove the claimed cross-cloud appHash against PCR 8 (SHA-384 bank on
	// AWS); PCR 11 is the per-cloud base.
	pcr8, pcr11 := pcrs[combinedAppPCR], pcrs[combinedBasePCR]
	if len(pcr8) == 0 || len(pcr11) == 0 {
		return "", "", fmt.Errorf("NitroTPM doc missing PCR %d/%d", combinedAppPCR, combinedBasePCR)
	}
	if subtle.ConstantTimeCompare(pcr8, expectedPCR8(env.AppHash, sha512.New384)) != 1 {
		return "", "", fmt.Errorf("PCR 8 does not match claimed app hash")
	}
	app, base = appBaseIdentity(env.AppHash, pcr11)
	return app, base, nil
}

func verifyAWSSEVBinding(raw, expected []byte, label string) error {
	sevAtt := &spb.Attestation{}
	if err := proto.Unmarshal(raw, sevAtt); err != nil {
		return fmt.Errorf("unmarshal AWS %s SEV report: %w", label, err)
	}
	opts := verify.DefaultOptions()
	opts.DisableCertFetching = true
	roots, err := amdTrustedRoots()
	if err != nil {
		return fmt.Errorf("AMD roots: %w", err)
	}
	opts.TrustedRoots = roots
	if err := verify.SnpAttestation(sevAtt, opts); err != nil {
		return fmt.Errorf("AWS %s SEV-SNP chain verification failed: %w", label, err)
	}
	if err := validateSnpAttestationPolicy(sevAtt); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(sevAtt.GetReport().GetReportData(), expected) != 1 {
		return fmt.Errorf("AWS %s SEV report_data binding mismatch", label)
	}
	return nil
}

// coseSign1 is a COSE_Sign1 structure (untagged CBOR 4-array).
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// SNPNitroLeafNotAfter extracts the NitroTPM leaf certificate's NotAfter from an
// AWS combined attestation (1-byte AWS tag + CBOR envelope). The NitroTPM leaf
// is the short-lived cert that bounds attestation freshness; callers use this to
// schedule their own refresh before it expires, so the cadence tracks whatever
// TTL AWS actually issues instead of a hardcoded guess. ok=false for non-AWS
// attestations (no short-lived leaf). No signature/chain check — this only reads
// the expiry of a doc the caller just generated, never to trust it.
func SNPNitroLeafNotAfter(attestation []byte) (time.Time, bool) {
	if len(attestation) < 1 || (attestation[0] != snpAttestTagAWS && attestation[0] != snpAttestTagSecureBootAWS) {
		return time.Time{}, false
	}
	var env combinedEnvelope
	if err := cbor.Unmarshal(attestation[1:], &env); err != nil || len(env.NitroTPM) == 0 {
		return time.Time{}, false
	}
	var cose coseSign1
	if err := cbor.Unmarshal(env.NitroTPM, &cose); err != nil {
		return time.Time{}, false
	}
	var doc nitroAttestationDoc
	if err := cbor.Unmarshal(cose.Payload, &doc); err != nil {
		return time.Time{}, false
	}
	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return time.Time{}, false
	}
	return leaf.NotAfter, true
}

// nitroAttestationDoc is the NitroTPM attestation document payload.
type nitroAttestationDoc struct {
	ModuleID    string            `cbor:"module_id"`
	Digest      string            `cbor:"digest"`
	Timestamp   uint64            `cbor:"timestamp"`
	PCRs        map[uint32][]byte `cbor:"nitrotpm_pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// verifyNitroTPMDocument verifies the COSE_Sign1 signature (ES384) with the
// leaf cert, chains the leaf -> cabundle -> pinned Nitro root, and returns the
// parsed doc, its PCR map, and user_data.
func verifyNitroTPMDocument(docBytes []byte) (*nitroAttestationDoc, map[uint32][]byte, []byte, error) {
	var cose coseSign1
	if err := cbor.Unmarshal(docBytes, &cose); err != nil {
		return nil, nil, nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	var doc nitroAttestationDoc
	if err := cbor.Unmarshal(cose.Payload, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("decode attestation doc: %w", err)
	}

	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	if err := verifyNitroChain(leaf, doc.CABundle); err != nil {
		return nil, nil, nil, fmt.Errorf("NitroTPM cert chain: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("NitroTPM leaf is not ECDSA")
	}

	// COSE_Sign1 ToBeSigned = ["Signature1", protected(bstr), external_aad h'', payload(bstr)].
	tbs, err := cbor.Marshal([]any{"Signature1", cose.Protected, []byte{}, cose.Payload})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode Sig_structure: %w", err)
	}
	digest := sha512.Sum384(tbs)
	if len(cose.Signature) != 96 {
		return nil, nil, nil, fmt.Errorf("COSE signature is %d bytes, want 96 (ES384)", len(cose.Signature))
	}
	r := new(big.Int).SetBytes(cose.Signature[:48])
	s := new(big.Int).SetBytes(cose.Signature[48:])
	if !ecdsa.Verify(leafPub, digest[:], r, s) {
		return nil, nil, nil, fmt.Errorf("COSE_Sign1 signature invalid")
	}
	return &doc, doc.PCRs, doc.UserData, nil
}

func verifyNitroChain(leaf *x509.Certificate, cabundle [][]byte) error {
	block, _ := pem.Decode(awsNitroRootPEM)
	if block == nil {
		return fmt.Errorf("parse embedded Nitro root PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse embedded Nitro root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	for _, der := range cabundle {
		if c, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
