package attestverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"fmt"

	"github.com/google/go-sev-guest/verify"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	tpmprotopb "github.com/google/go-tpm-tools/proto/tpm"
	gquote "github.com/google/go-tpm-tools/quote"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// Google's vTPM EK/AK CA (DER). The GCE attestation key cert chains to these;
// trusting them is what proves the AK is a genuine, restricted GCE vTPM key
// (so its PCR quote can't be forged). This is the residual Google trust root
// for code identity on GCP — unavoidable on a managed cloud.
//
//go:embed gcp_vtpm_ca_root.crt
var gcpVTPMRootDER []byte

//go:embed gcp_vtpm_ca_intermediate.crt
var gcpVTPMIntermediateDER []byte

// PCRs holding the two-tier code identity: PCR 8 = app bundle (loader-measured),
// PCR 11 = base UKI (sd-stub-measured).
const (
	combinedAppPCR  = 8
	combinedBasePCR = 11
)

// VerifyCombinedGCPAttestation verifies the GCP envelope (go-tpm-tools
// Attestation proto + claimed appHash) and returns (app, base) identities. It
// checks: (1) AK cert -> Google vTPM root, matches AkPub; (2) SEV report -> AMD
// root; (3) report_data == sha512(AkPub||SPKI) anti-splice binding; (4) the
// AK-signed quote over the PCRs (nonce sha256(SPKI)); (5) PCR 8 (SHA-256 bank)
// matches the claimed cross-cloud appHash. PCR 11 is the per-cloud base.
func verifyCombinedGCP(env combinedEnvelope, bound []byte) (app, base string, err error) {
	att := &tpmpb.Attestation{}
	if err := proto.Unmarshal(env.TPM, att); err != nil {
		return "", "", fmt.Errorf("unmarshal go-tpm-tools attestation: %w", err)
	}

	// (1) AK cert -> Google vTPM roots, and AkPub matches the cert.
	akCert, err := x509.ParseCertificate(att.GetAkCert())
	if err != nil {
		return "", "", fmt.Errorf("parse AK cert: %w", err)
	}
	if err := verifyAKCertChain(akCert, att.GetIntermediateCerts()); err != nil {
		return "", "", fmt.Errorf("AK cert not Google-rooted: %w", err)
	}
	akArea, err := tpm2.DecodePublic(att.GetAkPub())
	if err != nil {
		return "", "", fmt.Errorf("decode AkPub: %w", err)
	}
	akKey, err := akArea.Key()
	if err != nil {
		return "", "", fmt.Errorf("AkPub key: %w", err)
	}
	certKey, ok := akCert.PublicKey.(*ecdsa.PublicKey)
	akPubKey, ok2 := akKey.(*ecdsa.PublicKey)
	if !ok || !ok2 || !certKey.Equal(akPubKey) {
		return "", "", fmt.Errorf("AkPub does not match AK cert")
	}

	// (2) SEV-SNP report -> AMD root (genuine SEV-SNP hardware).
	sevAtt := att.GetSevSnpAttestation()
	if sevAtt == nil {
		return "", "", fmt.Errorf("attestation carries no SEV-SNP report")
	}
	opts := verify.DefaultOptions()
	opts.DisableCertFetching = true
	roots, err := amdTrustedRoots()
	if err != nil {
		return "", "", fmt.Errorf("AMD roots: %w", err)
	}
	opts.TrustedRoots = roots
	if err := verify.SnpAttestation(sevAtt, opts); err != nil {
		return "", "", fmt.Errorf("SEV-SNP chain verification failed: %w", err)
	}
	if err := validateSnpAttestationPolicy(sevAtt); err != nil {
		return "", "", err
	}

	// (3) Binding: report_data == sha512(AkPub || bound), where bound is the SPKI
	// (cert path) or the nonce commitment (claim path).
	bind := CombinedReportData(att.GetAkPub(), bound)
	if subtle.ConstantTimeCompare(sevAtt.GetReport().GetReportData(), bind[:]) != 1 {
		return "", "", fmt.Errorf("report_data does not bind AK+bound (splice attempt?)")
	}

	// (4) vTPM quote: signed by the AK over the PCRs, nonce = sha256(bound).
	nonce := sha256.Sum256(bound)
	pcr8, pcr11, err := verifiedPCRs(att, akCert.PublicKey, nonce[:])
	if err != nil {
		return "", "", err
	}

	// (5) Prove the claimed cross-cloud appHash against PCR 8 (SHA-256 bank on GCP).
	if subtle.ConstantTimeCompare(pcr8, expectedPCR8(env.AppHash, sha256.New)) != 1 {
		return "", "", fmt.Errorf("PCR 8 does not match claimed app hash")
	}
	app, base = appBaseIdentity(env.AppHash, pcr11)
	return app, base, nil
}

// verifiedPCRs finds the SHA-256 quote, verifies its signature + nonce + PCR
// digest under akPub (via go-tpm-tools' quote.Verify), and returns the trusted
// PCR 8 and PCR 11 values.
func verifiedPCRs(att *tpmpb.Attestation, akPub any, nonce []byte) (pcr8, pcr11 []byte, err error) {
	m, err := verifiedPCRValues(att, akPub, nonce)
	if err != nil {
		return nil, nil, err
	}
	pcr8, pcr11 = m[combinedAppPCR], m[combinedBasePCR]
	if len(pcr8) == 0 || len(pcr11) == 0 {
		return nil, nil, fmt.Errorf("quote missing PCR %d/%d", combinedAppPCR, combinedBasePCR)
	}
	return pcr8, pcr11, nil
}

// verifiedPCRValues returns the full trusted SHA-256 PCR map. The legacy SEV2
// path reads PCR 8/11 from it; Secure Boot additionally replays PCR 4/7/11.
func verifiedPCRValues(att *tpmpb.Attestation, akPub any, nonce []byte) (map[uint32][]byte, error) {
	for _, q := range att.GetQuotes() {
		if q.GetPcrs().GetHash() != tpmprotopb.HashAlgo_SHA256 {
			continue
		}
		if err := gquote.Verify(q, akPub, nonce); err != nil {
			return nil, fmt.Errorf("quote verification failed: %w", err)
		}
		return q.GetPcrs().GetPcrs(), nil
	}
	return nil, fmt.Errorf("no SHA-256 vTPM quote in attestation")
}

// verifyAKCertChain checks akCert chains to the embedded Google vTPM root, using
// the attestation-carried intermediates (GCE intermediates are regionalized +
// rotated; the producer fetches and embeds them). Only the root is pinned.
func verifyAKCertChain(akCert *x509.Certificate, carriedInters [][]byte) error {
	root, err := x509.ParseCertificate(gcpVTPMRootDER)
	if err != nil {
		return fmt.Errorf("parse embedded root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	// The known intermediate (best-effort) plus whatever the attestation carries.
	if inter, err := x509.ParseCertificate(gcpVTPMIntermediateDER); err == nil {
		inters.AddCert(inter)
	}
	for _, der := range carriedInters {
		if c, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(c)
		}
	}
	_, err = akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
