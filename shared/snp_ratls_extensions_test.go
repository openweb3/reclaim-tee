package shared

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
)

// This one stayed behind when the attestation verification cluster moved to
// shared/attestverify: what it exercises is the RA-TLS certificate this package
// builds, not how an attestation is read.
func TestSecureBootRATLSKeepsLegacyAndAddsSecureExtension(t *testing.T) {
	payload := []byte{0xa1, 0x01, 0x02}
	for _, test := range []struct {
		legacy byte
	}{
		{legacy: snpAttestTagGCP},
		{legacy: snpAttestTagAWS},
	} {
		exts := snpRATLSExtensions(test.legacy, payload, true)
		if len(exts) != 2 {
			t.Fatalf("tag 0x%02x extensions = %d, want 2", test.legacy, len(exts))
		}
		if !exts[0].Id.Equal(AttestationOIDSEVSNP) || exts[0].Critical || exts[0].Value[0] != test.legacy {
			t.Fatalf("legacy extension = %+v", exts[0])
		}
		if !exts[1].Id.Equal(AttestationOIDSecureBoot) || exts[1].Critical ||
			!bytes.Equal(exts[1].Value, []byte{secureBootRATLSExtensionVersion}) {
			t.Fatalf("Secure Boot extension = %+v", exts[1])
		}
		if !bytes.Equal(exts[0].Value[1:], payload) {
			t.Fatal("legacy RA-TLS extension changed the evidence")
		}

		typ, effective, err := snpAttestationFromCert(&x509.Certificate{Extensions: exts})
		if err != nil {
			t.Fatal(err)
		}
		if typ != AttestationTypeSecureBoot || !IsSecureBootAttestation(effective) ||
			!bytes.Equal(effective[1:], payload) {
			t.Fatalf("effective certificate evidence = type %q bytes %x", typ, effective)
		}
	}

	legacyOnly := snpRATLSExtensions(snpAttestTagGCP, payload, false)
	if len(legacyOnly) != 1 || !legacyOnly[0].Id.Equal(AttestationOIDSEVSNP) {
		t.Fatalf("legacy RA-TLS extensions = %+v", legacyOnly)
	}
}

func TestClientSecureBootVerificationDoesNotRequireLocalTEEMode(t *testing.T) {
	t.Setenv(snpAttestationTypeEnv, AttestationTypeSEVSNP)
	secure := []byte{snpAttestTagSecureBootGCP}

	_, _, err := validateSEVSNP(secure, nil)
	if err == nil {
		t.Fatal("malformed Secure Boot evidence accepted")
	}
	if strings.Contains(err.Error(), "generation does not match") {
		t.Fatalf("client-style validation applied TEE-only generation policy: %v", err)
	}
}
