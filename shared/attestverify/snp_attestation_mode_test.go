package attestverify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestCurrentSNPAttestationType(t *testing.T) {
	t.Setenv(snpAttestationTypeEnv, "")
	if got := CurrentSNPAttestationType(); got != AttestationTypeSEVSNP {
		t.Fatalf("default type = %q, want %q", got, AttestationTypeSEVSNP)
	}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSecureBoot)
	if got := CurrentSNPAttestationType(); got != AttestationTypeSecureBoot {
		t.Fatalf("secure type = %q, want %q", got, AttestationTypeSecureBoot)
	}
}

func TestValidateSNPAttestationType(t *testing.T) {
	for _, value := range []string{"", AttestationTypeSEVSNP, AttestationTypeSecureBoot} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(snpAttestationTypeEnv, value)
			if err := ValidateSNPAttestationType(); err != nil {
				t.Fatalf("valid value %q rejected: %v", value, err)
			}
		})
	}

	t.Setenv(snpAttestationTypeEnv, "secureboot")
	if err := ValidateSNPAttestationType(); err == nil {
		t.Fatal("unknown explicit attestation type accepted")
	}
}

func TestSecureBootTagsAreNotLegacySEV2(t *testing.T) {
	for _, tag := range []byte{snpAttestTagSecureBootGCP, snpAttestTagSecureBootAWS} {
		att := []byte{tag}
		if !IsSecureBootAttestation(att) {
			t.Fatalf("tag 0x%02x not recognized as Secure Boot", tag)
		}
		if _, _, err := VerifyCombinedSEVSNPAttestation(att, []byte("spki")); err == nil {
			t.Fatalf("legacy SEV2 verifier accepted Secure Boot tag 0x%02x", tag)
		}
	}
}

func TestSecureBootEvidenceHasLegacyCompatibleWireView(t *testing.T) {
	for _, test := range []struct {
		secure byte
		legacy byte
	}{
		{secure: snpAttestTagSecureBootGCP, legacy: snpAttestTagGCP},
		{secure: snpAttestTagSecureBootAWS, legacy: snpAttestTagAWS},
	} {
		original := []byte{test.secure, 0xa1, 0x01, 0x02}
		typ, wire, err := ClientCompatibleSNPAttestation(AttestationTypeSecureBoot, original)
		if err != nil {
			t.Fatal(err)
		}
		if typ != AttestationTypeSEVSNP || wire[0] != test.legacy {
			t.Fatalf("client wire = type %q tag 0x%02x", typ, wire[0])
		}
		if original[0] != test.secure {
			t.Fatal("client conversion mutated cached Secure Boot evidence")
		}
		restored, err := SecureBootAttestationFromCompatibleWire(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(restored, original) {
			t.Fatalf("restored evidence = %x, want %x", restored, original)
		}
	}
}

func TestLegacyCBORDecoderIgnoresSecureBootEventLog(t *testing.T) {
	type legacyCombinedEnvelope struct {
		AppHash  []byte   `cbor:"app"`
		TPM      []byte   `cbor:"tpm,omitempty"`
		NitroTPM []byte   `cbor:"nitrotpm,omitempty"`
		SEV      []byte   `cbor:"sev,omitempty"`
		SEV2     []byte   `cbor:"sev2,omitempty"`
		Nonces   []string `cbor:"nonces,omitempty"`
	}
	want := combinedEnvelope{
		AppHash: []byte("app"), SEV: []byte("sev"), SEV2: []byte("sev2"),
		EventLog: []byte("secure-boot-event-log"), Nonces: []string{"nonce"},
	}
	raw, err := cbor.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got legacyCombinedEnvelope
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatalf("pre-Secure-Boot decoder rejected additive eventlog field: %v", err)
	}
	if !bytes.Equal(got.AppHash, want.AppHash) || !bytes.Equal(got.SEV2, want.SEV2) || len(got.Nonces) != 1 {
		t.Fatalf("legacy decoder lost prerequisite fields: %+v", got)
	}
}

func TestPeerControlAttestationGenerationMustMatchLocalMode(t *testing.T) {
	legacy := []byte{snpAttestTagGCP}
	secure := []byte{snpAttestTagSecureBootGCP}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSEVSNP)
	if _, _, err := VerifyPeerSNPNonceAttestation(AttestationTypeSEVSNP, legacy); err == nil || strings.Contains(err.Error(), "generation") {
		t.Fatalf("matching SEV2 generation did not reach evidence verification: %v", err)
	}
	if _, _, err := VerifyPeerSNPNonceAttestation(AttestationTypeSecureBoot, secure); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("Secure Boot peer was not rejected at the SEV2 generation boundary: %v", err)
	}

	t.Setenv(snpAttestationTypeEnv, AttestationTypeSecureBoot)
	if _, _, err := VerifyPeerSNPNonceAttestation(AttestationTypeSecureBoot, secure); err == nil || strings.Contains(err.Error(), "generation") {
		t.Fatalf("matching Secure Boot generation did not reach evidence verification: %v", err)
	}
	if _, _, err := VerifyPeerSNPNonceAttestation(AttestationTypeSEVSNP, legacy); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("SEV2 peer was not rejected at the Secure Boot generation boundary: %v", err)
	}
}
