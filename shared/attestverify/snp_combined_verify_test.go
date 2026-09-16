//go:build !mobile

package attestverify

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyCombinedGCPAttestation drives the verifier against a real combined
// attestation captured from a GCP SEV-SNP CVM (snp-poc -combined). The .spki
// file is the ephemeral SPKI the producer bound into report_data.
func TestVerifyCombinedGCPAttestation(t *testing.T) {
	att, err := os.ReadFile("testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	spki, err := os.ReadFile("testdata/gcp_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	app, base, err := VerifyCombinedGCPAttestation(att, spki)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.HasPrefix(app, SEVSNPAppPrefix) || !strings.HasPrefix(base, SEVSNPBasePrefix) {
		t.Fatalf("bad identities app=%q base=%q", app, base)
	}
	t.Logf("verified: app=%s base=%s", app, base)
}

// TestVerifyCombinedGCPAttestation_RejectsWrongSPKI confirms the binding check:
// a different SPKI must not verify against report_data committed to the real one.
func TestVerifyCombinedGCPAttestation_RejectsWrongSPKI(t *testing.T) {
	att, err := os.ReadFile("testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	if _, _, err := VerifyCombinedGCPAttestation(att, []byte("not the bound spki")); err == nil {
		t.Fatal("expected binding failure with wrong SPKI")
	}
}
