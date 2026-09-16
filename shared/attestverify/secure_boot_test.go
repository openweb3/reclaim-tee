package attestverify

import (
	"strings"
	"testing"
)

func TestSecureBootAuthorityPolicy(t *testing.T) {
	valid := secureBootAuthorityPolicy{
		enabled: true, permittedKeys: 1, releaseDBEntries: 1,
		postAuthorities: 1, releasePostAuthorities: 1,
	}
	if !secureBootAuthorityPolicyOK(valid) {
		t.Fatal("valid R-only policy rejected")
	}

	tests := map[string]func(*secureBootAuthorityPolicy){
		"disabled":            func(p *secureBootAuthorityPolicy) { p.enabled = false },
		"additional db key":   func(p *secureBootAuthorityPolicy) { p.permittedKeys = 2 },
		"permitted hash":      func(p *secureBootAuthorityPolicy) { p.permittedHashes = 1 },
		"R absent from db":    func(p *secureBootAuthorityPolicy) { p.releaseDBEntries = 0 },
		"R revoked":           func(p *secureBootAuthorityPolicy) { p.releaseDBXEntries = 1 },
		"pre-boot authority":  func(p *secureBootAuthorityPolicy) { p.preAuthorities = 1 },
		"no executed image":   func(p *secureBootAuthorityPolicy) { p.postAuthorities = 0; p.releasePostAuthorities = 0 },
		"foreign signer used": func(p *secureBootAuthorityPolicy) { p.postAuthorities = 2; p.releasePostAuthorities = 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := valid
			mutate(&policy)
			if secureBootAuthorityPolicyOK(policy) {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestVerifyTypedSNPNonceAttestationDispatch(t *testing.T) {
	tests := []struct {
		name            string
		attestationType string
		report          []byte
		want            string
	}{
		{
			name:            "unknown type",
			attestationType: "future-type",
			want:            "unsupported attestation type",
		},
		{
			name:            "secure type requires secure evidence tag",
			attestationType: AttestationTypeSecureBoot,
			report:          []byte{snpAttestTagGCP},
			want:            "does not carry Secure Boot evidence",
		},
		{
			name:            "legacy type rejects secure evidence tag",
			attestationType: AttestationTypeSEVSNP,
			report:          []byte{snpAttestTagSecureBootGCP},
			want:            "carries Secure Boot evidence",
		},
		{
			name:            "secure type reaches secure verifier",
			attestationType: AttestationTypeSecureBoot,
			report:          []byte{snpAttestTagSecureBootGCP},
			want:            "decode Secure Boot envelope",
		},
		{
			name:            "legacy type reaches legacy verifier",
			attestationType: AttestationTypeSEVSNP,
			report:          []byte{snpAttestTagGCP},
			want:            "decode SEV-SNP envelope",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := VerifyTypedSNPNonceAttestation(test.attestationType, test.report)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verification error = %v, want %q", err, test.want)
			}
		})
	}
}
