//go:build !mobile

package verify

import (
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/platform"
)

// CheckEvidenceForDeployment must refuse deployment-bound verification: the
// policy set is loaded at runtime outside the measured bundle, so SEV-SNP
// evidence cannot attest a supplied digest, and accepting any evidence would
// let two deployments with different policies pass the same hardware check.
// The refusal is unconditional — it never inspects the identity — so a bare
// Identity with any (including zero) digest must error.
func TestCheckEvidenceForDeploymentRefused(t *testing.T) {
	v := Verifier{}
	hashes := []struct {
		name string
		hash [32]byte
	}{
		{name: "zero digest", hash: [32]byte{}},
		{name: "non-zero digest", hash: [32]byte{1, 2, 3}},
	}
	for _, h := range hashes {
		t.Run(h.name, func(t *testing.T) {
			if err := v.CheckEvidenceForDeployment(platform.Identity{Platform: platform.PlatformAWSSEVSNP}, h.hash); err == nil {
				t.Fatal("CheckEvidenceForDeployment accepted a policy-set hash the evidence cannot attest")
			}
		})
	}
}
