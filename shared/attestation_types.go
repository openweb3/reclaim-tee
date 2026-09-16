package shared

import "github.com/reclaimprotocol/reclaim-tee/shared/attestverify"

// Attestation types carried across the client, TEE, and router boundaries.
const (
	AttestationTypeCS = "cs"

	// Defined by attestverify, which is what reads attestations of these types.
	AttestationTypeSEVSNP     = attestverify.AttestationTypeSEVSNP
	AttestationTypeSecureBoot = attestverify.AttestationTypeSecureBoot
)

// AttestationReport represents a generic attestation envelope with runtime signing key
// Type: "gcp" (Google Confidential VM)
// Report: raw provider-specific attestation bytes
// SigningKey: TEE_T runtime ETH address to be used by clients
type AttestationReport struct {
	Type       string `json:"type"` // "gcp"
	Report     []byte `json:"report"`
	SigningKey []byte `json:"signing_key"`
}
