package attestverify

// Attestation types carried across the client, TEE, and router boundaries.
// They live here because this package decides what an attestation of each type
// means; shared re-exports them so existing callers keep their spelling.
const (
	AttestationTypeSEVSNP     = "sev-snp"
	AttestationTypeSecureBoot = "secure-boot"
)
