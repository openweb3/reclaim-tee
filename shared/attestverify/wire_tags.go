package attestverify

// Wire tags that mark which combined attestation an envelope carries. They are
// exported because the RA-TLS side of shared writes them into a certificate
// extension, while this package is what reads them back.
const (
	SNPAttestTagGCP = 0x01
	SNPAttestTagAWS = 0x02

	SNPAttestTagSecureBootGCP = 0x03
	SNPAttestTagSecureBootAWS = 0x04
)
