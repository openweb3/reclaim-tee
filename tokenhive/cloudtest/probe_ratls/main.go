// probe_ratls answers one question about a running TEE, from outside it:
//
//	How much slack does the RA-TLS rotation schedule actually have?
//
// It reads the attested evidence out of a TEE's RA-TLS leaf — the certificate
// its mTLS listener presents — and prints the two deadlines that bound that
// evidence, plus the arithmetic that decides whether a failed rotation stops the
// TEE signing:
//
//	admission  = NitroTPM leaf NotAfter          (handshakes stop here)
//	signing    = admission - SNPSigningMargin    (refresh target; receipts stop here)
//	next try   = clamp(until(signing), minRefreshFloor, RATLSRefreshIntervalSNP)
//	slack      = until(signing) - next try       (time to absorb failures)
//
// slack == 0 means the rotation is scheduled exactly AT the signing deadline, so
// any failure — one dropped HTTP fetch, one device hiccup — costs at least
// minRefreshFloor of refused receipts until a retry lands. Handshakes survive it:
// admission runs to the leaf's own NotAfter, so the listener keeps answering the
// Hub even while the TEE will not sign. Get the leaf over mTLS with the Hub
// client identity (the TEE has no sshd):
//
//	echo | openssl s_client -connect <tee-ip>:18090 \
//	    -cert /etc/tokhive/hive-client.pem -key /etc/tokhive/hive-client-key.pem \
//	    -showcerts 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > leaf.pem
//	go run ./tokenhive/cloudtest/probe_ratls leaf.pem
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// minRefreshFloor mirrors cmd/tee's floor on the retry cadence. Duplicated on
// purpose: it is a constant of the rotation loop, and a probe that imported the
// loop would have to import the whole TEE.
const minRefreshFloor = 2 * time.Minute

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe_ratls <leaf.pem>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(2)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		fmt.Fprintln(os.Stderr, "no PEM certificate in", os.Args[1])
		os.Exit(2)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(2)
	}

	now := time.Now().UTC()
	fmt.Printf("RA-TLS leaf      subject=%s\n", leaf.Subject.CommonName)
	fmt.Printf("                 notBefore=%s  notAfter=%s\n",
		leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	// ratls_manager backdates the leaf by an hour, so the rotation instant is
	// notBefore + 1h — the one field that dates the epoch actually being served.
	fmt.Printf("                 epoch generated ~%s\n", leaf.NotBefore.Add(time.Hour).UTC().Format(time.RFC3339))

	evidence, notAfter, ok := nitroEvidence(leaf)
	if evidence == nil {
		fmt.Println("no extension carries SEV-SNP evidence: not an attested leaf, or a format this probe does not know")
		os.Exit(1)
	}
	if !ok {
		fmt.Println("evidence carries no readable NitroTPM leaf: the loop falls back to the fixed ceiling")
		fmt.Printf("  deadline   = now + AttestationCacheTTL = %s\n", now.Add(shared.AttestationCacheTTL()).Format(time.RFC3339))
		return
	}
	// Two deadlines, and they are different instants. A handshake only has to be
	// verifiable when it happens, so admission runs to the leaf's own NotAfter —
	// exactly what the Hub's chain check compares. A receipt has to stay
	// verifiable afterwards, so signing stops SNPSigningMargin earlier, and that
	// earlier instant is what the rotation schedule aims at: it is the last
	// moment a receipt can be issued, and on AWS it is also the first moment the
	// platform is willing to hand out a newer leaf.
	admission := notAfter.UTC()
	deadline := admission.Add(-shared.SNPSigningMargin)
	// The schedule is decided when the epoch is built, not now: the loop sees
	// `until(deadline)` measured from that instant. Deriving the slack from
	// "remaining now" would understate it by however long the epoch has already
	// been served, and report a healthy schedule as if it were nearly out.
	generated := leaf.NotBefore.Add(time.Hour).UTC()
	untilDeadline := deadline.Sub(generated)
	scheduled := clamp(untilDeadline)
	slack := untilDeadline - scheduled

	fmt.Printf("NitroTPM leaf    notAfter=%s\n", admission.Format(time.RFC3339))
	fmt.Printf("admission        %s  (the leaf's own NotAfter: handshakes stop here)\n", admission.Format(time.RFC3339))
	fmt.Printf("signing deadline %s  (= admission - SNPSigningMargin %s; receipts stop here)\n",
		deadline.Format(time.RFC3339), shared.SNPSigningMargin)
	fmt.Printf("now              %s   to-admission=%s  to-signing=%s\n",
		now.Format(time.RFC3339), round(admission.Sub(now)), round(deadline.Sub(now)))
	fmt.Println()
	fmt.Printf("at generation    %s   lifetime-to-deadline=%s\n", generated.Format(time.RFC3339), round(untilDeadline))
	fmt.Printf("next rotation    %s  (clamp(lifetime-to-deadline, floor %s, ceiling %s))\n",
		round(scheduled), minRefreshFloor, shared.RATLSRefreshIntervalSNP)
	fmt.Printf("slack            %s\n", round(slack))
	switch {
	case admission.Before(now):
		fmt.Println("VERDICT          past the leaf's NotAfter: the listener is refusing every handshake right now")
	case deadline.Before(now):
		fmt.Printf("VERDICT          handshakes are admitted, receipts are not: the signing margin has passed\n"+
			"                 with %s of leaf left and no rotation published\n", round(admission.Sub(now)))
	case slack <= 0:
		fmt.Printf("VERDICT          ZERO slack: the rotation is due exactly at the signing deadline, so one\n"+
			"                 ask that comes back with the same leaf costs at least %s of refused receipts\n", minRefreshFloor)
	default:
		fmt.Printf("VERDICT          %d retr%s of slack before failures reach the signing deadline\n",
			int(slack/minRefreshFloor), plural(int(slack/minRefreshFloor)))
	}
}

func clamp(d time.Duration) time.Duration {
	if d > shared.RATLSRefreshIntervalSNP {
		d = shared.RATLSRefreshIntervalSNP
	}
	if d < minRefreshFloor {
		d = minRefreshFloor
	}
	return d
}

// nitroEvidence finds the extension carrying the SEV-SNP attestation and the
// NitroTPM leaf's expiry inside it. It scans rather than naming an OID: the
// attested-leaf extension has changed before (the Secure Boot path keeps a
// legacy one for old clients beside the current one), and which of them carries
// the readable NitroTPM leaf is exactly what this probe exists to report.
func nitroEvidence(cert *x509.Certificate) (evidence []byte, notAfter time.Time, ok bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(shared.AttestationOID) && ext.Id[0] != 1 {
			continue
		}
		if t, found := shared.SNPNitroLeafNotAfter(ext.Value); found {
			return ext.Value, t, true
		}
		if evidence == nil && looksLikeSEVSNPEvidence(ext.Value) {
			evidence = ext.Value
		}
	}
	return evidence, time.Time{}, false
}

// looksLikeSEVSNPEvidence is the weakest useful test: the combined AWS envelope
// is CBOR whose tag byte distinguishes the wire format. It only decides whether
// the "no readable NitroTPM leaf" message is worth printing, so it errs toward
// "yes" for anything binary of a plausible size.
func looksLikeSEVSNPEvidence(v []byte) bool {
	return len(v) > 256 && (v[0] == 0x82 || v[0] == 0x83 || v[0] == 0xa0 || v[0] == 0xd8)
}

func round(d time.Duration) string {
	if d < 0 {
		return "-" + d.Round(time.Second).Abs().String()
	}
	return d.Round(time.Second).String()
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
