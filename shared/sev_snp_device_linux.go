//go:build linux && !mobile

package shared

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/client"
	tpmclient "github.com/google/go-tpm-tools/client"
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// GenerateCombinedGCPAttestation produces a marshaled go-tpm-tools Attestation
// binding the GCE vTPM to the AMD SEV-SNP report. It loads the GCE-provided
// attestation key (Google-certified), sets the SEV report_data to
// sha512(AkPub || spkiDER) so the AMD-signed report commits to this exact vTPM
// key (anti-splice), and quotes the PCRs (incl. PCR 8 = app, PCR 11 = base).
// GCP-only: relies on the GCE AK. AWS (NitroTPM) needs its own producer.
func GenerateCombinedGCPAttestation(spkiDER, appHash []byte) ([]byte, error) {
	return generateCombinedGCP(spkiDER, appHash, nil)
}

// snpAttestMu serializes all SEV-SNP attestation generation. The vTPM (and, on
// AWS, the single NV index used for the NitroTPM vendor command) is a shared,
// stateful device with no internal queuing; the cert-refresh ticker and a
// per-session attestation can otherwise hit it concurrently and collide. CS got
// this serialization for free via the launcher socket.
var snpAttestMu sync.Mutex

// SEV-SNP attestations bind the RA-TLS SPKI / signing key that is current when
// they are generated. That key is rotated on every RA-TLS refresh
// (RATLSManager.Refresh generates a fresh keypair), not held for the life of the
// process — so an attestation is valid for exactly one key and one refresh
// interval. Keying the cache on the bound data is what keeps that honest: a
// rotation changes the key material, hence the cache key, so a rotated
// deployment can never be handed a document certifying the key it just retired.
//
// Within one key's life the document is worth reusing rather than regenerating
// per claim. It carries no freshness/challenge of its own — the attestor
// verifies the key binding and the image identity, not recency — while
// regenerating it is expensive: on AWS, NitroTPM document generation is
// CPU-heavy enough to hog the kernel's tpm workqueue. Cache by the bound data
// and reuse for snpAttestCacheTTL. Guarded by snpAttestMu.
const snpAttestCacheTTL = 50 * time.Minute

type snpAttestCacheEntry struct {
	att []byte
	exp time.Time
}

var snpAttestCache = map[string]snpAttestCacheEntry{}

func snpAttestCacheKey(cloud string, bound, appHash []byte, nonces []string) string {
	h := sha256.New()
	h.Write([]byte(cloud))
	h.Write(bound)
	h.Write(appHash)
	for _, n := range nonces {
		h.Write([]byte(n))
		h.Write([]byte{0})
	}
	return string(h.Sum(nil))
}

// snpAttestCacheGet/Put must be called with snpAttestMu held.
func snpAttestCacheGet(key string) ([]byte, bool) {
	e, ok := snpAttestCache[key]
	if !ok || time.Now().After(e.exp) {
		return nil, false
	}
	return e.att, true
}

func snpAttestCachePut(key string, att []byte) {
	snpAttestCache[key] = snpAttestCacheEntry{att: att, exp: time.Now().Add(snpAttestCacheTTL)}
}

// snpDeviceCooldown briefly holds a device error sticky so cache-miss callers
// can't hammer a throttled device (repeated ratelimit hits drive it fail-closed).
const snpDeviceCooldown = 2 * time.Second

var (
	snpLastDeviceErr     error
	snpLastDeviceErrTime time.Time
)

// snpDeviceInCooldown returns the recent device error while still inside the
// post-failure window; nil otherwise. Call with snpAttestMu held.
func snpDeviceInCooldown() error {
	if snpLastDeviceErr != nil && time.Since(snpLastDeviceErrTime) < snpDeviceCooldown {
		return snpLastDeviceErr
	}
	return nil
}

// snpRecordDeviceResult stamps the last device outcome for the cooldown. Call
// with snpAttestMu held.
func snpRecordDeviceResult(err error) {
	if err != nil {
		snpLastDeviceErr, snpLastDeviceErrTime = err, time.Now()
		return
	}
	snpLastDeviceErr = nil
}

// certChainHTTPClient serves the AK cert-issuer chain from an in-memory cache so
// the fetch inside ak.Attest (under snpAttestMu) is instant after the first warm.
var certChainHTTPClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &cachingRoundTripper{base: http.DefaultTransport},
}

type cachingRoundTripper struct {
	base http.RoundTripper
	mu   sync.Mutex
	body map[string][]byte
}

func (c *cachingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	mkResp := func(b []byte) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header), Request: req}
	}
	if req.Method == http.MethodGet {
		c.mu.Lock()
		b, ok := c.body[req.URL.String()]
		c.mu.Unlock()
		if ok {
			return mkResp(b), nil
		}
	}
	resp, err := c.base.RoundTrip(req)
	if err != nil || req.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	b, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	c.mu.Lock()
	if c.body == nil {
		c.body = map[string][]byte{}
	}
	c.body[req.URL.String()] = b
	c.mu.Unlock()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

// generateCombinedGCP binds the given blob (raw SPKI for the cert path, or the
// nonce commitment for the claim path) into report_data + the quote nonce, and
// carries the presentable nonces (if any) in the envelope.
func generateCombinedGCP(bound, appHash []byte, nonces []string) ([]byte, error) {
	snpAttestMu.Lock()
	defer snpAttestMu.Unlock()

	cacheKey := snpAttestCacheKey("gcp:"+CurrentSNPAttestationType(), bound, appHash, nonces)
	if att, ok := snpAttestCacheGet(cacheKey); ok {
		return att, nil
	}
	if cErr := snpDeviceInCooldown(); cErr != nil {
		return nil, cErr
	}
	envBytes, err := generateCombinedGCPUncached(bound, appHash, nonces)
	snpRecordDeviceResult(err)
	if err != nil {
		return nil, err
	}
	snpAttestCachePut(cacheKey, envBytes)
	return envBytes, nil
}

// generateCombinedGCPUncached does the vTPM + SEV device work; the caller holds
// snpAttestMu and owns caching + the post-failure cooldown.
func generateCombinedGCPUncached(bound, appHash []byte, nonces []string) ([]byte, error) {
	rwc, err := legacytpm.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("open tpm: %w", err)
	}
	defer rwc.Close()

	ak, err := tpmclient.GceAttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("load GCE attestation key: %w", err)
	}
	defer ak.Close()

	akPub, err := ak.PublicArea().Encode()
	if err != nil {
		return nil, fmt.Errorf("encode AK public area: %w", err)
	}
	rd := CombinedReportData(akPub, bound)
	nonce := sha256.Sum256(bound)

	sev, err := tpmclient.CreateSevSnpQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("create SEV-SNP quote provider: %w", err)
	}
	defer sev.Close()

	// Legacy SEV2 deliberately carries an empty event log. Secure Boot carries
	// the raw, uncompressed firmware log in the standard Attestation field so
	// verifiers can replay PCR 4/7/11 from this same AK-signed quote.
	// CertChainFetcher embeds the AK cert's issuing chain (GCE intermediates are
	// regionalized + rotated, so the verifier can't hardcode them) — it fetches
	// once here so the verifier stays offline, trusting only the stable root.
	eventLog := []byte{}
	if secureBootAttestationEnabled() {
		eventLog, err = readSecureBootEventLog()
		if err != nil {
			return nil, err
		}
	}
	att, err := ak.Attest(tpmclient.AttestOpts{
		Nonce:            nonce[:],
		TEENonce:         rd[:],
		TEEDevice:        sev,
		TCGEventLog:      eventLog,
		CertChainFetcher: certChainHTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	tpmBytes, err := proto.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation: %w", err)
	}
	envBytes, err := cbor.Marshal(combinedEnvelope{AppHash: appHash, TPM: tpmBytes, Nonces: nonces})
	if err != nil {
		return nil, err
	}
	return envBytes, nil
}

// GenerateSEVSNPNonceAttestation produces the app-layer claim attestation: a
// tagged combined attestation that binds snpNonceCommitment(nonces) in hardware
// and carries the nonces presentably (the SEV-SNP analogue of a CS JWT with an
// eat_nonce). appHash comes from SNP_APP_HASH (loader-exported). Dispatches to
// the AWS (NitroTPM) or GCP (GCE vTPM) producer.
func GenerateSEVSNPNonceAttestation(nonces []string) ([]byte, error) {
	appHash, err := hex.DecodeString(os.Getenv("SNP_APP_HASH"))
	if err != nil || len(appHash) == 0 {
		return nil, fmt.Errorf("SNP_APP_HASH not set by loader")
	}
	commitment := snpNonceCommitment(nonces)
	if IsAWSSEVSNP() {
		att, err := generateCombinedAWS(commitment, appHash, nonces)
		if err != nil {
			return nil, err
		}
		tag := byte(snpAttestTagAWS)
		if secureBootAttestationEnabled() {
			tag = snpAttestTagSecureBootAWS
		}
		return append([]byte{tag}, att...), nil
	}
	att, err := generateCombinedGCP(commitment, appHash, nonces)
	if err != nil {
		return nil, err
	}
	tag := byte(snpAttestTagGCP)
	if secureBootAttestationEnabled() {
		tag = snpAttestTagSecureBootGCP
	}
	return append([]byte{tag}, att...), nil
}

func readSecureBootEventLog() ([]byte, error) {
	raw, err := os.ReadFile(secureBootEventLogPath)
	if err != nil {
		return nil, fmt.Errorf("read Secure Boot event log: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("Secure Boot event log is empty")
	}
	if len(raw) > maxSecureBootEventLog {
		return nil, fmt.Errorf("Secure Boot event log is %d bytes; maximum is %d", len(raw), maxSecureBootEventLog)
	}
	return raw, nil
}

// sevGuestDevice is where the SEV-SNP guest driver exposes the report ioctl.
// Its presence is how we detect "running on a SEV-SNP CVM", the SEV-SNP
// counterpart to the Confidential Space launcher socket.
const sevGuestDevice = "/dev/sev-guest"

// IsSEVSNPMode reports whether this process is running on a SEV-SNP guest
// (the guest device node is present).
func IsSEVSNPMode() bool {
	_, err := os.Stat(sevGuestDevice)
	return err == nil
}

// IsAWSSEVSNP reports whether the SEV-SNP guest is on AWS (vs GCP), via the DMI
// system vendor. Selects the AWS (NitroTPM) attestation producer over the GCP
// (GCE vTPM) one.
func IsAWSSEVSNP() bool {
	v, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	return strings.Contains(string(v), "Amazon")
}

// GenerateSEVSNPAttestation pulls an extended attestation report (report +
// cached VCEK/ASK/ARK chain) bound to the given report_data, and returns it
// marshaled for embedding in the RA-TLS cert extension.
func GenerateSEVSNPAttestation(reportData [64]byte) ([]byte, error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("get SEV-SNP quote provider: %w", err)
	}
	att, err := client.GetQuoteProto(qp, reportData)
	if err != nil {
		return nil, fmt.Errorf("get SEV-SNP attestation: %w", err)
	}
	return marshalSEVSNPAttestation(att)
}
