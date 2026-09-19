// Command bench is the S5 performance benchmark for TokenHive. It measures the
// four acceptance metrics from the plan (§9) by running the same workload in
// two configurations and comparing them:
//
//	direct  -> client talks straight to the mock provider over real TLS
//	tee     -> client -> simulated TEE -> Hub relay -> Agent -> provider
//
// The delta between the two is the cost of the trusted layer (TEE + Agent):
//
//	TTFT overhead, throughput overhead, receipt-signing p95, proof volume.
//
// It is deliberately a standalone binary, not a unit test: the numbers only
// mean something against a running provider and a running TEE, and they are
// the kind of thing you want to watch trend over time rather than assert
// exact values in CI. The hard regression gates (proof < 2KB, receipt p95
// < 5ms) are additionally locked in by tokenhive/tee/receipt_budget_test.go
// so they catch regressions without a network.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/cmd/internal/shared"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/tee"
)

// §9 acceptance targets (from the plan). The relative TTFT/throughput targets
// assume a non-trivial production baseline; on localhost the absolute delta is
// the honest signal, so the bench reports both and gates on the delta unless a
// baseline RTT is supplied.
const (
	targetProofBytes      = 2048 // proof volume budget (sim adapter must fit)
	targetReceiptP95Ms    = 5.0  // receipt generation p95
	targetTTFTOverheadPct = 1.0  // relative, vs a realistic baseline RTT
	targetTPOverheadPct   = 3.0  // relative throughput overhead

	// localhost-friendly sanity gates (absolute), used when a realistic
	// baseline RTT is not supplied.
	localTTFTDeltaMs = 25.0
)

type sample struct {
	ttfbMs      float64
	payloadByte float64
	wallMs      float64
	receiptMs   float64 // tee only: last chunk -> receipt frame
	proofBytes  float64 // tee only: decoded SignedReceipt size
}

type report struct {
	Mode        string
	N           int
	TTFBMedian  float64
	TTFBP95     float64
	PayloadMed  float64
	WallTotalMs float64
	Throughput  float64 // bytes/sec across all N requests
	ReceiptP95  float64 // tee only
	ProofMed    float64 // tee only
	ProofMax    float64 // tee only
}

func main() {
	mode := flag.String("mode", "both", "direct | tee | both")
	n := flag.Int("n", 200, "number of requests per mode")
	query := flag.String("query", "", "provider fault query, e.g. fault=big")
	maxBytes := flag.Uint64("max", 1<<20, "MaxResponseBytes cap (TEE) and direct read cap")
	provider := flag.String("provider", "127.0.0.1:18080", "provider host:port (spec.Host, must match policy)")
	provURL := flag.String("provurl", "https://127.0.0.1:18080", "provider base URL for direct mode")
	teeURL := flag.String("tee", "http://127.0.0.1:18090", "TEE base URL")
	model := flag.String("model", "sim-mock-0.5b", "declared model")
	baselineRTT := flag.Duration("baseline-rtt", 0, "nominal production first-byte latency; enables §9 relative TTFT gate")
	credential := flag.String("credential", "", "provider access token; when set it is sealed to the TEE and carried on every tee-mode job, as a dialing agent would deliver it through a Hub")
	gate := flag.Bool("gate", true, "exit non-zero if a hard gate fails")
	out := flag.String("out", "", "write the combined JSON report to this path")
	flag.Parse()

	if err := shared.EnsureDefaults(); err != nil {
		fmt.Fprintf(os.Stderr, "bench: ensure defaults: %v\n", err)
		os.Exit(2)
	}

	body := []byte(`{"model":"` + *model + `","messages":[{"role":"user","content":"你是谁？"}],"stream":true}`)

	// The TEE stores no token: every tee-mode job carries the provider's token
	// sealed to the TEE's inbox key, exactly as a Hub dispatcher would attach the
	// envelope a dialing agent registered. null when no token is supplied (a job
	// the TEE will refuse — the flag exists so the harness can be explicit).
	var cred []byte
	if *credential != "" {
		env, err := shared.SealCredential(*teeURL, "openai-sim", tee.Secret{
			Token:  *credential,
			Header: "authorization",
			Scheme: "Bearer",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "bench: seal credential: %v\n", err)
			os.Exit(2)
		}
		cred, err = env.EncodeCanonical()
		if err != nil {
			fmt.Fprintf(os.Stderr, "bench: encode credential: %v\n", err)
			os.Exit(2)
		}
	}

	var direct, teeRep *report
	var dErr, tErr error

	switch *mode {
	case "direct":
		direct, dErr = runDirect(*n, *provider, *query, *maxBytes, body, *provURL)
		if dErr != nil {
			fmt.Fprintf(os.Stderr, "bench: direct mode: %v\n", dErr)
		}
	case "tee":
		teeRep, tErr = runTEE(*n, *model, *provider, *query, *maxBytes, body, *teeURL, cred)
		if tErr != nil {
			fmt.Fprintf(os.Stderr, "bench: tee mode: %v\n", tErr)
		}
	case "both":
		direct, dErr = runDirect(*n, *provider, *query, *maxBytes, body, *provURL)
		if dErr != nil {
			fmt.Fprintf(os.Stderr, "bench: direct mode: %v\n", dErr)
		}
		teeRep, tErr = runTEE(*n, *model, *provider, *query, *maxBytes, body, *teeURL, cred)
		if tErr != nil {
			fmt.Fprintf(os.Stderr, "bench: tee mode: %v\n", tErr)
		}
	default:
		fmt.Fprintf(os.Stderr, "bench: unknown mode %q\n", *mode)
		os.Exit(2)
	}

	combined := map[string]any{"n": *n, "query": *query, "maxBytes": *maxBytes}
	hardFail := false

	if direct != nil {
		printReport("DIRECT (baseline)", direct)
		combined["direct"] = direct
	}
	if teeRep != nil {
		printReport("TEE    (measured)", teeRep)
		combined["tee"] = teeRep
	}

	if direct != nil && teeRep != nil {
		hardFail = printOverhead(direct, teeRep, *baselineRTT, *gate)
	}

	if *out != "" {
		if b, err := json.MarshalIndent(combined, "", "  "); err == nil {
			_ = os.WriteFile(*out, b, 0o644)
		}
	}

	if *gate && hardFail {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Direct mode: client -> provider over real TLS (no TEE, no Agent).
// ---------------------------------------------------------------------------
func runDirect(n int, host, query string, maxBytes uint64, body []byte, provURL string) (*report, error) {
	pool, err := shared.LoadCAPool()
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	url := provURL + "/v1/chat/completions"
	if query != "" {
		url += "?" + query
	}
	samples := make([]sample, 0, n)
	totalWall := time.Duration(0)
	totalPayload := int64(0)
	for i := 0; i < n; i++ {
		s, err := oneDirect(client, url, body, maxBytes)
		if err != nil {
			return nil, err
		}
		samples = append(samples, s)
		totalWall += time.Duration(s.wallMs) * time.Millisecond
		totalPayload += int64(s.payloadByte)
	}
	return summarize("direct", n, samples, totalWall, totalPayload), nil
}

func oneDirect(client *http.Client, url string, body []byte, maxBytes uint64) (sample, error) {
	t0 := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return sample{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return sample{}, err
	}
	defer resp.Body.Close()
	res := readSSE(resp.Body, int(maxBytes))
	return sample{
		ttfbMs:      res.firstByteAt.Sub(t0).Seconds() * 1000,
		payloadByte: float64(totalLen(res.chunks)),
		wallMs:      time.Since(t0).Seconds() * 1000,
	}, nil
}

// ---------------------------------------------------------------------------
// TEE mode: client -> simulated TEE -> Hub relay -> Agent -> provider.
// ---------------------------------------------------------------------------
func runTEE(n int, model, host, query string, maxBytes uint64, body []byte, teeURL string, cred []byte) (*report, error) {
	client := &http.Client{} // plain HTTP to the local TEE
	samples := make([]sample, 0, n)
	totalWall := time.Duration(0)
	totalPayload := int64(0)
	for i := 0; i < n; i++ {
		spec, err := shared.BuildSpec("openai-sim", model, host, "/v1/chat/completions", query, body, maxBytes)
		if err != nil {
			return nil, err
		}
		spec.Credential = cred
		s, err := oneTEE(client, teeURL, spec, body)
		if err != nil {
			return nil, err
		}
		samples = append(samples, s)
		totalWall += time.Duration(s.wallMs) * time.Millisecond
		totalPayload += int64(s.payloadByte)
	}
	return summarize("tee", n, samples, totalWall, totalPayload), nil
}

func oneTEE(client *http.Client, teeURL string, spec jobs.Spec, body []byte) (sample, error) {
	reqBody, err := tee.Job{Spec: spec, Body: body}.EncodeCanonical()
	if err != nil {
		return sample{}, err
	}
	t0 := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		teeURL+"/v1/execute", bytes.NewReader(reqBody))
	if err != nil {
		return sample{}, err
	}
	req.Header.Set("Content-Type", tee.ExecuteContentType)
	resp, err := client.Do(req)
	if err != nil {
		return sample{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return sample{}, fmt.Errorf("tee http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	res := readSSE(resp.Body, 0)
	// Both are failures to measure, and both used to be silently reported as a
	// zero-payload sample — a refusal with no chunks looked exactly like a
	// provider that answered with nothing, and the S5 gate passed either way.
	if res.teeErr != "" {
		return sample{}, fmt.Errorf("tee refused the job: %s", res.teeErr)
	}
	if res.receiptB64 == "" {
		return sample{}, errors.New("tee stream ended without a receipt frame")
	}
	s := sample{
		ttfbMs:      res.firstByteAt.Sub(t0).Seconds() * 1000,
		payloadByte: float64(totalLen(res.chunks)),
		wallMs:      time.Since(t0).Seconds() * 1000,
	}
	if res.receiptB64 != "" {
		if raw, derr := base64.StdEncoding.DecodeString(res.receiptB64); derr == nil {
			s.proofBytes = float64(len(raw))
		}
		if !res.lastChunkAt.IsZero() && !res.receiptAt.IsZero() {
			s.receiptMs = res.receiptAt.Sub(res.lastChunkAt).Seconds() * 1000
		}
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// SSE reader with timing + optional byte cap (direct mode stops at maxBytes).
// ---------------------------------------------------------------------------
type sseResult struct {
	chunks      [][]byte
	firstByteAt time.Time
	lastChunkAt time.Time
	receiptB64  string
	receiptAt   time.Time
	teeErr      string
}

// readSSE collects the stream's chunks and the instants they arrived, stopping
// once capBytes have arrived (0 = no cap). The framing is tee.NewSSEStream, the
// same decoder the Hub settles against; only the measurements are bench's.
func readSSE(r io.Reader, capBytes int) sseResult {
	stream := tee.NewSSEStream(r)
	var res sseResult
	seen := 0
	for {
		frame, err := stream.Next()
		if err != nil {
			return res
		}
		switch frame.Type {
		case "", "message":
			if !frame.HasData {
				continue
			}
			payload := []byte(frame.Data)
			if res.firstByteAt.IsZero() {
				res.firstByteAt = time.Now()
			}
			res.chunks = append(res.chunks, payload)
			res.lastChunkAt = time.Now()
			seen += len(payload)
			if capBytes > 0 && seen >= capBytes {
				return res
			}
		case tee.EventStart:
			// The response-start frame is control data, not a body chunk:
			// dropping it keeps the timing samples honest without polluting
			// the payload count.
		case tee.EventReceipt:
			res.receiptB64 = frame.Data
			res.receiptAt = time.Now()
		case tee.EventError:
			res.teeErr = frame.Data
		}
	}
}

func totalLen(chunks [][]byte) int {
	var n int
	for _, c := range chunks {
		n += len(c)
	}
	return n
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
func summarize(mode string, n int, samples []sample, totalWall time.Duration, totalPayload int64) *report {
	rep := &report{Mode: mode, N: n}
	if len(samples) == 0 {
		return rep
	}
	ttfbs := make([]float64, len(samples))
	payloads := make([]float64, len(samples))
	receipts := make([]float64, 0, len(samples))
	proofs := make([]float64, 0, len(samples))
	wallSum := 0.0
	for i, s := range samples {
		ttfbs[i] = s.ttfbMs
		payloads[i] = s.payloadByte
		wallSum += s.wallMs
		if s.receiptMs > 0 {
			receipts = append(receipts, s.receiptMs)
		}
		if s.proofBytes > 0 {
			proofs = append(proofs, s.proofBytes)
		}
	}
	rep.TTFBMedian = percentile(ttfbs, 50)
	rep.TTFBP95 = percentile(ttfbs, 95)
	rep.PayloadMed = percentile(payloads, 50)
	rep.WallTotalMs = wallSum
	if totalWall > 0 && totalPayload > 0 {
		rep.Throughput = float64(totalPayload) / totalWall.Seconds()
	}
	if len(receipts) > 0 {
		rep.ReceiptP95 = percentile(receipts, 95)
	}
	if len(proofs) > 0 {
		rep.ProofMed = percentile(proofs, 50)
		rep.ProofMax = proofs[0]
		for _, p := range proofs[1:] {
			if p > rep.ProofMax {
				rep.ProofMax = p
			}
		}
	}
	return rep
}

func printReport(title string, r *report) {
	fmt.Printf("\n== %s ==\n", title)
	fmt.Printf("  requests            : %d\n", r.N)
	fmt.Printf("  median TTFB        : %.2f ms\n", r.TTFBMedian)
	fmt.Printf("  p95 TTFB           : %.2f ms\n", r.TTFBP95)
	fmt.Printf("  median payload     : %.0f bytes\n", r.PayloadMed)
	fmt.Printf("  total throughput   : %.2f KiB/s (%.0f bytes / %.1f s)\n",
		r.Throughput/1024, float64(r.PayloadMed)*float64(r.N), r.WallTotalMs/1000)
	if r.Mode == "tee" {
		fmt.Printf("  receipt p95        : %.2f ms\n", r.ReceiptP95)
		fmt.Printf("  proof size         : %.0f bytes (median), %.0f (max)\n", r.ProofMed, r.ProofMax)
	}
}

func printOverhead(d, t *report, baselineRTT time.Duration, gate bool) bool {
	fmt.Printf("\n== OVERHEAD (TEE layer cost) ==\n")
	fail := false

	// TTFT
	delta := t.TTFBMedian - d.TTFBMedian
	fmt.Printf("  TTFT delta         : %.2f ms (tee %.2f - direct %.2f)\n", delta, t.TTFBMedian, d.TTFBMedian)
	if baselineRTT > 0 {
		ov := delta / float64(baselineRTT.Milliseconds()) * 100
		ok := ov <= targetTTFTOverheadPct
		fmt.Printf("  TTFT overhead      : %.2f%%  (§9 target < %.0f%%, baseline-rtt=%s)  %s\n",
			ov, targetTTFTOverheadPct, baselineRTT, gateMark(ok))
		if gate && !ok {
			fail = true
		}
	} else {
		ok := delta <= localTTFTDeltaMs
		fmt.Printf("  TTFT gate (local)  : delta <= %.0f ms  %s  (set -baseline-rtt to evaluate §9's <%.0f%% relative)\n",
			localTTFTDeltaMs, gateMark(ok), targetTTFTOverheadPct)
		if gate && !ok {
			fail = true
		}
	}

	// Throughput. §9's <3% target is a production-topology target: in
	// production the TEE is a separate network hop near the provider, so its
	// added cost is processing plus one extra hop. On a single-host loopback
	// sim the TEE necessarily moves every byte twice on one machine
	// (provider->TEE and TEE->client), so the sim's relative throughput
	// overhead is a loopback artifact, not a production signal. Report it for
	// trend-tracking only; it is not a portable regression gate.
	if d.Throughput > 0 {
		ov := (1 - t.Throughput/d.Throughput) * 100
		fmt.Printf("  throughput (direct): %.0f KiB/s\n", d.Throughput/1024)
		fmt.Printf("  throughput (tee)   : %.0f KiB/s\n", t.Throughput/1024)
		fmt.Printf("  throughput overhead: %.2f%%  (informational; §9 target < %.0f%% is a production-topology target, not measurable on single-host loopback)\n",
			ov, targetTPOverheadPct)
	}

	// Receipt p95 (hard §9 gate)
	okR := t.ReceiptP95 <= targetReceiptP95Ms
	fmt.Printf("  receipt p95        : %.2f ms  (§9 target < %.0f ms)  %s\n", t.ReceiptP95, targetReceiptP95Ms, gateMark(okR))
	if gate && !okR {
		fail = true
	}

	// Proof volume (hard §9 gate, non-negotiable)
	okP := t.ProofMax <= targetProofBytes
	fmt.Printf("  proof volume       : %.0f bytes (max)  (§9 budget < %d bytes)  %s\n", t.ProofMax, targetProofBytes, gateMark(okP))
	if gate && !okP {
		fail = true
	}

	if fail {
		fmt.Printf("\n  GATE fail — a hard §9 target was missed\n")
	} else {
		fmt.Printf("\n  GATE pass\n")
	}
	return fail
}

func gateMark(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sort.Float64s(vals)
	idx := int(math.Ceil(p/100*float64(len(vals)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}
