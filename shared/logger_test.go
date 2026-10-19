//go:build !mobile

package shared

import (
	"errors"
	"testing"

	"go.uber.org/zap"
)

// TestAddFieldToPayloadDecodesFloats pins the one field type a payload cannot
// take at face value. zap keeps a float field as its IEEE-754 bits, so passing
// Integer through — which is what reading the field naively does — puts
// 4645666129713923682 where a latency of 0.4 was meant. That is a number that is
// wrong and still reads as a number, so nothing downstream will complain: the
// timing lines this instrumentation exists for would arrive at the GCP sink as
// integers nobody can use.
func TestAddFieldToPayloadDecodesFloats(t *testing.T) {
	payload := map[string]any{}
	addFieldToPayload(payload, zap.Float64("ttfb_ms", 903.1))
	addFieldToPayload(payload, zap.Float32("p95_ratio", 0.5))

	if got := payload["ttfb_ms"]; got != 903.1 {
		t.Errorf("ttfb_ms = %v (%T), want 903.1", got, got)
	}
	if got := payload["p95_ratio"]; got != float32(0.5) {
		t.Errorf("p95_ratio = %v (%T), want float32(0.5)", got, got)
	}
}

// TestAddFieldToPayloadKeepsTheOtherTypes guards the rest of the switch, since
// the decode above shares it: integers, strings, booleans and errors each have
// their own place in the field, and a decode that reached too far would show up
// here.
func TestAddFieldToPayloadKeepsTheOtherTypes(t *testing.T) {
	payload := map[string]any{}
	addFieldToPayload(payload, zap.Int("requests", 12))
	addFieldToPayload(payload, zap.Uint64("bytes", 4096))
	addFieldToPayload(payload, zap.String("job", "9f3a"))
	addFieldToPayload(payload, zap.Bool("cold", true))
	addFieldToPayload(payload, zap.Error(errors.New("boom")))

	for key, want := range map[string]any{
		"requests": int64(12),
		// A uint field arrives as int64: zap keeps every integer in one field,
		// and nothing this logger is handed comes near what that cannot hold.
		"bytes": int64(4096),
		"job":   "9f3a",
		"cold":  true,
		"error": "boom",
	} {
		if got := payload[key]; got != want {
			t.Errorf("%s = %v (%T), want %v (%T)", key, got, got, want, want)
		}
	}
}
