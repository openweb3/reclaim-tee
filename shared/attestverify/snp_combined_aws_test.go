//go:build !mobile

package attestverify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestVerifyCombinedAWSAttestationRejectsLegacy(t *testing.T) {
	env := combinedEnvelope{SEV: []byte("legacy report")}
	raw, err := cbor.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCombinedAWSAttestation(raw, []byte("spki")); err == nil || !strings.Contains(err.Error(), "no same-guest v2 proof") {
		t.Fatalf("legacy evidence accepted: %v", err)
	}
}

func TestAWSCombinedV2ReportDataBindsEveryField(t *testing.T) {
	bound := []byte("bound")
	app := bytes.Repeat([]byte{0x42}, 32)
	doc := []byte("signed NitroTPM document")
	want := awsCombinedV2ReportData(bound, app, doc)

	for name, fields := range map[string][][]byte{
		"bound": {[]byte("other"), app, doc},
		"app":   {bound, bytes.Repeat([]byte{0x43}, 32), doc},
		"doc":   {bound, app, []byte("other document")},
	} {
		t.Run(name, func(t *testing.T) {
			got := awsCombinedV2ReportData(fields[0], fields[1], fields[2])
			if got == want {
				t.Fatal("mutated transcript produced the same commitment")
			}
		})
	}
}

func TestAWSCombinedV2EnvelopeRemainsLegacyDecodable(t *testing.T) {
	type legacyEnvelope struct {
		AppHash  []byte   `cbor:"app"`
		NitroTPM []byte   `cbor:"nitrotpm,omitempty"`
		SEV      []byte   `cbor:"sev,omitempty"`
		Nonces   []string `cbor:"nonces,omitempty"`
	}

	want := combinedEnvelope{
		AppHash:  []byte("app"),
		NitroTPM: []byte("nitro"),
		SEV:      []byte("legacy"),
		SEV2:     []byte("same-guest"),
		Nonces:   []string{"nonce"},
	}
	raw, err := cbor.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got legacyEnvelope
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatalf("legacy decoder rejected expanded envelope: %v", err)
	}
	if !bytes.Equal(got.AppHash, want.AppHash) || !bytes.Equal(got.NitroTPM, want.NitroTPM) ||
		!bytes.Equal(got.SEV, want.SEV) || len(got.Nonces) != 1 || got.Nonces[0] != "nonce" {
		t.Fatalf("legacy fields changed: %+v", got)
	}
}
