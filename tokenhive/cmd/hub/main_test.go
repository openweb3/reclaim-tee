package main

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
)

func TestRequireServeKeys(t *testing.T) {
	// A real Accounts value stands in for "billing configured"; nil is the
	// "no ledger" case serve mode must refuse.
	accounts, _, err := hub.OpenAccounts(t.TempDir()+"/ledger.db", map[string]uint64{"t": 1})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	defer accounts.Close()
	cases := []struct {
		name      string
		serveAddr string
		agentKeys string
		relayKey  string
		accounts  *hub.Accounts
		maxJob    uint64
		sync      hub.SyncMode
		wantErr   string
	}{
		{name: "cli one-shot mode needs nothing"},
		{name: "serve mode requires agent keys", serveAddr: ":18085", relayKey: "r", accounts: accounts, maxJob: 1, sync: hub.SyncFull,
			wantErr: "agent-keys"},
		{name: "serve mode requires relay key", serveAddr: ":18085", agentKeys: "p=k", accounts: accounts, maxJob: 1, sync: hub.SyncFull,
			wantErr: "relay-key"},
		{name: "serve mode requires the ledger", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", maxJob: 1, sync: hub.SyncFull,
			wantErr: "-accounts"},
		{name: "serve mode requires a per-job ceiling", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", accounts: accounts, sync: hub.SyncFull,
			wantErr: "max-job-micros"},
		{name: "serve mode refuses a ledger that does not fsync", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", accounts: accounts, maxJob: 1, sync: hub.SyncOff,
			wantErr: "ledger-sync"},
		{name: "serve mode fully configured", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r", accounts: accounts, maxJob: 1, sync: hub.SyncFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireServeKeys(tc.serveAddr, tc.agentKeys, tc.relayKey, tc.accounts, tc.maxJob, tc.sync)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("requireServeKeys(%q, %q, %q) = %v, want nil", tc.serveAddr, tc.agentKeys, tc.relayKey, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("requireServeKeys(%q, %q, %q) = %v, want error containing %q",
					tc.serveAddr, tc.agentKeys, tc.relayKey, err, tc.wantErr)
			}
		})
	}
}
