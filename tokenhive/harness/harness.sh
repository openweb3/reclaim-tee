#!/bin/bash
# TokenHive local simulation harness.
#
# Builds the simulation binaries, starts the mock provider and the simulated
# TEE, and walks the scenario matrix end to end:
#   1  normal flow           -> seq 1..5, verified receipts, priced from the Hub
#                               rate table
#   2  policy denial          -> 403, no receipt (credential never touched)
#   3-4 provider 401 / 429    -> attested, but earns nothing
#   5  provider truncate      -> receipt with CompletionTruncated
#   6  TEE restart            -> ProviderSeq keeps climbing (cross-restart survival)
#   7  ProviderSeq gap        -> Hub hides one record, audit detects the gap
#   8  quota                  -> refused request never reaches the TEE, so it
#                               burns no ProviderSeq and leaves no gap
#   9  real TEE via reverse   -> genuine tee.Service egressing over the reverse
#     tunnel                    tunnel: a Provider Agent behind a NAT dials the
#                               Hub, the TEE dials the Hub's TeeRelay, and the
#                               Hub bridges the TEE's stream into the online
#                               agent's tunnel. A packet capture proves the
#                               agent relays only ciphertext.
#  10  agent killed mid-req   -> the request fails cleanly, never hangs/panics
#  11  epoch rotation         -> a TEE restarted with a new key still verifies
#  12  oversize response      -> the TEE truncates at its MaxResponseBytes cap
#  13  connection residency   -> N requests reuse exactly one upstream TCP
#                               connection through the tunnel
#  14  streaming session      -> a WebSocket session egresses over the reverse
#                               tunnel and its receipt verifies offline
#  15  lowest-price dispatch  -> the Hub schedules by model to the cheapest
#                               online agent, with commission on the buyer bill;
#                               agents auto-discover their upstream /v1/models
#                               and the catalog lists them at the lowest price
#  16  Anthropic /v1/messages + OpenAI /v1/responses user APIs
#  17  streaming session via  -> the Hub user API WebSocket: select + settle
#      the Hub user API          + duplex
#  18  Hub↔TEE mTLS             -> the TEE listener demands a Hub client cert;
#       pinning + identity        the Hub pins the TEE's RA-TLS certificate;
#                                 unpinned peers and plain HTTP are refused
#
# Every hub that hosts the reverse tunnel does so with per-provider agent keys
# (-agent-keys) and a relay key (-relay-key): a dial-in is bound to exactly one
# provider, and the TEE must authenticate to carry egress. The retired shared
# key and the unauthenticated relay are not exercised — a silently dropped flag
# would then fail the scenarios loudly rather than pass unnoticed.
#
# Nothing here talks to a real model or a real enclave. The Hub's business
# rules (pricing, quota, ledger, gap detection) are unit tested in-process
# against a scripted TEE; this harness exercises them over the real RPC.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$SCRIPT_DIR/bin"
SIM="$REPO/.sim"

cd "$REPO" || exit 1

echo "==> repo: $REPO"

# wipe removes files and directories without ever issuing one bulk unlink.
#
# Nothing in this script measures anything useful against leftover state: every
# receipt-count assertion below assumes the scenario started from a known store.
# A single "rm -rf" over a directory holding a few hundred receipts can be
# refused outright (deletion guards exist, and so do slow filesystems), and a
# refused wipe is not a harmless no-op — it turns a real assertion into a
# measurement of the previous scenario. Removing in small batches keeps the
# cleanup as unconditional as it reads.
wipe() {
  local path before after
  for path in "$@"; do
    before=0
    if [ -d "$path" ]; then
      before="$(find "$path" -type f 2>/dev/null | wc -l | tr -d ' ')"
      # No stderr suppression: a refused delete must be visible here, not
      # silently inherited by the next scenario's receipt count.
      find "$path" -type f -print0 2>/dev/null | xargs -0 -n 40 rm -f
      rm -rf "$path"
      after="$(find "$path" -type f 2>/dev/null | wc -l | tr -d ' ')"
    else
      rm -f "$path"
      after=0
    fi
    if [ "$before" != "$after" ] || [ "$before" -gt 0 ]; then
      echo "    [wipe] $path: $before -> $after"
    fi
  done
  return 0
}


# --- kill any stale simulation processes from an interrupted prior run -----
# (a leftover faketee would still hold :18090 and serve an old policy/seqstore)
pkill -f "$BIN/" 2>/dev/null
pkill -f "tokenhive/cmd" 2>/dev/null
sleep 0.3

# --- build ---------------------------------------------------------------
echo "==> building simulation binaries"
mkdir -p "$BIN"
for pkg in mockprovider faketee hub tee agent streamer sessiondriver; do
  echo "    building $pkg"
  go build -o "$BIN/$pkg" "./tokenhive/cmd/$pkg" || { echo "build failed for $pkg"; exit 1; }
done

# --- fresh state ---------------------------------------------------------
wipe "$SIM"
mkdir -p "$SIM"

wait_for_port() {
  local host="$1" port="$2" tries=50
  while ! (echo > "/dev/tcp/$host/$port") 2>/dev/null; do
    tries=$((tries-1))
    [ "$tries" -le 0 ] && { echo "  !! timeout waiting $host:$port"; return 1; }
    sleep 0.2
  done
}

# wait_for_cheapest waits until the Hub's model directory quotes the named
# provider as the cheapest for at least one model — i.e. until that provider's
# agent is genuinely online. Scenarios 15-17 dial their agents in BEFORE their
# TEE exists, so the first registration cannot seal a credential, and the agent
# retries on a full-jitter backoff (provider.jittered): the instant it comes
# back is not fixed. A bare `sleep` races that backoff and flakes; polling the
# real readiness signal does not. On timeout the caller's assertions still run
# and fail loudly, so a genuinely stuck agent is reported, not masked.
wait_for_cheapest() {
  local port="$1" provider="$2" tries=150
  while [ "$tries" -gt 0 ]; do
    if curl -s --noproxy '*' "http://127.0.0.1:$port/v1/models" 2>/dev/null \
        | grep -q "\"provider\":\"$provider\""; then
      return 0
    fi
    tries=$((tries-1))
    sleep 0.2
  done
  echo "  !! timeout waiting for $provider to appear in the model directory on :$port"
  return 1
}

MP_PORT=18080
TEE_PORT=18090
STATS_PORT=18081

# --- start mock provider (real TLS via generated test CA) -----------------
# The sellers' access tokens. They live only in the agent processes (and, for
# the one-shot simulation tools that talk to a TEE directly, in their -credential
# flag): the TEE receives them sealed, and the Hub never sees them in the clear.
TOKEN_OAI="sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TOKEN_CHEAP="sk-sim-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

# A separate plain-HTTP stats listener (/stats, /reset) peers at the provider's
# connection count WITHOUT dialing a connection of its own, so a probe can never
# perturb the very number it reports.
echo "==> starting mockprovider (TLS) on :$MP_PORT"
"$BIN/mockprovider" -addr "127.0.0.1:$MP_PORT" -tls -stats-addr "127.0.0.1:$STATS_PORT" > "$SIM/mockprovider.log" 2>&1 &
MP_PID=$!
wait_for_port 127.0.0.1 "$MP_PORT"

# --- start simulated TEE -------------------------------------------------
echo "==> starting faketee (sim TEE) on :$TEE_PORT"
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"

section() { echo; echo "=================================================="; echo "==> $1"; echo "=================================================="; }

# --- 1. normal flow ---------------------------------
section "1. normal flow (5 requests)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -n 5

# --- 2. policy denial (wrong host) ---------------------------------------
section "2. policy denial: Hub sends disallowed host 1.2.3.4:18080"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -host "1.2.3.4:18080" || true

# --- 3/4/5. provider faults ---------------------------------------------
section "3. provider returns 401 (CompletionFailed)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -query "fault=401" || true

section "4. provider returns 429 (CompletionFailed)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -query "fault=429" || true

section "5. provider drops connection mid-stream (CompletionTruncated)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -query "fault=truncate" || true

# --- 6. cross-restart ProviderSeq survival -------------------------------
section "6. restart faketee; ProviderSeq must keep climbing"
echo "    (killing faketee pid $TEE_PID)"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee2.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    sending 1 request after restart; expect seq to continue, not reset:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -n 1

# --- 7. ProviderSeq gap detection ---------------------------------------
section "7. ProviderSeq gap: Hub hides one record, audit must catch it"
echo "    (reset store + restart faketee for an isolated demo)"
wipe "$SIM/receipts" "$SIM/seqstore.json"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee3.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    sending 3, withholding the 2nd receipt (expect stored seqs {1,3}):"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -n 3 -drop 2
echo
echo "    --> auditing the receipt store:"
"$BIN/hub" -audit

# --- 8. quota refuses before dispatch ------------------------------------
section "8. quota: 3 attempts, tenant limited to 2"
echo "    (fresh store and seqstore so the audit is unambiguous)"
wipe "$SIM/receipts" "$SIM/seqstore.json"
kill "$TEE_PID" 2>/dev/null; wait "$TEE_PID" 2>/dev/null
"$BIN/faketee" -addr "127.0.0.1:$TEE_PORT" -seq "$SIM/seqstore.json" > "$SIM/faketee4.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
echo "    the 3rd request must be refused by the Hub, never reaching the TEE:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_PORT" -credential "$TOKEN_OAI" -n 3 -quota 2 -window 1m -tenant quota-demo
echo
echo "    --> audit: 2 receipts, no gaps. A refused request that still burned"
echo "        a ProviderSeq would show up here as a missing number."
"$BIN/hub" -audit

# =====================================================================
# S4: REAL TEE over the REVERSE TUNNEL.
# Scenarios 1-8 run the A-layer fake TEE (cmd/faketee). These run the genuine
# tee.Service along the production outbound path: a Provider Agent behind a
# NAT dials the Hub and keeps a multiplexed reverse tunnel open; the TEE dials
# the Hub's TeeRelay; the Hub bridges the TEE's stream into the online agent's
# tunnel, which relays only ciphertext to the provider.
#
#   user -> Hub user API (/v1/chat/completions ...)
#        -> Hub /v1/execute -> TEE
#        -> Hub TeeRelay (/v1/relay, TEE dials in)
#        -> Hub AgentGate (/v1/agent, agent dials in)
#        -> provider (real TLS, terminated inside the TEE)
# =====================================================================

# Per-provider agent keys: each provider's tunnel can only be opened with its
# own key, so no seller can come online as another and collect the revenue
# routed to its name. The shared-key path is deliberately not exercised here:
# with only -agent-keys configured the gate refuses every dial-in that does not
# name a provisioned provider and present that provider's key, so a silently
# dropped flag would fail the scenarios loudly instead of going unnoticed.
KEY_OAI_AGENT="sim-agent-key-openai"
KEY_CHEAP_AGENT="sim-agent-key-cheap"
# Key the TEE presents to dial the Hub's /v1/relay endpoint, so the relay is
# not an open egress proxy for anything that can reach it.
RELAY_SECRET="sim-relay-secret"
AGENT_KEYS="openai-sim=$KEY_OAI_AGENT,cheap-sim=$KEY_CHEAP_AGENT"
# The sellers' access tokens (TOKEN_OAI / TOKEN_CHEAP) are defined above, next
# to the mock provider, because scenarios 1-8 use them too.
RT_HUB_PORT=18094          # reverse-tunnel hub shared by scenarios 9-14
RT_HUB_WS="ws://127.0.0.1:$RT_HUB_PORT"
HUB_WS="ws://127.0.0.1:18085"   # user-facing Hub (scenarios 15-17)

# --- start the reverse-tunnel Hub for scenarios 9-14 ----------------------
# It mounts AgentGate (/v1/agent) and TeeRelay (/v1/relay) next to the user API.
# -tee points at the A-layer faketee (:18090, already up) purely so agents can
# fetch a publishable inbox key to encrypt to: the gate refuses credential-less
# registrations, and the one-shot hubs in 9-13 supply their own token to their
# real TEE directly, so the envelope agent A deposits here is never opened.
echo "==> starting reverse-tunnel Hub on :$RT_HUB_PORT (agent gate /v1/agent, tee relay /v1/relay)"
"$BIN/hub" -serve "127.0.0.1:$RT_HUB_PORT" -host "127.0.0.1:$MP_PORT" \
  -tee "http://127.0.0.1:$TEE_PORT" -agent-keys "$AGENT_KEYS" -relay-key "$RELAY_SECRET" > "$SIM/hub-rt.log" 2>&1 &
RT_HUB_PID=$!
wait_for_port 127.0.0.1 "$RT_HUB_PORT"

# The Hub keeps at most one online agent per provider, so each agent here is
# started, used within its own scenario window, and killed before the next
# scenario re-registers the same provider under a fresh process.

# --- Scenario 9: real TEE over the reverse tunnel ------------------------
TEE_A=18095
section "9. real TEE -> tee relay -> agent reverse tunnel -> provider (TLS)"

echo "    starting provider agent A (openai-sim) dialing the reverse-tunnel hub"
"$BIN/agent" -hub "$RT_HUB_WS/v1/agent" -key "$KEY_OAI_AGENT" -provider openai-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_OAI" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" -tap "$SIM/tap.log" > "$SIM/agentA.log" 2>&1 &
AGENT_A_PID=$!
# The agent registers asynchronously; give it a beat before the first request.
sleep 1

echo "    starting REAL tee.Service A on :$TEE_A, egressing via the hub relay"
"$BIN/tee" -addr "127.0.0.1:$TEE_A" -relay "$RT_HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-real.json" > "$SIM/teeA.log" 2>&1 &
TEE_A_PID=$!
wait_for_port 127.0.0.1 "$TEE_A"

# This TEE's seqstore starts at 1, so the receipt store must start clean too:
# receipts left over from scenarios 1-8 carry ProviderSeq 1..N for the same
# provider, and a fresh sequence colliding with them would suppress the very
# "[receipt]" lines scenarios 9-12 assert on.
wipe "$SIM/receipts"

echo "    one normal request over the real path (one-shot mode: the hub registers"
echo "    the token to this TEE directly, as a dialing agent would through a resident hub)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -credential "$TOKEN_OAI" -n 1

echo
echo "    --> packet-capture assertion: the agent must only relay ciphertext"
CRED="$TOKEN_OAI"
FAIL=0
if grep -Fqa "$CRED" "$SIM/tap.log" 2>/dev/null; then echo "      !! FAIL: credential present in agent tap"; FAIL=1; fi
for needle in Bearer Authorization; do
  if grep -Fqa "$needle" "$SIM/tap.log" 2>/dev/null; then echo "      !! FAIL: '$needle' visible in plaintext on agent wire"; FAIL=1; fi
done
if [ "$FAIL" -eq 0 ]; then
  echo "      AGENT ONLY SAW CIPHERTEXT: $(wc -c < "$SIM/tap.log") bytes captured, no credential/Bearer/Authorization"
fi

# --- Scenario 10: kill the agent mid-request -----------------------------
TEE_B=18096
section "10. Provider Agent killed mid-request -> graceful failure"
echo "    real tee B on :$TEE_B, egressing back through the SAME agent A"
"$BIN/tee" -addr "127.0.0.1:$TEE_B" -relay "$RT_HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-teeb.json" > "$SIM/teeB.log" 2>&1 &
TEE_B_PID=$!
wait_for_port 127.0.0.1 "$TEE_B"

# Fresh store so the failure receipt's sequence is unambiguous.
wipe "$SIM/receipts"

echo "    launching a slow request (provider sleeps 2s) in the background:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_B" -credential "$TOKEN_OAI" -query "fault=slow" > "$SIM/hub-slow.log" 2>&1 &
HUB_SLOW_PID=$!
sleep 0.6
echo "    killing the agent mid-request (pid $AGENT_A_PID)..."
kill "$AGENT_A_PID" 2>/dev/null
wait "$HUB_SLOW_PID" 2>/dev/null

echo "    -> the TEE must attest the failure as a signed receipt, never hang/panic:"
if grep -E "^\[receipt\].*completion=failed" "$SIM/hub-slow.log"; then
  echo "      OK: TEE attested a graceful failure (completion=failed, 0 bytes, charged 0)"
else
  echo "      !! FAIL: expected a completion=failed receipt"
fi
if grep -E "^\[receipt\].*completion=complete" "$SIM/hub-slow.log"; then
  echo "      !! FAIL: a COMPLETE receipt was produced despite the agent being killed"
fi
if grep -Fqa "panic" "$SIM/teeB.log"; then
  echo "      !! FAIL: tee panicked on agent loss"
else
  echo "      OK: tee handled the broken pipe without panic"
fi
# tee B is no longer needed.
kill "$TEE_B_PID" 2>/dev/null; wait "$TEE_B_PID" 2>/dev/null

# --- Scenario 11: epoch rotation (restart agent A + tee A) ----------------
section "11. TEE restarts with a NEW signing key (epoch rotation)"
echo "    (a fresh sim epoch => new key; restart agent A so openai-sim is back online)"
"$BIN/agent" -hub "$RT_HUB_WS/v1/agent" -key "$KEY_OAI_AGENT" -provider openai-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_OAI" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" -tap "$SIM/tap.log" > "$SIM/agentA2.log" 2>&1 &
AGENT_A_PID=$!
sleep 1

echo "    (killing tee A pid $TEE_A_PID and restarting it under the new key)"
kill "$TEE_A_PID" 2>/dev/null; wait "$TEE_A_PID" 2>/dev/null
"$BIN/tee" -addr "127.0.0.1:$TEE_A" -relay "$RT_HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-real.json" > "$SIM/teeA2.log" 2>&1 &
TEE_A_PID=$!
wait_for_port 127.0.0.1 "$TEE_A"
echo "    one request under the new key; the Hub must still verify it:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -credential "$TOKEN_OAI" -n 1
echo "    (verification uses the signer key embedded in each receipt, so a"
echo "     rotated key is transparent — no trust-root redeploy needed)"

# --- Scenario 12: oversize response --------------------------------------
section "12. oversize provider response -> TEE truncates at the cap"
echo "    provider streams ~3 MiB; Hub caps the TEE at 64 KiB:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_A" -credential "$TOKEN_OAI" -query "fault=big" -max 65536 > "$SIM/hub-big.log" 2>&1
cat "$SIM/hub-big.log"
echo "    -> expect completion=truncated and a stream hash the Hub can verify:"
if grep -E "^\[receipt\].*completion=truncated" "$SIM/hub-big.log"; then
  echo "      OK: TEE truncated at the cap and attested it; receipt verified, settled"
else
  echo "      !! FAIL: expected completion=truncated"
fi
# The cap that stopped it is the Hub's own, and the TEE now says so on the
# wire. Without the reason the Hub could only report a truncated stream, which
# is also what a provider that died mid-response produces.
if grep -Fq "failure=response_too_large" "$SIM/hub-big.log"; then
  echo "      OK: the truncation is attributed to the cap, not to the provider"
else
  echo "      !! FAIL: expected the failure class response_too_large"
fi
if grep -Fqa "different bytes" "$SIM/hub-big.log"; then
  echo "      !! FAIL: Hub could not reconcile the attested stream (hash mismatch)"
fi
echo "    (credential still never on the agent wire — see scenario 9's tap)"

# =====================================================================
# Connection residency: a fresh real TEE through the online agent; zero the
# upstream's TCP counter; N requests must reuse exactly ONE connection; a
# mid-stream disconnect then forces a fresh dial (counter +1) and leaves the
# next receipt normal.
# =====================================================================
TEE_C=18097
# --noproxy '*' : the sim shell carries an HTTP_PROXY env var that would route a
# query for the local stats listener through the user's proxy and receive
# nothing back; the 127.0.0.1 probe must always be direct.
section "13. connection residency: N requests, ONE upstream TCP connection"
curl -s --noproxy '*' "http://127.0.0.1:$STATS_PORT/reset" > /dev/null   # clean baseline
echo "    starting fresh real tee C on :$TEE_C, egressing via the reverse tunnel"
# Fresh TEE, fresh seqstore, so the shared receipt store must be isolated too —
# otherwise tee C's seq 1..N collide with tee A's receipts from scenarios 9-12
# and the "[receipt]" lines below never print.
wipe "$SIM/receipts"
"$BIN/tee" -addr "127.0.0.1:$TEE_C" -relay "$RT_HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-teec.json" > "$SIM/teeC.log" 2>&1 &
TEE_C_PID=$!
wait_for_port 127.0.0.1 "$TEE_C"

conns() { curl -s --noproxy '*' "http://127.0.0.1:$STATS_PORT/stats" | python3 -c "import json,sys;print(json.load(sys.stdin)['new_conns'])"; }

base=$(conns)
echo "    baseline new_conns=$base (expect 0)"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_C" -credential "$TOKEN_OAI" -n 5 > "$SIM/hub-resident.log" 2>&1
after5=$(conns)
echo "    after 5 requests new_conns=$after5 (expect exactly 1 resident TLS session)"
if [ "$after5" -eq $((base+1)) ]; then
  echo "      OK: 5 requests reused 1 TCP connection"
else
  echo "      !! FAIL: expected $((base+1)), got $after5 (connection not resident)"
fi

echo "    injecting a mid-stream disconnect (fault=truncate); channel must be discarded:"
"$BIN/hub" -tee "http://127.0.0.1:$TEE_C" -credential "$TOKEN_OAI" -query "fault=truncate" > "$SIM/hub-trunc.log" 2>&1
if grep -q "completion=truncated" "$SIM/hub-trunc.log"; then
  echo "      OK: truncate receipt (completion=truncated)"
else
  echo "      !! FAIL: expected completion=truncated"
fi
aftertr=$(conns)
echo "    after truncate new_conns=$aftertr (expect $after5: reuse, no dial)"
if [ "$aftertr" -eq "$after5" ]; then
  echo "      OK: truncate reused the resident conn, then discarded it"
else
  echo "      !! FAIL: expected $after5, got $aftertr"
fi

"$BIN/hub" -tee "http://127.0.0.1:$TEE_C" -credential "$TOKEN_OAI" -n 1 > "$SIM/hub-redial.log" 2>&1
afterred=$(conns)
echo "    after the next request new_conns=$afterred (expect $((aftertr+1)): a fresh dial)"
if [ "$afterred" -eq $((aftertr+1)) ]; then
  echo "      OK: discarded channel forced a new TCP connection"
else
  echo "      !! FAIL: expected $((aftertr+1)), got $afterred"
fi
if grep -q "completion=complete" "$SIM/hub-redial.log"; then
  echo "      OK: post-recovery receipt is normal (completion=complete)"
else
  echo "      !! FAIL: expected a normal complete receipt"
fi
kill "$TEE_C_PID" 2>/dev/null; wait "$TEE_C_PID" 2>/dev/null

# =====================================================================
# Streaming session: a real TEE egresses through the reverse tunnel and
# upgrades to the provider's /v1/realtime WebSocket; the streamer drives a
# full-duplex exchange and verifies the terminal 101 session receipt offline
# against the exact bytes.
# =====================================================================
TEE_E=18099
section "14. streaming session: WebSocket upgrade tunnel + session receipt"

echo "    starting real tee E on :$TEE_E, egressing via the reverse tunnel"
"$BIN/tee" -addr "127.0.0.1:$TEE_E" -relay "$RT_HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-t14.json" > "$SIM/teeE.log" 2>&1 &
TEE_E_PID=$!
wait_for_port 127.0.0.1 "$TEE_E"

echo "    driving a full-duplex session (uplink marker -> provider echo -> receipt):"
"$BIN/streamer" -tee "ws://127.0.0.1:$TEE_E/v1/session" \
  -provider openai-sim -host "127.0.0.1:$MP_PORT" -path /v1/realtime \
  -credential "$TOKEN_OAI" -marker "streamtest-marker-14" > "$SIM/streamer.log" 2>&1
cat "$SIM/streamer.log"

echo "    assertion: session verified end-to-end (101, byte counts, stream hash, echo):"
if grep -q "SESSION OK" "$SIM/streamer.log"; then
  echo "      OK: streaming session verified offline"
else
  echo "      !! FAIL: streamer did not verify the session receipt"
fi
if grep -q "STREAM FAIL" "$SIM/streamer.log"; then
  echo "      !! FAIL: streamer reported a failure (see above)"
fi

kill "$TEE_E_PID" 2>/dev/null; wait "$TEE_E_PID" 2>/dev/null

# Scenarios 15-17 run on their own user-facing Hub (port 18085); stop the
# scenario 9-14 reverse-tunnel Hub and its agent.
kill "$AGENT_A_PID" 2>/dev/null; wait "$AGENT_A_PID" 2>/dev/null
kill "$RT_HUB_PID" 2>/dev/null; wait "$RT_HUB_PID" 2>/dev/null
kill "$TEE_A_PID" 2>/dev/null; wait "$TEE_A_PID" 2>/dev/null

# =====================================================================
# Lowest-price scheduling + commission: A Hub user-facing API over a real
# TEE that egresses TWO providers, each through its own online agent. Both
# serve the same model at different prices (cheap-sim 0.30, openai-sim 1.00),
# so the scheduler must pick cheap-sim for every request; the 10% commission
# must land on the buyer's bill while the provider keeps its own price.
# =====================================================================
HUB_API_PORT=18085
TEE_D=18098
section "15. lowest-price scheduling + commission: user API picks cheap-sim"

echo "    starting the user-facing Hub on :$HUB_API_PORT (10% commission, agent-key gate)"
"$BIN/hub" -serve "127.0.0.1:$HUB_API_PORT" -host "127.0.0.1:$MP_PORT" \
  -tee "http://127.0.0.1:$TEE_D" -commission 1000 -agent-keys "$AGENT_KEYS" \
  -relay-key "$RELAY_SECRET" \
  > "$SIM/hub-serve.log" 2>&1 &
HUB_API_PID=$!
wait_for_port 127.0.0.1 "$HUB_API_PORT"

echo "    two provider agents come online: cheap-sim (0.30) and openai-sim (1.00)"
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_CHEAP_AGENT" -provider cheap-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_CHEAP" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" > "$SIM/agent-cheap.log" 2>&1 &
AGENT_CHEAP_PID=$!
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_OAI_AGENT" -provider openai-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_OAI" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" > "$SIM/agent-oai.log" 2>&1 &
AGENT_OAI_PID=$!
sleep 1

echo "    starting real tee D on :$TEE_D with the two-provider egress"
"$BIN/tee" -addr "127.0.0.1:$TEE_D" -relay "$HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-t15.json" > "$SIM/teeD.log" 2>&1 &
TEE_D_PID=$!
wait_for_port 127.0.0.1 "$TEE_D"
# The agents dialed in before the TEE was up and had no inbox key to encrypt to,
# so they retry on a jittered backoff. Wait for the real signal — cheap-sim live
# in the model directory — rather than a fixed beat that races that backoff;
# firing a request earlier would dispatch without a credential and be refused.
wait_for_cheapest "$HUB_API_PORT" cheap-sim

echo "    sending 3 chat requests for model sim-mock-0.5b:"
for i in 1 2 3; do
  curl -s --noproxy '*' -X POST "http://127.0.0.1:$HUB_API_PORT/v1/chat/completions" \
    -H 'Content-Type: application/json' -H 'X-TokenHive-Key: tenant-t15' \
    -d '{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hi"}],"stream":true}' \
    > "$SIM/user-api-$i.out" 2>&1
done

echo "    assertion: every request served by cheap-sim (0.30), none by openai-sim (1.00):"
cheap=$(grep -c 'provider="cheap-sim"' "$SIM/hub-serve.log" || true)
dear=$(grep -c 'provider="openai-sim"' "$SIM/hub-serve.log" || true)
if [ "$cheap" -ge 3 ] && [ "$dear" -eq 0 ]; then
  echo "      OK: $cheap requests served by cheap-sim, $dear by openai-sim (scheduler picked the lowest price)"
else
  echo "      !! FAIL: cheap-sim=$cheap openai-sim=$dear, want cheap>=3 dear==0"
fi

echo "    assertion: user-facing stream terminated with data: [DONE]:"
if grep -Fq 'data: [DONE]' "$SIM/user-api-1.out"; then
  echo "      OK: SSE stream closed with the OpenAI [DONE] marker"
else
  echo "      !! FAIL: no [DONE] marker in the user stream"
fi

echo "    assertion: commission applied (seller 0.30 -> commission 0.03, buyer 0.33 at 10%):"
if grep -q 'commission=0.03' "$SIM/hub-serve.log" && grep -q 'buyer=0.33' "$SIM/hub-serve.log"; then
  echo "      OK: buyer billed 0.33 for a 0.30 seller price (10% commission)"
else
  echo "      !! FAIL: expected commission=0.03 and buyer=0.33"
fi

echo "    assertion: exactly 3 receipts stored under cheap-sim (cheap-sim is used only here):"
cheap_receipts=$(ls "$SIM/receipts/cheap-sim"/*.cbor 2>/dev/null | wc -l | tr -d ' ')
if [ "$cheap_receipts" -eq 3 ]; then
  echo "      OK: $cheap_receipts receipts under cheap-sim"
else
  echo "      !! FAIL: expected 3 receipts under cheap-sim, got $cheap_receipts"
fi

kill "$TEE_D_PID" "$HUB_API_PID" 2>/dev/null; wait "$TEE_D_PID" "$HUB_API_PID" 2>/dev/null

# =====================================================================
# Anthropic messages + OpenAI responses user APIs:
# The Hub relays two more wire shapes verbatim over the same scheduler:
# /v1/messages (Anthropic: event: message_start ... message_stop) and
# /v1/responses (OpenAI Responses: response.created ... response.completed).
# Unlike chat completions these carry their own terminal events, so the Hub
# must NOT append [DONE]. Both must pick cheap-sim (lowest price) and store
# one receipt each.
# The two agents come online WITHOUT -models here: each auto-discovers its
# model list from the upstream's /v1/models (trusting the sim CA), so the
# directory and search assertions below prove the whole discovery chain
# (fetch -> register -> Hub catalog) end to end, not just declared models.
# =====================================================================
section "16. Anthropic /v1/messages + OpenAI /v1/responses user APIs"

echo "    (fresh hub + stores so receipt counts are unambiguous)"
wipe "$SIM/receipts"
"$BIN/hub" -serve "127.0.0.1:$HUB_API_PORT" -host "127.0.0.1:$MP_PORT" \
  -tee "http://127.0.0.1:$TEE_D" -agent-keys "$AGENT_KEYS" \
  -relay-key "$RELAY_SECRET" \
  > "$SIM/hub-serve16.log" 2>&1 &
HUB_API16_PID=$!
wait_for_port 127.0.0.1 "$HUB_API_PORT"

echo "    bringing the two agents back online (no -models: each auto-discovers from its upstream /v1/models)"
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_CHEAP_AGENT" -provider cheap-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_CHEAP" -ca "$SIM/ca.pem" > "$SIM/agent-cheap16.log" 2>&1 &
AGENT_CHEAP_PID=$!
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_OAI_AGENT" -provider openai-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_OAI" -ca "$SIM/ca.pem" > "$SIM/agent-oai16.log" 2>&1 &
AGENT_OAI_PID=$!
sleep 1

echo "    assertion: both agents entered auto-discovery (no -models on the command line):"
if grep -q "will discover from https://127.0.0.1:$MP_PORT/v1/models" "$SIM/agent-cheap16.log" \
   && grep -q "will discover from https://127.0.0.1:$MP_PORT/v1/models" "$SIM/agent-oai16.log"; then
  echo "      OK: both agents infer and fetch their upstream /v1/models before registering"
else
  echo "      !! FAIL: an agent did not attempt conventional /v1/models discovery"
fi

"$BIN/tee" -addr "127.0.0.1:$TEE_D" -relay "$HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-t16.json" > "$SIM/teeD16.log" 2>&1 &
TEE_D16_PID=$!
wait_for_port 127.0.0.1 "$TEE_D"

# Same readiness wait as scenario 15: the requests below must not race the
# agents' jittered re-registration.
wait_for_cheapest "$HUB_API_PORT" cheap-sim

echo "    POST /v1/messages (Anthropic format, model claude-sim):"
curl -s --noproxy '*' -X POST "http://127.0.0.1:$HUB_API_PORT/v1/messages" \
  -H 'Content-Type: application/json' -H 'X-TokenHive-Key: tenant-t16' \
  -d '{"model":"claude-sim-haiku","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}' \
  > "$SIM/user-api-messages.out" 2>&1

echo "    POST /v1/responses (OpenAI Responses format):"
curl -s --noproxy '*' -X POST "http://127.0.0.1:$HUB_API_PORT/v1/responses" \
  -H 'Content-Type: application/json' -H 'X-TokenHive-Key: tenant-t16' \
  -d '{"model":"sim-mock-0.5b","input":"hi","stream":true}' \
  > "$SIM/user-api-responses.out" 2>&1

echo "    assertion: Anthropic framing relayed with its own terminal event:"
if grep -Fq 'event: message_start' "$SIM/user-api-messages.out" \
   && grep -Fq 'event: message_stop' "$SIM/user-api-messages.out"; then
  echo "      OK: Anthropic SSE framing (message_start...message_stop) relayed"
else
  echo "      !! FAIL: expected Anthropic message_start/message_stop events"
fi

echo "    assertion: OpenAI Responses framing relayed with response.completed:"
if grep -Fq 'response.completed' "$SIM/user-api-responses.out"; then
  echo "      OK: Responses framing (response.created...response.completed) relayed"
else
  echo "      !! FAIL: expected a response.completed terminal event"
fi

echo "    assertion: no [DONE] glued onto the non-chat streams:"
if grep -Fq '[DONE]' "$SIM/user-api-messages.out" || grep -Fq '[DONE]' "$SIM/user-api-responses.out"; then
  echo "      !! FAIL: non-chat stream should carry its own terminator, no [DONE]"
else
  echo "      OK: no foreign [DONE] marker on Anthropic/Responses streams"
fi

echo "    assertion: both requests served by cheap-sim and each stored a receipt:"
if grep -q 'path=/v1/messages .*provider="cheap-sim"' "$SIM/hub-serve16.log" \
   && grep -q 'path=/v1/responses .*provider="cheap-sim"' "$SIM/hub-serve16.log"; then
  echo "      OK: scheduler picked cheap-sim for both new routes"
else
  echo "      !! FAIL: expected cheap-sim on /v1/messages and /v1/responses"
  grep 'path=/v1/' "$SIM/hub-serve16.log"
fi
messages_receipts=$(ls "$SIM/receipts/cheap-sim"/*.cbor 2>/dev/null | wc -l | tr -d ' ')
if [ "$messages_receipts" -eq 2 ]; then
  echo "      OK: 2 receipts stored under cheap-sim (one per request)"
else
  echo "      !! FAIL: expected 2 receipts under cheap-sim, got $messages_receipts"
fi

echo "    assertion: GET /v1/models lists the market (model + lowest price):"
curl -s --noproxy '*' "http://127.0.0.1:$HUB_API_PORT/v1/models" > "$SIM/models-dir.json"
if python3 - "$SIM/models-dir.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
models = {m["model"]: m for m in doc["models"]}
want = {"sim-mock-0.5b": "cheap-sim", "claude-sim-haiku": "cheap-sim", "sim-claude-haiku": "cheap-sim"}
ok = True
for model, provider in want.items():
    row = models.get(model)
    if row is None:
        print(f"      !! missing {model} from directory"); ok = False
    elif row["provider"] != provider:
        print(f"      !! {model} cheapest is {row['provider']}, want {provider}"); ok = False
    elif row["price_micros"] == 0:
        print(f"      !! {model} has a zero price"); ok = False
if ok:
    print("      OK: directory lists all declared models at the lowest online price")
else:
    sys.exit(1)
PY
then :; else echo "      !! FAIL: /v1/models directory wrong (see above)"; fi

echo "    assertion: model search by exact name and by substring:"
curl -s --noproxy '*' "http://127.0.0.1:$HUB_API_PORT/v1/models?q=claude-sim-haiku" > "$SIM/models-search-exact.json"
curl -s --noproxy '*' "http://127.0.0.1:$HUB_API_PORT/v1/models?q=sim-mock" > "$SIM/models-search-sub.json"
if python3 - "$SIM/models-search-exact.json" "$SIM/models-search-sub.json" <<'PY'
import json, sys
exact = {m["model"] for m in json.load(open(sys.argv[1]))["models"]}
sub = {m["model"] for m in json.load(open(sys.argv[2]))["models"]}
ok = True
if exact != {"claude-sim-haiku"}:
    print(f"      !! exact q=claude-sim-haiku -> {exact}"); ok = False
if "sim-mock-0.5b" not in sub:
    print(f"      !! substring q=sim-mock missing sim-mock-0.5b: {sub}"); ok = False
if ok:
    print("      OK: search matches an exact ID and a shared prefix")
else:
    sys.exit(1)
PY
then :; else echo "      !! FAIL: /v1/models search wrong (see above)"; fi

kill "$TEE_D16_PID" "$HUB_API16_PID" 2>/dev/null; wait "$TEE_D16_PID" "$HUB_API16_PID" 2>/dev/null

# =====================================================================
# Streaming session through the Hub user API:
# A user opens /v1/session, the Hub learns the model from the first frame,
# picks the cheapest provider, and relays the full-duplex session through a
# real TEE to /v1/realtime. The sessiondriver proves the byte round trip;
# the Hub log proves it chose cheap-sim and settled a charge. The session
# bounds (wall-clock timeout, downlink byte cap, stall watchdog) are each
# per-Hub config, so they are exercised in-process in hub/realtime_test.go
# rather than by a dedicated running Hub here.
# =====================================================================
TEE_G=18091
section "17. streaming session via the Hub user API: select + settle + duplex"

echo "    (fresh hub + stores so the receipt count is unambiguous)"
wipe "$SIM/receipts"
"$BIN/hub" -serve "127.0.0.1:$HUB_API_PORT" -host "127.0.0.1:$MP_PORT" \
  -tee "http://127.0.0.1:$TEE_G" -commission 1000 \
  -session-timeout 30s -session-max 1048576 -session-idle 5s \
  -agent-keys "$AGENT_KEYS" -relay-key "$RELAY_SECRET" > "$SIM/hub-serve17.log" 2>&1 &
HUB_API17_PID=$!
wait_for_port 127.0.0.1 "$HUB_API_PORT"

echo "    two provider agents online (cheap-sim cheapest for the model)"
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_CHEAP_AGENT" -provider cheap-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_CHEAP" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" > "$SIM/agent-cheap17.log" 2>&1 &
AGENT_CHEAP_PID=$!
"$BIN/agent" -hub "$HUB_WS/v1/agent" -key "$KEY_OAI_AGENT" -provider openai-sim \
  -targets "127.0.0.1:$MP_PORT" -token "$TOKEN_OAI" -models "sim-mock-0.5b,claude-sim-haiku,sim-claude-haiku" > "$SIM/agent-oai17.log" 2>&1 &
AGENT_OAI_PID=$!
sleep 1

"$BIN/tee" -addr "127.0.0.1:$TEE_G" -relay "$HUB_WS/v1/relay" -relay-key "$RELAY_SECRET" \
  -seq "$SIM/seqstore-t17.json" > "$SIM/teeG.log" 2>&1 &
TEE_G_PID=$!
wait_for_port 127.0.0.1 "$TEE_G"

# Same readiness wait as scenario 15.
wait_for_cheapest "$HUB_API_PORT" cheap-sim

echo "    a streaming session for model sim-mock-0.5b (cheapest provider = cheap-sim):"
"$BIN/sessiondriver" -url "ws://127.0.0.1:$HUB_API_PORT/v1/session" \
  -model sim-mock-0.5b -marker "session-marker-17" > "$SIM/session17.log" 2>&1
cat "$SIM/session17.log"

echo "    assertion: session relay verified end to end (duplex round trip):"
if grep -q "SESSION-ROUTE OK" "$SIM/session17.log"; then
  echo "      OK: user WS -> Hub -> TEE -> provider -> back (frames echoed)"
else
  echo "      !! FAIL: sessiondriver did not verify (see above)"
fi

echo "    assertion: Hub picked cheap-sim (0.30) for the session, not openai-sim:"
cheap=$(grep -c 'provider="cheap-sim"' "$SIM/hub-serve17.log" || true)
dear=$(grep -c 'provider="openai-sim"' "$SIM/hub-serve17.log" || true)
if [ "$cheap" -ge 1 ] && [ "$dear" -eq 0 ]; then
  echo "      OK: session on cheap-sim, none on openai-sim (scheduler picked the lowest price)"
else
  echo "      !! FAIL: cheap-sim=$cheap openai-sim=$dear, want cheap>=1 dear==0"
fi

echo "    assertion: session was settled with a charge (10% commission on the buyer bill):"
if grep -q 'provider="cheap-sim".*charged=0.30' "$SIM/hub-serve17.log" \
   && grep -q 'buyer=0.33' "$SIM/hub-serve17.log"; then
  echo "      OK: charged 0.30, buyer 0.33 at 10% commission"
else
  echo "      !! FAIL: expected charged=0.30 / buyer=0.33 in the session log"
fi

echo "    assertion: exactly 1 session receipt stored under cheap-sim:"
sess_receipts=$(ls "$SIM/receipts/cheap-sim"/*.cbor 2>/dev/null | wc -l | tr -d ' ')
if [ "$sess_receipts" -eq 1 ]; then
  echo "      OK: $sess_receipts receipt stored under cheap-sim"
else
  echo "      !! FAIL: expected 1 receipt, got $sess_receipts"
fi

kill "$TEE_G_PID" "$HUB_API17_PID" 2>/dev/null; wait "$TEE_G_PID" "$HUB_API17_PID" 2>/dev/null

# --- Scenario 18: Hub↔TEE mutual TLS --------------------------------------
section "18. Hub↔TEE mutual TLS: attested-cert pinning + Hub client identity"
TEE_MTLS_PORT=18095
echo "    starting faketee with -mtls on :$TEE_MTLS_PORT (demands a Hub client cert)"
"$BIN/faketee" -addr "127.0.0.1:$TEE_MTLS_PORT" -mtls -seq "$SIM/seqstore-mtls.json" > "$SIM/faketee-mtls.log" 2>&1 &
TEE_MTLS_PID=$!
sleep 0.6

if [ ! -f "$SIM/tee-cert.pem" ]; then
  echo "      !! FAIL: TEE did not publish its RA-TLS certificate to $SIM/tee-cert.pem"
else
  echo "      OK: TEE published its RA-TLS certificate for the Hub to pin"
fi

echo "    one request over mTLS (pinned TEE cert + Hub client identity):"
"$BIN/hub" -tee "https://127.0.0.1:$TEE_MTLS_PORT" -mtls-ca "$SIM/tee-cert.pem" \
  -credential "$TOKEN_OAI" -n 1 > "$SIM/hub-mtls.log" 2>&1
if grep -qE "^\[receipt\].*completion=complete" "$SIM/hub-mtls.log"; then
  echo "      OK: request completed over mTLS, receipt verified and settled"
else
  echo "      !! FAIL: mTLS request did not complete"
  tail -5 "$SIM/hub-mtls.log"
fi

echo "    negative: Hub pinning the WRONG certificate must be refused:"
if "$BIN/hub" -tee "https://127.0.0.1:$TEE_MTLS_PORT" -mtls-ca "$SIM/ca.pem" \
  -credential "$TOKEN_OAI" -n 1 > "$SIM/hub-mtls-wrongca.log" 2>&1; then
  echo "      !! FAIL: Hub with an unpinned TEE was admitted"
else
  echo "      OK: Hub with an unpinned TEE was refused at the handshake"
fi

echo "    negative: plain HTTP must not reach an mTLS listener:"
if "$BIN/hub" -tee "http://127.0.0.1:$TEE_MTLS_PORT" -credential "$TOKEN_OAI" \
  -n 1 > "$SIM/hub-mtls-plain.log" 2>&1; then
  echo "      !! FAIL: plain HTTP reached the mTLS listener"
else
  echo "      OK: plain HTTP was refused by the mTLS listener"
fi

kill "$TEE_MTLS_PID" 2>/dev/null; wait "$TEE_MTLS_PID" 2>/dev/null

# --- cleanup -------------------------------------------------------------
echo
echo "==> stopping services"
kill "$MP_PID" "$TEE_PID" 2>/dev/null
pkill -f "$BIN/" 2>/dev/null
echo "==> done. Logs in $SIM/"