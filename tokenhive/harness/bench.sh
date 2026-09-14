#!/bin/bash
# TokenHive S5 performance benchmark.
#
# Starts the same real components the S4 harness uses (mock provider over real
# TLS, Provider Agent over the reverse tunnel, simulated TEE on the genuine
# tee.Service) and runs tokenhive/cmd/bench in two configurations:
#
#   direct  -> client -> provider            (baseline, no TEE/Agent)
#   tee     -> client -> TEE -> Hub relay -> Agent -> provider
#
# The provider's token is registered at runtime, as in production: the agent
# dials the Hub's AgentGate and delivers the token sealed to the Hub's TEE.
#
# bench reports the four §9 acceptance metrics and gates the hard ones:
#   proof volume   < 2 KB        (sim adapter must fit; non-negotiable)
#   receipt p95    < 5 ms
#   TTFT overhead  < 1%          (relative; needs a realistic baseline RTT)
#   throughput     < 3%
#
# On localhost the baseline latency is near zero, so the relative TTFT target
# is not measurable directly; bench reports the absolute TEE delta and gates on
# a localhost-friendly delta instead. Pass -baseline-rtt to evaluate the §9
# relative TTFT target (e.g. the latency a real provider would add).
#
# Usage:
#   bash tokenhive/harness/bench.sh
#   bash tokenhive/harness/bench.sh -baseline-rtt 50ms

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$SCRIPT_DIR/bin"
SIM="$REPO/.sim"

cd "$REPO" || exit 1

BASELINE_RTT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -baseline-rtt) BASELINE_RTT="$2"; shift 2 ;;
    *) shift ;;
  esac
done

# kill stale simulation processes from an interrupted prior run
pkill -f "$BIN/" 2>/dev/null
pkill -f "tokenhive/cmd" 2>/dev/null
sleep 0.3

echo "==> repo: $REPO"
mkdir -p "$BIN"
echo "==> building: mockprovider agent hub tee bench"
for pkg in mockprovider agent hub tee bench; do
  go build -o "$BIN/$pkg" "./tokenhive/cmd/$pkg" || { echo "build failed for $pkg"; exit 1; }
done

rm -rf "$SIM"
mkdir -p "$SIM"

wait_for_port() {
  local host="$1" port="$2" tries=50
  while ! (echo > "/dev/tcp/$host/$port") 2>/dev/null; do
    tries=$((tries-1))
    [ "$tries" -le 0 ] && { echo "  !! timeout waiting $host:$port"; return 1; }
    sleep 0.2
  done
}

MP_PORT=18080
HUB_PORT=18085
TEE_PORT=18090
AGENT_SECRET="sim-agent-secret"
TOKEN="sk-sim-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

echo "==> starting mockprovider (TLS) on :$MP_PORT"
"$BIN/mockprovider" -addr "127.0.0.1:$MP_PORT" -tls > "$SIM/mockprovider.log" 2>&1 &
MP_PID=$!
wait_for_port 127.0.0.1 "$MP_PORT"

echo "==> starting reverse-tunnel Hub on :$HUB_PORT (agent gate /v1/agent, tee relay /v1/relay)"
# Serving requires a ledger and a per-job ceiling. Nothing here goes through
# the user API (bench drives the TEE directly and the Hub is only the relay), so
# the ledger stays idle and its commit cost stays out of the measured path.
"$BIN/hub" -serve "127.0.0.1:$HUB_PORT" -host "127.0.0.1:$MP_PORT" \
  -tee "http://127.0.0.1:$TEE_PORT" -agent-keys "openai-sim=$AGENT_SECRET" \
  -relay-key "$AGENT_SECRET" \
  -accounts "$SIM/ledger-bench.db" -max-job-micros 10000000 > "$SIM/hub.log" 2>&1 &
HUB_PID=$!
wait_for_port 127.0.0.1 "$HUB_PORT"

echo "==> starting provider agent (openai-sim), token registered at the gate"
"$BIN/agent" -hub "ws://127.0.0.1:$HUB_PORT/v1/agent" -key "$AGENT_SECRET" \
  -provider openai-sim -targets "127.0.0.1:$MP_PORT" -token "$TOKEN" > "$SIM/agent.log" 2>&1 &
AGENT_PID=$!
sleep 1

echo "==> starting simulated TEE on :$TEE_PORT (egress via the hub relay)"
"$BIN/tee" -addr "127.0.0.1:$TEE_PORT" -relay "ws://127.0.0.1:$HUB_PORT/v1/relay" \
  -relay-key "$AGENT_SECRET" -seq "$SIM/seqstore.json" > "$SIM/tee.log" 2>&1 &
TEE_PID=$!
wait_for_port 127.0.0.1 "$TEE_PORT"
sleep 1

RTT_ARG=""
if [ -n "$BASELINE_RTT" ]; then RTT_ARG="-baseline-rtt $BASELINE_RTT"; fi

FAIL=0

section() { echo; echo "=================================================="; echo "==> $1"; echo "=================================================="; }

# --- latency scenario: small interactive-style response -------------------
section "S5a. latency (normal small response, n=200)"
"$BIN/bench" -mode both -query "" -max 1048576 -n 200 $RTT_ARG || FAIL=1

# --- throughput scenario: large response, both modes capped at 1 MiB -------
section "S5b. throughput (fault=big, capped at 1 MiB, n=20)"
"$BIN/bench" -mode both -query "fault=big" -max 1048576 -n 20 $RTT_ARG || FAIL=1

echo
echo "==> stopping services"
kill "$MP_PID" "$AGENT_PID" "$TEE_PID" "$HUB_PID" 2>/dev/null
pkill -f "$BIN/" 2>/dev/null

if [ "$FAIL" -eq 0 ]; then
  echo "==> S5 benchmark: GATE pass"
  exit 0
else
  echo "==> S5 benchmark: GATE fail"
  exit 1
fi
