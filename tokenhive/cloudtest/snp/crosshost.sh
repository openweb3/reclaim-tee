#!/bin/bash
# Cross-host real-TEE test: a real SEV-SNP confidential instance (running the
# real `tee` binary under the two-tier loader) + an ordinary host running the
# real Hub / provider-agent / mockprovider. The whole business loop travels the
# real data planes:
#   request:  hub --mTLS(attested RA-TLS)--> tee /v1/execute
#   upstream: tee --relay WS--> hub --agent tunnel--> mockprovider
# The confidential instance has no sshd; its config is injected from EC2
# user-data by the loader. The Hub authenticates the TEE by verifying the
# SEV-SNP evidence the RA-TLS certificate embeds, pinned to the measured app
# identity — nothing is distributed out of band, so the TEE's hourly epoch
# rotation is invisible to the deployment. Tear-down is strictly by tag.
#
#   ./crosshost.sh build     certs + pack bundle(real tee)+AMI + linux binaries
#   ./crosshost.sh build-single  certs + pack supervisor bundle + AMI
#               (single-instance mode: tee+hub+agent+mockprovider all inside one
#                confidential instance, no ordinary host needed)
#   ./crosshost.sh up        launch ordinary host + confidential tee (crosshost.json)
#   ./crosshost.sh up --single  launch single-instance mode (one confidential tee)
#   ./crosshost.sh up --tee-only  launch ONLY the confidential tee (cross-host
#               bundle's real tee binary), no ordinary host / Hub anywhere.
#               Add --host-ip <hub-ip> when the Hub lives on a separate machine:
#               it becomes the tee's TEE_RELAY target (the address as the tee
#               sees the Hub, i.e. the private IP when both share this VPC/SG).
#   ./crosshost.sh up --new     launch a FRESH confidential tee even when a live
#               one is recorded, and leave the recorded one RUNNING: its record
#               moves to `superseded` instead of being overwritten. This is the
#               no-wait swap — start the new tee, repoint the Hub at it, then
#               retire the old one with `down --superseded`. Nothing is
#               terminated by `up` on any path.
#   ./crosshost.sh fetch     ssh to host: pull the tee's current RA-TLS leaf over
#                            the mTLS port (with the Hub client identity), for
#                            inspection only — the Hub verifies the evidence in
#                            it, it is not pinned
#   ./crosshost.sh deploy    scp binaries+certs, start mockprovider/hub/agent on host
#   ./crosshost.sh drive     curl a chat request via the host's Hub
#   ./crosshost.sh verify    hub/tee/agent logs + tee console attestation
#   ./crosshost.sh down      terminate BOTH instances strictly by tag
#   ./crosshost.sh down --tee-only  terminate ONLY the recorded confidential tee,
#               leaving a separately-provisioned Hub host untouched
#   ./crosshost.sh down --superseded  terminate ONLY the instances `up`
#               recorded as superseded, and only after checking the current tee
#               is recorded and running. Never enumerates by tag.
#   ./crosshost.sh down --dry-run   list what would be terminated, delete nothing
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # cloudtest/snp
# The host shell may carry PYTHONHOME/PYTHONPATH injected by an unrelated tool
# (e.g. a bundled Python runtime), which crashes BOTH the venv's python3 and any
# bare `python3`/aws-CLI invocation in pack.sh and snp-build.sh with
# "No module named 'encodings'". Drop them once at the top so every child step
# runs under a clean interpreter instead of needing per-call `env -u` sprinkles.
unset PYTHONHOME PYTHONPATH 2>/dev/null || true
# shellcheck source=../lib.sh
set -a; source "${HERE}/../lib.sh"; set +a
load_env
setup_logs

CLOUDTEST="${HERE}/.."
CERTS_DIR="${HERE}/.certs"
# POLICY_DIR is the deployment whitelist baked into the measured bundle. The
# enclave loads exactly this file at startup and refuses to serve without it, so
# it is not optional build input: a bundle built without it produces an AMI whose
# TEE cannot come up. It is regenerated on every build from the document in
# tokenhive/policy/whitelist.json — the document is deterministic, so re-emitting
# it is a no-op until the document changes, and a change to the document always
# reaches the bundle. Set SNP_POLICY_DIR to ship an operator-authored whitelist
# instead.
POLICY_DIR="${SNP_POLICY_DIR:-${CERTS_DIR}/policy}"
# BUNDLES_DIR keeps every built bundle under the digest it measures
# (<sha256>.tar). A bundle carries the whitelist its enclave enforces, and its
# sha256 IS the app identity the Hub pins, so the digest is the only name under
# which "the whitelist version A runs" can be recovered after a later build has
# overwritten everything else. A single mutable policy directory cannot answer
# that question (see cmd_deploy).
BUNDLES_DIR="${CLOUDTEST}/bin/bundles"
# The layout `deploy` creates on the ordinary host: ./tee (binaries + logs),
# ./mtls (certs) and ./policy (the whitelist). This is the only place the
# whitelist's remote location is written down — the upload and the Hub's
# -policy-dir both derive from it, so the two cannot disagree again.
REMOTE_POLICY_REL="policy"
REPO_ROOT="${HERE}/../../.."            # reclaim-tee
DEPLOY_DIR="${REPO_ROOT}/deploy"
HOSTS="${CLOUDTEST}/crosshost.json"

py() { "${PY}" "$@"; }
py_cd() { ( cd "${CLOUDTEST}" && "${PY}" "$@"; ); }

host_field() { "$PY" -c "import json,sys; print(json.load(open('$HOSTS'))['host']['$1'])"; }
tee_field() { "$PY" -c "import json,sys; print(json.load(open('$HOSTS'))['tee']['$1'])"; }

# dump_tee_console <public-ip>: print the confidential instance's console output
# (the loader/attestation log) by locating it strictly through our own tags.
dump_tee_console() {
  py_cd - "$1" <<'PY'
import boto3, sys
from config import load
cfg = load()
ec2 = boto3.client("ec2", region_name=cfg.region)
for r in ec2.describe_instances(Filters=[
    {"Name": f"tag:{cfg.tag_owner}", "Values":[cfg.tag_owner_value]},
    {"Name": f"tag:{cfg.tag_user}", "Values":[cfg.user]},
])["Reservations"]:
    for i in r["Instances"]:
        if i.get("PublicIpAddress") == sys.argv[1]:
            print(ec2.get_console_output(InstanceId=i["InstanceId"], Latest=True).get("Output",""))
            break
PY
}

ami_id() {
  local name="${1:-snp-tokenhive}"
  py_cd - "${name}" <<'PY'
import boto3, sys
from config import load
name = sys.argv[1]; cfg = load()
img = boto3.client("ec2", region_name=cfg.region).describe_images(
    Owners=["self"],
    Filters=[{"Name":"name","Values":[name]},{"Name":"state","Values":["available"]}],
)["Images"]
assert img, f"no AMI {name}; run ./crosshost.sh build"
img.sort(key=lambda i: i["CreationDate"])
print(img[-1]["ImageId"])
PY
}

# ami_app_digest <ami-id> prints the app digest the image was registered with:
# snp-build.sh tags every image it registers with the sha256 of the bundle it
# embedded, so the tag is the one statement about what an image measures that
# travels with the image itself.
ami_app_digest() {
  py_cd - "$1" <<'PYDIG'
import boto3, sys
from botocore.exceptions import ClientError
from config import load
cfg = load()
try:
    imgs = boto3.client("ec2", region_name=cfg.region).describe_images(ImageIds=[sys.argv[1]])["Images"]
except ClientError as e:
    # DescribeImages raises for an unknown id instead of returning nothing, and
    # a botocore traceback is not a refusal an operator can act on.
    sys.exit(f"cannot describe AMI {sys.argv[1]}: {e.response['Error']['Message']}")
tags = {t["Key"]: t["Value"] for t in imgs[0].get("Tags", [])}
digest = tags.get("snp-app")
if not digest:
    sys.exit(f"AMI {sys.argv[1]} carries no snp-app tag; rebuild it with './crosshost.sh build'")
print(digest)
PYDIG
}

# ensure_policy materializes the deployment whitelist the bundle carries.
#
# When the operator supplied a directory (SNP_POLICY_DIR) that is their
# document and this script must not touch it. Otherwise the whitelist is the
# document shipped in tokenhive/policy/whitelist.json, and it is regenerated on
# every build: the document is deterministic, so re-emitting it is a no-op until
# the document actually changes — and a frozen copy would silently keep shipping
# the old rules (a new host or path in the document would never reach the
# bundle).
ensure_policy() {
  if [ -n "${SNP_POLICY_DIR:-}" ]; then
    if [ ! -f "${POLICY_DIR}/policy.cbor" ]; then
      log "SNP_POLICY_DIR=${SNP_POLICY_DIR} has no policy.cbor"
      exit 1
    fi
    log "using operator whitelist ${POLICY_DIR}/policy.cbor"
    return
  fi
  mkdir -p "${POLICY_DIR}"
  ( cd "${REPO_ROOT}" && go run ./tokenhive/cmd/tee -emit-policy-dir "${POLICY_DIR}" )
  log "deployment whitelist -> ${POLICY_DIR}/policy.cbor"
}

# ensure_certs generates the Hub↔TEE and mock-provider TLS fixtures ONCE and
# reuses them across every build: the CAs are baked into each AMI's bundle at
# build time, and the same CAs must sign the client/server certs deployed
# later. Regenerating certs in one build would silently invalidate AMIs built
# earlier — their tee would reject the new hub client cert / provider cert.
ensure_certs() {
  if [ -f "${CERTS_DIR}/hub-ca.pem" ]; then
    log "reusing TLS fixtures in ${CERTS_DIR}"
    return
  fi
  mkdir -p "${CERTS_DIR}"
  ( cd "${REPO_ROOT}" && go run ./tokenhive/cloudtest/snp/gencerts "${CERTS_DIR}" )
  log "TLS fixtures -> ${CERTS_DIR}"
}

# archive_bundle <bundle-file> <snp-app:hash> files the freshly built bundle
# under the digest it measures. Every build does this, so that a deploy of an
# instance launched earlier can still recover that instance's whitelist.
archive_bundle() {
  local bundle="$1" digest="${2#snp-app:}"
  mkdir -p "${BUNDLES_DIR}"
  cp "${bundle}" "${BUNDLES_DIR}/${digest}.tar"
  log "bundle archived -> ${BUNDLES_DIR}/${digest}.tar"
}

# archived_bundle <app-hash> prints the path of the archived bundle measuring
# that app identity, or fails if there is none. The digest is recomputed rather
# than trusted from the filename: the caller is about to hand the Hub a
# whitelist on the strength of it being the one inside the attested app, so
# "this file still hashes to what it claims" is the whole point.
archived_bundle() {
  local want="$1" path="${BUNDLES_DIR}/${1}.tar" got
  [ -f "${path}" ] || return 1
  got="$(sha256sum "${path}" | cut -d' ' -f1)"
  [ "${got}" = "${want}" ] || return 1
  printf '%s\n' "${path}"
}

cmd_build() {
  log "step: build (certs + policy + real-tee bundle + AMI + linux binaries)"
  ensure_certs
  ensure_policy
  ( cd "${HERE}" && SNP_POLICY_DIR="${POLICY_DIR}" \
      SNP_HUB_CA="${CERTS_DIR}/hub-ca.pem" \
      SNP_MP_CA="${CERTS_DIR}/mp-ca.pem" SNP_MP_CERT="${CERTS_DIR}/mp-cert.pem" SNP_MP_KEY="${CERTS_DIR}/mp-key.pem" \
      ./pack.sh build )
  local bundle digest; bundle="${TOKENHIVE_OUT_BUNDLE:-${CLOUDTEST}/bin/tokenhive-app-bundle.tar}"
  digest="$(cd "${HERE}" && ./pack.sh digest "${bundle}")"
  log "bundle digest: ${digest}"
  archive_bundle "${bundle}" "${digest}"
  ( cd "${DEPLOY_DIR}" && SNP_EXTERNAL_BUNDLE="${bundle}" SNP_ALLOW_DIRTY=1 ./snp-build.sh t aws tokenhive )
  log "AMI registered"
  ( cd "${CLOUDTEST}" && ./run.sh build )
  log "linux binaries built"
}

cmd_build_single() {
  log "step: build (certs + policy + supervisor bundle + AMI)"
  ensure_certs
  ensure_policy
  # The supervisor bundle needs the Hub's TLS identity (hub-cert/key) and the
  # mock provider's TLS identity (mp-cert/key), which the cross-host bundle
  # does not carry (hub and mockprovider run on the ordinary host there).
  ( cd "${HERE}" && TOKENHIVE_BUILD_SINGLE=1 \
      SNP_POLICY_DIR="${POLICY_DIR}" \
      SNP_HUB_CA="${CERTS_DIR}/hub-ca.pem" \
      SNP_HUB_CERT="${CERTS_DIR}/hub-cert.pem" \
      SNP_HUB_KEY="${CERTS_DIR}/hub-key.pem" \
      SNP_MP_CA="${CERTS_DIR}/mp-ca.pem" \
      SNP_MP_CERT="${CERTS_DIR}/mp-cert.pem" \
      SNP_MP_KEY="${CERTS_DIR}/mp-key.pem" \
      ./pack.sh build )
  local bundle digest; bundle="${TOKENHIVE_OUT_BUNDLE:-${CLOUDTEST}/bin/tokenhive-app-bundle.tar}"
  digest="$(cd "${HERE}" && ./pack.sh digest "${bundle}")"
  log "bundle digest: ${digest}"
  archive_bundle "${bundle}" "${digest}"
  ( cd "${DEPLOY_DIR}" && SNP_EXTERNAL_BUNDLE="${bundle}" SNP_ALLOW_DIRTY=1 ./snp-build.sh t aws tokenhive-single )
  log "AMI snp-tokenhive-single registered"
}

cmd_up() {
  [ -f "${CERTS_DIR}/hub-ca.pem" ] || { echo "run ./crosshost.sh build first (certs)"; exit 1; }
  local a mode="" new_arg="" name="snp-tokenhive" digest host_ip="" host_arg=""
  shift || true                       # drop the "up" verb
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --single)   mode="--single";   name="snp-tokenhive-single" ;;
      --tee-only) mode="--tee-only" ;;
      --new)      new_arg="--new" ;;
      --host-ip)  shift; host_ip="${1:-}" ;;
      *) echo "up: unknown option $1" >&2; exit 2 ;;
    esac
    shift
  done
  # --host-ip names the Hub's address as the TEE reaches it. Only a bare tee
  # needs it: cross-host mode derives the relay from the ordinary host it just
  # launched, and single mode runs the Hub on loopback with no relay at all.
  # Refusing the mismatch is the point — ignoring it would leave a decoupled
  # deploy quietly aimed at the inert placeholder relay, and nothing dispatches
  # jobs without a Hub to notice.
  if [[ -n "${host_ip}" ]]; then
    [[ "${mode}" == "--tee-only" ]] || {
      echo "up: --host-ip requires --tee-only (cross-host derives the relay itself; --single has none)" >&2
      exit 2
    }
    host_arg="--host-ip ${host_ip}"
  fi
  a="$(ami_id "${name}")"
  log "AMI ${a}"
  # Pin the attested app identity for the Hub: the AMI embeds the app bundle
  # whose sha256 the loader exports as SNP_APP_HASH, so read it off the image
  # and record it in state for the later deploy to pass as -expected-app
  # (single mode reads the env instead).
  #
  # Read it from the image rather than by re-hashing a local file. bin/ is
  # overwritten by every build — build-single shares that path, and a build that
  # packed and then failed before registering an AMI leaves it describing an app
  # no image contains — so a locally computed digest can disagree with the TEE
  # actually running. The image's own tag cannot.
  #
  # And read it, refusing an image that carries none, BEFORE the launch below:
  # an unlabelled image can never be pinned, and discovering that afterwards
  # would have bought a confidential instance for a run that cannot finish.
  digest="snp-app:$(ami_app_digest "${a}")"
  ( cd "${HERE}" && "${PY}" crosshost.py "${a}" ${mode} ${new_arg} ${host_arg} ) | tee -a "${LOG_DIR}/run.log"
  # Record it only now that the instance exists: crosshost.py owns the state
  # file (it creates the tee record merged into below), and an identity recorded
  # for an instance that never came up would pin the next deploy to an app that
  # nothing is running.
  printf '%s\n' "${digest#snp-app:}" | "${PY}" -c "
import json, sys
p = json.load(open('${HOSTS}'))
p['tee']['app_hash'] = sys.stdin.read().strip()
json.dump(p, open('${HOSTS}', 'w'), indent=2)
" && log "tee app_hash -> ${digest}"
}

cmd_fetch() {
  local tip out
  # Cross-host traffic goes over the PRIVATE ips: both instances share the VPC
  # subnet and the SG's group-pair rule only matches in-VPC traffic (a public-ip
  # dial from a group member is dropped by AWS). ssh to the host still uses its
  # public ip.
  #
  # The leaf pulled here is NOT what the Hub trusts: `deploy` runs the Hub with
  # -tee-verify=attestation, so trust comes from the SEV-SNP evidence inside
  # whatever certificate the TEE presents. This stays as an operator's way to
  # read the current leaf (and its evidence) off the instance without sshd —
  # over the mTLS port itself, presenting the Hub client identity, so no
  # plaintext listener is needed for diagnosis.
  tip="$(tee_field private_ip)"
  log "step: fetch tee RA-TLS cert from mTLS ${tip}:18090 (inspection only)"
  out="$(remote_exec "$(host_field public_ip)" bash <<EOF
set -e
for _ in \$(seq 1 60); do
  echo | openssl s_client -connect ${tip}:18090 -cert mtls/hub-cert.pem -key mtls/hub-key.pem -showcerts 2>/dev/null | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' >tee-cert.pem
  [ -s tee-cert.pem ] && break
  sleep 5
done
[ -s tee-cert.pem ] || { echo 'mTLS fetch never succeeded'; exit 1; }
wc -c tee-cert.pem
EOF
)"
  log "mTLS fetch -> ${out}"
  remote_pull "$(host_field public_ip)" "tee-cert.pem" "${CLOUDTEST}/snp/.certs/tee-cert.pem" >/dev/null
  log "current tee RA-TLS leaf saved to ${CERTS_DIR} (for inspection)"
}

cmd_deploy() {
  local hip tip app_hash bundle policy_file
  hip="$(host_field public_ip)"; tip="$(tee_field private_ip)"  # cross-host plane over private ips
  app_hash="$(tee_field app_hash)"
  # The Hub admits agents and advertises /v1/policies from the same whitelist
  # the enclave enforces, so it has to read the very bytes the running TEE was
  # measured with. Those bytes come from exactly one place: the archived bundle
  # whose sha256 is the app identity in state. Taking the current build's policy
  # instead would mean that rebuilding for a newer whitelist and then deploying
  # an instance launched earlier hands the Hub rules the enclave does not run —
  # so the Hub admits agents the enclave refuses job by job, and advertises a
  # policy hash no receipt carries.
  if ! bundle="$(archived_bundle "${app_hash}")"; then
    log "no archived bundle measuring snp-app:${app_hash} — the app the running TEE attested"
    log "rebuild the AMI that instance runs (or run './crosshost.sh up' again), then deploy"
    exit 1
  fi
  policy_file="${BUNDLES_DIR}/${app_hash}.policy.cbor"
  if ! tar -xOf "${bundle}" ./policy/policy.cbor >"${policy_file}" 2>/dev/null || [ ! -s "${policy_file}" ]; then
    log "${bundle} carries no ./policy/policy.cbor; it was built without a whitelist"
    exit 1
  fi

  log "step: deploy runtime to host ${hip} (tee ${tip}, app ${app_hash})"
  log "whitelist from ${bundle} -> ~/${REMOTE_POLICY_REL}/policy.cbor"
  remote_exec "$hip" "mkdir -p tee mtls ${REMOTE_POLICY_REL}" >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/hub" "tee/hub" >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/agent" "tee/agent" >/dev/null
  remote_push "$hip" "${CLOUDTEST}/bin/mockprovider" "tee/mockprovider" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/hub-cert.pem" "mtls/hub-cert.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/hub-key.pem" "mtls/hub-key.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-ca.pem" "mtls/mp-ca.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-cert.pem" "mtls/mp-cert.pem" >/dev/null
  remote_push "$hip" "${CERTS_DIR}/mp-key.pem" "mtls/mp-key.pem" >/dev/null
  # No tee-cert.pem is shipped: the Hub does not pin the TEE's leaf, it verifies
  # the attested epoch the leaf carries. That is also why nothing here needs
  # refreshing when the TEE rotates (see the hub invocation below).
  remote_push "$hip" "${policy_file}" "${REMOTE_POLICY_REL}/policy.cbor" >/dev/null

  # Per-provider agent key and the tee relay key. The Hub now requires both
  # (-agent-keys and -relay-key); the tee must present the same relay key, which
  # crosshost.py injects into the confidential instance's user-data, so both
  # scripts read the same env with the same default.
  local agent_key relay_key
  agent_key="${TOKENHIVE_AGENT_KEY:-xhost-agent-key}"
  relay_key="${TOKENHIVE_RELAY_KEY:-xhost-relay-key}"
  remote_exec "$hip" bash -s <<EOF
set -e
cd ~
export TOKENHIVE_SIM_DIR="\$HOME/tee"
killall mockprovider hub agent 2>/dev/null || true
mkdir -p "\$TOKENHIVE_SIM_DIR"
chmod 755 ./tee/hub ./tee/agent ./tee/mockprovider
./tee/mockprovider -addr 127.0.0.1:18080 -tls -stats-addr 127.0.0.1:18081 \
  -ca mtls/mp-ca.pem -cert mtls/mp-cert.pem -key mtls/mp-key.pem >tee/mp.log 2>&1 &
sleep 1
# The Hub resolves a receipt's EvidenceHash from memory, then from its own
# evidence store, then from the TEE's /v1/evidence over the same mTLS channel
# (-evidence-fetch). That remote leg is what keeps a hash-only TEE
# (-evidence=false) verifiable here: Hub and TEE are on different machines, so
# the TEE's evidence store is never on this host. Harmless when the TEE embeds
# evidence inline (the fetch is never reached), essential the moment it does not.
./tee/hub -serve 0.0.0.0:18085 -agent-keys 'openai-sim=${agent_key}' -relay-key '${relay_key}' \
  -policy-dir "\$HOME/${REMOTE_POLICY_REL}" \
  -host 127.0.0.1:18080 \
  -model sim-mock-0.5b -tee https://${tip}:18090 -tee-verify attestation \
  -evidence-fetch https://${tip}:18090 \
  -mtls-cert mtls/hub-cert.pem -mtls-key mtls/hub-key.pem \
  -allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}' >tee/hub.log 2>&1 &
sleep 1
./tee/agent -hub ws://127.0.0.1:18085/v1/agent -key '${agent_key}' -provider openai-sim \
  -token sk-xhost-secret -targets 127.0.0.1:18080 -ca "\$TOKENHIVE_SIM_DIR/ca.pem" >tee/agent.log 2>&1 &
echo "deployed; logs under ~/tee"
EOF
  log "deployed & started on host"
  sleep 4
}

cmd_drive() {
  log "step: drive 2 chat requests via host Hub"
  remote_exec "$(host_field public_ip)" bash <<'EOF'
set -e
for i in 1 2; do
  code="$(curl -s -o resp$i.txt -w '%{http_code}' -N -X POST \
    http://127.0.0.1:18085/v1/chat/completions \
    -H 'content-type: application/json' -H 'X-TokenHive-Key: tenant-xhost' \
    -d '{"model":"sim-mock-0.5b","messages":[{"role":"user","content":"hello"}]}')"
  echo "request $i -> HTTP $code  $(head -c 120 resp$i.txt)"
done
EOF
}

cmd_verify() {
  # Single-instance mode has no separate host: the supervisor's tee+hub+agent+
  # mockprovider all log to the loader console inside the confidential instance,
  # so verify just dumps that console (which also holds the attestation proof).
  # --tee-only has no host either: the cross-host tee logs to the same console.
  # The tee record carries mode=single / tee-only from crosshost.py; a stale
  # "host" key left over from an earlier cross-host run must not flip us into
  # host mode.
  local mode; mode="$(tee_field mode)"
  if [[ "${mode}" == "single" ]]; then
    log "step: verify single-instance mode (dump confidential tee console)"
    dump_tee_console "$(tee_field public_ip)"
    return
  fi
  if [[ "${mode}" == "tee-only" ]]; then
    log "step: verify tee-only mode (dump confidential tee console; no ordinary host)"
    dump_tee_console "$(tee_field public_ip)"
    return
  fi
  log "step: verify logs on host"
  remote_exec "$(host_field public_ip)" bash <<'EOF'
echo "---- hub.log ----"; grep -E 'listening|relay|chat/completions' tee/hub.log | tail -8 || tail -12 tee/hub.log
echo "---- agent.log ----"; tail -6 tee/agent.log
echo "---- mockprovider.log ----"; tail -4 tee/mp.log
EOF
  log "step: dump confidential tee console (attestation proof)"
  dump_tee_console "$(tee_field public_ip)"
}

# cmd_down [--dry-run] [--tee-only] [--superseded]
# A plain down deletes EVERY instance carrying the cloudtest tag pair. That is
# right for a coupled run: both instances were launched for this state, and
# matching purely by tag is what keeps teardown working after crosshost.json is
# lost. It is wrong for a decoupled one, where the Hub host carries the same tag
# pair but was provisioned separately (a colleague's Hub, or an
# `up --tee-only --host-ip` placement) and has to outlive the tee.
# --tee-only narrows teardown to the tee recorded in crosshost.json. The record
# is never trusted on its own: the instance is re-checked for both tags before
# it is terminated, so a stale or hand-edited entry cannot widen the match.
# --superseded narrows it further still: only the instances an `up`
# recorded as superseded (retire.py), which is how a swap disposes of the old
# tee after the Hub has been repointed at the new one.
cmd_down() {
  local dry_run="" tee_only="" superseded="" arg iid
  for arg in "$@"; do
    case "${arg}" in
      --dry-run)    dry_run="--dry-run" ;;
      --tee-only)   tee_only="1" ;;
      --superseded) superseded="1" ;;
      *) echo "down: unknown option ${arg}" >&2; exit 2 ;;
    esac
  done
  if [[ -n "${tee_only}" && -n "${superseded}" ]]; then
    echo "down: --tee-only and --superseded are mutually exclusive" >&2
    exit 2
  fi
  if [[ -n "${superseded}" ]]; then
    log "step: down --superseded (terminate only the instances recorded by 'up')"
    ( cd "${HERE}" && "${PY}" retire.py --state "${HOSTS}" ${dry_run} ) | tee -a "${LOG_DIR}/run.log"
    return
  fi
  if [[ -z "${tee_only}" ]]; then
    log "step: down (strict tag deletion of all matching instances)"
    ( cd "${CLOUDTEST}" && "${PY}" delete.py ${dry_run} ) | tee -a "${LOG_DIR}/run.log"
    return
  fi
  iid="$(tee_field instance_id 2>/dev/null || true)"
  if [[ -z "${iid}" ]]; then
    log "step: down --tee-only (no tee record in ${HOSTS}; nothing to terminate)"
    return
  fi
  log "step: down --tee-only (terminate only the recorded confidential tee)"
  py_cd - "${iid}" ${dry_run} <<'PY' | tee -a "${LOG_DIR}/run.log"
import boto3, sys
from config import load

iid = sys.argv[1]
dry = "--dry-run" in sys.argv[2:]
cfg = load()
ec2 = boto3.client("ec2", region_name=cfg.region)
try:
    inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
except Exception as e:
    # The record can outlive its instance. Only "gone" is recoverable here; every
    # other failure (auth, throttling) has to surface rather than read as "done".
    code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
    if code not in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
        raise
    print(f"==> {iid} no longer exists; nothing to terminate")
    sys.exit(0)
tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
if tags.get(cfg.tag_owner) != cfg.tag_owner_value or tags.get(cfg.tag_user) != cfg.user:
    sys.exit(f"==> {iid} does not carry the cloudtest tags; refusing to terminate it")
print(f"    {iid}  {inst['State']['Name']}  {inst.get('PrivateIpAddress', '-')}")
if dry:
    print(f"==> dry-run: {iid} would be terminated; nothing deleted")
elif inst["State"]["Name"] in ("terminated", "shutting-down"):
    print(f"==> {iid} is already {inst['State']['Name']}; nothing to do")
else:
    ec2.terminate_instances(InstanceIds=[iid])
    print(f"==> terminated: {iid}")
PY
}

case "${1:-}" in
  build)   cmd_build ;;
  build-single) cmd_build_single ;;
  up)      cmd_up "${@}" ;;
  fetch)   cmd_fetch ;;
  deploy)  cmd_deploy ;;
  drive)   cmd_drive ;;
  verify)  cmd_verify ;;
  down)    cmd_down "${@:2}" ;;
  *)
    awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
    exit 1 ;;
esac