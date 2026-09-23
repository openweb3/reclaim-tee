#!/usr/bin/env python3
"""Cross-host launch: an ordinary host (Hub/agent/mockprovider) + a real SEV-SNP
confidential instance running the real `tee` binary under the two-tier loader.

The confidential instance has no sshd. Its runtime config is injected by the
loader from EC2 user-data, so this script encodes it as KEY=VAL lines:

    TOKENHIVE_SIM_DIR=/tmp/tee        writable state dir (loader mounts /tmp 0777)
    TEE_ADDR=0.0.0.0:18090            mTLS request plane the Hub dials
    TEE_RELAY=ws://<host-ip>:18085/v1/relay    reverse tunnel back to the Hub
    TEE_RELAY_KEY=<relay-key>          Hub TeeRelay authentication (shared with
                                       crosshost.sh's -relay-key)
    TEE_PLATFORM=sevsnp               real attestation (fail-fast off SNP)
    TEE_MTLS=1                         RA-TLS + demand a Hub client cert
    TEE_MTLS_CLIENT_CA=/run/bundle/mtls/hub-ca.pem

The confidential instance also carries an IAM instance profile when
TOKENHIVE_TEE_INSTANCE_PROFILE names one. That profile is what lets the TEE's
structured logger authenticate to CloudWatch Logs on AWS; with none, the TEE
still runs but has only its serial console to speak through, and a console is
a few minutes deep. The profile is bound at RunInstances, so it is an input to
launching rather than something a later call can add.

Both instances share one VPC/subnet/SG. The SG additionally permits the
cross-host ports (18085 hub relay, 18090 tee) between its own members
(source = the SG itself), so they reach each other regardless of public IP.

    TOKENHIVE_TEE_INSTANCE_PROFILE=<name> \
    python3 crosshost.py <snp-ami-id> [--host-ip <hub-public-ip>]
                          [--single] [--tee-only] [--new] [--dry-run]
Writes crosshost.json {host:{...}, tee:{...}, superseded:[...]} and never
deletes anything. Refuses to run without TOKENHIVE_USER.

--single launches ONLY the confidential tee, running the whole loop (tee + Hub +
agent + mockprovider) inside that one instance through the supervisor bundle
(TOKENHIVE_BUILD_SINGLE=1); no ordinary host is started.

--tee-only launches ONLY the confidential tee from the cross-host bundle (its
./app is the real `tee` binary, not the supervisor) and starts no ordinary host.
The tee still needs a Hub TeeRelay URL in TEE_RELAY, but with no Hub there is
nothing to dial — the relay connection is lazy (dialed only when a provider
connection is needed), so a placeholder is harmless at boot. Pass --host-ip to
aim TEE_RELAY at a real Hub instead of the placeholder.

--new launches a fresh confidential instance even when a live one is recorded,
WITHOUT terminating the recorded one: the old record is moved to
`superseded` in crosshost.json and the old instance keeps running. That is what
makes a swap not block on instance termination — bring the new tee up, repoint
the Hub at it, and retire the old one afterwards with `crosshost.sh down
--superseded` (see retire.py). The reciprocal invariant is the important half:
this script never terminates an instance on any path, so no `up` can destroy the
machine it is replacing.

A recorded tee that is no longer adoptable — stopped, terminated, shutting down —
is replaced the same way, record and all: it moves to `superseded` before the
launch overwrites `tee`, because a record dropped there would be an instance
still in AWS that no reader of crosshost.json could name.
"""

# Annotations stay unevaluated (as in aws.py): the operator-facing way to run
# these scripts is a bare `python3`, and `dict | None` is a TypeError at import
# time before 3.10 — a syntax-level trap rather than a graceful failure.
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # cloudtest dir

from aws import (  # noqa: E402
    ensure_igw,
    ensure_key,
    ensure_sg,
    ensure_subnet,
    ensure_vpc,
    latest_ami,
    wait_running,
)
from config import load  # noqa: E402

CLOUDTEST = Path(__file__).resolve().parents[1]  # cloudtest dir
HERE = Path(__file__).resolve().parent
HOSTS_FILE = CLOUDTEST / "crosshost.json"
KEY_FILE = CLOUDTEST / "ssh-key.pem"

CROSS_PORTS = [18085, 18090]

# The Hub's TeeRelay now requires the TEE to present a key, and the Hub refuses
# to serve without it. crosshost.sh starts the Hub with this same default, so a
# run with no TOKENHIVE_RELAY_KEY still lines up end to end.
DEFAULT_RELAY_KEY = "xhost-relay-key"

# --tee-only has no Hub to dial, but the tee binary still requires a TEE_RELAY
# URL. This placeholder is inert: the relay handshake only happens when the tee
# needs a provider connection, and nothing dispatches jobs without a Hub. Pass
# --host-ip (or edit this) to point TEE_RELAY at a real Hub.
TEE_ONLY_RELAY_PLACEHOLDER = "ws://127.0.0.1:18085/v1/relay"

# IAM instance profile for the confidential instance, by env name. On AWS the
# TEE's structured logger ships to CloudWatch Logs through the instance role
# (shared/logger_cloudwatch_linux.go), so an instance launched without a profile
# cannot ship a log at all — and it cannot say so from inside the enclave, where
# the AWS SDK builds its client happily and every ship is dropped. Naming a
# profile here makes "the TEE's logs exist somewhere durable" a property of the
# launch instead of something an operator has to remember separately.
#
# Empty (the default) launches exactly as before: no IamInstanceProfile, console
# logs only. A name that does not exist needs no check here — RunInstances
# rejects it outright, so there is no half-provisioned state to clean up.
TEE_PROFILE_ENV = "TOKENHIVE_TEE_INSTANCE_PROFILE"

# The instance states a recorded instance may be ADOPTED in. Adoption is a
# promise that the recorded machine can serve this run, so the only states that
# qualify are the ones where it is on its way up or already up.
#
# "shutting-down" is deliberately absent, and that is the whole point: a record
# written before a termination still names the dying instance, and adopting it
# prints a reassuring "reusing confidential tee i-…", launches nothing, and
# then stamps the NEW app digest onto a machine that is seconds from vanishing —
# a state file that looks correct and points at nothing (observed 2026-09-22).
# "stopping"/"stopped" are excluded for the same reason: neither is serving, and
# neither will come back on its own.
REUSABLE_STATES = ("pending", "running")


def adoptable(record: dict, state: str) -> bool:
    """Whether a recorded instance exists in a state this run may adopt."""
    return bool((record or {}).get("instance_id")) and state in REUSABLE_STATES


def recorded_state(ec2, record: dict) -> str:
    """Instance state of a record, or "" when the record names no instance."""
    iid = (record or {}).get("instance_id")
    return host_state(ec2, iid) if iid else ""


def supersede(state: dict, now: str) -> dict | None:
    """Move the recorded tee under `superseded`, returning the old record.

    A launch that replaces the tee record moves it rather than drops it,
    whatever the reason for replacing it — `--new`, or a record that can no
    longer be adopted — because the record is the ONLY thing that names the
    instance the operator still has to terminate. Nothing is terminated here:
    launching and deleting are separate programs on purpose (see retire.py), so
    no path through an `up` can destroy the machine it is replacing.
    """
    old = state.pop("tee", None)
    if not old or not old.get("instance_id"):
        return None
    state.setdefault("superseded", []).append(dict(old, superseded_at=now))
    return old


def save_state(state: dict) -> None:
    HOSTS_FILE.write_text(json.dumps(state, indent=2) + "\n")


def ensure_local_key() -> None:
    if KEY_FILE.exists():
        return
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(KEY_FILE)], check=True)


def open_cross_ports(ec2, cfg, sg_id: str) -> None:
    """Permit the cross-host ports to other members of the same SG (idempotent).
    The port sources may be CIDRs or group pairs; only the port itself matters.
    """
    existing = set()
    for gp in ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0].get(
        "IpPermissions", []
    ):
        if "FromPort" not in gp:
            continue
        lo, hi = gp["FromPort"], gp["ToPort"]
        existing.update(range(lo, hi + 1))
    to_add = [p for p in CROSS_PORTS if p not in existing]
    if not to_add:
        return
    try:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": p,
                    "ToPort": p,
                    "UserIdGroupPairs": [{"GroupId": sg_id}],
                }
                for p in to_add
            ],
        )
    except ec2.exceptions.ClientError as e:
        # A pre-existing identical rule is fine; anything else is a real error.
        if "Duplicate" not in str(e):
            raise
    print(f"  authorized cross-host ports {to_add} to SG members")


def run_ordinary(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id):
    return ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.small",
        MinCount=1,
        MaxCount=1,
        KeyName=cfg.key_name,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
            }
        ],
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix + "-host")}
        ],
    )["Instances"][0]


def run_confidential(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id, userdata: str, profile: str = ""):
    # The instance profile rides in only when named: boto3 rejects
    # IamInstanceProfile={"Name": ""}, and "no profile" has to stay the shape of
    # a launch that never wanted one rather than a name that happens to be empty.
    profile_arg = {"IamInstanceProfile": {"Name": profile}} if profile else {}
    return ec2.run_instances(
        ImageId=ami_id,
        InstanceType=cfg.instance_type,
        MinCount=1,
        MaxCount=1,
        NetworkInterfaces=[
            {
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": [sg_id],
            }
        ],
        CpuOptions={"AmdSevSnp": "enabled"},
        UserData=base64.b64encode(userdata.encode()).decode(),
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": cfg.tags(name=cfg.name_prefix + "-tee")}
        ],
        **profile_arg,
    )["Instances"][0]


def main() -> None:
    dry_run = "--dry-run" in sys.argv[1:]
    single = "--single" in sys.argv[1:]
    tee_only = "--tee-only" in sys.argv[1:]
    fresh = "--new" in sys.argv[1:]
    if single and tee_only:
        sys.exit("--single and --tee-only are mutually exclusive")
    # "no ordinary host" covers both --single (whole loop in the tee) and
    # --tee-only (a bare cross-host tee, no Hub anywhere).
    no_host = single or tee_only
    args = [a for a in sys.argv[1:] if a not in ("--dry-run", "--single", "--tee-only", "--new")]
    host_ip = None
    ami_id = None
    i = 0
    while i < len(args):
        if args[i] == "--token":
            # Removed with the /v1/init-cert bootstrap listener: accepted and
            # ignored so old crosshost.sh callers keep working.
            i += 2
        elif args[i] == "--host-ip":
            host_ip = args[i + 1]; i += 2
        else:
            ami_id = args[i]; i += 1
    # --host-ip is optional: the ordinary host is launched first and its public
    # ip feeds the tee's relay URL automatically when not supplied.
    if not ami_id:
        sys.exit("usage: python3 crosshost.py <snp-ami-id> [--host-ip <hub-public-ip>] "
                 "[--single] [--tee-only] [--new] [--dry-run]")
    cfg = load()
    if not cfg.user:
        sys.exit("TOKENHIVE_USER is empty; refusing to launch untagged instances")
    ensure_local_key()
    ec2 = boto3("ec2")

    print(f"==> ensuring infrastructure in {cfg.region} (user tag: {cfg.user})")
    vpc_id = ensure_vpc(ec2, cfg)
    subnet_id = ensure_subnet(ec2, cfg, vpc_id)
    ensure_igw(ec2, cfg, vpc_id)
    sg_id = ensure_sg(ec2, cfg, vpc_id)
    open_cross_ports(ec2, cfg, sg_id)
    ensure_key(ec2, cfg, public_key=(KEY_FILE).with_suffix(".pem.pub").read_text().strip())
    if dry_run:
        label = "confidential tee (single-mode)" if single else (
            "confidential tee only (tee-only, no ordinary host)" if tee_only
            else "ordinary-host + confidential-tee")
        print(f"==> dry-run: would launch {label}"
              + (" (fresh, recorded tee kept running as `superseded`)" if fresh else "")
              + "; nothing launched")
        return

    # Leftover from a previous interrupted run must not double-launch: load any
    # prior state and reuse the still-running records.
    state = {}
    if HOSTS_FILE.exists():
        try:
            state = json.loads(HOSTS_FILE.read_text())
        except Exception:
            state = {}

    # 1) Session basis: single/tee-only launch no ordinary host. Drop any stale
    # host record so a later cross-host run starts from a clean slate; tee-only
    # must also discard its ip, or a dead Hub address would leak into TEE_RELAY.
    if single:
        host = state.pop("host", None) or {}
    elif tee_only:
        state.pop("host", None)
        host = {}
    else:
        host = state.get("host") or {}
    if not no_host and adoptable(host, recorded_state(ec2, host)):
        print(f"==> reusing ordinary host {host['instance_id']} @ {host.get('public_ip')}")
    elif not no_host:
        host_ami = latest_ami(ec2, cfg)
        print(f"==> launching ordinary host ({host_ami}) t3.small")
        inst = run_ordinary(ec2, cfg, host_ami, vpc_id, subnet_id, sg_id)
        inst = wait_running(ec2, inst["InstanceId"])
        host = {
            "instance_id": inst["InstanceId"],
            "public_ip": inst.get("PublicIpAddress", ""),
            "private_ip": inst.get("PrivateIpAddress", ""),
            "role": "host",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        state["host"] = host
        save_state(state)

    host_ip = host_ip or host.get("public_ip", "")
    if not no_host:
        print(f"  -> ordinary host public ip: {host_ip}")

    # Records written before the private-ip fields existed may be missing them;
    # backfill from AWS so reused instances still route the cross-host plane.
    if host.get("instance_id") and not host.get("private_ip"):
        host["private_ip"] = describe(ec2, host["instance_id"]).get("PrivateIpAddress", "")

    # 2) Confidential tee with user-data injected config. In single mode the tee
    # supervises everything on loopback, so no relay back to an external hub.
    tee = state.get("tee") or {}
    if tee.get("instance_id") and not tee.get("private_ip"):
        tee["private_ip"] = describe(ec2, tee["instance_id"]).get("PrivateIpAddress", "")
    # Runtime config injected by the loader as EC2 user-data. TEE_RELAY (the
    # reverse tunnel back to the external Hub) only exists in cross-host mode:
    # the supervisor in single mode runs hub/agent/tee all on loopback and
    # ignores it. Cross-host traffic uses the PRIVATE ips: both instances share
    # one VPC/subnet/SG, and AWS group-pair SG rules only match in-VPC traffic —
    # a public-ip dial from a group member is not matched and gets dropped.
    host_priv = host.get("private_ip", "")
    # The relay key authenticates the TEE's dial-in to the Hub. In cross-host
    # mode it rides in as TEE_RELAY_KEY (the tee binary reads that env); in
    # single mode the supervisor reads TOKENHIVE_RELAY_KEY and hands it to both
    # its Hub and its tee child. Either way it matches crosshost.sh's Hub.
    relay_key = os.environ.get("TOKENHIVE_RELAY_KEY") or DEFAULT_RELAY_KEY
    # Where the TEE's logs go on AWS. Read here rather than at the launch so the
    # reuse branch below can compare it against what the reused instance carries.
    tee_profile = os.environ.get(TEE_PROFILE_ENV, "").strip()
    if single:
        relay_url = ""
        relay = ""
    else:
        # tee-only has no Hub to dial, so fall back to the documented placeholder
        # to keep the tee's required TEE_RELAY well-formed. The relay is lazy
        # (dialed only when a provider connection is needed), so this never fires
        # at boot; a later --host-ip aims it at a real Hub.
        if tee_only and not (host_priv or host_ip):
            relay_url = TEE_ONLY_RELAY_PLACEHOLDER
        else:
            relay_url = f"ws://{host_priv or host_ip}:18085/v1/relay"
        relay = f"TEE_RELAY={relay_url}\nTEE_RELAY_KEY={relay_key}\n"
    userdata = (
        "TOKENHIVE_SIM_DIR=/tmp/tee\n"
        "TEE_ADDR=0.0.0.0:18090\n"
        f"{relay}"
        "TEE_PLATFORM=sevsnp\n"
        "TEE_MTLS=1\n"
        "TEE_MTLS_CLIENT_CA=/run/bundle/mtls/hub-ca.pem\n"
        # The mock provider's CA rides in the measured bundle and is ADDED to the
        # TEE's upstream trust store, which is the system roots on sevsnp. It is
        # an addition, not a substitution: TEE_CA naming this CA must not stop
        # the TEE validating a real provider (chatgpt.com/api.anthropic.com),
        # which is what a replacing trust store would do — the handshake would
        # die in certificate verification having sent only a ClientHello.
        "TEE_CA=/run/bundle/mtls/mp-ca.pem\n"
    )
    if single:
        userdata += f"TOKENHIVE_RELAY_KEY={relay_key}\n"
        userdata += "TOKENHIVE_SUPERVISE=1\n"
        print("==> single-instance mode: whole loop inside the confidential tee")
    # --new, or a recorded tee that is on its way out, both mean the same thing
    # to the branch below: there is no instance here to adopt, so launch one.
    # Neither case terminates the old machine — it keeps running and keeps its
    # record, which is what lets the operator repoint the Hub with no window in
    # which the old tee is gone and the new one is not serving yet.
    if fresh and tee.get("instance_id"):
        old = supersede(state, time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        save_state(state)
        print(f"==> --new: recorded tee {old['instance_id']} @ {old.get('private_ip')} "
              f"stays RUNNING (moved to `superseded`; nothing was terminated)")
        print("    it keeps serving the Hub until the Hub is repointed, so this launch and")
        print("    the Hub's repoint do not have to wait for any termination; retire it after")
        print("    the repoint with './crosshost.sh down --superseded'")
        tee = {}
    # One lookup, used for both the diagnosis and the decision: a recorded
    # instance in any other state — most importantly shutting-down — is never
    # adopted, and naming the state is how an operator sees why a fresh instance
    # was launched instead of the one the state file names.
    tee_state = recorded_state(ec2, tee)
    if tee.get("instance_id") and tee_state not in REUSABLE_STATES:
        print(f"==> recorded tee {tee['instance_id']} is {tee_state}; not adoptable, launching fresh")
        # The record moves to `superseded` rather than being dropped, for the
        # same reason `--new` moves it: the launch below replaces state["tee"],
        # and the record is the only thing naming the instance — so overwriting
        # it would leave the old machine unreachable from `down --tee-only` and
        # from retire.py, an instance sitting in AWS with nothing on disk
        # pointing at it. Not adoptable is not the same as gone. Nothing is
        # terminated here either: launching and deleting stay separate programs
        # (see retire.py), so no path through an `up` can destroy what it
        # replaces.
        old = supersede(state, time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        if old:
            print(f"    its record moves to `superseded` so it stays reachable: "
                  f"./crosshost.sh down --superseded")
        save_state(state)
        tee = {}
    if adoptable(tee, tee_state):
        print(f"==> reusing confidential tee {tee['instance_id']} @ {tee.get('public_ip')}")
        print("  (N.B. user-data changes do not apply to a reused instance)")
        # An instance profile is bound at RunInstances too, so a reused TEE keeps
        # the one it launched with. Staying quiet here is how an operator adds
        # TOKENHIVE_TEE_INSTANCE_PROFILE, watches `up` succeed, and still ends up
        # with a TEE whose logs ship nowhere: say what it actually carries.
        have = (describe(ec2, tee["instance_id"]).get("IamInstanceProfile") or {}).get(
            "Arn", ""
        ).rsplit("/", 1)[-1]
        if have != tee_profile:
            print(f"  (N.B. its instance profile is {have or '<none>'}, not "
                  f"{tee_profile or '<none>'} — IamInstanceProfile is fixed at launch; "
                  f"terminate and `up` again to change it)")
        print("  (N.B. to launch a replacement while leaving this one running, use --new)")
    else:
        print(f"==> launching confidential tee ({ami_id}) {cfg.instance_type} AmdSevSnp=enabled")
        if tee_profile:
            print(f"  -> IAM instance profile {tee_profile} (TEE logs -> CloudWatch)")
        inst = run_confidential(ec2, cfg, ami_id, vpc_id, subnet_id, sg_id, userdata, tee_profile)
        inst = wait_running(ec2, inst["InstanceId"])
        tee = {
            "instance_id": inst["InstanceId"],
            "public_ip": inst.get("PublicIpAddress", ""),
            "private_ip": inst.get("PrivateIpAddress", ""),
            "role": "tee",
            "ami_id": ami_id,
            "mode": "single" if single else ("tee-only" if tee_only else "cross-host"),
            # Empty when the launch carried no profile. Recorded because "where
            # does this instance's log go" is otherwise unrecoverable from the
            # state file, and the answer differs per launch.
            "instance_profile": tee_profile,
            # Where this tee will dial for a provider connection. Recorded so a
            # decoupled deploy is self-describing: with no ordinary host in this
            # state, nothing else on disk says which Hub address the tee aims at
            # (or that --host-ip was left out and it holds the inert placeholder).
            "relay_url": relay_url,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        state["tee"] = tee
        save_state(state)

    print("==> wrote crosshost.json")
    if single:
        print(f"==> single tee {tee['instance_id']} @ {tee.get('public_ip')} (supervise=1)")
    elif tee_only:
        print(f"==> tee-only {tee['instance_id']} @ {tee.get('public_ip')} (no ordinary host)")
        print(f"==>    TEE_RELAY={relay_url}")
    else:
        print(f"==> host {host['instance_id']} @ {host['public_ip']}")
        print(f"==> tee  {tee['instance_id']} @ {tee.get('public_ip')}")
        print(f"==> tee relay {relay_url}; inspect the leaf over mTLS with ./crosshost.sh fetch")
    superseded = state.get("superseded") or []
    if superseded:
        print("==> superseded (nothing terminated): "
              + ", ".join(e.get("instance_id", "?") for e in superseded))
        print("    once the Hub points at the tee above: ./crosshost.sh down --superseded --dry-run")
        print("    then: ./crosshost.sh down --superseded")


def describe(ec2, iid: str) -> dict:
    """Describe one instance; {} when it no longer exists.

    A record in crosshost.json can outlive its instance (it was terminated, or
    purged after the retention window). Past AWS' ~1h retention window
    describe_instances does not return an empty Reservations list, it raises
    InvalidInstanceID — so "absent" has two shapes and both must collapse to {}
    here, or a caller that is deciding whether a recorded machine is still
    adoptable gets a traceback instead of an answer.

    Only InvalidInstanceID is absorbed. Auth/throttling failures still raise:
    reading them as "absent" would launch a duplicate machine while the real one
    is unreachable rather than gone.
    """
    try:
        res = ec2.describe_instances(InstanceIds=[iid]).get("Reservations", [])
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code not in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            raise
        return {}
    for r in res:
        for i in r.get("Instances", []):
            return i
    return {}


def host_state(ec2, iid: str) -> str:
    """Instance state, or "terminated" when the instance is gone.

    "Gone" collapses to "terminated" because neither can be reused: any recorded
    instance that no longer exists must trigger a fresh launch.
    """
    return describe(ec2, iid).get("State", {}).get("Name", "terminated")


def boto3(service: str):
    import boto3 as _boto3
    return _boto3.client(service, region_name=load().region)


if __name__ == "__main__":
    main()