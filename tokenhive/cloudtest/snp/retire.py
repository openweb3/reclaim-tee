#!/usr/bin/env python3
"""Terminate the TEE instances that `crosshost.sh up` superseded.

The swap it serves: bring a new confidential instance up while the old one
still runs, repoint the Hub at the new one, and only then retire the old one.
Nothing has to wait for an EC2 termination, and the window in which no tee
serves does not exist — the old instance is still there until the operator says
otherwise. crosshost.py is what puts records under `superseded`; this is the
only program that turns one of those records into a termination.

    python3 retire.py [--state <crosshost.json>] [--dry-run]

Deletion here is deliberately narrow, and every step is a refusal rather than a
best effort:

  * The only ids this program can terminate are the ones recorded under
    `superseded`. It never enumerates instances by tag and never consults the
    current `tee`/`host` records as candidates, so a wrong or stale state file
    cannot widen the match set — it can only fail to name something.
  * An id that also names the current tee or the current host is refused
    outright. That is the guard against retiring the machine that is serving.
  * Each candidate is re-checked for BOTH cloudtest tags before it is touched,
    exactly like `down --tee-only`: a hand-edited or foreign id gets a refusal,
    not a termination.
  * Retirement requires a live successor. The current tee must be recorded AND
    running. "Running" is the strongest thing this side can observe; whether the
    Hub has actually been repointed at it is not visible from here, so that part
    stays an operator step (see docs/cert-lifetime-audit.md §15).
"""

import json
import sys
from pathlib import Path

_CLOUDTEST = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CLOUDTEST))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # snp/, next to crosshost.py

from aws import terminate  # noqa: E402
from config import load  # noqa: E402
from crosshost import describe, host_state  # noqa: E402  (snp/crosshost.py)

# Default state file: the same crosshost.json the launcher writes. It lives one
# level up (cloudtest/), not next to this file, because every other cloudtest
# tool reads it there.
STATE_FILE = _CLOUDTEST / "crosshost.json"

SUCCESSOR_MUST_BE = "running"


class Refused(Exception):
    """A precondition failed. Nothing further is terminated."""


def _tagged(inst: dict, cfg) -> bool:
    """Both cloudtest tags, re-checked locally on the describe result."""
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    return tags.get(cfg.tag_owner) == cfg.tag_owner_value and tags.get(cfg.tag_user) == cfg.user


def retire(ec2, cfg, state: dict, dry_run: bool = False) -> dict:
    """Terminate the recorded superseded instances; prune what is gone.

    Mutates `state["superseded"]`, dropping the entries it has dealt with so a
    re-run is a no-op instead of a second termination attempt. Returns a summary
    for the caller to print; raises Refused before touching anything if a
    precondition fails.
    """
    entries = list(state.get("superseded") or [])
    summary = {"rows": [], "terminated": [], "dry_run": dry_run, "pruned": 0}
    if not entries:
        return summary

    # 1) The successor gate, before any termination: a swap retires the old tee
    # only once a replacement is up. Without this, an operator who retires the
    # superseded instance after the new one silently died ends up with no TEE at
    # all — the one failure mode this whole flow exists to avoid.
    successor = (state.get("tee") or {}).get("instance_id", "")
    if not successor:
        raise Refused(
            "no current tee is recorded, so retiring the superseded instance(s) "
            "would leave no TEE; run './crosshost.sh up' first"
        )
    st = host_state(ec2, successor)
    if st != SUCCESSOR_MUST_BE:
        raise Refused(
            f"the current tee {successor} is {st}, not {SUCCESSOR_MUST_BE}; refusing to "
            f"retire its predecessor — the replacement must be up before the old tee goes"
        )

    # 2) Ids this program may never terminate, whatever the state file says.
    protected = {successor, (state.get("host") or {}).get("instance_id", "")}

    dropped = set()
    for idx, entry in enumerate(entries):
        iid = (entry or {}).get("instance_id", "")
        if not iid:
            # A record naming nothing cannot be acted on, and keeping it would
            # make `down --superseded` a permanent no-op that looks like work.
            dropped.add(idx)
            continue
        if iid in protected:
            raise Refused(
                f"superseded record {iid} also names the current instance; refusing — "
                f"the state file was edited or is stale, fix it before retiring anything"
            )
        inst = describe(ec2, iid)
        if not inst:
            summary["rows"].append((iid, "gone", "-", entry.get("superseded_at", "?")))
            dropped.add(idx)
            continue
        if not _tagged(inst, cfg):
            raise Refused(
                f"{iid} does not carry the cloudtest tags; refusing to terminate it"
            )
        iid_state = inst["State"]["Name"]
        summary["rows"].append(
            (iid, iid_state, inst.get("PrivateIpAddress", "-"), entry.get("superseded_at", "?"))
        )
        if iid_state in ("terminated", "shutting-down"):
            dropped.add(idx)  # already on its way out; the record has done its job
            continue
        if dry_run:
            continue
        terminate(ec2, [iid])
        summary["terminated"].append(iid)
        dropped.add(idx)

    if not dry_run and dropped:
        kept = [e for i, e in enumerate(entries) if i not in dropped]
        if kept:
            state["superseded"] = kept
        else:
            state.pop("superseded", None)
        summary["pruned"] = len(dropped)
    return summary


def main() -> None:
    argv = sys.argv[1:]
    dry_run = "--dry-run" in argv
    state_file = STATE_FILE
    if "--state" in argv:
        state_file = Path(argv[argv.index("--state") + 1])

    cfg = load()
    if not state_file.exists():
        sys.exit(f"==> no state file at {state_file}; nothing recorded, nothing to retire")
    state = json.loads(state_file.read_text())

    # Say so before building a client: "nothing was superseded" is the answer for
    # a state file that predates the first `up --new`, and it needs no AWS at all.
    if not (state.get("superseded") or []):
        print(f"==> {state_file} records no superseded instance; nothing to do")
        print("    ('./crosshost.sh up --tee-only --host-ip <hub> --new' records one)")
        return

    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is not installed; run: ./setup.sh")
    ec2 = boto3.client("ec2", region_name=cfg.region)

    try:
        summary = retire(ec2, cfg, state, dry_run=dry_run)
    except Refused as e:
        sys.exit(f"==> refused: {e}")

    print(f"    current tee {(state.get('tee') or {}).get('instance_id', '?')} "
          f"({SUCCESSOR_MUST_BE}); superseded records: {len(summary['rows'])}")
    for iid, st, ip, when in summary["rows"]:
        print(f"    {iid}  {st:14s} {ip:16s} superseded {when}")
    if dry_run:
        print("==> dry-run: nothing terminated")
        return
    if summary["terminated"]:
        print(f"==> terminated: {', '.join(summary['terminated'])}")
    if summary["pruned"]:
        state_file.write_text(json.dumps(state, indent=2) + "\n")
        print(f"==> pruned {summary['pruned']} record(s) from {state_file.name}")
    print("==> note: this checks the successor tee is running; it cannot see whether the "
          "Hub was repointed — repoint the Hub BEFORE retiring")


if __name__ == "__main__":
    main()
