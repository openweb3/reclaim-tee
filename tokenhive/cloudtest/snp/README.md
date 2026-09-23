# Real SEV-SNP TEE test on AWS (`cloudtest/snp/`)

> **Fork limitation**: `build` requires `deploy/secure-boot/` populated with
> the original repo's keys (`R.key` etc.), which a fork cannot obtain. In a
> fork, skip this module and run the main `cloudtest/run.sh` flow with
> `TOKENHIVE_TEE_PLATFORM=simulated` (the default) — the full business flow on
> a real SNP instance, without real attestation.

This module turns the existing `simulated` cloudtest into a **real** TEE run:
it builds a two-tier SNP loader AMI whose measured app is a TokenHive
attestation probe, boots that AMI on a confidential (`m6a`/`c6a`/`r6a`)
instance, reads the attestation result back over console output, and tears the
instance down strictly by tag.

## What it proves (SNP_APP_HASH)

`SNP_APP_HASH` is not something we assemble — the loader guarantees it:

1. `deploy/snp-image/loader` hashes the raw length-prefixed app-partition
   **bytes** (the bundle tar): `SNP_APP_HASH = hex(sha256(bundle))`, and extends
   TPM PCR 8 with it.
2. The loader re-exports that hash into the app process environment. On AWS
   (`runAWSIsolated`) only the root *broker* copy strips it (it owns the TPM/SEV
   devices and doesn't need it); the unprivileged **app** keeps it.
3. `shared.NewRATLSManager`/`ExtractIdentityFromRATLS` (the exact code
   `tee_k`/`tee_t` and `tokenhive/cmd/tee` run) bind `SNP_APP_HASH` into the
   combined AWS SEV-SNP attestation's `report_data` and self-verify it.

So the earlier `SNP_APP_HASH not set by loader` failure had one cause: the TEE
was run directly on an Ubuntu instance, **outside the loader**. Booted by the
loader there is no gap. The probe here asserts the recovered app hash equals
`SNP_APP_HASH`, which is the one real-SNP property `simulated` cannot produce.

## Flow

```
snp.sh build   # pack.sh (probe -> reproducible bundle tar) + deploy/snp-build.sh (AMI)
snp.sh up      # launch tagged confidential instance from AMI (hosts.json written; no sshd)
snp.sh verify  # poll EC2 console for  SNP_TEST_RESULT matched=yes   (logs/)
snp.sh down    # terminate strictly by tag (never by hosts.json)
```

Only `build` requires the heavy upstream chain (Docker `--privileged` image
build, `qemu-img`, `aws vmimport`) and the Secure Boot `deploy/secure-boot/`
keys. `up`/`verify`/`down` only need boto3 + the EC2 permissions below.

## Prerequisites

- `go` (used by `pack.sh` / `snp-build.sh`), GNU `tar`, plus for `build`:
  `docker`, `qemu-img`, `aws` CLI, and the pinned toolchains in
  `deploy/snp-image/pins.env` / `deploy/.env`.
- `deploy/secure-boot/` populated (`PK`,`KEK`,`R` artifacts + `aws-uefi-data.b64`).
- `cloudtest/.env` with `TOKENHIVE_USER` (+ optional `TOKENHIVE_REGION`,
  `TOKENHIVE_INSTANCE_TYPE`). SEV-SNP instance types are AMD-only
  (`m6a`/`c6a`/`r6a` default `m6a.large`).

## IAM permissions

Attach `iam/aws-snp-policy.json` to the identity (user or role) running this.
CloudImport additionally requires the **`vmimport` service role**, created once:

```bash
# trust: allow AWS VM Import to assume it
cat > vmimport-trust.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": ["vmie.amazonaws.com"]},
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON
aws iam create-role --role-name vmimport --assume-role-policy-document file://vmimport-trust.json
# the role must read the staging bucket without conditions
aws iam put-role-policy --role-name vmimport --policy-name vmimport \
  --policy-document '{"Version":"2012-10-17","Statement":[
    {"Effect":"Allow","Action":["s3:GetObject","s3:GetBucketLocation"],"Resource":["arn:aws:s3:::snp-vmimport-*","arn:aws:s3:::snp-vmimport-*/*"]},
    {"Effect":"Allow","Action":["ec2:ImportSnapshot"],"Resource":"*"}]}'
```

The identity running `crosshost.py` also needs `iam:PassRole` on whichever
instance profile it hands the confidential instance (see below).

## Where the TEE's logs go

On AWS the TEE's structured logger ships to CloudWatch Logs **through the
instance's IAM role**, so a confidential instance launched with no instance
profile keeps running but cannot ship a log: the console is its only channel and
holds a few minutes. `crosshost.py` attaches one when
`TOKENHIVE_TEE_INSTANCE_PROFILE` names it, and records the result in
`crosshost.json` as `tee.instance_profile`:

```bash
# once, as an admin: a role that may only write this deployment's logs
aws iam create-role --role-name tokenhive-tee-logs \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name tokenhive-tee-logs --policy-name ship-logs \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:*:*:log-group:/reclaim-tee/snp:*"}]}'
aws iam create-instance-profile --instance-profile-name tokenhive-tee-logs
aws iam add-role-to-instance-profile --instance-profile-name tokenhive-tee-logs --role-name tokenhive-tee-logs

TOKENHIVE_TEE_INSTANCE_PROFILE=tokenhive-tee-logs ./crosshost.sh up --tee-only --host-ip <hub-ip>
```

The profile is bound at `RunInstances` and cannot be added to a running
instance, so a reused TEE keeps whatever it launched with — `up` prints the
difference rather than letting a just-configured profile quietly not apply.

Local tool check (no S3/VM import needed for this): `installed() { command -v %s >/dev/null; }, docker qemu-img aws`.

## Layout

- `runner/main.go` — the loader `./app` probe (broker split + attestation assert).
- `pack.sh` — cross-compile + deterministic bundle tar; prints the `snp-app:` digest.
- `launch.py` — idempotent infra + launch the confidential instance; writes `hosts.json`.
- `snp.sh` — orchestrator (`build|up|status|verify|down|delete-infra`, `--dry-run`).
- `iam/aws-snp-policy.json` — the precise EC2/S3/VM-import permissions.
- `tests/` — local unit tests (no AWS): bundle determinism, tar layout, tag-deletion safety,
  and the swap wiring (`up --new` forwards the flag; `down --superseded` goes through `retire.py`).