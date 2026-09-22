# Reclaim TEE xxxx

Secure TLS attestation protocol that uses Trusted Execution Environments (TEE) and Multi-Party Computation (MPC). It runs on GCP Confidential Space.

The preferred split-AEAD path keeps request and response views separate. The TLS 1.2 CBC compatibility path uses a different trust boundary.

## Architecture

Two TEE services split AEAD processing so neither service receives the complete request-response pair:

- **TEE_K** (`tee_k/`) -- Holds TLS keys, handles encryption, manages connections to target websites. Port 8080.
- **TEE_T** (`tee_t/`) -- Computes authentication tags without key access, verifies integrity. Port 8081.
- **Client** (`client/`, `demo_standalone/`) -- Orchestrates the protocol, handles redaction, generates proofs.

For trusted TLS 1.2 CBC, TEE_K receives the full request. TEE_T receives the full authenticated response.

Supporting:
- `minitls/` -- Custom TLS 1.2/1.3 with split AEAD support
- `mpc/` -- Optimized MPC OPRF with half-gates and KOS OT extension
- `oprfmpc/` -- Legacy MPC OPRF retained for differential tests
- `shared/` -- GCP integrations (KMS, attestation, logging, cert management)
- `proto/` -- Protocol buffer definitions
- `providers/` -- HTTP request/response parsing and validation

## Quick Start

```bash
# Build everything
./build.sh

# Run the demo (starts both TEEs + client)
./demo.sh
```

## Build

```bash
./build.sh                    # all services
cd tee_k && go build .        # just TEE_K
cd tee_t && go build .        # just TEE_T

# Regenerate protobuf (after .proto changes)
protoc -I proto --go_out=proto/ --go_opt=paths=source_relative proto/*.proto
```

## Test

```bash
go test ./...                 # all tests
go test ./minitls/...         # specific package
go test -cover ./...          # with coverage
```

## Protocol Flow

1. Client connects to TEE_K and TEE_T over WebSocket
2. TEE_K and TEE_T perform mutual attestation and OT precomputation (100,000 initial OTs)
3. TEE_K establishes TLS connection with the target website
4. TLS negotiation selects the split-AEAD path or the TLS 1.2 CBC path
5. TEEs process the request and response with the selected trust boundary
6. MPC OPRF with garbled circuits and precomputed random OT for key derivation proofs
7. Client generates ZK proofs and verification bundle
8. Attestor validates the bundle and issues a signed claim

## Deployment

Both TEE services run as GCP Confidential Space VMs. A single Docker image per service is used across all regions -- region-specific config (domain, KMS keys) is injected via instance metadata.

### Build & Deploy

```bash
./deploy/build.sh             # build reproducible images, push to registry
./deploy/build.sh v2 <commit> # rebuild from a specific commit
./deploy/update-image-history.sh  # record digests in image-history.json
```

### Update Pinned Versions

Base image (Go/Alpine) and BuildKit are pinned by digest for reproducibility:

```bash
./deploy/update-pins.sh           # show current versions
./deploy/update-pins.sh --update  # pull latest and update pins
```

## Reproducible Builds

Image digests serve as enclave identity (PCR0) in GCP Confidential Space. Anyone can verify deployed images match source code:

```bash
./deploy/verify.sh
```

This rebuilds both images from source using the pinned BuildKit, Go version, and `SOURCE_DATE_EPOCH` from `deploy/image-history.json`, then compares digests. No GCP credentials needed. Requires Docker with buildx and Python 3.

Current production digests: [`deploy/image-history.json`](deploy/image-history.json)

### What makes builds reproducible

- Pinned base image and BuildKit by digest
- `-trimpath -buildid=` eliminates host-dependent Go build artifacts
- `--chown=0:0` on all COPY instructions normalizes file ownership
- File mtimes normalized to commit timestamp before building
- `SOURCE_DATE_EPOCH` + `rewrite-timestamp` clamps all layer timestamps
- `crane push` preserves exact OCI digest

## Attestation & Certificate Verification

Each RA-TLS certificate contains provider evidence. This evidence binds the TLS public key (SPKI) to a hardware report.

The client verifies this evidence but does not pin an app hash or a base hash. The external attestor applies the code-identity policy later.

Each signed TEE result contains a second attestation. This attestation binds the TEE signing key and the app hash to hardware evidence.

The signed result contains these nonces:

- `tee_k_public_key:0x...` or `tee_t_public_key:0x...`
- `tee_k_spki_hash:<sha256>` or `tee_t_spki_hash:<sha256>`

The attestor returns both app hashes in the claim context. The claim consumer compares these hashes with its app policy.

### Secure Boot trust and client compatibility

Secure Boot adds a release-key check to the SEV2 checks. It does not make the AMD launch measurement identify the base image.

The provider TPM signs the measured PCR values. The AMD report binds the TPM evidence to the confidential VM.

The verifier replays the firmware event log against PCR 4, PCR 7, and PCR 11. The replay must prove an enabled `R`-only policy.

The app loader is part of an `R`-signed UKI. The loader measures the app bundle into PCR 8 before it runs the app.

The secure path trusts the stable public key `R` and the app hash. It does not use the PCR 11 base allowlist.

Secure RA-TLS certificates keep the full evidence in the legacy `.2` extension. They add a one-byte, non-critical `.3` Secure Boot marker.

Old clients ignore the `.3` marker and verify the unchanged SEV2 prerequisite. Updated clients use it to verify `R` during the TLS handshake.

Signed claim reports keep the legacy `sev-snp` report type and cloud tag for old clients. The evidence still contains the Secure Boot event log.

The signed TEE payload contains `attestation_type = "secure-boot"`. A change to this marker makes the TEE signature invalid.

Old `recordbuf-fix` clients ignore the new payload field. They preserve the original signed body when they create the verification bundle.

Updated clients and attestors read the signed marker. They require the event-log and `R` checks when the marker is `secure-boot`.

The native Secure Boot type remains on the TEE control channel. This rule prevents a Secure Boot half from pairing with an SEV2 half.

The secure base hashes do not belong in the legacy base allowlist. The signed marker selects the secure trust path instead.

### AWS same-guest evidence

New AWS bases run the network process as UID 65532. A measured root broker owns the NitroTPM and SEV-SNP devices.

The broker emits two SEV-SNP reports:

- `sev` keeps the previous caller binding for clients released before SEV2.
- `sev2` binds the caller value, app hash, and exact signed NitroTPM document.

Current clients, TEEs, and the router require and verify `sev2`. They ignore `sev`, and reject a `sev`-only AWS envelope. The legacy field remains in newly produced envelopes only so clients released before SEV2 can decode and verify them.

An AWS base without the measured attestation broker cannot produce `sev2` and is incompatible with current binaries. Restoring such a base also requires restoring a verifier version that predates mandatory SEV2. Keep the legacy `sev` producer until support for clients released before SEV2 is explicitly retired.

## Debugging

```bash
# Demo logs
tail -f /tmp/demo_teek.log
tail -f /tmp/demo_teet.log

# Force TLS version
FORCE_TLS_VERSION=1.3 ./demo.sh
```

TLS 1.2 CBC is always available. AEAD suites remain preferred.
