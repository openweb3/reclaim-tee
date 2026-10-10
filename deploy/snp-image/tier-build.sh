#!/bin/bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY 2>/dev/null || true

# Two-tier image (in container): an R-signed base UKI (kernel + loader init)
# plus the app bundle on a separate raw partition. The loader measures the app
# into PCR 8 and executes it. Verifiers prove R authorized the loader from the
# replayed Secure Boot log, then use PCR 8 as the cross-cloud app identity.

export SOURCE_DATE_EPOCH=1735689600
cd /work

LOADER=/work/mkosi.extra/usr/local/bin/snp-loader
if [[ "${SNP_SECUREBOOT_PROBE:-0}" == 1 ]]; then
    LOADER=/work/mkosi.extra/usr/local/bin/snp-prober
fi
# APP defaults to the prober; the `tee` build sets APP_BIN to the real tee_t.
APP="${APP_BIN:-/work/mkosi.extra/usr/local/bin/snp-prober}"
[[ -f "${LOADER}" && -f "${APP}" ]] || { echo "loader/app binary missing: ${LOADER} / ${APP}" >&2; exit 1; }
KERNEL="$(ls /boot/vmlinuz-* 2>/dev/null | grep -v -- '-rescue' | sort | tail -1)"
STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub
# clocksource=kvm-clock is load-bearing, not a preference. Under SEV-SNP the
# guest defaults to tsc, whose frequency comes back as an uncalibrated nominal
# ("Detected 2650.000 MHz"); the clocksource watchdog then promotes it over the
# already-registered kvm-clock. The resulting ~26.5 ppm error desynchronizes the
# guest from the NitroTPM leaf's NotBefore by ~2.3 s/day, and once that gap
# exceeds the refresh retry floor no rotation can ever succeed again. Pin the
# hypervisor-backed clock so timekeeping cannot drift away from attestation.
CMDLINE="${SNP_CMDLINE:-console=ttyS0,115200 clocksource=kvm-clock}"
SEED=b5f8a3c2-1d4e-4a6b-9c8d-7e0f1a2b3c4d

# 1) Base initrd: loader as /init (no app code, so app releases do not alter it).
rm -rf /tmp/ir; mkdir -p /tmp/ir/proc /tmp/ir/sys /tmp/ir/dev /tmp/ir/run
cp "${LOADER}" /tmp/ir/init; chmod 0755 /tmp/ir/init

# Bundle cloud-specific non-builtin modules; the loader inserts them at boot.
# MODULES: "gve" (GCP NIC) or "ena tsm_report sev-guest" (AWS NIC + attestation).
# Decompressed for a plain finit_module.
mkdir -p /tmp/ir/modules
KVER="$(ls /usr/lib/modules | head -1)"
for m in ${MODULES:-gve}; do
    ko="$(find "/usr/lib/modules/${KVER}" -name "${m}.ko*" | head -1)"
    [[ -n "${ko}" ]] || { echo "[tier] WARN: NIC module ${m} not found in kernel ${KVER}"; continue; }
    case "${ko}" in
        *.zst) zstd -dqf -o "/tmp/ir/modules/${m}.ko" "${ko}" ;;
        *)     cp "${ko}" "/tmp/ir/modules/${m}.ko" ;;
    esac
    echo "[tier] bundled NIC module: ${m}.ko ($(du -h "/tmp/ir/modules/${m}.ko" | cut -f1))"
done

# cpio --reproducible normalizes inode/device numbers but NOT mtimes, and the
# freshly-built loader has a per-build mtime; clamp everything to the epoch.
find /tmp/ir -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
( cd /tmp/ir && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort \
    | cpio --reproducible --quiet -o -H newc -R 0:0 ) | zstd -q -19 -f -o /work/base-initrd.zst

# 2) R-signed base UKI. The firmware and sd-stub also measure it into PCRs.
UKIFY_ARGS=(build --linux="${KERNEL}" --initrd=/work/base-initrd.zst
    --cmdline="${CMDLINE}" --stub "${STUB}" --output /work/snp-base.efi)
if [[ -n "${SNP_SECUREBOOT_KEY:-}" || -n "${SNP_SECUREBOOT_CERT:-}" ]]; then
    [[ -n "${SNP_SECUREBOOT_KEY:-}" && -n "${SNP_SECUREBOOT_CERT:-}" ]] || {
        echo "SNP_SECUREBOOT_KEY and SNP_SECUREBOOT_CERT must be set together" >&2
        exit 1
    }
    UKIFY_ARGS+=(--signtool=sbsign --secureboot-private-key="${SNP_SECUREBOOT_KEY}"
        --secureboot-certificate="${SNP_SECUREBOOT_CERT}")
fi
ukify "${UKIFY_ARGS[@]}"
if [[ -n "${SNP_SECUREBOOT_CERT:-}" ]]; then
    sbverify --cert "${SNP_SECUREBOOT_CERT}" /work/snp-base.efi >/dev/null
    echo "[tier] verified UKI signature against release key R"
fi

# Disk assembly (steps 3-4) uses systemd-repart -> loop devices + --privileged.
# Identity-only mode (verify) skips it: the UKI + app digest are the measured
# identity; the disk is just a carrier and nothing attests it.
if [[ "${SNP_IDENTITY_ONLY:-0}" != 1 ]]; then
# Assemble the systemd-repart source root. Note: with --root=, repart resolves
# CopyFiles= AND CopyBlocks= RELATIVE to this root, so the app blob lives here.
rm -rf /tmp/sysroot; mkdir -p /tmp/sysroot/EFI/BOOT
cp /work/snp-base.efi /tmp/sysroot/EFI/BOOT/BOOTX64.EFI

# 3) App blob: 8-byte LE length + app binary, padded to the partition size.
APPSZ=96
python3 -c 'import sys,struct
d=open(sys.argv[1],"rb").read()
b=struct.pack("<Q",len(d))+d
b=b.ljust(int(sys.argv[3])*1024*1024,b"\x00")
open(sys.argv[2],"wb").write(b)' "${APP}" /tmp/sysroot/app.blob "${APPSZ}"
[[ -f /tmp/sysroot/app.blob ]] || { echo "[tier] failed to create app.blob" >&2; exit 1; }
echo "[tier] app.blob: $(stat -c%s /tmp/sysroot/app.blob) bytes"

# 4) Disk: ESP (base UKI at fallback path) + raw app partition (CopyBlocks).
mkdir -p /tmp/defs
cat > /tmp/defs/00-esp.conf <<'EOF'
[Partition]
Type=esp
Format=vfat
CopyFiles=/EFI:/EFI
SizeMinBytes=512M
SizeMaxBytes=512M
EOF
cat > /tmp/defs/10-app.conf <<EOF
[Partition]
Type=linux-generic
CopyBlocks=/app.blob
SizeMinBytes=${APPSZ}M
SizeMaxBytes=${APPSZ}M
EOF
rm -f /work/snp-tier.raw
systemd-repart --empty=create --size=auto --seed="${SEED}" \
    --definitions=/tmp/defs --root=/tmp/sysroot --dry-run=no /work/snp-tier.raw
fi

# 5) Report the values a verifier would pin.
APPSHA="$(sha256sum "${APP}" | cut -d' ' -f1)"
echo "[tier] base UKI: $(du -h /work/snp-base.efi | cut -f1)$([[ -f /work/snp-tier.raw ]] && echo "  raw: $(du -h /work/snp-tier.raw | cut -f1)")"
echo "[tier] base_uki_sha256 = $(sha256sum /work/snp-base.efi | cut -d' ' -f1)  (stable across app changes)"
echo "[tier] app_sha256      = ${APPSHA}"
echo "[tier] expected_PCR8   = $(python3 -c "import hashlib,binascii;print(hashlib.sha256(b'\x00'*32+binascii.unhexlify('${APPSHA}')).hexdigest())")  (app, if PCR8 pristine)"
# PCR 11 = sd-stub sections + the initial empty phase (--phase=, the <:> value):
# our initrd /init is the loader, not systemd, so no pcrphase word is extended.
M=/usr/lib/systemd/systemd-measure
if [[ -x "${M}" ]]; then
    pd="$(mktemp -d)"; margs=""
    for s in linux osrel cmdline initrd uname sbat pcrpkey; do
        objcopy -O binary --only-section=.${s} /work/snp-base.efi "${pd}/${s}" 2>/dev/null && [[ -s "${pd}/${s}" ]] && margs="${margs} --${s}=${pd}/${s}"
    done
    pcr11="$("${M}" calculate ${margs} --bank="${SNP_PCR_BANK:-sha256}" --phase= 2>&1 | awk -F= '/^11:/{print $2; exit}')"
    echo "[tier] snp-base (PCR11 ${SNP_PCR_BANK:-sha256}) = snp-base:${pcr11}"
    rm -rf "${pd}"
fi
