#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build a minimal Ubuntu rootfs for embedding in openshell-vm.
#
# This produces a lightweight rootfs (~200-300MB) with:
# - Base Ubuntu with k3s binary
# - OpenShell supervisor binary
# - Helm charts and Kubernetes manifests
# - NO pre-loaded container images (pulled on demand)
# - NO pre-initialized k3s state (cold start on first boot)
#
# First boot will be slower (~30-60s) as k3s initializes and pulls images,
# but subsequent boots use cached state.
#
# Supports aarch64 and x86_64 guest architectures. The target architecture
# is auto-detected from the host but can be overridden with --arch.
#
# Usage:
#   ./build-rootfs-minimal.sh [--arch aarch64|x86_64] [output_dir]
#
# Requires: Docker, curl, helm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source pinned dependency versions (digests, checksums, commit SHAs).
# Environment variables override pins — see pins.env for details.
PINS_FILE="${SCRIPT_DIR}/../pins.env"
if [ -f "$PINS_FILE" ]; then
    # shellcheck source=../pins.env
    source "$PINS_FILE"
fi

# ── Architecture detection ─────────────────────────────────────────────
# Allow override via --arch flag; default to host architecture.
GUEST_ARCH=""
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            GUEST_ARCH="$2"; shift 2 ;;
        *)
            POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done

if [ -z "$GUEST_ARCH" ]; then
    case "$(uname -m)" in
        aarch64|arm64) GUEST_ARCH="aarch64" ;;
        x86_64)        GUEST_ARCH="x86_64" ;;
        *)
            echo "ERROR: Unsupported host architecture: $(uname -m)" >&2
            echo "       Use --arch aarch64 or --arch x86_64 to override." >&2
            exit 1
            ;;
    esac
fi

case "$GUEST_ARCH" in
    aarch64)
        DOCKER_PLATFORM="linux/arm64"
        K3S_BINARY_SUFFIX="-arm64"
        K3S_CHECKSUM_VAR="K3S_ARM64_SHA256"
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    x86_64)
        DOCKER_PLATFORM="linux/amd64"
        K3S_BINARY_SUFFIX=""    # x86_64 binary has no suffix
        K3S_CHECKSUM_VAR="K3S_AMD64_SHA256"
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    *)
        echo "ERROR: Unsupported guest architecture: ${GUEST_ARCH}" >&2
        echo "       Supported: aarch64, x86_64" >&2
        exit 1
        ;;
esac

DEFAULT_ROOTFS="${XDG_DATA_HOME:-${HOME}/.local/share}/openshell/openshell-vm/rootfs"
ROOTFS_DIR="${POSITIONAL_ARGS[0]:-${DEFAULT_ROOTFS}}"
CONTAINER_NAME="krun-rootfs-minimal-builder"
BASE_IMAGE_TAG="krun-rootfs:openshell-vm-minimal"
K3S_VERSION="${K3S_VERSION:-v1.35.2+k3s1}"
K3S_VERSION="${K3S_VERSION//-k3s/+k3s}"

# Project root (two levels up from crates/openshell-vm/scripts/)
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Cross-platform checksum helper
verify_checksum() {
    local expected="$1" file="$2"
    if command -v sha256sum &>/dev/null; then
        echo "${expected}  ${file}" | sha256sum -c -
    else
        echo "${expected}  ${file}" | shasum -a 256 -c -
    fi
}

echo "==> Building minimal openshell-vm rootfs"
echo "    Guest arch:  ${GUEST_ARCH}"
echo "    k3s version: ${K3S_VERSION}"
echo "    Output:      ${ROOTFS_DIR}"
echo "    Mode:        minimal (no pre-loaded images, cold start)"
echo ""

# ── Check for running VM ────────────────────────────────────────────────
VM_LOCK_FILE="$(dirname "${ROOTFS_DIR}")/$(basename "${ROOTFS_DIR}")-vm.lock"
if [ -f "${VM_LOCK_FILE}" ]; then
    if ! python3 -c "
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fd, fcntl.LOCK_UN)
except BlockingIOError:
    sys.exit(1)
finally:
    os.close(fd)
" "${VM_LOCK_FILE}" 2>/dev/null; then
        HOLDER_PID=$(cat "${VM_LOCK_FILE}" 2>/dev/null | tr -d '[:space:]')
        echo "ERROR: An openshell-vm (pid ${HOLDER_PID:-unknown}) holds a lock on this rootfs."
        echo "       Stop the VM first, then re-run this script."
        exit 1
    fi
fi

VM_STATE_FILE="$(dirname "${ROOTFS_DIR}")/$(basename "${ROOTFS_DIR}")-vm-state.json"
if [ -f "${VM_STATE_FILE}" ]; then
    VM_PID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pid'])" "${VM_STATE_FILE}" 2>/dev/null || echo "")
    if [ -n "${VM_PID}" ] && kill -0 "${VM_PID}" 2>/dev/null; then
        echo "ERROR: An openshell-vm is running (pid ${VM_PID}) using this rootfs."
        echo "       Stop the VM first, then re-run this script."
        exit 1
    else
        rm -f "${VM_STATE_FILE}"
    fi
fi

# ── Download k3s binary ─────────────────────────────────────────────────
K3S_BIN="/tmp/k3s-${GUEST_ARCH}-${K3S_VERSION}"
if [ -f "${K3S_BIN}" ]; then
    echo "==> Using cached k3s binary: ${K3S_BIN}"
else
    echo "==> Downloading k3s ${K3S_VERSION} for ${GUEST_ARCH}..."
    curl -fSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s${K3S_BINARY_SUFFIX}" \
        -o "${K3S_BIN}"
    chmod +x "${K3S_BIN}"
fi

# Verify k3s binary integrity.
K3S_CHECKSUM="${!K3S_CHECKSUM_VAR:-}"
if [ -n "${K3S_CHECKSUM}" ]; then
    echo "==> Verifying k3s binary checksum..."
    verify_checksum "${K3S_CHECKSUM}" "${K3S_BIN}"
else
    echo "WARNING: ${K3S_CHECKSUM_VAR} not set, skipping checksum verification"
fi

# ── Build base image ───────────────────────────────────────────────────
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

echo "==> Building base image..."
docker build --platform "${DOCKER_PLATFORM}" -t "${BASE_IMAGE_TAG}" \
    --build-arg "BASE_IMAGE=${VM_BASE_IMAGE}" -f - . <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        iproute2 \
        python3 \
        busybox-static \
        zstd \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /usr/share/udhcpc && \
    ln -sf /bin/busybox /sbin/udhcpc
RUN mkdir -p /var/lib/rancher/k3s /etc/rancher/k3s
DOCKERFILE

# Create container and export filesystem
echo "==> Creating container..."
docker create --platform "${DOCKER_PLATFORM}" --name "${CONTAINER_NAME}" "${BASE_IMAGE_TAG}" /bin/true

echo "==> Exporting filesystem..."
if [ -d "${ROOTFS_DIR}" ]; then
    chmod -R u+rwx "${ROOTFS_DIR}" 2>/dev/null || true
    rm -rf "${ROOTFS_DIR}"
fi
mkdir -p "${ROOTFS_DIR}"
docker export "${CONTAINER_NAME}" | tar -C "${ROOTFS_DIR}" -xf -
docker rm "${CONTAINER_NAME}"

# ── Inject k3s binary ──────────────────────────────────────────────────
echo "==> Injecting k3s binary..."
cp "${K3S_BIN}" "${ROOTFS_DIR}/usr/local/bin/k3s"
chmod +x "${ROOTFS_DIR}/usr/local/bin/k3s"
ln -sf /usr/local/bin/k3s "${ROOTFS_DIR}/usr/local/bin/kubectl"

# ── Inject scripts ─────────────────────────────────────────────────────
echo "==> Injecting scripts..."
mkdir -p "${ROOTFS_DIR}/srv"
cp "${SCRIPT_DIR}/openshell-vm-init.sh" "${ROOTFS_DIR}/srv/openshell-vm-init.sh"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-init.sh"

cp "${SCRIPT_DIR}/hello-server.py" "${ROOTFS_DIR}/srv/hello-server.py"
chmod +x "${ROOTFS_DIR}/srv/hello-server.py"

cp "${SCRIPT_DIR}/check-vm-capabilities.sh" "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"
chmod +x "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"

cp "${SCRIPT_DIR}/openshell-vm-exec-agent.py" "${ROOTFS_DIR}/srv/openshell-vm-exec-agent.py"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-exec-agent.py"

# ── Build and inject supervisor binary ─────────────────────────────────
SUPERVISOR_TARGET="${RUST_TARGET}"
SUPERVISOR_BIN="${PROJECT_ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"

echo "==> Building openshell-sandbox supervisor binary (${SUPERVISOR_TARGET})..."
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "ERROR: cargo-zigbuild is not installed."
    echo "       Install it with: cargo install cargo-zigbuild"
    exit 1
fi

cargo zigbuild --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" \
    --manifest-path "${PROJECT_ROOT}/Cargo.toml" 2>&1 | tail -5

if [ ! -f "${SUPERVISOR_BIN}" ]; then
    echo "ERROR: supervisor binary not found at ${SUPERVISOR_BIN}"
    exit 1
fi

echo "    Injecting supervisor binary into rootfs..."
mkdir -p "${ROOTFS_DIR}/opt/openshell/bin"
cp "${SUPERVISOR_BIN}" "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"
chmod +x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"

# ── Package and inject helm chart ──────────────────────────────────────
HELM_CHART_DIR="${PROJECT_ROOT}/deploy/helm/openshell"
CHART_DEST="${ROOTFS_DIR}/var/lib/rancher/k3s/server/static/charts"

if [ -d "${HELM_CHART_DIR}" ]; then
    echo "==> Packaging helm chart..."
    mkdir -p "${CHART_DEST}"
    helm package "${HELM_CHART_DIR}" -d "${CHART_DEST}"
    mkdir -p "${ROOTFS_DIR}/opt/openshell/charts"
    cp "${CHART_DEST}"/*.tgz "${ROOTFS_DIR}/opt/openshell/charts/"
fi

# ── Inject Kubernetes manifests ────────────────────────────────────────
MANIFEST_SRC="${PROJECT_ROOT}/deploy/kube/manifests"
MANIFEST_DEST="${ROOTFS_DIR}/opt/openshell/manifests"

echo "==> Injecting Kubernetes manifests..."
mkdir -p "${MANIFEST_DEST}"

for manifest in openshell-helmchart.yaml agent-sandbox.yaml; do
    if [ -f "${MANIFEST_SRC}/${manifest}" ]; then
        cp "${MANIFEST_SRC}/${manifest}" "${MANIFEST_DEST}/"
        echo "    ${manifest}"
    fi
done

# ── Create empty images directory ──────────────────────────────────────
# k3s expects this directory to exist for airgap image loading.
mkdir -p "${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images"

# ── Mark as minimal (not pre-initialized) ──────────────────────────────
# The init script checks for this file to determine if cold start is expected.
echo "minimal" > "${ROOTFS_DIR}/opt/openshell/.rootfs-type"

# ── Verify ─────────────────────────────────────────────────────────────
if [ ! -f "${ROOTFS_DIR}/usr/local/bin/k3s" ]; then
    echo "ERROR: k3s binary not found in rootfs."
    exit 1
fi

if [ ! -x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" ]; then
    echo "ERROR: openshell-sandbox supervisor binary not found in rootfs."
    exit 1
fi

echo ""
echo "==> Minimal rootfs ready at: ${ROOTFS_DIR}"
echo "    Size: $(du -sh "${ROOTFS_DIR}" | cut -f1)"
echo "    Type: minimal (cold start, images pulled on demand)"
echo ""
echo "Note: First boot will take ~30-60s as k3s initializes."
echo "      Container images will be pulled from registries on first use."
