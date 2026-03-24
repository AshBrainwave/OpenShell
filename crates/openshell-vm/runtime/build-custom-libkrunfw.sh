#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build a custom libkrunfw with bridge/netfilter kernel support.
#
# This script clones libkrunfw, applies the OpenShell kernel config
# fragment (bridge CNI, iptables, conntrack), builds the library, and
# stages the artifact with provenance metadata.
#
# Prerequisites:
#   - Rust toolchain (cargo)
#   - make, git, curl
#   - Cross-compilation toolchain for aarch64 (if building on x86_64)
#   - On macOS: Xcode command line tools
#
# Usage:
#   ./build-custom-libkrunfw.sh [--output-dir DIR] [--libkrunfw-ref REF]
#
# Environment:
#   LIBKRUNFW_REF      - git ref to check out (default: main)
#   LIBKRUNFW_REPO     - git repo URL (default: github.com/containers/libkrunfw)
#   OPENSHELL_RUNTIME_OUTPUT_DIR - output directory for built artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
KERNEL_CONFIG_FRAGMENT="${SCRIPT_DIR}/kernel/bridge-cni.config"

# Defaults
LIBKRUNFW_REPO="${LIBKRUNFW_REPO:-https://github.com/containers/libkrunfw.git}"
LIBKRUNFW_REF="${LIBKRUNFW_REF:-main}"
OUTPUT_DIR="${OPENSHELL_RUNTIME_OUTPUT_DIR:-${PROJECT_ROOT}/target/custom-runtime}"
BUILD_DIR="${PROJECT_ROOT}/target/libkrunfw-build"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"; shift 2 ;;
        --libkrunfw-ref)
            LIBKRUNFW_REF="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--output-dir DIR] [--libkrunfw-ref REF]"
            echo ""
            echo "Build a custom libkrunfw with bridge/netfilter kernel support."
            echo ""
            echo "Options:"
            echo "  --output-dir DIR     Output directory for built artifacts"
            echo "  --libkrunfw-ref REF  Git ref to check out (default: main)"
            echo ""
            echo "Environment:"
            echo "  LIBKRUNFW_REPO                  Git repo URL"
            echo "  LIBKRUNFW_REF                   Git ref (branch/tag/commit)"
            echo "  OPENSHELL_RUNTIME_OUTPUT_DIR    Output directory"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

echo "==> Building custom libkrunfw"
echo "    Repo:            ${LIBKRUNFW_REPO}"
echo "    Ref:             ${LIBKRUNFW_REF}"
echo "    Config fragment: ${KERNEL_CONFIG_FRAGMENT}"
echo "    Output:          ${OUTPUT_DIR}"
echo ""

# ── Clone / update libkrunfw ────────────────────────────────────────────

if [ -d "${BUILD_DIR}/libkrunfw/.git" ]; then
    echo "==> Updating existing libkrunfw checkout..."
    git -C "${BUILD_DIR}/libkrunfw" fetch origin
    git -C "${BUILD_DIR}/libkrunfw" checkout "${LIBKRUNFW_REF}"
    git -C "${BUILD_DIR}/libkrunfw" pull --ff-only 2>/dev/null || true
else
    echo "==> Cloning libkrunfw..."
    mkdir -p "${BUILD_DIR}"
    git clone "${LIBKRUNFW_REPO}" "${BUILD_DIR}/libkrunfw"
    git -C "${BUILD_DIR}/libkrunfw" checkout "${LIBKRUNFW_REF}"
fi

LIBKRUNFW_DIR="${BUILD_DIR}/libkrunfw"
LIBKRUNFW_COMMIT=$(git -C "${LIBKRUNFW_DIR}" rev-parse HEAD)
LIBKRUNFW_SHORT=$(git -C "${LIBKRUNFW_DIR}" rev-parse --short HEAD)

echo "    Commit: ${LIBKRUNFW_COMMIT}"

# ── Detect the kernel version libkrunfw targets ────────────────────────

# libkrunfw's Makefile typically sets KERNEL_VERSION or has it in a
# config file. Try to detect it.
KERNEL_VERSION=""
if [ -f "${LIBKRUNFW_DIR}/Makefile" ]; then
    KERNEL_VERSION=$(grep -oE 'KERNEL_VERSION\s*=\s*linux-[^\s]+' "${LIBKRUNFW_DIR}/Makefile" 2>/dev/null | head -1 | sed 's/.*= *//' || true)
fi
if [ -z "$KERNEL_VERSION" ] && [ -f "${LIBKRUNFW_DIR}/kernel_version" ]; then
    KERNEL_VERSION=$(cat "${LIBKRUNFW_DIR}/kernel_version")
fi
echo "    Kernel version: ${KERNEL_VERSION:-unknown}"

# ── Apply kernel config fragment ────────────────────────────────────────

echo "==> Applying OpenShell kernel config fragment..."

# libkrunfw builds the kernel with a config generated from its own
# sources. The config merge happens after `make olddefconfig` runs
# on the base config. We use the kernel's scripts/kconfig/merge_config.sh
# when available, otherwise do a simple append+olddefconfig.

MERGE_HOOK="${LIBKRUNFW_DIR}/openshell-kconfig-hook.sh"
cat > "${MERGE_HOOK}" << 'HOOKEOF'
#!/usr/bin/env bash
# Hook called by the libkrunfw build after extracting the kernel source.
# Merges the OpenShell kernel config fragment into .config.
set -euo pipefail

KERNEL_DIR="$1"
FRAGMENT="$2"

if [ ! -d "$KERNEL_DIR" ]; then
    echo "ERROR: kernel source dir not found: $KERNEL_DIR" >&2
    exit 1
fi

if [ ! -f "$FRAGMENT" ]; then
    echo "ERROR: config fragment not found: $FRAGMENT" >&2
    exit 1
fi

cd "$KERNEL_DIR"

if [ -f scripts/kconfig/merge_config.sh ]; then
    echo "  Using kernel merge_config.sh"
    KCONFIG_CONFIG=.config ./scripts/kconfig/merge_config.sh -m .config "$FRAGMENT"
else
    echo "  Appending fragment and running olddefconfig"
    cat "$FRAGMENT" >> .config
fi

make ARCH=arm64 olddefconfig

# Verify critical configs are set
REQUIRED=(
    CONFIG_BRIDGE
    CONFIG_BRIDGE_NETFILTER
    CONFIG_NETFILTER
    CONFIG_NF_CONNTRACK
    CONFIG_NF_NAT
    CONFIG_IP_NF_IPTABLES
    CONFIG_IP_NF_FILTER
    CONFIG_IP_NF_NAT
    CONFIG_VETH
    CONFIG_NET_NS
)

MISSING=()
for cfg in "${REQUIRED[@]}"; do
    if ! grep -q "^${cfg}=[ym]" .config; then
        MISSING+=("$cfg")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "ERROR: Required kernel configs not set after merge:" >&2
    printf "  %s\n" "${MISSING[@]}" >&2
    exit 1
fi

echo "  All required kernel configs verified."
HOOKEOF
chmod +x "${MERGE_HOOK}"

# ── Build libkrunfw ────────────────────────────────────────────────────

echo "==> Building libkrunfw (this may take 10-30 minutes)..."

cd "${LIBKRUNFW_DIR}"

# Detect macOS vs Linux and pick the right library extension / target
if [ "$(uname -s)" = "Darwin" ]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

# Detect the kernel source directory name from the Makefile
KERNEL_DIR_NAME=$(grep -oE 'KERNEL_VERSION\s*=\s*linux-[^\s]+' Makefile | head -1 | sed 's/KERNEL_VERSION *= *//')
if [ -z "$KERNEL_DIR_NAME" ]; then
    echo "ERROR: Could not detect KERNEL_VERSION from Makefile" >&2
    exit 1
fi
echo "  Kernel source dir: ${KERNEL_DIR_NAME}"

if [ "$(uname -s)" = "Darwin" ]; then
    # On macOS, the entire kernel build (extract, patch, config, compile)
    # must happen inside a Linux container since the kernel build system
    # requires a Linux toolchain. We mount the checkout, inject the
    # config fragment, and produce kernel.c inside the container.

    if ! command -v docker &>/dev/null; then
        echo "ERROR: docker is required to build the kernel on macOS" >&2
        exit 1
    fi

    echo "==> Building kernel inside Docker (macOS detected)..."

    # Pre-build a Docker image with all build dependencies so the
    # (potentially emulated) apt-get/pip work is cached across runs.
    BUILDER_IMAGE="libkrunfw-builder:bookworm"
    if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
        echo "  Building Docker toolchain image (first time only)..."
        docker build --platform linux/arm64 -t "${BUILDER_IMAGE}" - <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get update -qq && \
    apt-get install -y -qq make gcc bc flex bison libelf-dev python3 \
        coreutils curl xz-utils patch libssl-dev cpio >/dev/null 2>&1 && \
    rm -rf /var/lib/apt/lists/*
DOCKERFILE
    fi

    # Stage only the files the build needs into a temp dir so we
    # avoid copying the enormous kernel source tree over virtiofs.
    DOCKER_STAGE=$(mktemp -d)
    trap 'rm -rf "${DOCKER_STAGE}"' EXIT

    echo "  Staging build inputs..."
    cp "${LIBKRUNFW_DIR}/Makefile" "${DOCKER_STAGE}/"
    cp "${LIBKRUNFW_DIR}/bin2cbundle.py" "${DOCKER_STAGE}/"
    # Copy base kernel config(s) and patches
    for f in "${LIBKRUNFW_DIR}"/config-libkrunfw*; do
        [ -f "$f" ] && cp "$f" "${DOCKER_STAGE}/"
    done
    if [ -d "${LIBKRUNFW_DIR}/patches" ]; then
        cp -r "${LIBKRUNFW_DIR}/patches" "${DOCKER_STAGE}/patches"
    fi
    if [ -d "${LIBKRUNFW_DIR}/patches-tee" ]; then
        cp -r "${LIBKRUNFW_DIR}/patches-tee" "${DOCKER_STAGE}/patches-tee"
    fi
    # Copy the cached tarball if present so we don't re-download
    if [ -d "${LIBKRUNFW_DIR}/tarballs" ]; then
        cp -r "${LIBKRUNFW_DIR}/tarballs" "${DOCKER_STAGE}/tarballs"
    fi

    docker run --rm \
        -v "${DOCKER_STAGE}:/work" \
        -v "${KERNEL_CONFIG_FRAGMENT}:/fragment/bridge-cni.config:ro" \
        -v "${MERGE_HOOK}:/fragment/merge-hook.sh:ro" \
        -w /build \
        --platform linux/arm64 \
        "${BUILDER_IMAGE}" \
        bash -c '
            set -euo pipefail

            KDIR="'"${KERNEL_DIR_NAME}"'"

            # Copy staged inputs to container-local filesystem so tar
            # extraction does not hit macOS APFS bind-mount limitations.
            echo "  Copying build inputs to container filesystem..."
            cp -r /work/* /build/

            # Patch bin2cbundle.py to make the elftools import lazy.
            # We only use -t Image (raw path) which does not need elftools,
            # but the top-level import would fail without pyelftools installed.
            sed -i "s/^from elftools/# lazy: from elftools/" bin2cbundle.py

            # Step 1: prepare kernel sources (download, extract, patch, base config, olddefconfig)
            echo "  Preparing kernel sources..."
            make "$KDIR"

            # Step 2: merge the OpenShell config fragment
            echo "  Merging OpenShell kernel config fragment..."
            bash /fragment/merge-hook.sh "/build/$KDIR" /fragment/bridge-cni.config

            # Step 3: build the kernel and generate the C bundle
            echo "  Building kernel (this is the slow part)..."
            make -j"$(nproc)" "$KDIR"/arch/arm64/boot/Image

            echo "  Generating kernel.c bundle..."
            python3 bin2cbundle.py -t Image "$KDIR"/arch/arm64/boot/Image kernel.c

            # Copy artifacts back to the bind-mounted staging dir
            echo "  Copying artifacts back to host..."
            cp /build/kernel.c /work/kernel.c
            cp /build/"$KDIR"/.config /work/kernel.config
        '

    # Move artifacts from staging dir to the libkrunfw checkout
    cp "${DOCKER_STAGE}/kernel.c" "${LIBKRUNFW_DIR}/kernel.c"
    if [ -f "${DOCKER_STAGE}/kernel.config" ]; then
        mkdir -p "${LIBKRUNFW_DIR}/${KERNEL_DIR_NAME}"
        cp "${DOCKER_STAGE}/kernel.config" "${LIBKRUNFW_DIR}/${KERNEL_DIR_NAME}/.config"
    fi

    # Compile the shared library on the host (uses host cc for a .dylib)
    echo "==> Compiling libkrunfw.dylib on host..."
    ABI_VERSION=$(grep -oE 'ABI_VERSION\s*=\s*[0-9]+' Makefile | head -1 | sed 's/[^0-9]//g')
    cc -fPIC -DABI_VERSION="${ABI_VERSION}" -shared -o "libkrunfw.${ABI_VERSION}.dylib" kernel.c
else
    # On Linux, we can do everything natively in three steps:

    # Step 1: prepare kernel sources
    echo "  Preparing kernel sources..."
    make "${KERNEL_DIR_NAME}"

    # Step 2: merge config fragment
    echo "==> Merging OpenShell kernel config fragment..."
    bash "${MERGE_HOOK}" "${LIBKRUNFW_DIR}/${KERNEL_DIR_NAME}" "${KERNEL_CONFIG_FRAGMENT}"

    # Step 3: build the kernel and shared library
    make -j"$(nproc)" "$(grep -oE 'KRUNFW_BINARY_Linux\s*=\s*\S+' Makefile | head -1 | sed 's/[^=]*= *//')" || \
    make -j"$(nproc)" libkrunfw.so
fi

# ── Stage output artifacts ──────────────────────────────────────────────

echo "==> Staging artifacts..."
mkdir -p "${OUTPUT_DIR}"

# Find the built library — check versioned names (e.g. libkrunfw.5.dylib) first
BUILT_LIB=""
for candidate in \
    "${LIBKRUNFW_DIR}"/libkrunfw*.${LIB_EXT} \
    "${LIBKRUNFW_DIR}/libkrunfw.${LIB_EXT}" \
    "${LIBKRUNFW_DIR}/target/release/libkrunfw.${LIB_EXT}" \
    "${LIBKRUNFW_DIR}/build/libkrunfw.${LIB_EXT}"; do
    if [ -f "$candidate" ]; then
        BUILT_LIB="$candidate"
        break
    fi
done

if [ -z "$BUILT_LIB" ]; then
    echo "ERROR: Could not find built libkrunfw.${LIB_EXT}" >&2
    echo "  Searched in ${LIBKRUNFW_DIR}/ for libkrunfw*.${LIB_EXT}"
    exit 1
fi

echo "  Found library: ${BUILT_LIB}"

# Compute SHA-256 (shasum on macOS, sha256sum on Linux)
if command -v sha256sum &>/dev/null; then
    ARTIFACT_HASH=$(sha256sum "${BUILT_LIB}" | cut -d' ' -f1)
else
    ARTIFACT_HASH=$(shasum -a 256 "${BUILT_LIB}" | cut -d' ' -f1)
fi
ARTIFACT_HASH_SHORT="${ARTIFACT_HASH:0:12}"

# Copy the library — always stage as libkrunfw.dylib / libkrunfw.so
# (the base name the runtime loader expects) plus the original name
cp "${BUILT_LIB}" "${OUTPUT_DIR}/libkrunfw.${LIB_EXT}"
BUILT_BASENAME="$(basename "${BUILT_LIB}")"
if [ "${BUILT_BASENAME}" != "libkrunfw.${LIB_EXT}" ]; then
    cp "${BUILT_LIB}" "${OUTPUT_DIR}/${BUILT_BASENAME}"
fi

# Copy the kernel config that was actually used (for reproducibility)
KERNEL_SRC_DIR=""
for candidate in \
    "${LIBKRUNFW_DIR}/linux-"* \
    "${LIBKRUNFW_DIR}/build/linux-"* \
    "${LIBKRUNFW_DIR}/kernel/linux-"*; do
    if [ -d "$candidate" ] && [ -f "${candidate}/.config" ]; then
        KERNEL_SRC_DIR="$candidate"
        break
    fi
done

if [ -n "$KERNEL_SRC_DIR" ] && [ -f "${KERNEL_SRC_DIR}/.config" ]; then
    cp "${KERNEL_SRC_DIR}/.config" "${OUTPUT_DIR}/kernel.config"
fi

# Copy our fragment for reference
cp "${KERNEL_CONFIG_FRAGMENT}" "${OUTPUT_DIR}/bridge-cni.config"

# ── Write provenance metadata ──────────────────────────────────────────

cat > "${OUTPUT_DIR}/provenance.json" << EOF
{
  "artifact": "libkrunfw-custom",
  "version": "0.1.0-openshell",
  "build_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "libkrunfw_repo": "${LIBKRUNFW_REPO}",
  "libkrunfw_ref": "${LIBKRUNFW_REF}",
  "libkrunfw_commit": "${LIBKRUNFW_COMMIT}",
  "kernel_version": "${KERNEL_VERSION:-unknown}",
  "kernel_config_fragment": "bridge-cni.config",
  "artifact_sha256": "${ARTIFACT_HASH}",
  "host_os": "$(uname -s)",
  "host_arch": "$(uname -m)",
  "builder": "build-custom-libkrunfw.sh"
}
EOF

echo ""
echo "==> Build complete"
echo "    Library:    ${OUTPUT_DIR}/libkrunfw.${LIB_EXT}"
echo "    SHA256:     ${ARTIFACT_HASH_SHORT}..."
echo "    Provenance: ${OUTPUT_DIR}/provenance.json"
echo "    Commit:     ${LIBKRUNFW_SHORT}"
echo ""
echo "To use this runtime:"
echo "  export OPENSHELL_VM_RUNTIME_SOURCE_DIR=${OUTPUT_DIR}"
echo "  mise run vm:bundle-runtime"
