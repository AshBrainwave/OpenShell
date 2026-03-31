#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build libkrun and libkrunfw from source on Linux.
#
# This script builds libkrun (VMM) and libkrunfw (kernel firmware) from source
# with OpenShell's custom kernel configuration for bridge/netfilter support.
#
# Prerequisites:
#   - Linux (aarch64 or x86_64)
#   - Build tools: make, git, gcc, flex, bison, bc
#   - Python 3 with pyelftools
#   - Rust toolchain
#
# Usage:
#   ./build-libkrun.sh
#
# The script will install missing dependencies on Debian/Ubuntu and Fedora.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT}/target/libkrun-build"
OUTPUT_DIR="${BUILD_DIR}"
KERNEL_CONFIG="${ROOT}/crates/openshell-vm/runtime/kernel/openshell.kconfig"

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: This script only runs on Linux" >&2
  exit 1
fi

ARCH="$(uname -m)"
echo "==> Building libkrun for Linux ${ARCH}"
echo "    Build directory: ${BUILD_DIR}"
echo "    Kernel config: ${KERNEL_CONFIG}"
echo ""

# ── Install dependencies ────────────────────────────────────────────────

install_deps() {
  echo "==> Checking/installing build dependencies..."
  
  if command -v apt-get &>/dev/null; then
    # Debian/Ubuntu
    DEPS="build-essential git python3 python3-pyelftools flex bison libelf-dev libssl-dev bc curl"
    MISSING=""
    for dep in $DEPS; do
      if ! dpkg -s "$dep" &>/dev/null; then
        MISSING="$MISSING $dep"
      fi
    done
    if [ -n "$MISSING" ]; then
      echo "    Installing:$MISSING"
      sudo apt-get update
      sudo apt-get install -y $MISSING
    else
      echo "    All dependencies installed"
    fi
    
  elif command -v dnf &>/dev/null; then
    # Fedora/RHEL
    DEPS="make git python3 python3-pyelftools gcc flex bison elfutils-libelf-devel openssl-devel bc glibc-static curl"
    echo "    Installing dependencies via dnf..."
    sudo dnf install -y $DEPS
    
  else
    echo "Warning: Unknown package manager. Please install manually:" >&2
    echo "  build-essential git python3 python3-pyelftools flex bison" >&2
    echo "  libelf-dev libssl-dev bc curl" >&2
  fi
}

install_deps

# ── Setup build directory ───────────────────────────────────────────────

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Build libkrunfw (kernel firmware) ───────────────────────────────────

echo ""
echo "==> Building libkrunfw with custom kernel config..."

if [ ! -d libkrunfw ]; then
  echo "    Cloning libkrunfw..."
  git clone --depth 1 https://github.com/containers/libkrunfw.git
fi

cd libkrunfw

# Copy custom kernel config
if [ -f "$KERNEL_CONFIG" ]; then
  cp "$KERNEL_CONFIG" openshell.kconfig
  echo "    Applied custom kernel config: openshell.kconfig"
else
  echo "Warning: Custom kernel config not found at ${KERNEL_CONFIG}" >&2
  echo "    Building with default config (k3s networking may not work)" >&2
fi

# Build libkrunfw
echo "    Building kernel and libkrunfw (this may take 15-20 minutes)..."
if [ -f openshell.kconfig ]; then
  make KCONFIG_FRAGMENT=openshell.kconfig -j"$(nproc)"
else
  make -j"$(nproc)"
fi

# Copy output
cp libkrunfw.so* "$OUTPUT_DIR/"
echo "    Built: $(ls "$OUTPUT_DIR"/libkrunfw.so* | xargs -n1 basename | tr '\n' ' ')"

cd "$BUILD_DIR"

# ── Build libkrun (VMM) ─────────────────────────────────────────────────

echo ""
echo "==> Building libkrun..."

if [ ! -d libkrun ]; then
  echo "    Cloning libkrun..."
  git clone --depth 1 https://github.com/containers/libkrun.git
fi

cd libkrun

# Build with NET support for gvproxy networking
echo "    Building libkrun with NET=1..."
make NET=1 -j"$(nproc)"

# Copy output
cp target/release/libkrun.so "$OUTPUT_DIR/"
echo "    Built: libkrun.so"

cd "$BUILD_DIR"

# ── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "==> Build complete!"
echo "    Output directory: ${OUTPUT_DIR}"
echo ""
echo "    Artifacts:"
ls -lah "$OUTPUT_DIR"/*.so*

echo ""
echo "Next step: mise run vm:runtime:compress"
