#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Gather VM runtime artifacts from local sources and compress for embedding.
#
# This script collects libkrun, libkrunfw, and gvproxy from local sources
# (Homebrew on macOS, built from source on Linux) and compresses them with
# zstd for embedding into the openshell-vm binary.
#
# Usage:
#   ./compress-vm-runtime.sh
#
# Environment:
#   OPENSHELL_VM_RUNTIME_COMPRESSED_DIR - Output directory (default: target/vm-runtime-compressed)
#
# The script sets OPENSHELL_VM_RUNTIME_COMPRESSED_DIR for use by build.rs.

set -euo pipefail

# Use git to find the project root reliably
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── macOS dylib portability helpers ─────────────────────────────────────

# Make a dylib portable by rewriting paths to use @loader_path
make_dylib_portable() {
    local dylib="$1"
    local dylib_name
    dylib_name="$(basename "$dylib")"
    
    # Rewrite install name
    install_name_tool -id "@loader_path/${dylib_name}" "$dylib" 2>/dev/null || true
    
    # Rewrite libkrunfw reference if present
    local krunfw_path
    krunfw_path=$(otool -L "$dylib" 2>/dev/null | grep libkrunfw | awk '{print $1}' || true)
    if [ -n "$krunfw_path" ] && [[ "$krunfw_path" != @* ]]; then
        install_name_tool -change "$krunfw_path" "@loader_path/libkrunfw.dylib" "$dylib"
    fi
    
    # Re-codesign
    codesign -f -s - "$dylib" 2>/dev/null || true
}

# Bundle GPU dependencies (libepoxy, virglrenderer, MoltenVK) for Homebrew libkrun
bundle_gpu_dependencies() {
    local work_dir="$1"
    local brew_prefix
    brew_prefix="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
    
    # Dependencies to bundle
    local deps=(
        "${brew_prefix}/opt/libepoxy/lib/libepoxy.0.dylib"
        "${brew_prefix}/opt/virglrenderer/lib/libvirglrenderer.1.dylib"
        "${brew_prefix}/opt/molten-vk/lib/libMoltenVK.dylib"
    )
    
    for dep in "${deps[@]}"; do
        if [ -f "$dep" ]; then
            local dep_name
            dep_name="$(basename "$dep")"
            cp "$dep" "${work_dir}/${dep_name}"
            echo "      Copied: ${dep_name}"
        fi
    done
    
    # Rewrite all paths to use @loader_path
    for dylib in "${work_dir}"/*.dylib; do
        [ -f "$dylib" ] || continue
        
        # Rewrite install name
        local dylib_name
        dylib_name="$(basename "$dylib")"
        install_name_tool -id "@loader_path/${dylib_name}" "$dylib" 2>/dev/null || true
        
        # Rewrite all Homebrew references to @loader_path
        for dep in "${deps[@]}"; do
            local dep_name
            dep_name="$(basename "$dep")"
            install_name_tool -change "$dep" "@loader_path/${dep_name}" "$dylib" 2>/dev/null || true
        done
        
        # Also rewrite libkrunfw
        local krunfw_path
        krunfw_path=$(otool -L "$dylib" 2>/dev/null | grep libkrunfw | awk '{print $1}' || true)
        if [ -n "$krunfw_path" ] && [[ "$krunfw_path" != @* ]]; then
            install_name_tool -change "$krunfw_path" "@loader_path/libkrunfw.dylib" "$dylib"
        fi
        
        # Re-codesign
        codesign -f -s - "$dylib" 2>/dev/null || true
    done
    
    echo "      All dependencies rewritten to use @loader_path"
}
WORK_DIR="${ROOT}/target/vm-runtime"
OUTPUT_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${ROOT}/target/vm-runtime-compressed}"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

echo "==> Detecting platform..."

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    PLATFORM="darwin-aarch64"
    echo "    Platform: macOS ARM64"
    
    # Source priority for libkrun:
    # 1. Custom build from build-libkrun-macos.sh (portable, no GPU deps)
    # 2. Custom runtime with custom libkrunfw
    # 3. Homebrew (has GPU deps, not portable)
    LIBKRUN_BUILD_DIR="${ROOT}/target/libkrun-build"
    CUSTOM_DIR="${ROOT}/target/custom-runtime"
    BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
    
    if [ -f "${LIBKRUN_BUILD_DIR}/libkrun.dylib" ]; then
      echo "    Using portable libkrun from ${LIBKRUN_BUILD_DIR}"
      cp "${LIBKRUN_BUILD_DIR}/libkrun.dylib" "$WORK_DIR/"
      cp "${LIBKRUN_BUILD_DIR}/libkrunfw.dylib" "$WORK_DIR/"
      
      # Verify portability
      if otool -L "${LIBKRUN_BUILD_DIR}/libkrun.dylib" | grep -q "/opt/homebrew"; then
        echo "    Warning: libkrun has hardcoded Homebrew paths - may not be portable"
      else
        echo "    ✓ libkrun is portable (no hardcoded paths)"
      fi
    elif [ -f "${CUSTOM_DIR}/provenance.json" ]; then
      echo "    Using custom runtime from ${CUSTOM_DIR}"
      
      # libkrun from Homebrew (needs path rewriting for portability)
      if [ -f "${CUSTOM_DIR}/libkrun.dylib" ]; then
        cp "${CUSTOM_DIR}/libkrun.dylib" "$WORK_DIR/"
      else
        cp "${BREW_PREFIX}/lib/libkrun.dylib" "$WORK_DIR/"
        make_dylib_portable "$WORK_DIR/libkrun.dylib"
      fi
      
      # libkrunfw from custom build
      cp "${CUSTOM_DIR}/libkrunfw.dylib" "$WORK_DIR/"
    else
      echo "    Using Homebrew runtime from ${BREW_PREFIX}/lib"
      echo "    Warning: Homebrew libkrun has GPU dependencies (libepoxy, virglrenderer)"
      echo "             For a portable build, run: mise run vm:runtime:build-libkrun-macos"
      
      cp "${BREW_PREFIX}/lib/libkrun.dylib" "$WORK_DIR/"
      
      # Copy libkrunfw
      for krunfw in "${BREW_PREFIX}/lib"/libkrunfw*.dylib; do
        [ -f "$krunfw" ] || continue
        if [ -L "$krunfw" ]; then
          target=$(readlink "$krunfw")
          if [[ "$target" != /* ]]; then
            target="${BREW_PREFIX}/lib/${target}"
          fi
          cp "$target" "$WORK_DIR/$(basename "$krunfw")"
        else
          cp "$krunfw" "$WORK_DIR/"
        fi
      done
      
      # If using Homebrew libkrun with GPU, we need to bundle the GPU dependencies
      # for portability. Check if libkrun has GPU deps:
      if otool -L "$WORK_DIR/libkrun.dylib" | grep -q "libepoxy\|virglrenderer"; then
        echo "    Bundling GPU dependencies for portability..."
        bundle_gpu_dependencies "$WORK_DIR"
      fi
    fi
    
    # Normalize libkrunfw naming - ensure we have libkrunfw.dylib
    if [ ! -f "$WORK_DIR/libkrunfw.dylib" ] && [ -f "$WORK_DIR/libkrunfw.5.dylib" ]; then
      cp "$WORK_DIR/libkrunfw.5.dylib" "$WORK_DIR/libkrunfw.dylib"
    fi
    
    # gvproxy - prefer Podman, fall back to Homebrew
    if [ -x /opt/podman/bin/gvproxy ]; then
      cp /opt/podman/bin/gvproxy "$WORK_DIR/"
      echo "    Using gvproxy from Podman"
    elif [ -x "$(brew --prefix 2>/dev/null)/bin/gvproxy" ]; then
      cp "$(brew --prefix)/bin/gvproxy" "$WORK_DIR/"
      echo "    Using gvproxy from Homebrew"
    else
      echo "Error: gvproxy not found. Install Podman Desktop or run: brew install gvproxy" >&2
      exit 1
    fi
    ;;
    
  Linux-aarch64)
    PLATFORM="linux-aarch64"
    echo "    Platform: Linux ARM64"
    
    BUILD_DIR="${ROOT}/target/libkrun-build"
    if [ ! -f "${BUILD_DIR}/libkrun.so" ]; then
      echo "Error: libkrun not found. Run: mise run vm:runtime:build-libkrun" >&2
      exit 1
    fi
    
    cp "${BUILD_DIR}/libkrun.so" "$WORK_DIR/"
    
    # Copy libkrunfw - find the versioned .so file
    for krunfw in "${BUILD_DIR}"/libkrunfw.so*; do
      [ -f "$krunfw" ] || continue
      cp "$krunfw" "$WORK_DIR/"
    done
    
    # Ensure the soname symlink (libkrunfw.so.5) exists alongside the fully
    # versioned file (libkrunfw.so.5.x.y). libloading loads by soname.
    if [ ! -f "$WORK_DIR/libkrunfw.so.5" ]; then
      versioned=$(ls "$WORK_DIR"/libkrunfw.so.5.* 2>/dev/null | head -n1)
      if [ -n "$versioned" ]; then
        cp "$versioned" "$WORK_DIR/libkrunfw.so.5"
      fi
    fi

    # Download gvproxy if not present
    if [ ! -f "$WORK_DIR/gvproxy" ]; then
      echo "    Downloading gvproxy for linux-arm64..."
      curl -fsSL -o "$WORK_DIR/gvproxy" \
        "https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.8/gvproxy-linux-arm64"
      chmod +x "$WORK_DIR/gvproxy"
    fi
    ;;
    
  Linux-x86_64)
    PLATFORM="linux-x86_64"
    echo "    Platform: Linux x86_64"
    
    BUILD_DIR="${ROOT}/target/libkrun-build"
    if [ ! -f "${BUILD_DIR}/libkrun.so" ]; then
      echo "Error: libkrun not found. Run: mise run vm:runtime:build-libkrun" >&2
      exit 1
    fi
    
    cp "${BUILD_DIR}/libkrun.so" "$WORK_DIR/"
    
    # Copy libkrunfw
    for krunfw in "${BUILD_DIR}"/libkrunfw.so*; do
      [ -f "$krunfw" ] || continue
      cp "$krunfw" "$WORK_DIR/"
    done
    
    # Ensure the soname symlink (libkrunfw.so.5) exists alongside the fully
    # versioned file (libkrunfw.so.5.x.y). libloading loads by soname.
    if [ ! -f "$WORK_DIR/libkrunfw.so.5" ]; then
      versioned=$(ls "$WORK_DIR"/libkrunfw.so.5.* 2>/dev/null | head -n1)
      if [ -n "$versioned" ]; then
        cp "$versioned" "$WORK_DIR/libkrunfw.so.5"
      fi
    fi

    # Download gvproxy if not present
    if [ ! -f "$WORK_DIR/gvproxy" ]; then
      echo "    Downloading gvproxy for linux-amd64..."
      curl -fsSL -o "$WORK_DIR/gvproxy" \
        "https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.8/gvproxy-linux-amd64"
      chmod +x "$WORK_DIR/gvproxy"
    fi
    ;;
    
  *)
    echo "Error: Unsupported platform: $(uname -s)-$(uname -m)" >&2
    echo "Supported platforms: Darwin-arm64, Linux-aarch64, Linux-x86_64" >&2
    exit 1
    ;;
esac

echo ""
echo "==> Collected artifacts:"
ls -lah "$WORK_DIR"

echo ""
echo "==> Compressing with zstd (level 19)..."

for file in "$WORK_DIR"/*; do
  [ -f "$file" ] || continue
  name=$(basename "$file")
  original_size=$(du -h "$file" | cut -f1)
  zstd -19 -f -q -o "${OUTPUT_DIR}/${name}.zst" "$file"
  # Ensure compressed file is readable/writable (source may be read-only)
  chmod 644 "${OUTPUT_DIR}/${name}.zst"
  compressed_size=$(du -h "${OUTPUT_DIR}/${name}.zst" | cut -f1)
  echo "    ${name}: ${original_size} -> ${compressed_size}"
done

# Check for rootfs tarball (built separately by build-rootfs-tarball.sh)
ROOTFS_TARBALL="${OUTPUT_DIR}/rootfs.tar.zst"
if [ -f "$ROOTFS_TARBALL" ]; then
    echo "    rootfs.tar.zst: $(du -h "$ROOTFS_TARBALL" | cut -f1) (pre-built)"
else
    echo ""
    echo "Note: rootfs.tar.zst not found."
    echo "      For full embedded build, run: mise run vm:build:rootfs-tarball"
    echo "      For quick build (without rootfs), the binary will still work but"
    echo "      require the rootfs to be built separately on first run."
fi

echo ""
echo "==> Compressed artifacts in ${OUTPUT_DIR}:"
ls -lah "$OUTPUT_DIR"

TOTAL=$(du -sh "$OUTPUT_DIR" | cut -f1)
echo ""
echo "==> Total compressed size: ${TOTAL}"
echo ""
echo "Set this environment variable for cargo build:"
echo "  export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR=${OUTPUT_DIR}"
