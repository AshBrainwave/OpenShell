#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# setup-protected-egress-vf.sh
#
# One-shot host-side setup for the openshell-vm protected-egress path.
# Creates one SR-IOV VF on the BlueField-3 PF, verifies that the DPU-side
# representor (pf0vf0) appears in OVS bridge ovsbr1, then launches vf-bridge
# to relay frames between the VF and the UNIX stream socket that libkrun uses
# for the guest eth1 virtio-net device.
#
# Usage:
#   sudo ./deploy/setup-protected-egress-vf.sh [OPTIONS]
#
# Options:
#   --pf <dev>       Host PF netdev for the BF3 (default: enp179s0f0np0)
#   --pci <addr>     PCI address of the BF3 PF (default: 0000:b3:00.0)
#   --socket <path>  UNIX stream socket path for vf-bridge (default: /run/openshell/vf-bridge/eth1.sock)
#   --skip-vf        Skip VF creation (VF already exists)
#   --help           Show this help
#
# Prerequisites:
#   - SR-IOV enabled in BIOS and kernel (iommu=pt intel_iommu=on)
#   - vfio, vfio_pci modules loaded
#   - DPU in switchdev mode with pf0vf0 wired into ovsbr1 (verify via rshim SSH)
#   - vf-bridge binary in PATH or at /usr/local/bin/vf-bridge
#
# DPU verification (run via rshim SSH: ssh ubuntu@192.168.100.2):
#   sudo ovs-vsctl show          # pf0vf0 should be in ovsbr1
#   sudo ovs-ofctl dump-flows ovsbr1   # check for drop/allow rules on pf0vf0
#
# Example:
#   sudo ./deploy/setup-protected-egress-vf.sh
#   openshell-vm --protected-egress-socket /run/openshell/vf-bridge/eth1.sock

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────
PF_DEV="${PF_DEV:-enp179s0f0np0}"
PF_PCI="${PF_PCI:-0000:b3:00.0}"
SOCKET_PATH="${SOCKET_PATH:-/run/openshell/vf-bridge/eth1.sock}"
SKIP_VF=false
VF_BRIDGE_BIN="${VF_BRIDGE_BIN:-$(command -v vf-bridge 2>/dev/null || echo /usr/local/bin/vf-bridge)}"

# ── Argument parsing ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pf)      PF_DEV="$2";      shift 2 ;;
        --pci)     PF_PCI="$2";      shift 2 ;;
        --socket)  SOCKET_PATH="$2"; shift 2 ;;
        --skip-vf) SKIP_VF=true;     shift ;;
        --help)
            sed -n '/^# Usage:/,/^[^#]/{ /^[^#]/d; s/^# \?//; p }' "$0"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────────
log() { echo "[$(date +%T)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ── Prerequisite checks ────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "must run as root (sudo)"

for mod in vfio vfio_pci; do
    lsmod | grep -q "^$mod " || die "kernel module '$mod' not loaded — run: modprobe $mod"
done

[[ -e "/sys/bus/pci/devices/$PF_PCI" ]] \
    || die "PCI device $PF_PCI not found — check --pci"

ip link show "$PF_DEV" >/dev/null 2>&1 \
    || die "netdev $PF_DEV not found — check --pf"

[[ -x "$VF_BRIDGE_BIN" ]] \
    || die "vf-bridge not found at $VF_BRIDGE_BIN — build or install it first"

# ── Step 1: Create the VF ──────────────────────────────────────────────────
SRIOV_FILE="/sys/bus/pci/devices/$PF_PCI/sriov_numvfs"

if $SKIP_VF; then
    log "Skipping VF creation (--skip-vf)"
else
    CURRENT_VFS=$(cat "$SRIOV_FILE" 2>/dev/null || echo 0)
    if [[ "$CURRENT_VFS" -ge 1 ]]; then
        log "VF already exists (sriov_numvfs=$CURRENT_VFS) — skipping creation"
    else
        log "Creating 1 VF on $PF_PCI ($PF_DEV)..."
        echo 1 > "$SRIOV_FILE"
        # Give the kernel a moment to enumerate the VF
        sleep 1
    fi
fi

# Discover the VF netdev (enp179s0f0v0 or similar)
VF_DEV=$(ip link show | awk -F': ' '/enp.*v0/{print $2; exit}' | tr -d ' ')
[[ -n "$VF_DEV" ]] || die "VF netdev not found after creation — check dmesg"
log "VF netdev: $VF_DEV"

# ── Step 2: Verify the DPU representor hint ────────────────────────────────
# We can't reach OVS directly from the host; just log a reminder.
log "NOTE: Verify DPU side via rshim SSH (ssh ubuntu@192.168.100.2):"
log "  sudo ovs-vsctl show        # pf0vf0 should be in ovsbr1"
log "  sudo ovs-ofctl dump-flows ovsbr1  # check drop/allow rules"

# ── Step 3: Prepare the socket directory ──────────────────────────────────
SOCKET_DIR=$(dirname "$SOCKET_PATH")
mkdir -p "$SOCKET_DIR"
# Remove stale socket if present from a previous run
[[ -S "$SOCKET_PATH" ]] && rm -f "$SOCKET_PATH"

# ── Step 4: Launch vf-bridge ───────────────────────────────────────────────
log "Launching vf-bridge: $VF_DEV → $SOCKET_PATH"
log "  vf-bridge provides a UNIX stream socket for libkrun krun_add_net_unixstream"
log "  Connect openshell-vm with: --protected-egress-socket $SOCKET_PATH"

exec "$VF_BRIDGE_BIN" \
    --netdev "$VF_DEV" \
    --socket "$SOCKET_PATH"
