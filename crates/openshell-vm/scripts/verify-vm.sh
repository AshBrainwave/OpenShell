#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# VM Verification Matrix
#
# Runs a comprehensive set of checks against a running gateway VM to
# validate networking, service reachability, and overall health.
#
# This script is designed to run both locally and in CI as a pass/fail
# gate for merge readiness.
#
# Usage:
#   ./verify-vm.sh [--kubeconfig PATH] [--timeout SECS]
#
# Prerequisites:
#   - A running gateway VM (`mise run vm`)
#   - kubectl available in PATH
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed
#   2 = script error / prerequisites not met

set -euo pipefail

KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/gateway.yaml}"
TIMEOUT="${TIMEOUT:-120}"
PASS=0
FAIL=0
WARN=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kubeconfig) KUBECONFIG="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--kubeconfig PATH] [--timeout SECS]"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

export KUBECONFIG

# ── Helpers ─────────────────────────────────────────────────────────────

check() {
    local name="$1"
    local category="$2"
    shift 2
    local cmd=("$@")

    printf "  %-50s " "$name"
    if output=$(eval "${cmd[@]}" 2>&1); then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        if [ -n "$output" ]; then
            echo "    $output" | head -3
        fi
        FAIL=$((FAIL + 1))
    fi
}

wait_for_api() {
    local deadline=$((SECONDS + TIMEOUT))
    while [ $SECONDS -lt $deadline ]; do
        if kubectl get nodes -o name >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    return 1
}

echo "VM Verification Matrix"
echo "======================"
echo ""
echo "Kubeconfig: ${KUBECONFIG}"
echo "Timeout:    ${TIMEOUT}s"
echo ""

# ── Prerequisites ──────────────────────────────────────────────────────

if [ ! -f "$KUBECONFIG" ]; then
    echo "ERROR: Kubeconfig not found at ${KUBECONFIG}"
    echo "Is the gateway VM running? Start with: mise run vm"
    exit 2
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: kubectl not found in PATH"
    exit 2
fi

echo "[Waiting for API server...]"
if ! wait_for_api; then
    echo "ERROR: API server not reachable after ${TIMEOUT}s"
    exit 2
fi
echo ""

# ── Node Health ────────────────────────────────────────────────────────

echo "[Node Health]"

check "node exists" "node" \
    "kubectl get nodes -o name | grep -q 'node/'"

check "node is Ready" "node" \
    "kubectl get nodes -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

echo ""

# ── System Pods ────────────────────────────────────────────────────────

echo "[System Pods]"

check "kube-system pods running" "pods" \
    "kubectl -n kube-system get pods -o jsonpath='{.items[*].status.phase}' | grep -qv Pending"

check "no FailedCreatePodSandBox events" "pods" \
    "! kubectl get events -A --field-selector reason=FailedCreatePodSandBox -o name 2>/dev/null | grep -q ."

check "no CrashLoopBackOff pods" "pods" \
    "! kubectl get pods -A -o jsonpath='{.items[*].status.containerStatuses[*].state.waiting.reason}' 2>/dev/null | grep -q CrashLoopBackOff"

echo ""

# ── OpenShell Namespace ────────────────────────────────────────────────

echo "[OpenShell Namespace]"

check "openshell namespace exists" "openshell" \
    "kubectl get namespace openshell -o name"

check "openshell-0 pod exists" "openshell" \
    "kubectl -n openshell get pod openshell-0 -o name"

check "openshell-0 pod is Ready" "openshell" \
    "kubectl -n openshell get pod openshell-0 -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

echo ""

# ── Networking ─────────────────────────────────────────────────────────

echo "[Networking]"

check "services exist" "networking" \
    "kubectl get svc -A -o name | grep -q ."

check "kubernetes service has ClusterIP" "networking" \
    "kubectl get svc kubernetes -o jsonpath='{.spec.clusterIP}' | grep -q ."

# Check if bridge CNI is in use (cni0 bridge exists)
CNI_PROFILE="unknown"
if kubectl exec -n openshell openshell-0 -- ip link show cni0 >/dev/null 2>&1; then
    CNI_PROFILE="bridge"
else
    CNI_PROFILE="legacy-vm-net"
fi
echo "  CNI profile detected: ${CNI_PROFILE}"

if [ "$CNI_PROFILE" = "bridge" ]; then
    check "cni0 bridge exists in pod" "networking" \
        "kubectl exec -n openshell openshell-0 -- ip link show cni0 2>/dev/null"

    # With bridge CNI, kubernetes.default.svc should be reachable.
    check "kubernetes.default.svc reachable from pod" "networking" \
        "kubectl exec -n openshell openshell-0 -- wget -q -O /dev/null --timeout=5 https://kubernetes.default.svc/healthz 2>/dev/null || kubectl exec -n openshell openshell-0 -- curl -sk --connect-timeout 5 https://kubernetes.default.svc/healthz 2>/dev/null"
else
    echo "  (skipping bridge-specific checks for legacy-vm-net profile)"
fi

check "no bridge creation errors in events" "networking" \
    "! kubectl get events -A 2>/dev/null | grep -qi 'bridge.*fail\\|cni0.*error\\|FailedCreatePodSandBox.*bridge'"

echo ""

# ── Host Port Connectivity ─────────────────────────────────────────────

echo "[Host Connectivity]"

check "port 6443 (kube-apiserver) reachable" "host" \
    "timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/6443' 2>/dev/null || nc -z -w5 127.0.0.1 6443 2>/dev/null"

check "port 30051 (gateway service) reachable" "host" \
    "timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/30051' 2>/dev/null || nc -z -w5 127.0.0.1 30051 2>/dev/null"

echo ""

# ── Event / Log Checks ────────────────────────────────────────────────

echo "[Events / Logs]"

check "no repeated bind/listen conflicts" "events" \
    "! kubectl get events -A 2>/dev/null | grep -ci 'bind.*address already in use\\|listen.*address already in use' | grep -qv '^0$'"

check "no hostNetwork fallback warnings" "events" \
    "! kubectl get events -A 2>/dev/null | grep -ci 'hostNetwork.*fallback' | grep -qv '^0$'"

echo ""

# ── Summary ────────────────────────────────────────────────────────────

echo "─────────────────────────────────────────────────────"
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
echo "CNI Profile: ${CNI_PROFILE}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: ${FAIL} check(s) failed."
    echo ""
    echo "Debugging:"
    echo "  kubectl get nodes,pods -A"
    echo "  kubectl get events -A --sort-by=.lastTimestamp"
    echo "  cat ~/.local/share/openshell/gateway/console.log"
    exit 1
else
    echo "PASS: All checks passed."
    exit 0
fi
