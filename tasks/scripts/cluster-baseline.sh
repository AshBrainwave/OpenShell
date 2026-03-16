#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -uo pipefail

MODE="both"
WITH_DEPLOY=0
OUTPUT_DIR="${PERF_OUTPUT_DIR:-.cache/perf}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
FAILURES=0
CARGO_BUILD_PROFILE="${OPENSHELL_CARGO_PROFILE:-local-fast}"

usage() {
  cat <<'EOF'
Usage: tasks/scripts/cluster-baseline.sh [options]

Capture local baseline timings for:
  - CLI compile (cargo build -p openshell-cli)
  - Gateway image build
  - Supervisor-only build stage
  - Cluster image build
  - Optional cluster deploy

Options:
  --mode <cold|warm|both>  Which measurement passes to run (default: both)
  --with-deploy            Include `mise run --skip-deps cluster`
  --output-dir <path>      Output directory for CSV/markdown (default: .cache/perf)
  -h, --help               Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --with-deploy)
      WITH_DEPLOY=1
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "${MODE}" != "cold" && "${MODE}" != "warm" && "${MODE}" != "both" ]]; then
  echo "Invalid --mode value: ${MODE}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

CSV_FILE="${OUTPUT_DIR}/cluster-baseline-${RUN_ID}.csv"
SUMMARY_FILE="${OUTPUT_DIR}/cluster-baseline-${RUN_ID}.md"
echo "run,category,step,status,duration_s" > "${CSV_FILE}"

normalize_arch() {
  case "$1" in
    x86_64) echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

record_result() {
  local run_label=$1
  local category=$2
  local step=$3
  local status=$4
  local duration_s=$5

  echo "${run_label},${category},${step},${status},${duration_s}" >> "${CSV_FILE}"
}

run_step() {
  local run_label=$1
  local category=$2
  local step=$3
  local command=$4
  shift 4

  local start_s end_s duration_s status
  start_s=$(date +%s)

  echo ""
  echo "[${run_label}] ${category}/${step}"
  echo "  ${command}"

  if env "$@" bash -lc "${command}"; then
    status="ok"
  else
    status="fail"
    FAILURES=$((FAILURES + 1))
  fi

  end_s=$(date +%s)
  duration_s=$((end_s - start_s))
  record_result "${run_label}" "${category}" "${step}" "${status}" "${duration_s}"
}

run_pass() {
  local run_label=$1
  local scope_seed=$2

  local cli_target_dir gateway_cache_dir cluster_cache_dir supervisor_output_dir
  local image_tag docker_arch
  local supervisor_version_arg supervisor_profile_arg cargo_version

  cli_target_dir=".cache/perf/target-${scope_seed}"
  gateway_cache_dir=".cache/perf/buildkit-gateway-${scope_seed}"
  cluster_cache_dir=".cache/perf/buildkit-cluster-${scope_seed}"
  supervisor_output_dir="${OUTPUT_DIR}/supervisor-${scope_seed}"
  image_tag="perf-${scope_seed}"
  docker_arch="$(normalize_arch "$(docker version --format '{{.Server.Arch}}')")"
  supervisor_version_arg=""
  supervisor_profile_arg=" --build-arg OPENSHELL_CARGO_PROFILE=${CARGO_BUILD_PROFILE}"
  cargo_version=$(uv run python tasks/scripts/release.py get-version --cargo 2>/dev/null || true)
  if [[ -n "${cargo_version}" ]]; then
    supervisor_version_arg=" --build-arg OPENSHELL_CARGO_VERSION=${cargo_version}"
  fi

  if [[ "${run_label}" == "cold" ]]; then
    rm -rf "${cli_target_dir}" "${gateway_cache_dir}" "${cluster_cache_dir}" "${supervisor_output_dir}"
  fi

  run_step "${run_label}" "rust" "cli_debug" \
    "cargo build -p openshell-cli" \
    "CARGO_TARGET_DIR=${cli_target_dir}"

  run_step "${run_label}" "docker" "gateway_image" \
    "tasks/scripts/docker-build-component.sh gateway" \
    "RUST_TOOLCHAIN_SCOPE=${scope_seed}" \
    "DOCKER_BUILD_CACHE_DIR=${gateway_cache_dir}" \
    "OPENSHELL_CARGO_PROFILE=${CARGO_BUILD_PROFILE}" \
    "IMAGE_TAG=${image_tag}"

  run_step "${run_label}" "docker" "supervisor_stage" \
    "docker buildx build --file deploy/docker/Dockerfile.cluster --target supervisor-export --build-arg BUILDARCH=${docker_arch} --build-arg TARGETARCH=${docker_arch} --build-arg CARGO_TARGET_CACHE_SCOPE=${scope_seed}${supervisor_profile_arg}${supervisor_version_arg} --output type=local,dest=${supervisor_output_dir} --platform linux/${docker_arch} ." \
    "DOCKER_BUILD_CACHE_DIR=${cluster_cache_dir}" \
    "IMAGE_TAG=${image_tag}"

  run_step "${run_label}" "docker" "cluster_image" \
    "tasks/scripts/docker-build-cluster.sh" \
    "DOCKER_BUILD_CACHE_DIR=${cluster_cache_dir}" \
    "OPENSHELL_CARGO_PROFILE=${CARGO_BUILD_PROFILE}" \
    "IMAGE_TAG=${image_tag}"

  if [[ "${WITH_DEPLOY}" == "1" ]]; then
    run_step "${run_label}" "deploy" "cluster_task" \
      "mise run --skip-deps cluster" \
      "OPENSHELL_CARGO_PROFILE=${CARGO_BUILD_PROFILE}"
  fi
}

SCOPE_SEED="baseline-${RUN_ID}"

case "${MODE}" in
  cold)
    run_pass "cold" "${SCOPE_SEED}"
    ;;
  warm)
    run_pass "warm" "baseline-warm"
    ;;
  both)
    run_pass "cold" "${SCOPE_SEED}"
    run_pass "warm" "${SCOPE_SEED}"
    ;;
esac

{
  echo "# Cluster Baseline Report"
  echo ""
  echo "- run_id: \`${RUN_ID}\`"
  echo "- mode: \`${MODE}\`"
  echo "- include_deploy: \`${WITH_DEPLOY}\`"
  echo "- cargo_build_profile: \`${CARGO_BUILD_PROFILE}\`"
  echo "- csv: \`${CSV_FILE}\`"
  echo ""
  echo "| run | category | step | status | duration_s |"
  echo "|---|---|---|---|---|"
  tail -n +2 "${CSV_FILE}" | while IFS=, read -r run_label category step status duration_s; do
    echo "| ${run_label} | ${category} | ${step} | ${status} | ${duration_s} |"
  done
} > "${SUMMARY_FILE}"

echo ""
echo "Baseline report written:"
echo "  ${SUMMARY_FILE}"
echo "  ${CSV_FILE}"

if [[ "${FAILURES}" -gt 0 ]]; then
  echo "Completed with ${FAILURES} failed step(s)." >&2
  exit 1
fi

echo "Completed successfully."
