# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the OpenShell Policy Prover."""

from pathlib import Path

from openshell.prover.binary_registry import load_binary_registry
from openshell.prover.credential_loader import load_credential_set
from openshell.prover.policy_parser import PolicyIntent, parse_policy
from openshell.prover.queries import RiskLevel, run_all_queries
from openshell.prover.z3_model import build_model

_TESTDATA = Path(__file__).parent / "testdata"
_REGISTRY = Path(__file__).parent / "registry"


def _run_prover(policy_name: str, credentials_name: str):
    policy = parse_policy(_TESTDATA / policy_name)
    creds = load_credential_set(_TESTDATA / credentials_name, _REGISTRY)
    binaries = load_binary_registry(_REGISTRY)
    model = build_model(policy, creds, binaries)
    return run_all_queries(model)


def test_parse_policy():
    """Verify policy parsing produces correct structure."""
    policy = parse_policy(_TESTDATA / "policy.yaml")
    assert policy.version == 1
    assert "github_readonly" in policy.network_policies

    rule = policy.network_policies["github_readonly"]
    assert len(rule.endpoints) == 2
    assert len(rule.binaries) == 3

    # First endpoint: L7 enforced read-only
    ep0 = rule.endpoints[0]
    assert ep0.host == "api.github.com"
    assert ep0.is_l7_enforced
    assert ep0.intent == PolicyIntent.READ_ONLY

    # Second endpoint: L4 only
    ep1 = rule.endpoints[1]
    assert ep1.host == "github.com"
    assert not ep1.is_l7_enforced
    assert ep1.intent == PolicyIntent.L4_ONLY


def test_filesystem_policy():
    """Verify filesystem policy parsing."""
    policy = parse_policy(_TESTDATA / "policy.yaml")
    fs = policy.filesystem_policy
    assert "/usr" in fs.read_only
    assert "/sandbox" in fs.read_write
    assert "/usr" in fs.readable_paths
    assert "/sandbox" in fs.readable_paths


def test_git_push_bypass_findings():
    """End-to-end: detect git push bypass in L4-only + L7 policy."""
    findings = _run_prover("policy.yaml", "credentials.yaml")
    risks = {f.risk for f in findings}
    queries = {f.query for f in findings}

    assert RiskLevel.CRITICAL in risks, "Should detect critical exfil paths"
    assert RiskLevel.HIGH in risks, "Should detect write bypass"
    assert "data_exfiltration" in queries
    assert "write_bypass" in queries
    assert "binary_inheritance" in queries

    # Verify git bypass specifically detected
    write_findings = [f for f in findings if f.query == "write_bypass"]
    assert len(write_findings) == 1
    bypass_binaries = {p.binary for p in write_findings[0].paths}
    assert "/usr/bin/git" in bypass_binaries, "Git should be flagged for L7 bypass"


def test_empty_policy_advisory_only():
    """Deny-all policy should only produce the inference relay advisory."""
    findings = _run_prover("empty_policy.yaml", "empty_credentials.yaml")
    queries = {f.query for f in findings}
    risks = {f.risk for f in findings}

    assert "inference_relay" in queries
    assert RiskLevel.CRITICAL not in risks
    assert RiskLevel.HIGH not in risks
    assert len(findings) == 1
    assert findings[0].risk == RiskLevel.ADVISORY
