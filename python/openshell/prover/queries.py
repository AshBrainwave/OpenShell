# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verification queries — two Zelkova-like yes/no security questions.

1. Can data leave this sandbox? (exfiltration)
2. Can the agent write despite read-only intent? (write bypass)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import z3

from .policy_parser import PolicyIntent

if TYPE_CHECKING:
    from .z3_model import ReachabilityModel


class RiskLevel(Enum):
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExfilPath:
    """A concrete path through which data can be exfiltrated."""

    binary: str
    endpoint_host: str
    endpoint_port: int
    mechanism: str
    policy_name: str
    l7_status: str  # "l4_only", "l7_allows_write", "l7_bypassed"


@dataclass
class WriteBypassPath:
    """A path that allows writing despite read-only intent."""

    binary: str
    endpoint_host: str
    endpoint_port: int
    policy_name: str
    policy_intent: str
    bypass_reason: str  # "l4_only", "l7_bypass_protocol"
    credential_actions: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single verification finding."""

    query: str
    title: str
    description: str
    risk: RiskLevel
    paths: list[ExfilPath | WriteBypassPath] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    accepted: bool = False
    accepted_reason: str = ""


def check_data_exfiltration(model: ReachabilityModel) -> list[Finding]:
    """Can data leave this sandbox?

    Maps every path from readable filesystem locations to writable egress
    channels: L4-only endpoints, wire protocol bypasses, and L7 write channels.
    """
    findings = []

    if not model.policy.filesystem_policy.readable_paths:
        return findings

    exfil_paths: list[ExfilPath] = []

    for bpath in model.binary_paths:
        cap = model.binary_registry.get_or_unknown(bpath)
        if not cap.can_exfiltrate:
            continue

        for eid in model.endpoints:
            expr = model.can_exfil_via_endpoint(bpath, eid)
            s = z3.Solver()
            s.add(model.solver.assertions())
            s.add(expr)

            if s.check() == z3.sat:
                ek = eid.key
                bypass = cap.bypasses_l7

                if bypass:
                    l7_status = "l7_bypassed"
                    mechanism = f"{cap.description} — uses non-HTTP protocol, bypasses L7 inspection"
                elif ek not in model.l7_enforced:
                    l7_status = "l4_only"
                    mechanism = f"L4-only endpoint — no HTTP inspection, {bpath} can send arbitrary data"
                else:
                    ep_is_l7 = False
                    for _pn, rule in model.policy.network_policies.items():
                        for ep in rule.endpoints:
                            if ep.host == eid.host and eid.port in ep.effective_ports:
                                ep_is_l7 = ep.is_l7_enforced
                    if not ep_is_l7:
                        l7_status = "l4_only"
                        mechanism = f"L4-only endpoint — no HTTP inspection, {bpath} can send arbitrary data"
                    else:
                        # L7 is enforced and allows write — policy is
                        # working as intended. Not a finding.
                        continue

                if cap.exfil_mechanism:
                    mechanism += f". Exfil via: {cap.exfil_mechanism}"

                exfil_paths.append(
                    ExfilPath(
                        binary=bpath,
                        endpoint_host=eid.host,
                        endpoint_port=eid.port,
                        mechanism=mechanism,
                        policy_name=eid.policy_name,
                        l7_status=l7_status,
                    )
                )

    if exfil_paths:
        readable = model.policy.filesystem_policy.readable_paths
        has_l4_only = any(p.l7_status == "l4_only" for p in exfil_paths)
        has_bypass = any(p.l7_status == "l7_bypassed" for p in exfil_paths)
        risk = RiskLevel.CRITICAL if (has_l4_only or has_bypass) else RiskLevel.HIGH

        remediation = []
        if has_l4_only:
            remediation.append(
                "Add `protocol: rest` with specific L7 rules to L4-only endpoints "
                "to enable HTTP inspection and restrict to safe methods/paths."
            )
        if has_bypass:
            remediation.append(
                "Binaries using non-HTTP protocols (git, ssh, nc) bypass L7 inspection. "
                "Remove these binaries from the policy if write access is not intended, "
                "or restrict credential scopes to read-only."
            )
        remediation.append(
            "Restrict filesystem read access to only the paths the agent needs."
        )

        findings.append(
            Finding(
                query="data_exfiltration",
                title="Data Exfiltration Paths Detected",
                description=(
                    f"{len(exfil_paths)} exfiltration path(s) found from "
                    f"{len(readable)} readable filesystem path(s) to external endpoints."
                ),
                risk=risk,
                paths=exfil_paths,
                remediation=remediation,
            )
        )

    return findings


def check_write_bypass(model: ReachabilityModel) -> list[Finding]:
    """Can the agent write despite read-only intent?

    Checks whether any combination of binary capabilities, credential scopes,
    and transport protocols allows write operations that the policy intends to block.
    """
    findings = []
    bypass_paths: list[WriteBypassPath] = []

    for policy_name, rule in model.policy.network_policies.items():
        for ep in rule.endpoints:
            if ep.intent != PolicyIntent.READ_ONLY:
                continue

            for port in ep.effective_ports:
                for b in rule.binaries:
                    cap = model.binary_registry.get_or_unknown(b.path)

                    # Check: binary bypasses L7 and can write
                    if cap.bypasses_l7 and cap.can_write:
                        creds = model.credentials.credentials_for_host(ep.host)
                        api = model.credentials.api_for_host(ep.host)
                        cred_actions = []
                        for cred in creds:
                            if api:
                                for wa in api.write_actions_for_scopes(cred.scopes):
                                    cred_actions.append(
                                        f"{wa.method} {wa.path} ({wa.action})"
                                    )
                            else:
                                cred_actions.append(
                                    f"credential '{cred.name}' has scopes: {cred.scopes}"
                                )

                        if cred_actions or not creds:
                            bypass_paths.append(
                                WriteBypassPath(
                                    binary=b.path,
                                    endpoint_host=ep.host,
                                    endpoint_port=port,
                                    policy_name=policy_name,
                                    policy_intent=ep.intent.value,
                                    bypass_reason="l7_bypass_protocol",
                                    credential_actions=cred_actions,
                                )
                            )

                    # Check: L4-only endpoint + binary can construct HTTP + credential has write
                    if not ep.is_l7_enforced and cap.can_construct_http:
                        creds = model.credentials.credentials_for_host(ep.host)
                        api = model.credentials.api_for_host(ep.host)
                        cred_actions = []
                        for cred in creds:
                            if api:
                                for wa in api.write_actions_for_scopes(cred.scopes):
                                    cred_actions.append(
                                        f"{wa.method} {wa.path} ({wa.action})"
                                    )
                            else:
                                cred_actions.append(
                                    f"credential '{cred.name}' has scopes: {cred.scopes}"
                                )

                        if cred_actions:
                            bypass_paths.append(
                                WriteBypassPath(
                                    binary=b.path,
                                    endpoint_host=ep.host,
                                    endpoint_port=port,
                                    policy_name=policy_name,
                                    policy_intent=ep.intent.value,
                                    bypass_reason="l4_only",
                                    credential_actions=cred_actions,
                                )
                            )

    if bypass_paths:
        findings.append(
            Finding(
                query="write_bypass",
                title="Write Bypass Detected — Read-Only Intent Violated",
                description=(
                    f"{len(bypass_paths)} path(s) allow write operations despite "
                    f"read-only policy intent."
                ),
                risk=RiskLevel.HIGH,
                paths=bypass_paths,
                remediation=[
                    "For L4-only endpoints: add `protocol: rest` with `access: read-only` "
                    "to enable HTTP method filtering.",
                    "For L7-bypassing binaries (git, ssh, nc): remove them from the policy's "
                    "binary list if write access is not intended.",
                    "Restrict credential scopes to read-only where possible.",
                ],
            )
        )

    return findings


def run_all_queries(model: ReachabilityModel) -> list[Finding]:
    """Run all verification queries and return findings."""
    findings = []
    findings.extend(check_data_exfiltration(model))
    findings.extend(check_write_bypass(model))
    return findings
