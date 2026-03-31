# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verification queries that ask reachability questions against the Z3 model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import z3

from .policy_parser import PolicyIntent

if TYPE_CHECKING:
    from .z3_model import ReachabilityModel


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    ADVISORY = "advisory"


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
    bypass_reason: str  # "l4_only", "l7_bypass_protocol", "credential_write_scope"
    credential_actions: list[str] = field(default_factory=list)


@dataclass
class InheritancePath:
    """A binary that inherits network access through the ancestor chain."""

    parent: str
    child: str
    endpoint_host: str
    endpoint_port: int
    child_capabilities: list[str]


@dataclass
class OverpermissiveMethodPath:
    """An endpoint where wildcard or overly broad HTTP methods are allowed."""

    endpoint_host: str
    endpoint_port: int
    policy_name: str
    binary: str
    allowed_methods: str  # e.g. "*" or "GET, POST, PUT, PATCH, DELETE"
    needed_methods: str  # e.g. "POST" — what the endpoint likely needs
    excess_methods: str  # e.g. "DELETE, PUT, PATCH" — what's unnecessary
    risk_detail: str  # why the excess matters


@dataclass
class L4PolicyGapPath:
    """An endpoint missing L7 enforcement where HTTP-capable binaries have access."""

    endpoint_host: str
    endpoint_port: int
    policy_name: str
    binary: str
    binary_can_http: bool
    binary_bypasses_l7: bool
    has_sibling_l7: bool  # True if other endpoints in same policy group have L7
    detail: str


@dataclass
class Finding:
    """A single verification finding."""

    query: str
    title: str
    description: str
    risk: RiskLevel
    paths: list[
        ExfilPath
        | WriteBypassPath
        | InheritancePath
        | OverpermissiveMethodPath
        | L4PolicyGapPath
    ] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    accepted: bool = False
    accepted_reason: str = ""


def check_data_exfiltration(model: ReachabilityModel) -> list[Finding]:
    """Check for data exfiltration paths from readable filesystem to writable egress channels."""
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
            # Use a fresh solver to check each path independently
            s = z3.Solver()
            s.add(model.solver.assertions())
            s.add(expr)

            if s.check() == z3.sat:
                # Determine the mechanism
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
                        l7_status = "l7_allows_write"
                        mechanism = (
                            f"L7 allows write methods — {bpath} can POST/PUT data"
                        )

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
    """Check for write capabilities that bypass read-only policy intent."""
    findings = []
    bypass_paths: list[WriteBypassPath] = []

    for policy_name, rule in model.policy.network_policies.items():
        for ep in rule.endpoints:
            if ep.intent not in (PolicyIntent.READ_ONLY, PolicyIntent.L4_ONLY):
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


def check_binary_inheritance(model: ReachabilityModel) -> list[Finding]:
    """Check for binaries that inherit network access through the ancestor chain."""
    findings = []
    inheritance_paths: list[InheritancePath] = []

    for bpath in model.binary_paths:
        children = model.binary_registry.transitive_spawns(bpath)
        if not children:
            continue

        for eid in model.endpoints:
            access_key = f"{bpath}:{eid.key}"
            if access_key not in model.policy_allows:
                continue

            for child in children:
                child_cap = model.binary_registry.get_or_unknown(child)
                capabilities = []
                if child_cap.can_write:
                    capabilities.append("can_write")
                if child_cap.bypasses_l7:
                    capabilities.append("bypasses_l7")
                if child_cap.can_exfiltrate:
                    capabilities.append("can_exfiltrate")
                if child_cap.can_construct_http:
                    capabilities.append("can_construct_http")

                if capabilities:
                    inheritance_paths.append(
                        InheritancePath(
                            parent=bpath,
                            child=child,
                            endpoint_host=eid.host,
                            endpoint_port=eid.port,
                            child_capabilities=capabilities,
                        )
                    )

    if inheritance_paths:
        seen = set()
        deduped = []
        for ip in inheritance_paths:
            key = (ip.parent, ip.child)
            if key not in seen:
                seen.add(key)
                deduped.append(ip)

        findings.append(
            Finding(
                query="binary_inheritance",
                title="Binary Ancestor Chain — Transitive Access Inheritance",
                description=(
                    f"{len(deduped)} binary pair(s) where child processes inherit "
                    f"network access from parent binaries via ancestor matching."
                ),
                risk=RiskLevel.MEDIUM,
                paths=deduped,
                remediation=[
                    "Review which child processes are spawned by allowed binaries.",
                    "If a child binary (e.g., git, curl) has write or L7-bypass capabilities "
                    "that exceed the policy intent, consider removing the parent binary or "
                    "restricting it to a more specific binary path.",
                ],
            )
        )

    return findings


def check_inference_relay(_model: ReachabilityModel) -> list[Finding]:
    """Flag inference.local as a potential side channel for policy bypass."""
    return [
        Finding(
            query="inference_relay",
            title="Inference Relay — inference.local Bypasses Policy",
            description=(
                "inference.local is always reachable from within the sandbox and bypasses "
                "OPA policy evaluation entirely. If the backing model supports tool use "
                "or function calling, the agent may instruct it to access external services, "
                "creating a side channel outside the policy boundary."
            ),
            risk=RiskLevel.ADVISORY,
            paths=[],
            remediation=[
                "Verify that the inference backend does not support unrestricted tool use "
                "or code execution.",
                "If using tool-use models, ensure the inference router restricts which tools "
                "are available and what external access they can perform.",
                "Consider auditing inference.local traffic for unexpected patterns.",
            ],
        )
    ]


def check_overpermissive_methods(model: ReachabilityModel) -> list[Finding]:
    """Flag endpoints using wildcard or overly broad HTTP method rules."""
    endpoint_hints: dict[str, tuple[set[str], str]] = {
        "integrate.api.nvidia.com": (
            {"POST"},
            "NVIDIA Cloud Functions management APIs (DELETE /v2/nvcf/assets, "
            "DELETE /v2/nvcf/deployments) share this host",
        ),
        "inference-api.nvidia.com": (
            {"POST"},
            "Inference endpoint — only POST to completion paths is needed",
        ),
        "api.anthropic.com": (
            {"POST"},
            "Anthropic management APIs (DELETE /v1/files, DELETE /v1/skills) share this host",
        ),
        "statsig.anthropic.com": (
            {"POST"},
            "Telemetry endpoint — only POST to ingest paths is needed",
        ),
        "sentry.io": (
            {"POST"},
            "Error reporting — only POST to ingest paths is needed; "
            "Sentry management APIs (DELETE projects, releases) share this host",
        ),
        "registry.npmjs.org": (
            {"GET"},
            "Package installation is read-only (GET); wildcard allows npm publish (PUT)",
        ),
    }

    paths: list[OverpermissiveMethodPath] = []

    for policy_name, rule in model.policy.network_policies.items():
        for ep in rule.endpoints:
            if not ep.is_l7_enforced:
                continue

            allowed = ep.allowed_methods
            if not allowed:
                continue

            has_wildcard = any(r.method == "*" for r in ep.rules)
            has_delete = "DELETE" in allowed

            if not has_wildcard and not has_delete:
                continue

            hint = endpoint_hints.get(ep.host)
            if hint:
                needed, risk_detail = hint
                excess = allowed - needed - {"HEAD", "OPTIONS"}
            else:
                if not has_delete:
                    continue
                needed = allowed - {"DELETE"}
                excess = {"DELETE"}
                risk_detail = "DELETE method allowed but likely not required"

            if not excess:
                continue

            for b in rule.binaries:
                for port in ep.effective_ports:
                    paths.append(
                        OverpermissiveMethodPath(
                            endpoint_host=ep.host,
                            endpoint_port=port,
                            policy_name=policy_name,
                            binary=b.path,
                            allowed_methods="*"
                            if has_wildcard
                            else ", ".join(sorted(allowed)),
                            needed_methods=", ".join(sorted(needed)),
                            excess_methods=", ".join(sorted(excess)),
                            risk_detail=risk_detail,
                        )
                    )

    if not paths:
        return []

    unique_endpoints = {
        (p.endpoint_host, p.endpoint_port, p.policy_name) for p in paths
    }

    return [
        Finding(
            query="overpermissive_methods",
            title="Overpermissive HTTP Methods — Destructive Operations Allowed",
            description=(
                f"{len(unique_endpoints)} endpoint(s) allow HTTP methods beyond what is needed. "
                f'Wildcard (method: "*") or explicit DELETE on endpoints that share hosts with '
                f"management APIs enables destructive operations."
            ),
            risk=RiskLevel.HIGH,
            paths=paths,
            remediation=[
                'Replace `method: "*"` with explicit method lists matching actual usage.',
                "Inference endpoints: restrict to `POST` on `/v1/chat/completions`, "
                "`/v1/messages`, `/v1/responses`.",
                "Telemetry endpoints: restrict to `POST` on known ingest paths.",
                "Package registries: restrict to `GET` for installation (no publish).",
            ],
        )
    ]


def check_l4_policy_gaps(model: ReachabilityModel) -> list[Finding]:
    """Flag endpoints without L7 enforcement where HTTP-capable binaries have access."""
    paths: list[L4PolicyGapPath] = []

    for policy_name, rule in model.policy.network_policies.items():
        has_any_l7 = any(ep.is_l7_enforced for ep in rule.endpoints)

        for ep in rule.endpoints:
            if ep.is_l7_enforced:
                continue

            for b in rule.binaries:
                cap = model.binary_registry.get_or_unknown(b.path)
                if not (
                    cap.can_construct_http or cap.bypasses_l7 or cap.can_exfiltrate
                ):
                    continue

                detail_parts = []
                if has_any_l7:
                    l7_siblings = [
                        f"{sib.host}:{sib.effective_ports[0]}"
                        for sib in rule.endpoints
                        if sib.is_l7_enforced and sib.effective_ports
                    ]
                    detail_parts.append(
                        f"Inconsistent: sibling endpoint(s) {', '.join(l7_siblings)} "
                        f"in '{policy_name}' have L7, but this one does not"
                    )

                if cap.can_construct_http:
                    detail_parts.append(
                        f"{b.path} can construct arbitrary HTTP — all methods/paths "
                        f"pass uninspected"
                    )
                if cap.bypasses_l7:
                    detail_parts.append(
                        f"{b.path} uses non-HTTP protocol — even with L7, "
                        f"traffic would bypass inspection"
                    )

                for port in ep.effective_ports:
                    paths.append(
                        L4PolicyGapPath(
                            endpoint_host=ep.host,
                            endpoint_port=port,
                            policy_name=policy_name,
                            binary=b.path,
                            binary_can_http=cap.can_construct_http,
                            binary_bypasses_l7=cap.bypasses_l7,
                            has_sibling_l7=has_any_l7,
                            detail="; ".join(detail_parts),
                        )
                    )

    if not paths:
        return []

    has_inconsistent = any(p.has_sibling_l7 for p in paths)
    unique_endpoints = {(p.endpoint_host, p.endpoint_port) for p in paths}

    return [
        Finding(
            query="l4_policy_gaps",
            title="L4-Only Endpoints — No HTTP Inspection",
            description=(
                f"{len(unique_endpoints)} endpoint(s) lack `protocol: rest` — all traffic "
                f"passes without HTTP method or path enforcement. "
                + (
                    "Some share a policy group with L7-enforced siblings, indicating "
                    "inconsistent enforcement."
                    if has_inconsistent
                    else "HTTP-capable binaries have unrestricted access."
                )
            ),
            risk=RiskLevel.HIGH if has_inconsistent else RiskLevel.MEDIUM,
            paths=paths,
            remediation=[
                "Add `protocol: rest` with `enforcement: enforce` and `tls: terminate` "
                "to enable HTTP inspection.",
                'Define explicit method and path rules (e.g., `allow: { method: GET, path: "/**" }`) '
                "to restrict what traffic is permitted.",
                "If L4-only is intentional (e.g., for binary protocols like git), "
                "document the rationale and restrict the binary list tightly.",
            ],
        )
    ]


def run_all_queries(model: ReachabilityModel) -> list[Finding]:
    """Run all verification queries and return findings."""
    findings = []
    findings.extend(check_data_exfiltration(model))
    findings.extend(check_write_bypass(model))
    findings.extend(check_overpermissive_methods(model))
    findings.extend(check_l4_policy_gaps(model))
    findings.extend(check_binary_inheritance(model))
    findings.extend(check_inference_relay(model))
    return findings
