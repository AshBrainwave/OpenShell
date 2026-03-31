# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parse OpenShell sandbox policy YAML into typed dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from pathlib import Path


class PolicyIntent(Enum):
    L4_ONLY = "l4_only"
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    FULL = "full"
    CUSTOM = "custom"


@dataclass
class L7Rule:
    method: str
    path: str
    command: str = ""


@dataclass
class Endpoint:
    host: str
    port: int
    ports: list[int] = field(default_factory=list)
    protocol: str = ""
    tls: str = ""
    enforcement: str = "audit"
    access: str = ""
    rules: list[L7Rule] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)

    @property
    def is_l7_enforced(self) -> bool:
        return bool(self.protocol)

    @property
    def intent(self) -> PolicyIntent:
        if not self.protocol:
            return PolicyIntent.L4_ONLY
        if self.access == "read-only":
            return PolicyIntent.READ_ONLY
        if self.access == "read-write":
            return PolicyIntent.READ_WRITE
        if self.access == "full":
            return PolicyIntent.FULL
        if self.rules:
            methods = {r.method.upper() for r in self.rules}
            if methods <= {"GET", "HEAD", "OPTIONS"}:
                return PolicyIntent.READ_ONLY
            if "DELETE" not in methods:
                return PolicyIntent.READ_WRITE
            return PolicyIntent.FULL
        return PolicyIntent.CUSTOM

    @property
    def effective_ports(self) -> list[int]:
        if self.ports:
            return self.ports
        if self.port:
            return [self.port]
        return []

    @property
    def allowed_methods(self) -> set[str]:
        """Return the set of HTTP methods this endpoint allows. Empty means all (L4-only)."""
        if not self.protocol:
            return set()  # L4-only: all traffic passes
        if self.access == "read-only":
            return {"GET", "HEAD", "OPTIONS"}
        if self.access == "read-write":
            return {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
        if self.access == "full":
            return {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
        if self.rules:
            methods = set()
            for r in self.rules:
                m = r.method.upper()
                if m == "*":
                    return {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
                methods.add(m)
            return methods
        return set()


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Binary:
    path: str


@dataclass
class NetworkPolicyRule:
    name: str
    endpoints: list[Endpoint] = field(default_factory=list)
    binaries: list[Binary] = field(default_factory=list)


@dataclass
class FilesystemPolicy:
    include_workdir: bool = True
    read_only: list[str] = field(default_factory=list)
    read_write: list[str] = field(default_factory=list)

    @property
    def readable_paths(self) -> list[str]:
        return self.read_only + self.read_write


@dataclass
class PolicyModel:
    version: int = 1
    filesystem_policy: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network_policies: dict[str, NetworkPolicyRule] = field(default_factory=dict)

    @property
    def all_endpoints(self) -> list[tuple[str, Endpoint]]:
        """Return all (policy_name, endpoint) pairs."""
        result = []
        for name, rule in self.network_policies.items():
            for ep in rule.endpoints:
                result.append((name, ep))
        return result

    @property
    def all_binaries(self) -> list[Binary]:
        """Return deduplicated list of all binaries across all policies."""
        seen = set()
        result = []
        for rule in self.network_policies.values():
            for b in rule.binaries:
                if b.path not in seen:
                    seen.add(b.path)
                    result.append(b)
        return result

    @property
    def binary_endpoint_pairs(self) -> list[tuple[Binary, str, Endpoint]]:
        """Return all (binary, policy_name, endpoint) triples."""
        result = []
        for name, rule in self.network_policies.items():
            for b in rule.binaries:
                for ep in rule.endpoints:
                    result.append((b, name, ep))
        return result


def parse_policy(path: Path) -> PolicyModel:
    """Parse an OpenShell policy YAML file into a PolicyModel."""
    with open(path) as f:  # noqa: PTH123
        raw = yaml.safe_load(f)

    if not raw:
        return PolicyModel()

    fs_raw = raw.get("filesystem_policy", {}) or {}
    fs = FilesystemPolicy(
        include_workdir=fs_raw.get("include_workdir", True),
        read_only=fs_raw.get("read_only", []),
        read_write=fs_raw.get("read_write", []),
    )

    network_policies = {}
    for key, rule_raw in (raw.get("network_policies") or {}).items():
        endpoints = []
        for ep_raw in rule_raw.get("endpoints", []):
            rules = []
            for r in ep_raw.get("rules", []):
                allow = r.get("allow", {})
                rules.append(
                    L7Rule(
                        method=allow.get("method", ""),
                        path=allow.get("path", ""),
                        command=allow.get("command", ""),
                    )
                )
            endpoints.append(
                Endpoint(
                    host=ep_raw.get("host", ""),
                    port=ep_raw.get("port", 0),
                    ports=ep_raw.get("ports", []),
                    protocol=ep_raw.get("protocol", ""),
                    tls=ep_raw.get("tls", ""),
                    enforcement=ep_raw.get("enforcement", "audit"),
                    access=ep_raw.get("access", ""),
                    rules=rules,
                    allowed_ips=ep_raw.get("allowed_ips", []),
                )
            )

        binaries = []
        for b_raw in rule_raw.get("binaries", []):
            binaries.append(Binary(path=b_raw.get("path", "")))

        network_policies[key] = NetworkPolicyRule(
            name=rule_raw.get("name", key),
            endpoints=endpoints,
            binaries=binaries,
        )

    return PolicyModel(
        version=raw.get("version", 1),
        filesystem_policy=fs,
        network_policies=network_policies,
    )
