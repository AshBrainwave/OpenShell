# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Encode OpenShell policy + credentials + binary capabilities as Z3 SMT constraints."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import z3

from .policy_parser import WRITE_METHODS, PolicyModel

if TYPE_CHECKING:
    from .binary_registry import BinaryRegistry
    from .credential_loader import CredentialSet


@dataclass
class EndpointId:
    """Unique identifier for an endpoint in the model."""

    policy_name: str
    host: str
    port: int

    @property
    def key(self) -> str:
        return f"{self.policy_name}:{self.host}:{self.port}"


@dataclass
class ReachabilityModel:
    """Z3-backed reachability model for an OpenShell sandbox policy."""

    policy: PolicyModel
    credentials: CredentialSet
    binary_registry: BinaryRegistry

    # Indexed facts derived from the inputs
    endpoints: list[EndpointId] = field(default_factory=list)
    binary_paths: list[str] = field(default_factory=list)

    # Z3 boolean variables — indexed by string keys
    # policy_allows[binary_key:endpoint_key] = True if policy allows this binary on this endpoint
    policy_allows: dict[str, z3.BoolRef] = field(default_factory=dict)
    # l7_enforced[endpoint_key] = True if endpoint has protocol field
    l7_enforced: dict[str, z3.BoolRef] = field(default_factory=dict)
    # l7_allows_write[endpoint_key] = True if L7 rules permit write methods
    l7_allows_write: dict[str, z3.BoolRef] = field(default_factory=dict)
    # binary_bypasses_l7[binary_path] = True if binary uses non-HTTP protocol
    binary_bypasses_l7: dict[str, z3.BoolRef] = field(default_factory=dict)
    # binary_can_write[binary_path] = True if binary can perform write actions
    binary_can_write: dict[str, z3.BoolRef] = field(default_factory=dict)
    # binary_can_exfil[binary_path] = True if binary can exfiltrate data
    binary_can_exfil: dict[str, z3.BoolRef] = field(default_factory=dict)
    # binary_can_construct_http[binary_path] = True if binary can make arbitrary HTTP requests
    binary_can_construct_http: dict[str, z3.BoolRef] = field(default_factory=dict)
    # credential_has_write[host] = True if any credential for this host has write capabilities
    credential_has_write: dict[str, z3.BoolRef] = field(default_factory=dict)
    # credential_has_destructive[host] = True if any credential has destructive capabilities
    credential_has_destructive: dict[str, z3.BoolRef] = field(default_factory=dict)
    # spawns[parent:child] = True if parent spawns child
    spawns_rel: dict[str, z3.BoolRef] = field(default_factory=dict)
    # inherits_access[child:endpoint_key] = True if child inherits access to endpoint
    inherits_access: dict[str, z3.BoolRef] = field(default_factory=dict)
    # filesystem_readable[path] = True
    filesystem_readable: dict[str, z3.BoolRef] = field(default_factory=dict)

    solver: z3.Solver = field(default_factory=z3.Solver)

    def __post_init__(self):
        self._build()

    def _build(self):
        """Build all Z3 constraints from the inputs."""
        self._index_endpoints()
        self._index_binaries()
        self._encode_policy_allows()
        self._encode_l7_enforcement()
        self._encode_binary_capabilities()
        self._encode_credentials()
        self._encode_spawn_chains()
        self._encode_filesystem()

    def _index_endpoints(self):
        """Collect all unique endpoints from the policy."""
        for policy_name, rule in self.policy.network_policies.items():
            for ep in rule.endpoints:
                for port in ep.effective_ports:
                    eid = EndpointId(policy_name, ep.host, port)
                    self.endpoints.append(eid)

    def _index_binaries(self):
        """Collect all unique binary paths from the policy."""
        seen = set()
        for rule in self.policy.network_policies.values():
            for b in rule.binaries:
                if b.path not in seen:
                    seen.add(b.path)
                    self.binary_paths.append(b.path)

    def _encode_policy_allows(self):
        """Encode which (binary, endpoint) pairs the policy allows."""
        for policy_name, rule in self.policy.network_policies.items():
            for ep in rule.endpoints:
                for port in ep.effective_ports:
                    eid = EndpointId(policy_name, ep.host, port)
                    for b in rule.binaries:
                        key = f"{b.path}:{eid.key}"
                        var = z3.Bool(f"policy_allows_{key}")
                        self.policy_allows[key] = var
                        self.solver.add(var == True)  # noqa: E712 — Z3 constraint

    def _encode_l7_enforcement(self):
        """Encode which endpoints have L7 enforcement and what they allow."""
        for policy_name, rule in self.policy.network_policies.items():
            for ep in rule.endpoints:
                for port in ep.effective_ports:
                    eid = EndpointId(policy_name, ep.host, port)
                    ek = eid.key

                    # L7 enforced?
                    l7_var = z3.Bool(f"l7_enforced_{ek}")
                    self.l7_enforced[ek] = l7_var
                    self.solver.add(l7_var == ep.is_l7_enforced)

                    # L7 allows write?
                    allowed = ep.allowed_methods
                    has_write = bool(allowed & WRITE_METHODS) if allowed else True
                    l7w_var = z3.Bool(f"l7_allows_write_{ek}")
                    self.l7_allows_write[ek] = l7w_var
                    if ep.is_l7_enforced:
                        self.solver.add(l7w_var == has_write)
                    else:
                        # L4-only: all methods pass through
                        self.solver.add(l7w_var == True)  # noqa: E712

    def _encode_binary_capabilities(self):
        """Encode binary capabilities from the registry."""
        for bpath in self.binary_paths:
            cap = self.binary_registry.get_or_unknown(bpath)

            bypass_var = z3.Bool(f"binary_bypasses_l7_{bpath}")
            self.binary_bypasses_l7[bpath] = bypass_var
            self.solver.add(bypass_var == cap.bypasses_l7)

            write_var = z3.Bool(f"binary_can_write_{bpath}")
            self.binary_can_write[bpath] = write_var
            self.solver.add(write_var == cap.can_write)

            exfil_var = z3.Bool(f"binary_can_exfil_{bpath}")
            self.binary_can_exfil[bpath] = exfil_var
            self.solver.add(exfil_var == cap.can_exfiltrate)

            http_var = z3.Bool(f"binary_can_construct_http_{bpath}")
            self.binary_can_construct_http[bpath] = http_var
            self.solver.add(http_var == cap.can_construct_http)

    def _encode_credentials(self):
        """Encode credential capabilities per host."""
        hosts = {eid.host for eid in self.endpoints}

        for host in hosts:
            creds = self.credentials.credentials_for_host(host)
            api = self.credentials.api_for_host(host)

            has_write = False
            has_destructive = False

            for cred in creds:
                if api:
                    write_actions = api.write_actions_for_scopes(cred.scopes)
                    destructive_actions = api.destructive_actions_for_scopes(
                        cred.scopes
                    )
                    if write_actions:
                        has_write = True
                    if destructive_actions:
                        has_destructive = True
                elif cred.scopes:
                    # No API registry — conservatively assume credential enables writes
                    has_write = True

            cw_var = z3.Bool(f"credential_has_write_{host}")
            self.credential_has_write[host] = cw_var
            self.solver.add(cw_var == has_write)

            cd_var = z3.Bool(f"credential_has_destructive_{host}")
            self.credential_has_destructive[host] = cd_var
            self.solver.add(cd_var == has_destructive)

    def _encode_spawn_chains(self):
        """Encode binary spawn relationships and transitive access inheritance."""
        for bpath in self.binary_paths:
            cap = self.binary_registry.get_or_unknown(bpath)
            for child in cap.spawns:
                key = f"{bpath}:{child}"
                var = z3.Bool(f"spawns_{key}")
                self.spawns_rel[key] = var
                self.solver.add(var == True)  # noqa: E712

        # Encode transitive access inheritance
        for bpath in self.binary_paths:
            all_children = self.binary_registry.transitive_spawns(bpath)
            for eid in self.endpoints:
                parent_key = f"{bpath}:{eid.key}"
                if parent_key in self.policy_allows:
                    for child in all_children:
                        inherit_key = f"{child}:{eid.key}"
                        var = z3.Bool(f"inherits_access_{inherit_key}")
                        self.inherits_access[inherit_key] = var
                        self.solver.add(var == True)  # noqa: E712

    def _encode_filesystem(self):
        """Encode filesystem readability."""
        for path in self.policy.filesystem_policy.readable_paths:
            var = z3.Bool(f"fs_readable_{path}")
            self.filesystem_readable[path] = var
            self.solver.add(var == True)  # noqa: E712

    # --- Query helpers ---

    def _has_access(self, bpath: str, ek: str) -> z3.BoolRef | None:
        """Return Z3 expression for access (direct or inherited), or None."""
        access_key = f"{bpath}:{ek}"
        direct = self.policy_allows.get(access_key)
        inherited = self.inherits_access.get(access_key)
        if direct is not None and inherited is not None:
            return z3.Or(direct, inherited)
        if direct is not None:
            return direct
        return inherited  # may be None

    def can_write_to_endpoint(self, bpath: str, eid: EndpointId) -> z3.BoolRef:
        """Return a Z3 expression for whether a binary can write to an endpoint."""
        ek = eid.key

        has_access = self._has_access(bpath, ek)
        if has_access is None:
            return z3.BoolVal(False)

        bypass = self.binary_bypasses_l7.get(bpath, z3.BoolVal(False))
        l7_enforced = self.l7_enforced.get(ek, z3.BoolVal(False))
        l7_write = self.l7_allows_write.get(ek, z3.BoolVal(False))
        binary_write = self.binary_can_write.get(bpath, z3.BoolVal(False))
        cred_write = self.credential_has_write.get(eid.host, z3.BoolVal(False))

        return z3.And(
            has_access,
            binary_write,
            z3.Or(
                z3.Not(l7_enforced),  # L4-only
                l7_write,  # L7 allows write
                bypass,  # binary bypasses L7
            ),
            cred_write,
        )

    def can_exfil_via_endpoint(self, bpath: str, eid: EndpointId) -> z3.BoolRef:
        """Return a Z3 expression for whether data can be exfiltrated via this path."""
        ek = eid.key

        has_access = self._has_access(bpath, ek)
        if has_access is None:
            return z3.BoolVal(False)

        exfil = self.binary_can_exfil.get(bpath, z3.BoolVal(False))
        bypass = self.binary_bypasses_l7.get(bpath, z3.BoolVal(False))
        l7_enforced = self.l7_enforced.get(ek, z3.BoolVal(False))
        l7_write = self.l7_allows_write.get(ek, z3.BoolVal(False))
        http = self.binary_can_construct_http.get(bpath, z3.BoolVal(False))

        return z3.And(
            has_access,
            exfil,
            z3.Or(
                z3.And(z3.Not(l7_enforced), http),  # L4-only + HTTP
                z3.And(l7_write, http),  # L7 write + HTTP
                bypass,  # non-HTTP protocol bypass
            ),
        )


def build_model(
    policy: PolicyModel,
    credentials: CredentialSet,
    binary_registry: BinaryRegistry,
) -> ReachabilityModel:
    """Build a Z3 reachability model from policy, credentials, and binary registry."""
    return ReachabilityModel(
        policy=policy,
        credentials=credentials,
        binary_registry=binary_registry,
    )
