# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Parse credential descriptors and API capability registries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class Credential:
    name: str
    type: str
    scopes: list[str] = field(default_factory=list)
    injected_via: str = ""
    target_hosts: list[str] = field(default_factory=list)


@dataclass
class ApiAction:
    method: str
    path: str
    action: str


@dataclass
class ApiCapability:
    api: str
    host: str
    port: int = 443
    credential_type: str = ""
    scope_capabilities: dict[str, list[ApiAction]] = field(default_factory=dict)
    action_risk: dict[str, str] = field(default_factory=dict)

    def actions_for_scopes(self, scopes: list[str]) -> list[ApiAction]:
        """Return all API actions enabled by the given scopes."""
        result = []
        for scope in scopes:
            result.extend(self.scope_capabilities.get(scope, []))
        return result

    def write_actions_for_scopes(self, scopes: list[str]) -> list[ApiAction]:
        """Return API actions that involve writing (POST, PUT, PATCH, DELETE)."""
        return [
            a
            for a in self.actions_for_scopes(scopes)
            if a.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        ]

    def destructive_actions_for_scopes(self, scopes: list[str]) -> list[ApiAction]:
        """Return actions classified as high or critical risk."""
        actions = self.actions_for_scopes(scopes)
        return [
            a
            for a in actions
            if self.action_risk.get(a.action, "low") in {"high", "critical"}
        ]


@dataclass
class CredentialSet:
    credentials: list[Credential] = field(default_factory=list)
    api_registries: dict[str, ApiCapability] = field(default_factory=dict)

    def credentials_for_host(self, host: str) -> list[Credential]:
        return [c for c in self.credentials if host in c.target_hosts]

    def api_for_host(self, host: str) -> ApiCapability | None:
        for api in self.api_registries.values():
            if api.host == host:
                return api
        return None


def load_credentials(path: Path) -> list[Credential]:
    """Load credential descriptors from YAML."""
    with open(path) as f:  # noqa: PTH123
        raw = yaml.safe_load(f)

    credentials = []
    for c_raw in raw.get("credentials", []):
        credentials.append(
            Credential(
                name=c_raw.get("name", ""),
                type=c_raw.get("type", ""),
                scopes=c_raw.get("scopes", []),
                injected_via=c_raw.get("injected_via", ""),
                target_hosts=c_raw.get("target_hosts", []),
            )
        )
    return credentials


def load_api_registry(path: Path) -> ApiCapability:
    """Load an API capability registry from YAML."""
    with open(path) as f:  # noqa: PTH123
        raw = yaml.safe_load(f)

    scope_caps = {}
    for scope, actions_raw in (raw.get("scope_capabilities") or {}).items():
        scope_caps[scope] = [
            ApiAction(
                method=a.get("method", ""),
                path=a.get("path", ""),
                action=a.get("action", ""),
            )
            for a in actions_raw
        ]

    return ApiCapability(
        api=raw.get("api", ""),
        host=raw.get("host", ""),
        port=raw.get("port", 443),
        credential_type=raw.get("credential_type", ""),
        scope_capabilities=scope_caps,
        action_risk=raw.get("action_risk", {}),
    )


def load_credential_set(
    credentials_path: Path,
    registry_dir: Path,
) -> CredentialSet:
    """Load credentials and all API registries from a registry directory."""
    creds = load_credentials(credentials_path)

    api_registries = {}
    apis_dir = registry_dir / "apis"
    if apis_dir.is_dir():
        for api_file in apis_dir.glob("*.yaml"):
            api = load_api_registry(api_file)
            api_registries[api.api] = api

    return CredentialSet(credentials=creds, api_registries=api_registries)
