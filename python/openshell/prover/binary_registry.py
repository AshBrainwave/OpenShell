# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Load binary capability descriptors from YAML registry."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from pathlib import Path


class ActionType(Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


@dataclass
class BinaryAction:
    name: str
    type: ActionType
    description: str = ""


@dataclass
class BinaryProtocol:
    name: str
    transport: str = ""
    description: str = ""
    bypasses_l7: bool = False
    actions: list[BinaryAction] = field(default_factory=list)

    @property
    def can_write(self) -> bool:
        return any(
            a.type in (ActionType.WRITE, ActionType.DESTRUCTIVE) for a in self.actions
        )

    @property
    def can_destroy(self) -> bool:
        return any(a.type == ActionType.DESTRUCTIVE for a in self.actions)


@dataclass
class BinaryCapability:
    path: str
    description: str = ""
    protocols: list[BinaryProtocol] = field(default_factory=list)
    spawns: list[str] = field(default_factory=list)
    can_exfiltrate: bool = False
    exfil_mechanism: str = ""
    can_construct_http: bool = False

    @property
    def bypasses_l7(self) -> bool:
        return any(p.bypasses_l7 for p in self.protocols)

    @property
    def can_write(self) -> bool:
        return any(p.can_write for p in self.protocols) or self.can_construct_http

    @property
    def can_destroy(self) -> bool:
        return any(p.can_destroy for p in self.protocols)

    @property
    def write_mechanisms(self) -> list[str]:
        mechanisms = []
        for p in self.protocols:
            if p.can_write:
                for a in p.actions:
                    if a.type in (ActionType.WRITE, ActionType.DESTRUCTIVE):
                        mechanisms.append(f"{p.name}: {a.name}")
        if self.can_construct_http:
            mechanisms.append("arbitrary HTTP request construction")
        return mechanisms


@dataclass
class BinaryRegistry:
    binaries: dict[str, BinaryCapability] = field(default_factory=dict)

    def get(self, path: str) -> BinaryCapability | None:
        return self.binaries.get(path)

    def get_or_unknown(self, path: str) -> BinaryCapability:
        """Return known capability or a default 'unknown' descriptor."""
        if path in self.binaries:
            return self.binaries[path]
        # Check glob patterns (e.g., registry has /usr/bin/python* matching /usr/bin/python3.13)
        for reg_path, cap in self.binaries.items():
            if "*" in reg_path and fnmatch.fnmatch(path, reg_path):
                return cap
        return BinaryCapability(
            path=path,
            description="Unknown binary — not in registry",
            can_exfiltrate=True,  # conservative: assume unknown can exfil
            can_construct_http=True,  # conservative: assume unknown can make HTTP requests
        )

    def transitive_spawns(self, path: str, visited: set[str] | None = None) -> set[str]:
        """Return all binaries transitively spawned by this binary."""
        if visited is None:
            visited = set()
        if path in visited:
            return set()
        visited.add(path)

        cap = self.get(path)
        if not cap:
            return set()

        result = set(cap.spawns)
        for child in cap.spawns:
            result |= self.transitive_spawns(child, visited)
        return result


def load_binary_capability(path: Path) -> BinaryCapability:
    """Load a single binary capability descriptor from YAML."""
    with open(path) as f:  # noqa: PTH123
        raw = yaml.safe_load(f)

    protocols = []
    for p_raw in raw.get("protocols", []):
        actions = []
        for a_raw in p_raw.get("actions", []):
            actions.append(
                BinaryAction(
                    name=a_raw.get("name", ""),
                    type=ActionType(a_raw.get("type", "read")),
                    description=a_raw.get("description", ""),
                )
            )
        protocols.append(
            BinaryProtocol(
                name=p_raw.get("name", ""),
                transport=p_raw.get("transport", ""),
                description=p_raw.get("description", ""),
                bypasses_l7=p_raw.get("bypasses_l7", False),
                actions=actions,
            )
        )

    return BinaryCapability(
        path=raw.get("binary", ""),
        description=raw.get("description", ""),
        protocols=protocols,
        spawns=raw.get("spawns", []),
        can_exfiltrate=raw.get("can_exfiltrate", False),
        exfil_mechanism=raw.get("exfil_mechanism", ""),
        can_construct_http=raw.get("can_construct_http", False),
    )


def load_binary_registry(registry_dir: Path) -> BinaryRegistry:
    """Load all binary capability descriptors from a registry directory."""
    binaries = {}
    binaries_dir = registry_dir / "binaries"
    if binaries_dir.is_dir():
        for yaml_file in binaries_dir.glob("*.yaml"):
            cap = load_binary_capability(yaml_file)
            binaries[cap.path] = cap
    return BinaryRegistry(binaries=binaries)
