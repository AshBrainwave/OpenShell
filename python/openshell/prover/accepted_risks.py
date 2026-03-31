# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Load and match accepted risk annotations against findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import yaml

from .queries import Finding

if TYPE_CHECKING:
    from pathlib import Path


@dataclass
class AcceptedRisk:
    query: str
    reason: str
    accepted_by: str = ""
    binary: str = ""
    endpoint: str = ""


def load_accepted_risks(path: Path) -> list[AcceptedRisk]:
    """Load accepted risks from YAML."""
    with open(path) as f:  # noqa: PTH123
        raw = yaml.safe_load(f)

    return [
        AcceptedRisk(
            query=r.get("query", ""),
            reason=r.get("reason", ""),
            accepted_by=r.get("accepted_by", ""),
            binary=r.get("binary", ""),
            endpoint=r.get("endpoint", ""),
        )
        for r in (raw.get("accepted_risks") or [])
    ]


def _path_matches_risk(path, risk: AcceptedRisk) -> bool:
    """Check if a single finding path matches an accepted risk."""
    if risk.binary:
        path_binary = getattr(path, "binary", "") or getattr(path, "parent", "")
        if path_binary != risk.binary:
            return False

    if risk.endpoint:
        endpoint_host = getattr(path, "endpoint_host", "")
        if endpoint_host != risk.endpoint:
            return False

    return True


def apply_accepted_risks(
    findings: list[Finding],
    accepted: list[AcceptedRisk],
) -> list[Finding]:
    """Mark findings as accepted where they match accepted risk annotations.

    A finding is accepted if ALL of its paths match at least one accepted risk
    entry for that query. If only some paths match, the finding stays active
    with the unmatched paths.
    """
    if not accepted:
        return findings

    result = []
    for finding in findings:
        matching_risks = [r for r in accepted if r.query == finding.query]
        if not matching_risks:
            result.append(finding)
            continue

        if not finding.paths:
            # Pathless finding (e.g., inference relay) — accept if query matches
            accepted_finding = Finding(
                query=finding.query,
                title=finding.title,
                description=finding.description,
                risk=finding.risk,
                paths=finding.paths,
                remediation=finding.remediation,
                accepted=True,
                accepted_reason=matching_risks[0].reason,
            )
            result.append(accepted_finding)
            continue

        unmatched_paths = []
        matched_reason = ""
        for path in finding.paths:
            path_accepted = False
            for risk in matching_risks:
                if _path_matches_risk(path, risk):
                    path_accepted = True
                    matched_reason = risk.reason
                    break
            if not path_accepted:
                unmatched_paths.append(path)

        if not unmatched_paths:
            accepted_finding = Finding(
                query=finding.query,
                title=finding.title,
                description=finding.description,
                risk=finding.risk,
                paths=finding.paths,
                remediation=finding.remediation,
                accepted=True,
                accepted_reason=matched_reason,
            )
            result.append(accepted_finding)
        elif len(unmatched_paths) < len(finding.paths):
            result.append(
                Finding(
                    query=finding.query,
                    title=finding.title,
                    description=finding.description,
                    risk=finding.risk,
                    paths=unmatched_paths,
                    remediation=finding.remediation,
                )
            )
        else:
            result.append(finding)

    return result
