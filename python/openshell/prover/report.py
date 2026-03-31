# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rich terminal report, Mermaid graph, and HTML report generation for verification findings."""

from __future__ import annotations

import html as html_mod
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .queries import (
    ExfilPath,
    Finding,
    InheritancePath,
    L4PolicyGapPath,
    OverpermissiveMethodPath,
    RiskLevel,
    WriteBypassPath,
)

if TYPE_CHECKING:
    from .binary_registry import BinaryRegistry
    from .policy_parser import PolicyModel

RISK_COLORS = {
    RiskLevel.CRITICAL: "bold red",
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.ADVISORY: "cyan",
}

RISK_ICONS = {
    RiskLevel.CRITICAL: "CRITICAL",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.LOW: "LOW",
    RiskLevel.ADVISORY: "ADVISORY",
}


def _hl(text: str) -> str:
    """Highlight key terms in finding summaries with rich markup."""
    highlights = {
        "L4-only": "[bold red]L4-only[/bold red]",
        "L7": "[bold green]L7[/bold green]",
        "wire protocol": "[bold red]wire protocol[/bold red]",
        "no HTTP inspection": "[bold red]no HTTP inspection[/bold red]",
        "inference.local": "[bold cyan]inference.local[/bold cyan]",
        "github.com:443": "[bold]github.com:443[/bold]",
        "api.github.com:443": "[bold]api.github.com:443[/bold]",
    }
    for term, markup in highlights.items():
        text = text.replace(term, markup)
    return text


def _compact_detail(finding: Finding) -> str:
    """Generate a short detail string for compact output."""
    if finding.query == "data_exfiltration":
        by_status: dict[str, set[str]] = {}
        for p in finding.paths:
            if hasattr(p, "l7_status") and hasattr(p, "endpoint_host"):
                by_status.setdefault(p.l7_status, set()).add(
                    f"{p.endpoint_host}:{p.endpoint_port}"
                )
        parts = []
        if "l4_only" in by_status:
            parts.append(f"L4-only: {', '.join(sorted(by_status['l4_only']))}")
        if "l7_bypassed" in by_status:
            parts.append(
                f"wire protocol bypass: {', '.join(sorted(by_status['l7_bypassed']))}"
            )
        if "l7_allows_write" in by_status:
            parts.append(f"L7 write: {', '.join(sorted(by_status['l7_allows_write']))}")
        return "; ".join(parts)
    elif finding.query == "write_bypass":
        reasons = set()
        endpoints = set()
        for p in finding.paths:
            if hasattr(p, "bypass_reason"):
                reasons.add(p.bypass_reason)
            if hasattr(p, "endpoint_host"):
                endpoints.add(f"{p.endpoint_host}:{p.endpoint_port}")
        ep_list = ", ".join(sorted(endpoints))
        if "l4_only" in reasons and "l7_bypass_protocol" in reasons:
            return f"L4-only + wire protocol: {ep_list}"
        if "l4_only" in reasons:
            return f"L4-only (no inspection): {ep_list}"
        if "l7_bypass_protocol" in reasons:
            return f"wire protocol bypasses L7: {ep_list}"
        return ""
    elif finding.query == "overpermissive_methods":
        endpoints = set()
        for p in finding.paths:
            if hasattr(p, "endpoint_host"):
                endpoints.add(f"{p.endpoint_host}:{p.endpoint_port}")
        return f'method: "*" or DELETE on: {", ".join(sorted(endpoints))}'
    elif finding.query == "l4_policy_gaps":
        endpoints = set()
        inconsistent = False
        for p in finding.paths:
            if hasattr(p, "endpoint_host"):
                endpoints.add(f"{p.endpoint_host}:{p.endpoint_port}")
            if hasattr(p, "has_sibling_l7") and p.has_sibling_l7:
                inconsistent = True
        prefix = "inconsistent enforcement" if inconsistent else "no protocol: rest"
        return f"{prefix}: {', '.join(sorted(endpoints))}"
    elif finding.query == "binary_inheritance":
        return f"{len(finding.paths)} via ancestor chain"
    return ""


def render_compact(
    findings: list[Finding],
    _policy_path: str,
    _credentials_path: str,
    console: Console | None = None,
) -> int:
    """Compact output for demos and CI. Two lines per finding: summary + detail."""
    if console is None or console.width > 72:
        console = Console(width=72)

    active = [f for f in findings if not f.accepted]
    accepted_findings = [f for f in findings if f.accepted]

    compact_titles = {
        "data_exfiltration": "Data exfiltration possible",
        "write_bypass": "Write bypass — read-only intent violated",
        "overpermissive_methods": "Overpermissive HTTP methods — destructive ops allowed",
        "l4_policy_gaps": "L4-only endpoints — no HTTP inspection",
        "binary_inheritance": "Binaries inherit unintended access",
        "inference_relay": "inference.local bypasses policy",
    }

    for finding in active:
        style = RISK_COLORS[finding.risk]
        label = RISK_ICONS[finding.risk]
        title = compact_titles.get(finding.query, finding.title)
        detail = _compact_detail(finding)

        console.print(f"  [{style}]{label:>8}[/{style}]  {_hl(title)}")
        if detail:
            console.print(f"             {_hl(detail)}")
        console.print()

    for finding in accepted_findings:
        title = compact_titles.get(finding.query, finding.title)
        console.print(f"  [dim]ACCEPTED  {title}[/dim]")

    if accepted_findings:
        console.print()

    counts = {}
    for f in active:
        counts[f.risk] = counts.get(f.risk, 0) + 1
    has_critical = RiskLevel.CRITICAL in counts
    has_high = RiskLevel.HIGH in counts
    accepted_note = f", {len(accepted_findings)} accepted" if accepted_findings else ""

    if has_critical or has_high:
        n = counts.get(RiskLevel.CRITICAL, 0) + counts.get(RiskLevel.HIGH, 0)
        console.print(
            f"  [bold white on red] FAIL [/bold white on red] {n} critical/high gaps{accepted_note}"
        )
        return 1
    elif active:
        console.print(
            f"  [bold black on yellow] PASS [/bold black on yellow] advisories only{accepted_note}"
        )
        return 0
    else:
        console.print(
            f"  [bold white on green] PASS [/bold white on green] all findings accepted{accepted_note}"
        )
        return 0


def render_report(
    findings: list[Finding],
    policy_path: str,
    credentials_path: str,
    console: Console | None = None,
) -> int:
    """Render findings to the terminal. Returns exit code (0 = clean, 1 = critical/high)."""
    if console is None or console.width > 80:
        console = Console(width=80)

    # Header
    policy_name = Path(policy_path).name
    creds_name = Path(credentials_path).name

    console.print()
    console.print(
        Panel(
            "[bold]OpenShell Policy Prover[/bold]",
            border_style="blue",
        )
    )
    console.print(f"  Policy:      {policy_name}")
    console.print(f"  Credentials: {creds_name}")
    console.print()

    active = [f for f in findings if not f.accepted]
    accepted_findings = [f for f in findings if f.accepted]

    # Summary table
    counts = {}
    for f in active:
        counts[f.risk] = counts.get(f.risk, 0) + 1

    summary = Table(title="Finding Summary", show_header=True, border_style="dim")
    summary.add_column("Risk Level", style="bold")
    summary.add_column("Count", justify="right")
    for level in [
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.ADVISORY,
    ]:
        if level in counts:
            style = RISK_COLORS[level]
            summary.add_row(
                Text(RISK_ICONS[level], style=style),
                Text(str(counts[level]), style=style),
            )
    if accepted_findings:
        summary.add_row(
            Text("ACCEPTED", style="dim"),
            Text(str(len(accepted_findings)), style="dim"),
        )
    console.print(summary)
    console.print()

    if not active and not accepted_findings:
        console.print("[bold green]No findings. Policy posture is clean.[/bold green]")
        return 0

    for i, finding in enumerate(active, 1):
        risk_style = RISK_COLORS[finding.risk]
        risk_label = RISK_ICONS[finding.risk]

        console.print(
            Panel(
                f"[{risk_style}]{risk_label}[/{risk_style}]  {finding.title}",
                border_style=risk_style,
                title=f"Finding #{i}",
                title_align="left",
            )
        )
        console.print(f"  {finding.description}")
        console.print()

        if finding.paths:
            _render_paths(console, finding.paths)

        if finding.remediation:
            console.print("  [bold]Remediation:[/bold]")
            for r in finding.remediation:
                console.print(f"    - {r}")
            console.print()

    if accepted_findings:
        console.print(Panel("[dim]Accepted Risks[/dim]", border_style="dim"))
        for finding in accepted_findings:
            console.print(f"  [dim]{RISK_ICONS[finding.risk]}  {finding.title}[/dim]")
            console.print(f"  [dim]Reason: {finding.accepted_reason}[/dim]")
            console.print()

    has_critical = RiskLevel.CRITICAL in counts
    has_high = RiskLevel.HIGH in counts
    accepted_note = f" ({len(accepted_findings)} accepted)" if accepted_findings else ""

    if has_critical:
        console.print(
            Panel(
                f"[bold red]FAIL[/bold red] — Critical gaps found.{accepted_note}",
                border_style="red",
            )
        )
        return 1
    elif has_high:
        console.print(
            Panel(
                f"[bold red]FAIL[/bold red] — High-risk gaps found.{accepted_note}",
                border_style="red",
            )
        )
        return 1
    elif active:
        console.print(
            Panel(
                f"[bold yellow]PASS[/bold yellow] — Advisories only.{accepted_note}",
                border_style="yellow",
            )
        )
        return 0
    else:
        console.print(
            Panel(
                f"[bold green]PASS[/bold green] — All findings accepted.{accepted_note}",
                border_style="green",
            )
        )
        return 0


def _render_paths(console: Console, paths: list) -> None:
    """Render finding paths as a tree or table depending on type."""
    if not paths:
        return

    first = paths[0]

    if isinstance(first, ExfilPath):
        _render_exfil_paths(console, paths)
    elif isinstance(first, WriteBypassPath):
        _render_write_bypass_paths(console, paths)
    elif isinstance(first, OverpermissiveMethodPath):
        _render_overpermissive_paths(console, paths)
    elif isinstance(first, L4PolicyGapPath):
        _render_l4_gap_paths(console, paths)
    elif isinstance(first, InheritancePath):
        _render_inheritance_paths(console, paths)


def _render_exfil_paths(console: Console, paths: list[ExfilPath]) -> None:
    table = Table(show_header=True, border_style="dim", padding=(0, 1))
    table.add_column("Binary", style="bold")
    table.add_column("Endpoint")
    table.add_column("L7 Status")
    table.add_column("Mechanism", max_width=60)

    for p in paths:
        l7_style = {
            "l4_only": "bold red",
            "l7_bypassed": "red",
            "l7_allows_write": "yellow",
        }.get(p.l7_status, "white")

        table.add_row(
            p.binary,
            f"{p.endpoint_host}:{p.endpoint_port}",
            Text(p.l7_status, style=l7_style),
            p.mechanism,
        )

    console.print(table)
    console.print()


def _render_write_bypass_paths(console: Console, paths: list[WriteBypassPath]) -> None:
    for p in paths:
        tree = Tree(f"[bold]{p.binary}[/bold] -> {p.endpoint_host}:{p.endpoint_port}")
        tree.add(f"Policy: {p.policy_name} (intent: {p.policy_intent})")
        tree.add(f"[red]Bypass: {p.bypass_reason}[/red]")
        if p.credential_actions:
            cred_branch = tree.add("Credential enables:")
            for action in p.credential_actions[:5]:
                cred_branch.add(action)
            if len(p.credential_actions) > 5:
                cred_branch.add(f"... and {len(p.credential_actions) - 5} more")
        console.print(tree)

    console.print()


def _render_overpermissive_paths(
    console: Console, paths: list[OverpermissiveMethodPath]
) -> None:
    table = Table(show_header=True, border_style="dim", padding=(0, 1))
    table.add_column("Endpoint", style="bold")
    table.add_column("Policy")
    table.add_column("Allowed")
    table.add_column("Needed")
    table.add_column("Excess", style="red")
    table.add_column("Risk Detail", max_width=40)

    seen = set()
    for p in paths:
        key = (p.endpoint_host, p.endpoint_port, p.policy_name)
        if key in seen:
            continue
        seen.add(key)
        table.add_row(
            f"{p.endpoint_host}:{p.endpoint_port}",
            p.policy_name,
            p.allowed_methods,
            p.needed_methods,
            p.excess_methods,
            p.risk_detail,
        )

    console.print(table)
    console.print()


def _render_l4_gap_paths(console: Console, paths: list[L4PolicyGapPath]) -> None:
    by_endpoint: dict[str, list[L4PolicyGapPath]] = {}
    for p in paths:
        key = f"{p.endpoint_host}:{p.endpoint_port}"
        by_endpoint.setdefault(key, []).append(p)

    for endpoint, eps in by_endpoint.items():
        first = eps[0]
        style = "red" if first.has_sibling_l7 else "yellow"
        label = "INCONSISTENT" if first.has_sibling_l7 else "L4-ONLY"
        tree = Tree(
            f"[{style}]{label}[/{style}]  [{style} bold]{endpoint}[/{style} bold]"
            f"  (policy: {first.policy_name})"
        )
        binaries = sorted({p.binary for p in eps})
        tree.add(f"Binaries: {', '.join(binaries)}")
        tree.add(f"[dim]{first.detail}[/dim]")
        console.print(tree)

    console.print()


def _render_inheritance_paths(console: Console, paths: list[InheritancePath]) -> None:
    by_parent: dict[str, list[InheritancePath]] = {}
    for p in paths:
        by_parent.setdefault(p.parent, []).append(p)

    for parent, children in by_parent.items():
        tree = Tree(f"[bold]{parent}[/bold] (allowed by policy)")
        for child in children:
            caps = ", ".join(child.child_capabilities)
            style = "red" if "bypasses_l7" in child.child_capabilities else "yellow"
            tree.add(f"[{style}]{child.child}[/{style}] — [{style}]{caps}[/{style}]")
        console.print(tree)

    console.print()


def _m_id(prefix: str, s: str) -> str:
    """Generate a Mermaid-safe node ID from a string."""
    return (
        prefix
        + "_"
        + s.replace("/", "_")
        .replace(".", "_")
        .replace(":", "_")
        .replace("-", "_")
        .replace("*", "star")
    )


def _m_escape(s: str) -> str:
    """Escape a string for use in Mermaid labels."""
    return s.replace('"', "'").replace("<", "&lt;").replace(">", "&gt;")


def _m_short_binary(path: str) -> str:
    """Shorten a binary path for display."""
    return path.rsplit("/", 1)[-1]


def generate_mermaid(findings: list[Finding]) -> str:
    """Generate a Mermaid findings graph showing all risk paths across query types."""
    lines = [
        "flowchart LR",
        "",
        "    %% Style definitions",
        "    classDef l4only fill:#e74c3c,stroke:#c0392b,color:#fff",
        "    classDef l7bypass fill:#e67e22,stroke:#d35400,color:#fff",
        "    classDef l7write fill:#f39c12,stroke:#e67e22,color:#fff",
        "    classDef l7safe fill:#27ae60,stroke:#1e8449,color:#fff",
        "    classDef binary fill:#3498db,stroke:#2980b9,color:#fff",
        "    classDef filesystem fill:#95a5a6,stroke:#7f8c8d,color:#fff",
        "    classDef overperm fill:#e74c3c,stroke:#c0392b,color:#fff",
        "    classDef inherited fill:#9b59b6,stroke:#8e44ad,color:#fff",
        "",
    ]

    declared_nodes: set[str] = set()
    edges: list[str] = []

    exfil_paths: list[ExfilPath] = []
    write_bypasses: list[WriteBypassPath] = []
    overperm_paths: list[OverpermissiveMethodPath] = []
    l4_gaps: list[L4PolicyGapPath] = []
    inherit_paths: list[InheritancePath] = []

    for finding in findings:
        if finding.accepted:
            continue
        for p in finding.paths:
            if isinstance(p, ExfilPath):
                exfil_paths.append(p)
            elif isinstance(p, WriteBypassPath):
                write_bypasses.append(p)
            elif isinstance(p, OverpermissiveMethodPath):
                overperm_paths.append(p)
            elif isinstance(p, L4PolicyGapPath):
                l4_gaps.append(p)
            elif isinstance(p, InheritancePath):
                inherit_paths.append(p)

    # Filesystem source node
    if exfil_paths:
        fs_id = "FS"
        if fs_id not in declared_nodes:
            lines.append(f'    {fs_id}[("Filesystem — readable paths")]:::filesystem')
            declared_nodes.add(fs_id)

    # Exfiltration paths
    if exfil_paths:
        lines.append("")
        lines.append("    subgraph exfil [Data Exfiltration]")
        lines.append("    direction LR")

        seen_exfil: set[tuple[str, str, int]] = set()
        for p in exfil_paths:
            key = (p.binary, p.endpoint_host, p.endpoint_port)
            if key in seen_exfil:
                continue
            seen_exfil.add(key)

            b_id = _m_id("B", p.binary)
            e_id = _m_id("E", f"{p.endpoint_host}_{p.endpoint_port}")

            if b_id not in declared_nodes:
                lines.append(f'    {b_id}["{_m_short_binary(p.binary)}"]:::binary')
                declared_nodes.add(b_id)

            style_class = {
                "l4_only": "l4only",
                "l7_bypassed": "l7bypass",
                "l7_allows_write": "l7write",
            }.get(p.l7_status, "l7write")
            label_text = {
                "l4_only": "L4 only",
                "l7_bypassed": "wire protocol",
                "l7_allows_write": "L7 write",
            }.get(p.l7_status, "")

            if e_id not in declared_nodes:
                lines.append(
                    f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}"]:::{style_class}'
                )
                declared_nodes.add(e_id)

            edges.append(f"    FS -.->|read| {b_id}")
            edges.append(f"    {b_id} -->|{label_text}| {e_id}")

        lines.append("    end")

    # Write bypass paths
    if write_bypasses:
        lines.append("")
        lines.append("    subgraph wbypass [Write Bypass]")
        lines.append("    direction LR")

        seen_wb: set[tuple[str, str, int]] = set()
        for p in write_bypasses:
            key = (p.binary, p.endpoint_host, p.endpoint_port)
            if key in seen_wb:
                continue
            seen_wb.add(key)

            b_id = _m_id("B", p.binary)
            e_id = _m_id("WE", f"{p.endpoint_host}_{p.endpoint_port}")

            if b_id not in declared_nodes:
                lines.append(f'    {b_id}["{_m_short_binary(p.binary)}"]:::binary')
                declared_nodes.add(b_id)

            reason_label = {
                "l4_only": "L4 bypass",
                "l7_bypass_protocol": "wire protocol",
            }.get(p.bypass_reason, p.bypass_reason)
            if e_id not in declared_nodes:
                lines.append(
                    f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}'
                    f'<br/>intent: {p.policy_intent}"]:::l4only'
                )
                declared_nodes.add(e_id)

            edges.append(f"    {b_id} ==>|{reason_label}| {e_id}")

        lines.append("    end")

    # Overpermissive methods
    if overperm_paths:
        lines.append("")
        lines.append("    subgraph operm [Overpermissive Methods]")
        lines.append("    direction LR")

        seen_op: set[tuple[str, int, str]] = set()
        for p in overperm_paths:
            key = (p.endpoint_host, p.endpoint_port, p.policy_name)
            if key in seen_op:
                continue
            seen_op.add(key)

            e_id = _m_id("OP", f"{p.endpoint_host}_{p.endpoint_port}")
            if e_id not in declared_nodes:
                excess = (
                    p.excess_methods if len(p.excess_methods) < 30 else "DELETE, ..."
                )
                lines.append(
                    f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}'
                    f'<br/>excess: {_m_escape(excess)}"]:::overperm'
                )
                declared_nodes.add(e_id)

        lines.append("    end")

    # L4 policy gaps
    if l4_gaps:
        lines.append("")
        lines.append("    subgraph l4gap [L4 Policy Gaps]")
        lines.append("    direction LR")

        seen_l4: set[tuple[str, int]] = set()
        for p in l4_gaps:
            key = (p.endpoint_host, p.endpoint_port)
            if key in seen_l4:
                continue
            seen_l4.add(key)

            e_id = _m_id("L4", f"{p.endpoint_host}_{p.endpoint_port}")
            label_suffix = "INCONSISTENT" if p.has_sibling_l7 else "no L7"
            if e_id not in declared_nodes:
                lines.append(
                    f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}'
                    f'<br/>{label_suffix}"]:::l4only'
                )
                declared_nodes.add(e_id)

            b_id = _m_id("B", p.binary)
            if b_id not in declared_nodes:
                lines.append(f'    {b_id}["{_m_short_binary(p.binary)}"]:::binary')
                declared_nodes.add(b_id)

            edges.append(f"    {b_id} -.->|no inspection| {e_id}")

        lines.append("    end")

    # Binary inheritance
    if inherit_paths:
        lines.append("")
        lines.append("    subgraph inherit [Binary Inheritance]")
        lines.append("    direction TB")

        seen_inh: set[tuple[str, str]] = set()
        for p in inherit_paths:
            key = (p.parent, p.child)
            if key in seen_inh:
                continue
            seen_inh.add(key)

            parent_id = _m_id("IB", p.parent)
            child_id = _m_id("IC", p.child)

            if parent_id not in declared_nodes:
                lines.append(f'    {parent_id}["{_m_short_binary(p.parent)}"]:::binary')
                declared_nodes.add(parent_id)
            if child_id not in declared_nodes:
                caps = ", ".join(p.child_capabilities)
                style = (
                    "l7bypass" if "bypasses_l7" in p.child_capabilities else "inherited"
                )
                lines.append(
                    f'    {child_id}["{_m_short_binary(p.child)}'
                    f'<br/>{_m_escape(caps)}"]:::{style}'
                )
                declared_nodes.add(child_id)

            edges.append(f"    {parent_id} -->|spawns| {child_id}")

        lines.append("    end")

    # Add all edges after subgraphs
    if edges:
        lines.append("")
        lines.append("    %% Edges")
        for edge in dict.fromkeys(edges):
            lines.append(edge)

    if not any([exfil_paths, write_bypasses, overperm_paths, l4_gaps, inherit_paths]):
        lines.append("    PASS([No active findings]):::l7safe")

    return "\n".join(lines)


def generate_mermaid_topology(
    policy: PolicyModel,
    binary_registry: BinaryRegistry,
    findings: list[Finding],
) -> str:
    """Generate a full policy topology map showing all endpoints, binaries, and enforcement levels."""
    lines = [
        "flowchart LR",
        "",
        "    %% Style definitions",
        "    classDef l4only fill:#e74c3c,stroke:#c0392b,color:#fff",
        "    classDef l7enforce fill:#27ae60,stroke:#1e8449,color:#fff",
        "    classDef l7warn fill:#f39c12,stroke:#e67e22,color:#fff",
        "    classDef binary fill:#3498db,stroke:#2980b9,color:#fff",
        "    classDef child fill:#9b59b6,stroke:#8e44ad,color:#fff",
        "    classDef filesystem fill:#95a5a6,stroke:#7f8c8d,color:#fff",
        "    classDef finding fill:#e74c3c,stroke:#c0392b,color:#fff,stroke-width:3px",
        "",
    ]

    declared: set[str] = set()
    edges: list[str] = []

    problem_endpoints: set[tuple[str, int]] = set()
    problem_binaries: set[str] = set()
    for f in findings:
        if f.accepted:
            continue
        if f.query in ("l4_policy_gaps", "overpermissive_methods", "write_bypass"):
            for p in f.paths:
                if hasattr(p, "endpoint_host"):
                    problem_endpoints.add(
                        (p.endpoint_host, getattr(p, "endpoint_port", 443))
                    )
                if hasattr(p, "binary"):
                    problem_binaries.add(p.binary)

    # Filesystem
    lines.append('    FS[("Filesystem")]:::filesystem')
    declared.add("FS")

    # Endpoints by policy group
    for policy_name, rule in policy.network_policies.items():
        safe_name = policy_name.replace("-", "_").replace(" ", "_")
        lines.append("")
        lines.append(f"    subgraph {safe_name} [{policy_name}]")
        lines.append("    direction TB")

        for ep in rule.endpoints:
            for port in ep.effective_ports:
                e_id = _m_id("E", f"{ep.host}_{port}")
                if e_id in declared:
                    continue
                declared.add(e_id)

                is_problem = (ep.host, port) in problem_endpoints

                if ep.is_l7_enforced:
                    methods = ep.allowed_methods
                    has_write = (
                        bool(methods & {"POST", "PUT", "PATCH", "DELETE"})
                        if methods
                        else True
                    )
                    has_delete = "DELETE" in methods if methods else True
                    has_wildcard = any(r.method == "*" for r in ep.rules)

                    if has_wildcard or has_delete:
                        style = "l7warn"
                        enforcement_label = (
                            "L7 method:*" if has_wildcard else "L7 +DELETE"
                        )
                    elif has_write:
                        style = "l7enforce"
                        enforcement_label = "L7 " + ",".join(
                            sorted(methods - {"HEAD", "OPTIONS"})
                        )
                    else:
                        style = "l7enforce"
                        enforcement_label = "L7 read-only"
                else:
                    style = "l4only"
                    enforcement_label = "L4 only"

                if is_problem:
                    style = "finding"

                lines.append(
                    f'    {e_id}["{_m_escape(ep.host)}:{port}<br/>{enforcement_label}"]:::{style}'
                )

        lines.append("    end")

    # Binaries and their connections
    lines.append("")
    lines.append("    subgraph binaries [Binaries]")
    lines.append("    direction TB")

    all_binaries: dict[str, list[tuple[str, str]]] = {}
    for policy_name, rule in policy.network_policies.items():
        for b in rule.binaries:
            for ep in rule.endpoints:
                for port in ep.effective_ports:
                    e_id = _m_id("E", f"{ep.host}_{port}")
                    all_binaries.setdefault(b.path, []).append((policy_name, e_id))

    for bpath in all_binaries:
        b_id = _m_id("B", bpath)
        if b_id not in declared:
            style = "finding" if bpath in problem_binaries else "binary"
            lines.append(f'    {b_id}["{_m_short_binary(bpath)}"]:::{style}')
            declared.add(b_id)

    # Spawn chains
    for bpath in all_binaries:
        children = binary_registry.transitive_spawns(bpath)
        for child in children:
            child_id = _m_id("C", child)
            if child_id not in declared:
                cap = binary_registry.get_or_unknown(child)
                caps = []
                if cap.bypasses_l7:
                    caps.append("L7-bypass")
                if cap.can_exfiltrate:
                    caps.append("exfil")
                if cap.can_construct_http:
                    caps.append("http")
                cap_str = f"<br/>{', '.join(caps)}" if caps else ""
                lines.append(
                    f'    {child_id}["{_m_short_binary(child)}{cap_str}"]:::child'
                )
                declared.add(child_id)

            b_id = _m_id("B", bpath)
            edges.append(f"    {b_id} -.->|spawns| {child_id}")

    lines.append("    end")

    # Binary -> Endpoint edges
    lines.append("")
    lines.append("    %% Binary -> Endpoint access")
    for bpath, endpoint_ids in all_binaries.items():
        b_id = _m_id("B", bpath)
        for _, e_id in endpoint_ids:
            edges.append(f"    {b_id} --> {e_id}")

    # Filesystem -> Binary edges (for exfil-capable binaries)
    for bpath in all_binaries:
        cap = binary_registry.get_or_unknown(bpath)
        if cap.can_exfiltrate:
            b_id = _m_id("B", bpath)
            edges.append(f"    FS -.->|read| {b_id}")

    # Deduplicated edges
    if edges:
        lines.append("")
        lines.append("    %% Edges")
        for edge in dict.fromkeys(edges):
            lines.append(edge)

    return "\n".join(lines)


# Per-finding focused Mermaid diagrams

_MERMAID_STYLES = """\
    classDef l4only fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef l7bypass fill:#e67e22,stroke:#d35400,color:#fff
    classDef l7write fill:#f39c12,stroke:#e67e22,color:#fff
    classDef l7safe fill:#27ae60,stroke:#1e8449,color:#fff
    classDef binary fill:#3498db,stroke:#2980b9,color:#fff
    classDef filesystem fill:#95a5a6,stroke:#7f8c8d,color:#fff
    classDef overperm fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef inherited fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef finding fill:#e74c3c,stroke:#c0392b,color:#fff,stroke-width:3px
    classDef l7enforce fill:#27ae60,stroke:#1e8449,color:#fff
    classDef l7warn fill:#f39c12,stroke:#e67e22,color:#fff
    classDef child fill:#9b59b6,stroke:#8e44ad,color:#fff"""


def _mermaid_for_l4_gaps(finding: Finding) -> str:
    """Focused diagram: which endpoints are missing L7 and which binaries reach them."""
    lines = ["flowchart LR", _MERMAID_STYLES, ""]
    declared: set[str] = set()

    by_ep: dict[tuple[str, int], list[L4PolicyGapPath]] = {}
    for p in finding.paths:
        if isinstance(p, L4PolicyGapPath):
            by_ep.setdefault((p.endpoint_host, p.endpoint_port), []).append(p)

    for (host, port), ep_paths in by_ep.items():
        e_id = _m_id("E", f"{host}_{port}")
        first = ep_paths[0]
        label = "INCONSISTENT" if first.has_sibling_l7 else "no L7"
        lines.append(f'    {e_id}["{_m_escape(host)}:{port}<br/>{label}"]:::l4only')
        declared.add(e_id)

        for p in ep_paths:
            b_id = _m_id("B", p.binary)
            if b_id not in declared:
                lines.append(f'    {b_id}["{_m_short_binary(p.binary)}"]:::binary')
                declared.add(b_id)
            lines.append(f"    {b_id} -->|no inspection| {e_id}")

    return "\n".join(lines)


def _mermaid_for_overperm(finding: Finding) -> str:
    """Focused diagram: endpoints with wildcard/excess methods."""
    lines = ["flowchart LR", _MERMAID_STYLES, ""]
    seen: set[tuple[str, int]] = set()

    for p in finding.paths:
        if not isinstance(p, OverpermissiveMethodPath):
            continue
        key = (p.endpoint_host, p.endpoint_port)
        if key in seen:
            continue
        seen.add(key)

        e_id = _m_id("E", f"{p.endpoint_host}_{p.endpoint_port}")
        needed_id = _m_id("N", f"{p.endpoint_host}_{p.endpoint_port}")
        excess_id = _m_id("X", f"{p.endpoint_host}_{p.endpoint_port}")

        lines.append(
            f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}'
            f'<br/>policy: {p.policy_name}"]:::binary'
        )
        lines.append(f'    {needed_id}(["{_m_escape(p.needed_methods)}"]):::l7safe')
        lines.append(f'    {excess_id}(["{_m_escape(p.excess_methods)}"]):::overperm')
        lines.append(f"    {e_id} -->|needed| {needed_id}")
        lines.append(f"    {e_id} -->|excess| {excess_id}")

    return "\n".join(lines)


def _mermaid_for_write_bypass(finding: Finding) -> str:
    """Focused diagram: how writes bypass read-only intent."""
    lines = ["flowchart LR", _MERMAID_STYLES, ""]
    declared: set[str] = set()

    seen: set[tuple[str, str, int]] = set()
    for p in finding.paths:
        if not isinstance(p, WriteBypassPath):
            continue
        key = (p.binary, p.endpoint_host, p.endpoint_port)
        if key in seen:
            continue
        seen.add(key)

        b_id = _m_id("B", p.binary)
        e_id = _m_id("E", f"{p.endpoint_host}_{p.endpoint_port}")

        if b_id not in declared:
            lines.append(f'    {b_id}["{_m_short_binary(p.binary)}"]:::binary')
            declared.add(b_id)
        if e_id not in declared:
            lines.append(
                f'    {e_id}["{_m_escape(p.endpoint_host)}:{p.endpoint_port}'
                f'<br/>intent: {p.policy_intent}"]:::l4only'
            )
            declared.add(e_id)

        reason = {
            "l4_only": "L4 bypass",
            "l7_bypass_protocol": "wire protocol",
        }.get(p.bypass_reason, p.bypass_reason)
        lines.append(f"    {b_id} ==>|{reason}| {e_id}")

        if p.credential_actions:
            c_id = _m_id("CR", f"{p.endpoint_host}_{p.endpoint_port}")
            if c_id not in declared:
                acts = p.credential_actions[:3]
                if len(p.credential_actions) > 3:
                    acts.append(f"+{len(p.credential_actions) - 3} more")
                label = "<br/>".join(_m_escape(a) for a in acts)
                lines.append(f'    {c_id}["{label}"]:::overperm')
                declared.add(c_id)
            lines.append(f"    {e_id} -.->|credential enables| {c_id}")

    return "\n".join(lines)


def _mermaid_for_exfil(finding: Finding) -> str:
    """Focused diagram: exfiltration paths grouped by mechanism type."""
    lines = ["flowchart LR", _MERMAID_STYLES, ""]
    declared: set[str] = set()

    lines.append('    FS[("Filesystem — readable paths")]:::filesystem')
    declared.add("FS")

    by_status: dict[str, list[ExfilPath]] = {}
    seen: set[tuple[str, str, int]] = set()
    for p in finding.paths:
        if not isinstance(p, ExfilPath):
            continue
        key = (p.binary, p.endpoint_host, p.endpoint_port)
        if key in seen:
            continue
        seen.add(key)
        by_status.setdefault(p.l7_status, []).append(p)

    status_labels = {
        "l4_only": "L4-only — no inspection",
        "l7_bypassed": "Wire Protocol Bypass",
        "l7_allows_write": "L7 Write Channels",
    }

    for status, status_paths in by_status.items():
        label = status_labels.get(status, status)
        safe = "sg_" + status.replace("_", "")
        lines.append(f"    subgraph {safe} [{label}]")
        lines.append("    direction LR")

        style_class = {
            "l4_only": "l4only",
            "l7_bypassed": "l7bypass",
            "l7_allows_write": "l7write",
        }.get(status, "l7write")

        by_binary: dict[str, list[str]] = {}
        for p in status_paths:
            by_binary.setdefault(p.binary, []).append(
                f"{p.endpoint_host}:{p.endpoint_port}"
            )

        for bpath, endpoints in by_binary.items():
            b_id = _m_id("B", f"{bpath}_{status}")
            if b_id not in declared:
                lines.append(f'    {b_id}["{_m_short_binary(bpath)}"]:::binary')
                declared.add(b_id)

            shown = endpoints[:4]
            for ep_str in shown:
                e_id = _m_id("E", f"{ep_str}_{status}")
                if e_id not in declared:
                    lines.append(f'    {e_id}["{_m_escape(ep_str)}"]:::{style_class}')
                    declared.add(e_id)
                lines.append(f"    {b_id} --> {e_id}")

            if len(endpoints) > 4:
                more_id = _m_id("M", f"{bpath}_{status}")
                lines.append(
                    f'    {more_id}["+{len(endpoints) - 4} more"]:::{style_class}'
                )
                lines.append(f"    {b_id} --> {more_id}")

        lines.append("    end")
        for bpath in by_binary:
            b_id = _m_id("B", f"{bpath}_{status}")
            lines.append(f"    FS -.-> {b_id}")

    return "\n".join(lines)


def _mermaid_for_inheritance(finding: Finding) -> str:
    """Focused diagram: spawn tree from allowed binaries to inherited children."""
    lines = ["flowchart TB", _MERMAID_STYLES, ""]
    declared: set[str] = set()

    seen_pairs: set[tuple[str, str]] = set()
    for p in finding.paths:
        if not isinstance(p, InheritancePath):
            continue
        key = (p.parent, p.child)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)

        parent_id = _m_id("P", p.parent)
        child_id = _m_id("C", p.child)

        if parent_id not in declared:
            lines.append(
                f'    {parent_id}["{_m_short_binary(p.parent)}<br/>allowed by policy"]:::binary'
            )
            declared.add(parent_id)

        if child_id not in declared:
            caps = ", ".join(p.child_capabilities)
            style = "l7bypass" if "bypasses_l7" in p.child_capabilities else "inherited"
            lines.append(
                f'    {child_id}["{_m_short_binary(p.child)}<br/>{_m_escape(caps)}"]:::{style}'
            )
            declared.add(child_id)

        lines.append(f"    {parent_id} -->|spawns| {child_id}")

    return "\n".join(lines)


# HTML Report

_FINDING_DIAGRAM_GENERATORS = {
    "l4_policy_gaps": _mermaid_for_l4_gaps,
    "overpermissive_methods": _mermaid_for_overperm,
    "write_bypass": _mermaid_for_write_bypass,
    "data_exfiltration": _mermaid_for_exfil,
    "binary_inheritance": _mermaid_for_inheritance,
}

_RISK_COLORS_HTML = {
    RiskLevel.CRITICAL: "#e74c3c",
    RiskLevel.HIGH: "#e67e22",
    RiskLevel.MEDIUM: "#f39c12",
    RiskLevel.LOW: "#27ae60",
    RiskLevel.ADVISORY: "#3498db",
}

_RISK_BG_COLORS_HTML = {
    RiskLevel.CRITICAL: "#fdedec",
    RiskLevel.HIGH: "#fdebd0",
    RiskLevel.MEDIUM: "#fef9e7",
    RiskLevel.LOW: "#eafaf1",
    RiskLevel.ADVISORY: "#ebf5fb",
}


def render_html(
    findings: list[Finding],
    policy_path: str,
    _credentials_path: str,
    policy: PolicyModel,
    binary_registry: BinaryRegistry,
    output_path: Path,
) -> int:
    """Render findings as a self-contained HTML file with per-finding Mermaid diagrams."""
    policy_name = Path(policy_path).name
    active = [f for f in findings if not f.accepted]
    accepted_findings = [f for f in findings if f.accepted]

    counts: dict[RiskLevel, int] = {}
    for f in active:
        counts[f.risk] = counts.get(f.risk, 0) + 1

    has_critical = RiskLevel.CRITICAL in counts
    has_high = RiskLevel.HIGH in counts
    verdict_pass = not (has_critical or has_high)

    finding_sections = []
    for _i, finding in enumerate(active, 1):
        color = _RISK_COLORS_HTML[finding.risk]
        bg = _RISK_BG_COLORS_HTML[finding.risk]
        risk_label = finding.risk.value.upper()

        diagram_html = ""
        gen = _FINDING_DIAGRAM_GENERATORS.get(finding.query)
        if gen and finding.paths:
            mermaid_code = gen(finding)
            diagram_html = f'<div class="mermaid">\n{mermaid_code}\n</div>'

        remediation_html = ""
        if finding.remediation:
            items = "".join(
                f"<li>{html_mod.escape(r)}</li>" for r in finding.remediation
            )
            remediation_html = f"<h4>Remediation</h4><ul>{items}</ul>"

        finding_sections.append(f"""
        <div class="finding" style="border-left: 4px solid {color}; background: {bg};">
            <div class="finding-header">
                <span class="risk-badge" style="background: {color};">{risk_label}</span>
                <span class="finding-title">{html_mod.escape(finding.title)}</span>
            </div>
            <p class="finding-desc">{html_mod.escape(finding.description)}</p>
            {diagram_html}
            {remediation_html}
        </div>""")

    accepted_html = ""
    if accepted_findings:
        items = []
        for f in accepted_findings:
            items.append(
                f"<li><strong>{f.risk.value.upper()}</strong> {html_mod.escape(f.title)}"
                f"<br/><em>{html_mod.escape(f.accepted_reason)}</em></li>"
            )
        accepted_html = f"""
        <div class="accepted-section">
            <h2>Accepted Risks</h2>
            <ul>{"".join(items)}</ul>
        </div>"""

    summary_badges = []
    for level in [
        RiskLevel.CRITICAL,
        RiskLevel.HIGH,
        RiskLevel.MEDIUM,
        RiskLevel.LOW,
        RiskLevel.ADVISORY,
    ]:
        if level in counts:
            color = _RISK_COLORS_HTML[level]
            summary_badges.append(
                f'<span class="risk-badge" style="background: {color};">'
                f"{counts[level]} {level.value.upper()}</span>"
            )
    if accepted_findings:
        summary_badges.append(
            f'<span class="risk-badge" style="background: #95a5a6;">'
            f"{len(accepted_findings)} ACCEPTED</span>"
        )

    verdict_color = "#27ae60" if verdict_pass else "#e74c3c"
    verdict_text = "PASS" if verdict_pass else "FAIL"
    if verdict_pass and accepted_findings:
        verdict_detail = "All findings accepted"
    elif verdict_pass and active:
        verdict_detail = "Advisories only"
    elif not verdict_pass:
        n = counts.get(RiskLevel.CRITICAL, 0) + counts.get(RiskLevel.HIGH, 0)
        verdict_detail = f"{n} critical/high gap{'s' if n != 1 else ''}"
    else:
        verdict_detail = "No findings"

    topology_mermaid = generate_mermaid_topology(policy, binary_registry, findings)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>OPP Report — {html_mod.escape(policy_name)}</title>
<style>
    :root {{ --bg: #fafafa; --text: #2c3e50; --border: #e0e0e0; --card-bg: #fff; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, sans-serif;
           background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1100px; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
    h2 {{ font-size: 1.2rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
    h4 {{ font-size: 0.9rem; margin: 1rem 0 0.5rem; color: #555; }}
    .subtitle {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .verdict {{ display: inline-block; padding: 0.4rem 1rem; border-radius: 4px; color: #fff;
                font-weight: 700; font-size: 1.1rem; margin-bottom: 0.25rem; }}
    .verdict-detail {{ color: #666; font-size: 0.9rem; margin-left: 0.5rem; }}
    .summary {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 1rem 0; }}
    .risk-badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 3px;
                   color: #fff; font-size: 0.8rem; font-weight: 600; }}
    .finding {{ background: var(--card-bg); border-radius: 6px; padding: 1.25rem; margin-bottom: 1.25rem; }}
    .finding-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
    .finding-title {{ font-weight: 600; font-size: 1rem; }}
    .finding-desc {{ color: #555; font-size: 0.9rem; margin-bottom: 1rem; }}
    .finding ul {{ padding-left: 1.5rem; font-size: 0.85rem; color: #555; }}
    .finding li {{ margin-bottom: 0.3rem; }}
    .mermaid {{ background: #fff; border: 1px solid var(--border); border-radius: 4px;
                padding: 1rem; margin: 1rem 0; overflow-x: auto; }}
    .accepted-section {{ background: #f5f5f5; border-radius: 6px; padding: 1.25rem; margin-top: 2rem; }}
    .accepted-section ul {{ padding-left: 1.5rem; font-size: 0.85rem; color: #666; }}
    .accepted-section li {{ margin-bottom: 0.5rem; }}
    .topology-section {{ margin-top: 2rem; }}
    .legend {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.75rem 0; font-size: 0.8rem; }}
    .legend-item {{ display: flex; align-items: center; gap: 0.3rem; }}
    .legend-swatch {{ width: 14px; height: 14px; border-radius: 3px; display: inline-block; }}
    footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
              font-size: 0.8rem; color: #999; }}
</style>
</head>
<body>

<h1>OpenShell Policy Prover</h1>
<div class="subtitle">Policy: {html_mod.escape(policy_name)}</div>

<div>
    <span class="verdict" style="background: {verdict_color};">{verdict_text}</span>
    <span class="verdict-detail">{html_mod.escape(verdict_detail)}</span>
</div>
<div class="summary">{"".join(summary_badges)}</div>

<h2>Findings</h2>
{"".join(finding_sections) if finding_sections else '<p style="color: #27ae60; font-weight: 600;">No active findings.</p>'}

{accepted_html}

<div class="topology-section">
    <h2>Policy Topology</h2>
    <p style="color: #666; font-size: 0.9rem; margin-bottom: 0.5rem;">
        Full map of all endpoints, binaries, and enforcement levels.
        Red nodes have structural findings. Green nodes are properly configured.
    </p>
    <div class="legend">
        <span class="legend-item"><span class="legend-swatch" style="background: #27ae60;"></span> L7 enforced</span>
        <span class="legend-item"><span class="legend-swatch" style="background: #f39c12;"></span> L7 warn (wildcard)</span>
        <span class="legend-item"><span class="legend-swatch" style="background: #e74c3c;"></span> L4 only / finding</span>
        <span class="legend-item"><span class="legend-swatch" style="background: #3498db;"></span> Binary</span>
        <span class="legend-item"><span class="legend-swatch" style="background: #9b59b6;"></span> Inherited child</span>
    </div>
    <div class="mermaid">
{topology_mermaid}
    </div>
</div>

<footer>
    Generated by OpenShell Policy Prover (OPP)
</footer>

<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script>mermaid.initialize({{ startOnLoad: true, theme: "neutral", securityLevel: "loose" }});</script>
</body>
</html>"""

    output_path.write_text(page)
    return 1 if not verdict_pass else 0
