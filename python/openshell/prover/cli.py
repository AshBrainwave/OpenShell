# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for OpenShell Policy Prover (OPP)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from .binary_registry import load_binary_registry
from .credential_loader import load_credential_set
from .policy_parser import parse_policy
from .queries import run_all_queries
from .report import render_report
from .z3_model import build_model

_DEFAULT_REGISTRY = Path(__file__).parent / "registry"


def main():
    parser = argparse.ArgumentParser(
        prog="opp",
        description="OpenShell Policy Prover — formal verification for sandbox policies",
    )
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser(
        "prove",
        help="Prove properties of a sandbox policy — or find counterexamples",
    )
    verify_parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Path to OpenShell sandbox policy YAML",
    )
    verify_parser.add_argument(
        "--credentials",
        required=True,
        type=Path,
        help="Path to credential descriptor YAML",
    )
    verify_parser.add_argument(
        "--registry",
        type=Path,
        default=_DEFAULT_REGISTRY,
        help="Path to capability registry directory (default: bundled registry)",
    )
    verify_parser.add_argument(
        "--accepted-risks",
        type=Path,
        default=None,
        help="Path to accepted risks YAML (findings matching these are marked accepted)",
    )
    verify_parser.add_argument(
        "--compact",
        action="store_true",
        help="One-line-per-finding output (for demos and CI)",
    )
    verify_parser.add_argument(
        "--color",
        action="store_true",
        help="Force colored output even when piped",
    )
    verify_parser.add_argument(
        "--mermaid",
        action="store_true",
        help="Output Mermaid findings graph (risk paths by query type)",
    )
    verify_parser.add_argument(
        "--mermaid-topology",
        action="store_true",
        help="Output Mermaid policy topology map (all endpoints, binaries, enforcement levels)",
    )
    verify_parser.add_argument(
        "--html",
        type=Path,
        default=None,
        metavar="PATH",
        help="Output self-contained HTML report with interactive diagrams (e.g., --html report.html)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "prove":
        exit_code = cmd_prove(args)
        sys.exit(exit_code)


def cmd_prove(args) -> int:
    """Execute the prove command."""
    console = Console(force_terminal=args.color) if args.color else Console()

    # Load inputs
    try:
        policy = parse_policy(args.policy)
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        return 2

    try:
        credential_set = load_credential_set(args.credentials, args.registry)
    except Exception as e:
        console.print(f"[red]Error loading credentials: {e}[/red]")
        return 2

    try:
        binary_registry = load_binary_registry(args.registry)
    except Exception as e:
        console.print(f"[red]Error loading binary registry: {e}[/red]")
        return 2

    # Build model
    model = build_model(policy, credential_set, binary_registry)

    # Run queries
    findings = run_all_queries(model)

    # Apply accepted risks
    if args.accepted_risks:
        try:
            from .accepted_risks import apply_accepted_risks, load_accepted_risks

            accepted = load_accepted_risks(args.accepted_risks)
            findings = apply_accepted_risks(findings, accepted)
        except Exception as e:
            console.print(f"[red]Error loading accepted risks: {e}[/red]")
            return 2

    # Render
    has_critical_high = any(
        f.risk.value in ("critical", "high") and not f.accepted for f in findings
    )
    if args.html:
        from .report import render_html

        exit_code = render_html(
            findings,
            str(args.policy),
            str(args.credentials),
            policy,
            binary_registry,
            args.html,
        )
        console.print(f"Report written to {args.html}")
        return exit_code
    elif args.mermaid_topology:
        from .report import generate_mermaid_topology

        print(generate_mermaid_topology(policy, binary_registry, findings))
        return 1 if has_critical_high else 0
    elif args.mermaid:
        from .report import generate_mermaid

        print(generate_mermaid(findings))
        return 1 if has_critical_high else 0
    elif args.compact:
        from .report import render_compact

        return render_compact(
            findings,
            str(args.policy),
            str(args.credentials),
            console=console,
        )
    else:
        return render_report(
            findings,
            str(args.policy),
            str(args.credentials),
            console=console,
        )


if __name__ == "__main__":
    main()
