<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Policy Capability Engine

The `openshell-policy` crate now includes a capability-oriented layer on top of the existing YAML and protobuf sandbox policy schema.

## Data model

- Capability definitions live in the repository-level `capabilities/` directory.
- Each capability file includes:
  - `id`
  - `title`
  - `risk`
  - `description`
  - `policy_name`
  - `constraints`
  - `recommended_usage`
  - `block`
- `block` is converted into a `NetworkPolicyRule` and merged into `SandboxPolicy.network_policies`.

## Profiles

The first built-in profiles are hard-coded in `crates/openshell-policy/src/capabilities.rs`:

- `restricted`
- `medium-dev`
- `medium-api`
- `open`

Profiles resolve to capability IDs, then apply those capabilities through the same merge path as individual capability adds.

## Merge semantics

Capability application is intentionally narrow:

- `add_capability()` preserves existing rules and merges endpoints and binaries into the named policy block.
- `replace_capability()` replaces only the named policy block.
- `remove_capability()` deletes only the named policy block.

Endpoint merging matches on lowercase host plus normalized port set.

## Risk engine

`openshell-policy` exposes:

- `analyze_policy_risk()`
- `show_risk_delta()`
- `lint_policy()`

Current risk heuristics flag:

- wildcard hosts
- arbitrary-internet hosts
- messaging APIs
- `access: full`
- transport-only HTTP/REST access without L7 constraints
- broad REST path rules
- powerful network binaries such as `curl`, `wget`, `bash`, `python`, `uv`, and `pip`

The risk engine is heuristic by design. It is intended to expose likely widening, not to replace policy enforcement.
