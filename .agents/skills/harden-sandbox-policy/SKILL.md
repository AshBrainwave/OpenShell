---
name: harden-sandbox-policy
description: Harden sandbox policies to minimum-access using the OpenShell Policy Prover (OPP). Fetches policies from local files or GitHub repos, runs formal verification to find gaps (L4-only endpoints, overpermissive methods, data exfiltration paths, write bypass attacks), and suggests concrete policy changes. Trigger keywords - harden policy, verify policy, prove policy, policy gaps, policy audit, opp, policy prover.
---

# Harden Sandbox Policy

Run the OpenShell Policy Prover (OPP) against a sandbox policy to find security gaps and suggest hardening changes.

## Prerequisites

- Python 3.12+ with the prover dependencies installed: `uv pip install 'openshell[prover]'`
- A sandbox policy YAML file
- A credential descriptor YAML file

## Workflow

### Step 1: Locate inputs

Find or receive the following files:
1. **Policy YAML** — the sandbox network/filesystem policy to verify
2. **Credentials YAML** — describes what credentials the sandbox has and their scopes
3. **Accepted risks YAML** (optional) — previously acknowledged risks to filter from results

If the user provides a GitHub URL or repo path, fetch the policy from there.
If the user points to a running sandbox, use `openshell policy get <name> --full` to export the current policy.

### Step 2: Run the prover

```bash
python3 -m openshell.prover.cli prove \
  --policy <policy.yaml> \
  --credentials <credentials.yaml> \
  [--accepted-risks <accepted.yaml>] \
  --compact
```

Or via the Rust CLI:
```bash
openshell policy prove \
  --policy <policy.yaml> \
  --credentials <credentials.yaml> \
  [--accepted-risks <accepted.yaml>] \
  --compact
```

### Step 3: Interpret findings

The prover returns findings at these risk levels:
- **CRITICAL** — data exfiltration via L4-only or wire protocol bypass
- **HIGH** — write bypass violating read-only intent, overpermissive HTTP methods, inconsistent L7 enforcement
- **MEDIUM** — L4-only endpoints without sibling L7, binary inheritance chains
- **ADVISORY** — inference.local side channel (architectural, always reported)

Exit code: 0 = PASS (advisories only), 1 = FAIL (critical/high gaps found), 2 = input error.

### Step 4: Suggest hardening changes

For each finding, suggest concrete policy YAML changes:

- **L4-only endpoints**: Add `protocol: rest` with `enforcement: enforce`, `tls: terminate`, and explicit `access: read-only` or method rules
- **Overpermissive methods**: Replace `method: "*"` with specific methods (e.g., `POST` for inference, `GET` for package registries)
- **Write bypass via wire protocol**: Remove binaries like `git`, `ssh`, `nc` from the policy if write access is not intended, or restrict credential scopes
- **Binary inheritance**: Review spawn chains — if a parent binary (e.g., `python3`) spawns children with L7-bypass capabilities, consider using a more specific binary path

### Step 5: Generate report (optional)

For a shareable HTML report with interactive Mermaid diagrams:
```bash
python3 -m openshell.prover.cli prove \
  --policy <policy.yaml> \
  --credentials <credentials.yaml> \
  --html report.html
```

## Workflow Chain

This skill complements `generate-sandbox-policy`:
1. `generate-sandbox-policy` — author a policy from requirements
2. `harden-sandbox-policy` — verify and tighten the authored policy
3. Iterate until the prover returns PASS

## Output Format

Report findings as a structured summary:
```
## Policy Verification Results

**Verdict:** FAIL — 3 critical/high gaps

### Findings
1. **CRITICAL** Data Exfiltration Paths Detected
   - ...
2. **HIGH** Write Bypass — Read-Only Intent Violated
   - ...

### Suggested Changes
- [ ] Add `protocol: rest` to `github.com:443` endpoint
- [ ] Remove `/usr/bin/git` from `github_readonly` binaries
- ...
```
