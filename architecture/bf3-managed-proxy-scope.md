# BF3 Managed Proxy Scope

This note marks the intended scope of branch `openshell-bf-support`.

The branch exists to absorb the reusable runtime/product code needed for the
BF3 managed-proxy architecture.

## What belongs here

- supervisor proxy changes
- protected-egress runtime support
- `openshell-vm` runtime changes
- `vf-bridge`
- DPU control agent
- DPU proxy
- shared policy/state contracts
- runtime tests for the above

## What does not belong here

- BF3 lab bring-up wrappers
- demo-specific policies
- one-off diagnostics that are only for the demo harness
- DPU SSH orchestration scripts

## Companion Repo

The BF3-specific demo/integration layer lives in:

- `/home/ubuntu/work/openshell-bf3-managed-proxy-demo`

That repo should depend on this branch, not the other way around.
