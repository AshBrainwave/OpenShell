# Custom libkrunfw Runtime

This directory contains the build infrastructure for a custom `libkrunfw` runtime
that enables bridge CNI and netfilter support in the OpenShell gateway VM.

## Why

The stock `libkrunfw` (from Homebrew) ships a kernel without bridge, netfilter,
or conntrack support. This means the VM cannot:

- Create `cni0` bridge interfaces (required by the bridge CNI plugin)
- Run kube-proxy (requires iptables/nftables)
- Route service VIP traffic (requires NAT/conntrack)

The custom runtime builds libkrunfw with an additional kernel config fragment
that enables these features.

## Directory Structure

```
runtime/
  build-custom-libkrunfw.sh   # Build script for custom libkrunfw
  kernel/
    bridge-cni.config          # Kernel config fragment (bridge + netfilter)
```

## Building

### Prerequisites

- Rust toolchain
- make, git, curl
- On macOS: Xcode command line tools and cross-compilation tools for aarch64

### Quick Build

```bash
# Build custom libkrunfw (clones libkrunfw repo, applies config, builds)
./crates/openshell-vm/runtime/build-custom-libkrunfw.sh

# Or via mise task:
mise run vm:build-custom-runtime
```

### Output

Build artifacts are placed in `target/custom-runtime/`:

```
target/custom-runtime/
  libkrunfw.dylib              # The custom library
  libkrunfw.<version>.dylib    # Version-suffixed copy
  provenance.json              # Build metadata (commit, hash, timestamp)
  bridge-cni.config            # The config fragment used
  kernel.config                # Full kernel .config (for debugging)
```

### Using the Custom Runtime

```bash
# Point the bundle script at the custom build:
export OPENSHELL_VM_RUNTIME_SOURCE_DIR=target/custom-runtime
mise run vm:bundle-runtime

# Then boot the VM as usual:
mise run vm
```

## Network Profiles

The VM init script (`gateway-init.sh`) auto-detects the kernel capabilities
and selects the appropriate networking profile:

| Profile | Kernel | CNI | kube-proxy | Service VIPs |
|---------|--------|-----|------------|--------------|
| `bridge` | Custom (bridge+netfilter) | bridge CNI (`cni0`) | Enabled | Yes |
| `legacy-vm-net` | Stock (no netfilter) | ptp CNI | Disabled | No (direct IP) |

To force a specific profile:

```bash
# Inside the VM (set in gateway-init.sh env):
export OPENSHELL_VM_NET_PROFILE=bridge      # Force bridge CNI
export OPENSHELL_VM_NET_PROFILE=legacy-vm-net  # Force legacy ptp CNI
```

## Runtime Provenance

At VM boot, the gateway binary logs provenance information about the loaded
runtime:

```
runtime: /path/to/gateway.runtime
  libkrunfw: libkrunfw.dylib
  sha256: a1b2c3d4e5f6...
  type: custom (OpenShell-built)
  libkrunfw-commit: abc1234
  kernel-version: 6.6.30
  build-timestamp: 2026-03-23T10:00:00Z
```

For stock runtimes:
```
runtime: /path/to/gateway.runtime
  libkrunfw: libkrunfw.dylib
  sha256: f6e5d4c3b2a1...
  type: stock (system/homebrew)
```

## Verification

### Capability Check (inside VM)

```bash
# Run inside the VM to verify kernel capabilities:
/srv/check-vm-capabilities.sh

# JSON output for CI:
/srv/check-vm-capabilities.sh --json
```

### Full Verification Matrix

```bash
# Run from the host with a running VM:
./crates/openshell-vm/scripts/verify-vm.sh

# Or via mise task:
mise run vm:verify
```

## Rollback

To revert to the stock runtime:

```bash
# Unset the custom runtime source:
unset OPENSHELL_VM_RUNTIME_SOURCE_DIR

# Re-bundle with stock libraries:
mise run vm:bundle-runtime

# Boot — will auto-detect legacy-vm-net profile:
mise run vm
```

## Troubleshooting

### "FailedCreatePodSandBox" bridge errors

The kernel does not have bridge support. Verify:
```bash
# Inside VM:
ip link add test0 type bridge && echo "bridge OK" && ip link del test0
```

If this fails, you are running the stock runtime. Build and use the custom one.

### kube-proxy CrashLoopBackOff

The kernel does not have netfilter support. Verify:
```bash
# Inside VM:
iptables -L -n
```

If this fails with "iptables not found" or "modprobe: can't change directory",
the kernel lacks CONFIG_NETFILTER. Use the custom runtime.

### Runtime mismatch after upgrade

If libkrunfw is updated (e.g., via `brew upgrade`), the stock runtime may
change. Check provenance:
```bash
# Look for provenance info in VM boot output
grep "runtime:" ~/.local/share/openshell/gateway/console.log
```

Re-build the custom runtime if needed:
```bash
mise run vm:build-custom-runtime
mise run vm:bundle-runtime
```
