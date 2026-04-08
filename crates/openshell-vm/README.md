# openshell-vm

> Status: Experimental and work in progress (WIP). VM support is under active development and may change.

MicroVM runtime for OpenShell, powered by [libkrun](https://github.com/containers/libkrun). Boots a lightweight ARM64 Linux VM on macOS (Apple Hypervisor.framework) or Linux (KVM) running a single-node k3s cluster with the OpenShell control plane.

## Quick Start

Build and run the VM in one command:

```bash
mise run vm
```

This will:

1. Compress runtime artifacts (libkrun, libkrunfw, gvproxy, rootfs)
2. Build the `openshell-vm` binary with embedded runtime
3. Codesign it (macOS)
4. Build the rootfs if needed
5. Boot the VM

## Prerequisites

- **macOS (Apple Silicon)** or **Linux (aarch64 with KVM)**
- Rust toolchain
- [mise](https://mise.jdx.dev/) task runner
- Docker (for rootfs builds)

### macOS-Specific

The binary must be codesigned with the Hypervisor.framework entitlement. The `mise run vm` flow handles this automatically. To codesign manually:

```bash
codesign --entitlements crates/openshell-vm/entitlements.plist --force -s - target/debug/openshell-vm
```

## Build

### Embedded Binary (Recommended)

Produces a single self-extracting binary with all runtime artifacts baked in:

```bash
mise run vm:build:embedded
```

On first run, the binary extracts its runtime to `~/.local/share/openshell/vm-runtime/<version>/`.

### Quick Rebuild (Skip Rootfs)

If you already have a cached rootfs tarball and just want to rebuild the binary:

```bash
mise run vm:build:embedded:quick
```

### Force Full Rebuild

Rebuilds everything including the rootfs:

```bash
mise run vm:build
```

## Run

### Default (Gateway Mode)

Boots the full OpenShell gateway --- k3s + openshell-server + openshell-sandbox:

```bash
mise run vm
```

Or run the binary directly:

```bash
./target/debug/openshell-vm
```

### Custom Process

Run an arbitrary process inside a fresh VM instead of k3s:

```bash
./target/debug/openshell-vm --exec /bin/sh --vcpus 2 --mem 2048
```

### Execute in a Running VM

Attach to a running VM and run a command:

```bash
./target/debug/openshell-vm exec -- ls /
./target/debug/openshell-vm exec -- sh   # interactive shell
```

### Named Instances

Run multiple isolated VM instances side-by-side:

```bash
./target/debug/openshell-vm --name dev
./target/debug/openshell-vm --name staging
```

Each instance gets its own extracted rootfs under `~/.local/share/openshell/openshell-vm/<version>/instances/<name>/rootfs`.

## CLI Reference

```
openshell-vm [OPTIONS] [COMMAND]

Options:
  --rootfs <PATH>          Path to aarch64 Linux rootfs directory
  --name <NAME>            Named VM instance (auto-clones rootfs)
  --exec <PATH>            Run a custom process instead of k3s
  --args <ARGS>...         Arguments to the executable
  --env <KEY=VALUE>...     Environment variables
  --workdir <DIR>          Working directory inside the VM [default: /]
  -p, --port <H:G>...     Port mappings (host_port:guest_port)
  --vcpus <N>              Virtual CPUs [default: 4 gateway, 2 exec]
  --mem <MiB>              RAM in MiB [default: 8192 gateway, 2048 exec]
  --krun-log-level <0-5>   libkrun log level [default: 1]
  --net <BACKEND>          Networking: gvproxy, tsi, none [default: gvproxy]
  --reset                  Wipe runtime state before booting

Subcommands:
  prepare-rootfs           Ensure the target rootfs exists
  exec                     Execute a command inside a running VM
```

## Rootfs

The rootfs is an aarch64 Ubuntu filesystem containing k3s, pre-loaded container images, and the OpenShell binaries.

### Full Rootfs (~2GB+)

Pre-initialized k3s cluster state for fast boot (~3-5s):

```bash
mise run vm:build:rootfs-tarball
```

### Minimal Rootfs (~200-300MB)

Just k3s + supervisor, cold starts in ~30-60s:

```bash
mise run vm:build:rootfs-tarball:base
```

## Custom Kernel (libkrunfw)

The stock libkrunfw (e.g. from Homebrew) lacks bridge, netfilter, and conntrack support needed for pod networking. OpenShell builds a custom libkrunfw with these enabled.

Build it:

```bash
mise run vm:runtime:build-libkrunfw
```

See [`runtime/README.md`](runtime/README.md) for details on the kernel config and troubleshooting.

## Architecture

```
Host (macOS / Linux)
  openshell-vm binary
    ├── Embedded runtime (libkrun, libkrunfw, gvproxy, rootfs.tar.zst)
    ├── FFI: loads libkrun at runtime via dlopen
    ├── gvproxy: virtio-net networking (real eth0 + DHCP)
    ├── virtio-fs: shares rootfs with guest
    └── vsock: host-to-guest command execution (port 10777)

Guest VM (aarch64 Linux)
  PID 1: openshell-vm-init.sh
    ├── Mounts filesystems, configures networking
    ├── Sets up bridge CNI, generates PKI
    └── Execs k3s server
        ├── openshell-server (gateway control plane)
        └── openshell-sandbox (pod supervisor)
```

## Environment Variables

| Variable | When | Purpose |
|----------|------|---------|
| `OPENSHELL_VM_RUNTIME_COMPRESSED_DIR` | Build time | Path to compressed runtime artifacts |
| `OPENSHELL_VM_RUNTIME_DIR` | Runtime | Override the runtime bundle directory |
| `OPENSHELL_VM_DIAG=1` | Runtime | Enable diagnostic output inside the VM |

## mise Tasks Reference

| Task | Description |
|------|-------------|
| `vm` | Build and run the VM using a per-instance rootfs |
| `vm:build` | Force full rebuild including rootfs |
| `vm:rootfs` | Prepare the default named VM rootfs |
| `vm:build:embedded` | Build single binary with embedded runtime |
| `vm:build:embedded:quick` | Build using cached rootfs tarball |
| `vm:build:rootfs-tarball` | Build full rootfs tarball |
| `vm:build:rootfs-tarball:base` | Build base rootfs tarball |
| `vm:runtime:compress` | Compress runtime artifacts for embedding |
| `vm:runtime:build-libkrunfw` | Build custom libkrunfw |
| `vm:runtime:build-libkrun` | Build libkrun from source (Linux) |
| `vm:runtime:build-libkrun-macos` | Build libkrun from source (macOS) |
| `vm:check-capabilities` | Check VM kernel capabilities |

## Testing

Integration tests require a built rootfs and macOS ARM64 with libkrun:

```bash
cargo test -p openshell-vm -- --ignored
```

Individual tests:

```bash
# Full gateway boot test (boots VM, waits for gRPC on port 30051)
cargo test -p openshell-vm gateway_boots -- --ignored

# Run a command inside the VM
cargo test -p openshell-vm gateway_exec_runs -- --ignored

# Exec into a running VM
cargo test -p openshell-vm gateway_exec_attaches -- --ignored
```

Verify kernel capabilities inside a running VM:

```bash
./target/debug/openshell-vm exec -- /srv/check-vm-capabilities.sh
./target/debug/openshell-vm exec -- /srv/check-vm-capabilities.sh --json
```
