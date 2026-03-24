#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Init script for the gateway microVM. Runs as PID 1 inside the libkrun VM.
#
# Mounts essential virtual filesystems, configures networking, then execs
# k3s server. If the rootfs was pre-initialized by build-rootfs.sh (sentinel
# at /opt/openshell/.initialized), the full manifest setup is skipped and
# k3s resumes from its persisted state (~3-5s startup).

set -e

BOOT_START=$(date +%s%3N 2>/dev/null || date +%s)

ts() {
    local now
    now=$(date +%s%3N 2>/dev/null || date +%s)
    local elapsed=$(( (now - BOOT_START) ))
    printf "[%d.%03ds] %s\n" $((elapsed / 1000)) $((elapsed % 1000)) "$*"
}

PRE_INITIALIZED=false
if [ -f /opt/openshell/.initialized ]; then
    PRE_INITIALIZED=true
    ts "pre-initialized rootfs detected (fast path)"
fi

# ── Mount essential filesystems (parallel) ──────────────────────────────
# These are independent; mount them concurrently.

mount -t proc     proc     /proc     2>/dev/null &
mount -t sysfs    sysfs    /sys      2>/dev/null &
mount -t tmpfs    tmpfs    /tmp      2>/dev/null &
mount -t tmpfs    tmpfs    /run      2>/dev/null &
mount -t devtmpfs devtmpfs /dev      2>/dev/null &
wait

# These depend on /dev being mounted.
mkdir -p /dev/pts /dev/shm
mount -t devpts   devpts   /dev/pts  2>/dev/null &
mount -t tmpfs    tmpfs    /dev/shm  2>/dev/null &

# cgroup2 (unified hierarchy) — required by k3s/containerd.
mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null &
wait

ts "filesystems mounted"

# ── Networking ──────────────────────────────────────────────────────────

hostname gateway 2>/dev/null || true

# Ensure loopback is up (k3s binds to 127.0.0.1).
ip link set lo up 2>/dev/null || true

# Detect whether we have a real network interface (gvproxy) or need a
# dummy interface (TSI / no networking).
if ip link show eth0 >/dev/null 2>&1; then
    # gvproxy networking — bring up eth0 and get an IP via DHCP.
    # gvproxy has a built-in DHCP server that assigns 192.168.127.2/24
    # with gateway 192.168.127.1 and configures ARP properly.
    ts "detected eth0 (gvproxy networking)"
    ip link set eth0 up 2>/dev/null || true

    # Use DHCP to get IP and configure routes. gvproxy's DHCP server
    # handles ARP resolution which static config does not.
    if command -v udhcpc >/dev/null 2>&1; then
        # udhcpc needs a script to apply the lease. Use the busybox
        # default script if available, otherwise write a minimal one.
        UDHCPC_SCRIPT="/usr/share/udhcpc/default.script"
        if [ ! -f "$UDHCPC_SCRIPT" ]; then
            mkdir -p /usr/share/udhcpc
            cat > "$UDHCPC_SCRIPT" << 'DHCP_SCRIPT'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr flush dev "$interface"
        ip addr add "$ip/$mask" dev "$interface"
        if [ -n "$router" ]; then
            ip route add default via $router dev "$interface"
        fi
        if [ -n "$dns" ]; then
            echo -n > /etc/resolv.conf
            for d in $dns; do
                echo "nameserver $d" >> /etc/resolv.conf
            done
        fi
        ;;
esac
DHCP_SCRIPT
            chmod +x "$UDHCPC_SCRIPT"
        fi
        # -f: stay in foreground, -q: quit after obtaining lease,
        # -n: exit if no lease, -T 1: 1s between retries, -t 3: 3 retries
        # -A 1: wait 1s before first retry (aggressive for local gvproxy)
        udhcpc -i eth0 -f -q -n -T 1 -t 3 -A 1 -s "$UDHCPC_SCRIPT" 2>&1 || true
    else
        # Fallback to static config if no DHCP client available.
        ts "no DHCP client, using static config"
        ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
        ip route add default via 192.168.127.1 2>/dev/null || true
    fi

    # Ensure DNS is configured. DHCP should have set /etc/resolv.conf,
    # but if it didn't (or static fallback was used), provide a default.
    if [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi

    # Read back the IP we got (from DHCP or static).
    NODE_IP=$(ip -4 addr show eth0 | grep -oP 'inet \K[^/]+' || echo "192.168.127.2")
    ts "eth0 IP: $NODE_IP"
else
    # TSI or no networking — create a dummy interface for k3s.
    ts "no eth0 found, using dummy interface (TSI mode)"
    ip link add dummy0 type dummy  2>/dev/null || true
    ip addr add 10.0.2.15/24 dev dummy0  2>/dev/null || true
    ip link set dummy0 up  2>/dev/null || true
    ip route add default dev dummy0  2>/dev/null || true

    NODE_IP="10.0.2.15"
fi

# ── k3s data directories ───────────────────────────────────────────────

mkdir -p /var/lib/rancher/k3s
mkdir -p /etc/rancher/k3s

# Clean stale runtime artifacts from previous boots (virtio-fs persists
# the rootfs between VM restarts).
rm -rf /var/lib/rancher/k3s/server/tls/temporary-certs 2>/dev/null || true
rm -f  /var/lib/rancher/k3s/server/kine.sock           2>/dev/null || true
# Clean stale node password so k3s doesn't fail validation on reboot.
# Each k3s start generates a new random node password; the old hash in
# the database will not match. Removing the local password file forces
# k3s to re-register with a fresh one.
rm -f /var/lib/rancher/k3s/server/cred/node-passwd      2>/dev/null || true
# Also clean any stale pid files and unix sockets
find /var/lib/rancher/k3s -name '*.sock' -delete 2>/dev/null || true
find /run -name '*.sock' -delete 2>/dev/null || true

# Clean stale containerd runtime state from previous boots.
#
# The rootfs persists across VM restarts via virtio-fs. We PRESERVE the
# bolt metadata database (meta.db) because it contains snapshot and image
# metadata that containerd needs to avoid re-extracting all image layers
# on every boot. The native snapshotter on virtio-fs takes ~2 min to
# extract the openshell/gateway image; keeping meta.db lets containerd
# know the snapshots already exist.
#
# The kine (SQLite) DB cleanup in build-rootfs.sh already removes stale
# pod/sandbox records from k3s etcd, preventing kubelet from reconciling
# against stale sandboxes. Containerd's internal sandbox records in
# meta.db are harmless because the CRI plugin reconciles with kubelet
# on startup — any sandboxes unknown to kubelet are cleaned up gracefully
# without triggering SandboxChanged events.
CONTAINERD_DIR="/var/lib/rancher/k3s/agent/containerd"
if [ -d "$CONTAINERD_DIR" ]; then
    # Remove runtime task state (stale shim PIDs, sockets from dead processes).
    rm -rf "${CONTAINERD_DIR}/io.containerd.runtime.v2.task" 2>/dev/null || true
    # Clean stale ingest temp files from the content store.
    rm -rf "${CONTAINERD_DIR}/io.containerd.content.v1.content/ingest" 2>/dev/null || true
    mkdir -p "${CONTAINERD_DIR}/io.containerd.content.v1.content/ingest"
    # Preserve meta.db — snapshot/image metadata avoids re-extraction.
    ts "cleaned containerd runtime state (preserved meta.db + content store + snapshotter)"
fi
rm -rf /run/k3s 2>/dev/null || true

ts "stale artifacts cleaned"

# ── Deploy bundled manifests (cold boot only) ───────────────────────────
# On pre-initialized rootfs, manifests are already in place from the
# build-time k3s boot. Skip this entirely for fast startup.

K3S_MANIFESTS="/var/lib/rancher/k3s/server/manifests"
BUNDLED_MANIFESTS="/opt/openshell/manifests"

if [ "$PRE_INITIALIZED" = false ]; then

    mkdir -p "$K3S_MANIFESTS"

    if [ -d "$BUNDLED_MANIFESTS" ]; then
        ts "deploying bundled manifests (cold boot)..."
        for manifest in "$BUNDLED_MANIFESTS"/*.yaml; do
            [ ! -f "$manifest" ] && continue
            cp "$manifest" "$K3S_MANIFESTS/"
        done

        # Remove stale OpenShell-managed manifests from previous boots.
        for existing in "$K3S_MANIFESTS"/openshell-*.yaml \
                        "$K3S_MANIFESTS"/agent-*.yaml; do
            [ ! -f "$existing" ] && continue
            basename=$(basename "$existing")
            if [ ! -f "$BUNDLED_MANIFESTS/$basename" ]; then
                rm -f "$existing"
            fi
        done
    fi

    ts "manifests deployed"
else
    ts "skipping manifest deploy (pre-initialized)"
fi

# Patch manifests for VM deployment constraints.
HELMCHART="$K3S_MANIFESTS/openshell-helmchart.yaml"
if [ -f "$HELMCHART" ]; then
    # Use pre-loaded images — don't pull from registry.
    sed -i 's|pullPolicy: Always|pullPolicy: IfNotPresent|' "$HELMCHART"

    if [ "$NET_PROFILE" = "bridge" ]; then
        # Bridge CNI: pods use normal pod networking, not hostNetwork.
        sed -i 's|__HOST_NETWORK__|false|g' "$HELMCHART"
        sed -i 's|__AUTOMOUNT_SA_TOKEN__|true|g' "$HELMCHART"
    else
        # Legacy: VM bootstrap runs without CNI bridge networking.
        sed -i 's|__HOST_NETWORK__|true|g' "$HELMCHART"
        sed -i 's|__AUTOMOUNT_SA_TOKEN__|false|g' "$HELMCHART"
    fi

    sed -i 's|__KUBECONFIG_HOST_PATH__|"/etc/rancher/k3s"|g' "$HELMCHART"
    sed -i 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART"
    sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Clear SSH gateway placeholders (default 127.0.0.1 is correct for local VM).
    sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
fi

AGENT_MANIFEST="$K3S_MANIFESTS/agent-sandbox.yaml"
if [ -f "$AGENT_MANIFEST" ]; then
    if [ "$NET_PROFILE" = "bridge" ]; then
        # Bridge CNI: agent-sandbox uses normal pod networking.
        # kube-proxy is enabled so kubernetes.default.svc is reachable
        # via ClusterIP — no need for KUBERNETES_SERVICE_HOST override.
        sed -i '/hostNetwork: true/d' "$AGENT_MANIFEST"
        sed -i '/dnsPolicy: ClusterFirstWithHostNet/d' "$AGENT_MANIFEST"
        ts "agent-sandbox: using pod networking (bridge profile)"
    else
        # Legacy: keep agent-sandbox on pod networking to avoid host port
        # clashes. Point in-cluster client traffic at the API server node
        # IP because kube-proxy is disabled in VM mode.
        sed -i '/hostNetwork: true/d' "$AGENT_MANIFEST"
        sed -i '/dnsPolicy: ClusterFirstWithHostNet/d' "$AGENT_MANIFEST"
        if ! grep -q 'metrics-bind-address=:8082' "$AGENT_MANIFEST"; then
            sed -i 's|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0\
            args:\
            - -metrics-bind-address=:8082\
            env:\
            - name: KUBERNETES_SERVICE_HOST\
              value: 192.168.127.2\
            - name: KUBERNETES_SERVICE_PORT\
              value: "6443"|g' "$AGENT_MANIFEST"
        else
            sed -i 's|value: 127.0.0.1|value: 192.168.127.2|g' "$AGENT_MANIFEST"
        fi
        if grep -q 'hostNetwork: true' "$AGENT_MANIFEST" \
            || grep -q 'ClusterFirstWithHostNet' "$AGENT_MANIFEST" \
            || ! grep -q 'KUBERNETES_SERVICE_HOST' "$AGENT_MANIFEST" \
            || ! grep -q 'metrics-bind-address=:8082' "$AGENT_MANIFEST"; then
            echo "ERROR: failed to patch agent-sandbox manifest for VM networking constraints: $AGENT_MANIFEST" >&2
            exit 1
        fi
        ts "agent-sandbox: patched for legacy-vm-net (API server override)"
    fi
fi

# local-storage implies local-path-provisioner. In legacy mode it
# requires CNI bridge networking that is unavailable. In bridge mode
# it can work but we leave it disabled for now until validated.
if [ "$NET_PROFILE" != "bridge" ]; then
    rm -f "$K3S_MANIFESTS/local-storage.yaml" 2>/dev/null || true
fi

# ── CNI configuration ───────────────────────────────────────────────────
# Two networking profiles:
#
# 1. "bridge" (default when kernel supports it):
#    Uses the bridge CNI plugin with iptables masquerade. Requires
#    CONFIG_BRIDGE, CONFIG_NETFILTER, CONFIG_NF_NAT in the VM kernel.
#    This is the standard Kubernetes CNI path — compatible with
#    kube-proxy, service VIPs, and portmap.
#
# 2. "legacy-vm-net" (fallback for stock libkrunfw without netfilter):
#    Uses ptp CNI without iptables. No masquerade, no portmap.
#    kube-proxy must be disabled. This is the original VM path.
#
# The profile is auto-detected from kernel capabilities but can be
# forced via OPENSHELL_VM_NET_PROFILE=bridge|legacy-vm-net.

NET_PROFILE="${OPENSHELL_VM_NET_PROFILE:-auto}"

detect_net_profile() {
    # Check for bridge + netfilter kernel support.
    # If we can create a bridge and the netfilter sysctl exists, use bridge CNI.
    local has_bridge=false
    local has_netfilter=false

    if ip link add _probe_br0 type bridge 2>/dev/null; then
        ip link del _probe_br0 2>/dev/null || true
        has_bridge=true
    fi

    if [ -d /proc/sys/net/netfilter ] || [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        has_netfilter=true
    fi

    if [ "$has_bridge" = true ] && [ "$has_netfilter" = true ]; then
        echo "bridge"
    else
        echo "legacy-vm-net"
    fi
}

if [ "$NET_PROFILE" = "auto" ]; then
    NET_PROFILE=$(detect_net_profile)
fi

ts "network profile: ${NET_PROFILE}"

CNI_CONF_DIR="/etc/cni/net.d"
CNI_BIN_DIR="/opt/cni/bin"
mkdir -p "$CNI_CONF_DIR" "$CNI_BIN_DIR"

if [ "$NET_PROFILE" = "bridge" ]; then
    # ── Bridge CNI (full Kubernetes networking) ─────────────────────
    # This path requires a custom libkrunfw with bridge + netfilter
    # kernel support. Creates a cni0 bridge, uses iptables masquerade,
    # and is compatible with kube-proxy.

    # Enable IP forwarding (required for masquerade).
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

    # Enable bridge netfilter call (required for kube-proxy to see
    # bridged traffic).
    if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || true
    fi

    cat > "$CNI_CONF_DIR/10-bridge.conflist" << 'CNICFG'
{
  "cniVersion": "1.0.0",
  "name": "bridge",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "isDefaultGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{ "subnet": "10.42.0.0/24" }]],
        "routes": [{ "dst": "0.0.0.0/0" }]
      }
    },
    {
      "type": "portmap",
      "capabilities": { "portMappings": true },
      "snat": true
    },
    {
      "type": "loopback"
    }
  ]
}
CNICFG

    # Remove any legacy ptp config.
    rm -f "$CNI_CONF_DIR/10-ptp.conflist" 2>/dev/null || true

    ts "bridge CNI configured (cni0 + iptables masquerade)"
else
    # ── Legacy ptp CNI (iptables-free) ─────────────────────────────
    # The libkrun VM kernel has no netfilter/iptables support. Flannel's
    # masquerade rules and kube-proxy both require iptables and crash
    # without it. We disable both and use a simple ptp CNI with
    # host-local IPAM instead. This avoids linux bridge requirements.
    #
    # ipMasq=false avoids any iptables calls in the plugin.
    # portmap plugin removed — it requires iptables for DNAT rules.

    cat > "$CNI_CONF_DIR/10-ptp.conflist" << 'CNICFG'
{
  "cniVersion": "1.0.0",
  "name": "ptp",
  "plugins": [
    {
      "type": "ptp",
      "ipMasq": false,
      "ipam": {
        "type": "host-local",
        "ranges": [[{ "subnet": "10.42.0.0/24" }]],
        "routes": [{ "dst": "0.0.0.0/0" }]
      }
    },
    {
      "type": "loopback"
    }
  ]
}
CNICFG

    # Remove any bridge config.
    rm -f "$CNI_CONF_DIR/10-bridge.conflist" 2>/dev/null || true

    ts "ptp CNI configured (iptables-free, no linux bridge)"
fi

# Symlink k3s-bundled CNI binaries to the default containerd bin path.
# k3s extracts its tools to /var/lib/rancher/k3s/data/<hash>/bin/.
K3S_DATA_BIN=$(find /var/lib/rancher/k3s/data -maxdepth 2 -name bin -type d 2>/dev/null | head -1)
if [ -n "$K3S_DATA_BIN" ]; then
    for plugin in bridge ptp host-local loopback bandwidth portmap; do
        [ -f "$K3S_DATA_BIN/$plugin" ] && ln -sf "$K3S_DATA_BIN/$plugin" "$CNI_BIN_DIR/$plugin"
    done
    ts "CNI binaries linked from $K3S_DATA_BIN"
else
    ts "WARNING: k3s data bin dir not found, CNI binaries may be missing"
fi

# Also clean up any flannel config from the k3s-specific CNI directory
# (pre-baked state from the Docker build used host-gw flannel).
rm -f "/var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist" 2>/dev/null || true

# ── Start k3s ──────────────────────────────────────────────────────────
# Flags tuned for fast single-node startup. The k3s flags vary depending
# on the network profile:
#
# bridge: kube-proxy enabled, flannel disabled (bridge CNI handles it)
# legacy-vm-net: kube-proxy disabled (no iptables), flannel disabled

K3S_ARGS=(
    --disable=traefik,servicelb,metrics-server,coredns
    --disable-network-policy
    --write-kubeconfig-mode=644
    --node-ip="$NODE_IP"
    --kube-apiserver-arg=bind-address=0.0.0.0
    --resolv-conf=/etc/resolv.conf
    --tls-san=localhost,127.0.0.1,10.0.2.15,192.168.127.2
    --flannel-backend=none
    --snapshotter=native
)

if [ "$NET_PROFILE" = "bridge" ]; then
    # With bridge CNI + iptables, kube-proxy can run. Don't disable it.
    # local-storage can also work with bridge networking.
    ts "starting k3s server (bridge profile — kube-proxy enabled)"
else
    # Legacy: no iptables means no kube-proxy and no local-storage.
    K3S_ARGS+=(
        --disable=local-storage
        --disable-kube-proxy
    )
    ts "starting k3s server (legacy-vm-net profile — kube-proxy disabled)"
fi

exec /usr/local/bin/k3s server "${K3S_ARGS[@]}"
