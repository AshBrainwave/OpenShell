// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell DPU Proxy — standalone TLS proxy for the BlueField DPU ARM.
//!
//! Runs on the DPU ARM (`aarch64`). Accepts HTTP CONNECT from host agents,
//! terminates TLS, evaluates policy via the OPA REST daemon at 127.0.0.1:8181,
//! injects credentials from a local vault file, and forwards traffic.
//!
//! Usage (TCP mode — rshim, dev/testing only):
//!   openshell-dpu-proxy \
//!     --listen 0.0.0.0:8080 \
//!     --opa-url http://127.0.0.1:8181 \
//!     --credentials /home/ubuntu/openshell-dpu/credentials.json \
//!     --inference-routes /home/ubuntu/openshell-dpu/routes.yaml
//!
//! Usage (Comm Channel mode — untrusted-host, production):
//!   openshell-dpu-proxy --mode comch \
//!     --pci 03:00.0 \
//!     --opa-url http://127.0.0.1:8181 \
//!     --credentials /home/ubuntu/openshell-dpu/credentials.json

use clap::{Parser, ValueEnum};
use miette::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use openshell_sandbox::{run_dpu_proxy, run_dpu_proxy_cc};

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    /// TCP over rshim/tmfifo — for dev/testing only, not for untrusted-host use.
    Tcp,
    /// DOCA Comm Channel over PCIe — hardware-enforced, works in untrusted-host mode.
    Comch,
}

#[derive(Parser, Debug)]
#[command(name = "openshell-dpu-proxy")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell TLS proxy for BlueField DPU ARM")]
struct Args {
    /// Transport mode: tcp (rshim, dev) or comch (PCIe Comm Channel, production).
    #[arg(long, value_enum, default_value = "tcp", env = "OPENSHELL_MODE")]
    mode: Mode,

    // ---- TCP mode args ----

    /// [tcp] TCP address to listen on.
    #[arg(long, default_value = "0.0.0.0:8080", env = "OPENSHELL_LISTEN")]
    listen: String,

    /// Path to write the ephemeral CA certificate (tcp mode).
    #[arg(
        long,
        default_value = "/tmp/openshell-dpu-ca.crt",
        env = "OPENSHELL_DPU_CA_CERT_OUT"
    )]
    ca_cert_out: String,

    // ---- Comm Channel mode args ----

    /// [comch] PCI address of the BlueField device (e.g. 03:00.0).
    #[arg(long, default_value = "03:00.0", env = "OPENSHELL_PCI_ADDR")]
    pci: String,

    /// [comch] DOCA Comm Channel service name (must match host shim).
    #[arg(
        long,
        default_value = "openshell-proxy",
        env = "OPENSHELL_CC_SERVICE"
    )]
    service: String,

    // ---- Shared args ----

    /// OPA REST daemon URL on the DPU ARM.
    #[arg(
        long,
        default_value = "http://127.0.0.1:8181",
        env = "OPENSHELL_DPU_OPA_URL"
    )]
    opa_url: String,

    /// Path to credentials JSON file: `{"NVIDIA_API_KEY": "nvapi-..."}`.
    #[arg(long, env = "OPENSHELL_DPU_CREDENTIALS")]
    credentials: Option<String>,

    /// Path to inference routes YAML file for inference.local routing (tcp mode only).
    #[arg(long, env = "OPENSHELL_INFERENCE_ROUTES")]
    inference_routes: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(filter),
        )
        .init();

    let _ = rustls::crypto::ring::default_provider().install_default();

    match args.mode {
        Mode::Tcp => {
            info!(
                listen = %args.listen,
                opa_url = %args.opa_url,
                "Starting OpenShell DPU proxy (tcp/rshim mode)"
            );
            run_dpu_proxy(
                args.listen,
                args.opa_url,
                args.credentials,
                args.inference_routes,
                Some(args.ca_cert_out),
            )
            .await
        }
        Mode::Comch => {
            info!(
                pci = %args.pci,
                service = %args.service,
                opa_url = %args.opa_url,
                "Starting OpenShell DPU proxy (comch/PCIe mode)"
            );
            run_dpu_proxy_cc(
                args.pci,
                args.service,
                args.opa_url,
                args.credentials,
                args.inference_routes,
            )
            .await
        }
    }
}
