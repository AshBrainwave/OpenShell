// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell DPU Proxy — standalone TLS proxy for the BlueField DPU ARM.
//!
//! Runs on the DPU ARM (`aarch64`). Accepts HTTP CONNECT from host agents,
//! terminates TLS, evaluates policy via the OPA REST daemon at 127.0.0.1:8181,
//! injects credentials from a local vault file, and forwards traffic.
//!
//! Usage:
//!   openshell-dpu-proxy \
//!     --listen 0.0.0.0:8080 \
//!     --opa-url http://127.0.0.1:8181 \
//!     --credentials /home/ubuntu/openshell-dpu/credentials.json \
//!     --inference-routes /home/ubuntu/openshell-dpu/routes.yaml

use clap::Parser;
use miette::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use openshell_sandbox::run_dpu_proxy;

#[derive(Parser, Debug)]
#[command(name = "openshell-dpu-proxy")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell TLS proxy for BlueField DPU ARM")]
struct Args {
    /// TCP address to listen on.
    /// Host agents set HTTPS_PROXY=http://<dpu-ip>:<port> to reach this.
    #[arg(long, default_value = "0.0.0.0:8080", env = "OPENSHELL_LISTEN")]
    listen: String,

    /// OPA REST daemon URL on the DPU ARM.
    /// The daemon evaluates per-connection policy from openshell.rego.
    #[arg(
        long,
        default_value = "http://127.0.0.1:8181",
        env = "OPENSHELL_DPU_OPA_URL"
    )]
    opa_url: String,

    /// Path to credentials JSON file: `{"ANTHROPIC_API_KEY": "sk-..."}`.
    /// Keys are injected into agent requests at the proxy layer — agents never
    /// see the real values.
    #[arg(long, env = "OPENSHELL_DPU_CREDENTIALS")]
    credentials: Option<String>,

    /// Path to inference routes YAML file for inference.local routing.
    #[arg(long, env = "OPENSHELL_INFERENCE_ROUTES")]
    inference_routes: Option<String>,

    /// Path to write the ephemeral CA certificate.
    /// Install this cert in the host agent's trust store so it trusts the DPU's TLS.
    #[arg(
        long,
        default_value = "/tmp/openshell-dpu-ca.crt",
        env = "OPENSHELL_DPU_CA_CERT_OUT"
    )]
    ca_cert_out: String,

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

    info!(
        listen = %args.listen,
        opa_url = %args.opa_url,
        credentials = ?args.credentials,
        inference_routes = ?args.inference_routes,
        "Starting OpenShell DPU proxy"
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
