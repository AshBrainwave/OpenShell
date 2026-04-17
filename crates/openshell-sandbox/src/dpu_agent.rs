// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenShell DPU control agent.
//!
//! Pulls per-sandbox policy and provider environment from OpenShell over gRPC
//! and writes DPU-local runtime state for the BF3 managed proxy MVP.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use miette::Result;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use openshell_sandbox::dpu_control_agent::{DpuControlAgentConfig, run_dpu_control_agent};

#[derive(Parser, Debug)]
#[command(name = "openshell-dpu-agent")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell DPU control-plane agent for BF3 managed-proxy MVP")]
struct Args {
    /// OpenShell gRPC endpoint used by the DPU control plane.
    #[arg(long, env = "OPENSHELL_ENDPOINT")]
    openshell_endpoint: String,

    /// Sandbox id whose policy/runtime state should be materialized on the DPU.
    #[arg(long, env = "OPENSHELL_SANDBOX_ID")]
    sandbox_id: String,

    /// Output directory for the local OPA bundle, credentials, and state files.
    #[arg(
        long,
        default_value = "/var/lib/openshell-dpu",
        env = "OPENSHELL_DPU_OUTPUT_DIR"
    )]
    output_dir: PathBuf,

    /// Poll interval in seconds when running continuously.
    #[arg(long, default_value_t = 30, env = "OPENSHELL_DPU_POLL_INTERVAL_SECS")]
    poll_interval_secs: u64,

    /// Run a single sync pass and exit.
    #[arg(long, env = "OPENSHELL_DPU_ONESHOT")]
    oneshot: bool,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(filter),
        )
        .init();

    let config = DpuControlAgentConfig {
        openshell_endpoint: args.openshell_endpoint,
        sandbox_id: args.sandbox_id,
        output_dir: args.output_dir,
        poll_interval: Duration::from_secs(args.poll_interval_secs.max(1)),
        oneshot: args.oneshot,
    };

    run_dpu_control_agent(config).await
}
