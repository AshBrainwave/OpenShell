// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Long-running DPU attachment controller for the OpenShell managed proxy.
//!
//! This is intentionally small: it exposes a localhost HTTP API on the DPU,
//! materializes one active sandbox attachment, starts the DPU-local OPA and
//! proxy processes, and keeps the backend manifest current.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use miette::{Context, IntoDiagnostic, Result, bail, miette};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

use openshell_sandbox::dpu_control_agent::{DpuControlAgentConfig, run_dpu_control_agent};

#[derive(Parser, Debug, Clone)]
#[command(name = "openshell-dpu-control")]
#[command(version = openshell_core::VERSION)]
#[command(about = "OpenShell DPU managed-proxy attachment controller")]
struct Args {
    /// Localhost HTTP control API listen address on the DPU.
    #[arg(
        long,
        default_value = "127.0.0.1:9090",
        env = "OPENSHELL_DPU_CONTROL_ADDR"
    )]
    control_addr: String,

    /// OpenShell gRPC endpoint reachable from the DPU.
    #[arg(
        long,
        default_value = "https://192.168.100.1:30051",
        env = "OPENSHELL_ENDPOINT"
    )]
    openshell_endpoint: String,

    /// Backend name exported in the manifest.
    #[arg(long, default_value = "bluefield0", env = "OPENSHELL_DPU_BACKEND_NAME")]
    backend_name: String,

    /// Base directory for backend manifest and per-sandbox DPU state.
    #[arg(
        long,
        default_value = "/var/lib/openshell-dpu",
        env = "OPENSHELL_DPU_OUTPUT_BASE"
    )]
    output_base: PathBuf,

    /// DPU proxy listen address.
    #[arg(long, default_value = "10.99.2.1:3128", env = "PROXY_LISTEN")]
    proxy_listen: String,

    /// DPU-local OPA REST listen address.
    #[arg(long, default_value = "127.0.0.1:8181", env = "OPA_ADDR")]
    opa_addr: String,

    /// Enable DPU TLS termination/re-encryption. Accepts 1/0 or true/false.
    #[arg(long, default_value = "1", env = "DPU_TLS_MITM")]
    dpu_tls_mitm: String,

    /// Apply OVS protected-path intent after materializing an attachment.
    #[arg(long, default_value = "0", env = "OPENSHELL_DPU_APPLY_OVS_INTENT")]
    apply_ovs_intent: String,

    /// Maximum active sandbox attachments supported by this backend instance.
    #[arg(long, default_value_t = 1, env = "OPENSHELL_DPU_MAX_ATTACHMENTS")]
    max_attachments: usize,

    #[arg(long, default_value = "ovsbr1", env = "OPENSHELL_DPU_BRIDGE")]
    bridge: String,

    #[arg(long, default_value = "pf0vf0", env = "OPENSHELL_DPU_VF_REP")]
    vf_representor: String,

    #[arg(long, default_value = "en3f0pf0sf0", env = "OPENSHELL_DPU_SF_REP")]
    sf_representor: String,

    #[arg(long, default_value = "enp3s0f0s0", env = "OPENSHELL_DPU_SF_APP_DEV")]
    sf_app_device: String,

    #[arg(
        long,
        default_value = "10.99.2.1/24",
        env = "OPENSHELL_DPU_PROTECTED_GATEWAY_CIDR"
    )]
    protected_gateway_cidr: String,

    #[arg(long, default_value = "10.99.2.2", env = "OPENSHELL_DPU_GUEST_IP")]
    guest_ip: String,

    #[arg(
        long,
        default_value = "10.99.2.2/24",
        env = "OPENSHELL_DPU_GUEST_IP_CIDR"
    )]
    guest_ip_cidr: String,

    #[arg(long, default_value = "10.42.0.0/16", env = "OPENSHELL_DPU_POD_CIDR")]
    pod_cidr: String,

    #[arg(
        long,
        default_value = "02:00:00:00:00:01",
        env = "OPENSHELL_DPU_GATEWAY_MAC"
    )]
    gateway_mac: String,

    #[arg(long, default_value = "local", env = "OPENSHELL_DPU_INGRESS_MODE")]
    ingress_mode: String,

    #[arg(long, default_value = "localhost", env = "OPENSHELL_TLS_SERVER_NAME")]
    tls_server_name: String,

    #[arg(
        long,
        default_value = "/etc/openshell/mtls/ca.crt",
        env = "OPENSHELL_TLS_CA"
    )]
    tls_ca: PathBuf,

    #[arg(
        long,
        default_value = "/etc/openshell/mtls/tls.crt",
        env = "OPENSHELL_TLS_CERT"
    )]
    tls_cert: PathBuf,

    #[arg(
        long,
        default_value = "/etc/openshell/mtls/tls.key",
        env = "OPENSHELL_TLS_KEY"
    )]
    tls_key: PathBuf,

    #[arg(
        long,
        default_value = "/usr/local/bin/opa",
        env = "OPENSHELL_DPU_OPA_BIN"
    )]
    opa_bin: PathBuf,

    #[arg(
        long,
        default_value = "/usr/local/bin/openshell-dpu-proxy",
        env = "OPENSHELL_DPU_PROXY_BIN"
    )]
    proxy_bin: PathBuf,

    /// Log level.
    #[arg(long, default_value = "info", env = "OPENSHELL_LOG_LEVEL")]
    log_level: String,
}

#[derive(Debug, Clone)]
struct ControllerConfig {
    control_addr: String,
    openshell_endpoint: String,
    backend_name: String,
    output_base: PathBuf,
    manifest_yaml: PathBuf,
    manifest_json: PathBuf,
    proxy_listen: String,
    opa_addr: String,
    dpu_tls_mitm: bool,
    apply_ovs_intent: bool,
    max_attachments: usize,
    bridge: String,
    vf_representor: String,
    sf_representor: String,
    sf_app_device: String,
    protected_gateway_cidr: String,
    guest_ip: String,
    guest_ip_cidr: String,
    pod_cidr: String,
    gateway_mac: String,
    ingress_mode: String,
    tls_server_name: String,
    tls_ca: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    opa_bin: PathBuf,
    proxy_bin: PathBuf,
}

impl TryFrom<Args> for ControllerConfig {
    type Error = miette::Report;

    fn try_from(args: Args) -> Result<Self> {
        let dpu_tls_mitm = parse_boolish(&args.dpu_tls_mitm, "DPU_TLS_MITM")?;
        let apply_ovs_intent =
            parse_boolish(&args.apply_ovs_intent, "OPENSHELL_DPU_APPLY_OVS_INTENT")?;
        Ok(Self {
            control_addr: args.control_addr,
            openshell_endpoint: args.openshell_endpoint,
            backend_name: args.backend_name,
            manifest_yaml: args.output_base.join("backend-manifest.yaml"),
            manifest_json: args.output_base.join("backend-manifest.json"),
            output_base: args.output_base,
            proxy_listen: args.proxy_listen,
            opa_addr: args.opa_addr,
            dpu_tls_mitm,
            apply_ovs_intent,
            max_attachments: args.max_attachments.max(1),
            bridge: args.bridge,
            vf_representor: args.vf_representor,
            sf_representor: args.sf_representor,
            sf_app_device: args.sf_app_device,
            protected_gateway_cidr: args.protected_gateway_cidr,
            guest_ip: args.guest_ip,
            guest_ip_cidr: args.guest_ip_cidr,
            pod_cidr: args.pod_cidr,
            gateway_mac: args.gateway_mac,
            ingress_mode: args.ingress_mode,
            tls_server_name: args.tls_server_name,
            tls_ca: args.tls_ca,
            tls_cert: args.tls_cert,
            tls_key: args.tls_key,
            opa_bin: args.opa_bin,
            proxy_bin: args.proxy_bin,
        })
    }
}

#[derive(Debug)]
struct ControllerState {
    config: ControllerConfig,
    phase: String,
    active_attachment: Option<Attachment>,
    opa_child: Option<Child>,
    proxy_child: Option<Child>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    metadata: Metadata,
    spec: Spec,
    attachments: Vec<Attachment>,
    status: Status,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    name: String,
    backend: &'static str,
    #[serde(rename = "dpuHost")]
    dpu_host: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Spec {
    mode: &'static str,
    proxy: ProxySpec,
    control: ControlSpec,
    datapath: DatapathSpec,
    capabilities: Capabilities,
    requirements: Requirements,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxySpec {
    scheme: &'static str,
    host: String,
    port: u16,
    listen: String,
    tls_inspection: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlSpec {
    openshell_endpoint: String,
    mtls_required: bool,
    tls_server_name: String,
    attachment_api: AttachmentApiSpec,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentApiSpec {
    transport: &'static str,
    listen: String,
    url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DatapathSpec {
    protected_gateway_cidr: String,
    protected_gateway_ip: String,
    guest_ip: String,
    guest_ip_cidr: String,
    pod_cidr: String,
    gateway_mac: String,
    bridge: String,
    vf_representor: String,
    sf_representor: String,
    sf_app_device: String,
    ingress_mode: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    l4_policy: Vec<&'static str>,
    l7_inspection: Vec<&'static str>,
    credential_owner: Vec<&'static str>,
    policy_runtime: Vec<&'static str>,
    trust_export: Vec<&'static str>,
    attachment_mode: Vec<&'static str>,
    attachment_api: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Requirements {
    sandbox_env: BTreeMap<String, String>,
    sandbox_trust: SandboxTrust,
    host: HostRequirements,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxTrust {
    ca_bundle_source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostRequirements {
    requires_protected_vf: bool,
    requires_vf_bridge: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Attachment {
    sandbox_id: String,
    output_dir: String,
    ca_path: String,
    state_path: String,
    ovs_intent_path: String,
    phase: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    ready: bool,
    phase: String,
    version: &'static str,
    max_attachments: usize,
    current_attachments: usize,
    apply_ovs_intent: bool,
    last_updated: String,
}

#[derive(Debug, Deserialize)]
struct AttachRequest {
    #[serde(alias = "sandboxId", alias = "sandbox_id")]
    sandbox_id: String,
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
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

    let config = ControllerConfig::try_from(args)?;
    fs::create_dir_all(&config.output_base)
        .into_diagnostic()
        .wrap_err("failed to create DPU output base")?;

    let state = Arc::new(Mutex::new(ControllerState {
        config: config.clone(),
        phase: "Ready".to_string(),
        active_attachment: None,
        opa_child: None,
        proxy_child: None,
    }));

    {
        let locked = state.lock().await;
        locked.write_manifest(&locked.phase)?;
    }

    let listener = TcpListener::bind(&config.control_addr)
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind DPU control API at {}", config.control_addr))?;
    info!(
        control_addr = %config.control_addr,
        manifest = %config.manifest_yaml.display(),
        "OpenShell DPU attachment controller is running"
    );

    loop {
        let (stream, _) = listener.accept().await.into_diagnostic()?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, state).await {
                warn!(error = %error, "DPU control API request failed");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<ControllerState>>,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;

    let response = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => http_json(
            200,
            json!({ "ok": true, "service": "openshell-dpu-control" }),
        ),
        ("GET", "/v1/manifest") | ("GET", "/v1/backend-manifest") => {
            let locked = state.lock().await;
            http_json(200, locked.manifest(&locked.phase)?)
        }
        ("GET", "/v1/manifest.yaml") | ("GET", "/v1/backend-manifest.yaml") => {
            let locked = state.lock().await;
            let yaml = serde_yml::to_string(&locked.manifest(&locked.phase)?).into_diagnostic()?;
            http_response(200, "application/yaml", yaml)
        }
        ("GET", "/v1/attachments") => {
            let locked = state.lock().await;
            http_json(
                200,
                json!({
                    "ok": true,
                    "attachments": locked.active_attachment.iter().collect::<Vec<_>>()
                }),
            )
        }
        ("POST", "/v1/attachments") => {
            let attach: AttachRequest = serde_json::from_slice(&request.body)
                .into_diagnostic()
                .wrap_err("invalid attachment request JSON")?;
            let mut locked = state.lock().await;
            match locked.attach(attach.sandbox_id).await {
                Ok(manifest) => http_json(200, json!({ "ok": true, "manifest": manifest })),
                Err(error) => {
                    let message = error.to_string();
                    error!(error = %message, "DPU attachment failed");
                    locked.phase = "Error".to_string();
                    let _ = locked.write_manifest("Error");
                    http_json(500, json!({ "ok": false, "error": message }))
                }
            }
        }
        (method, path) if method == "DELETE" && path.starts_with("/v1/attachments/") => {
            let sandbox_id = path.trim_start_matches("/v1/attachments/").to_string();
            let mut locked = state.lock().await;
            locked.detach(&sandbox_id)?;
            http_json(
                200,
                json!({ "ok": true, "manifest": locked.manifest(&locked.phase)? }),
            )
        }
        _ => http_json(
            404,
            json!({ "ok": false, "error": format!("unknown route: {} {}", request.method, request.path) }),
        ),
    };

    stream
        .write_all(response.as_bytes())
        .await
        .into_diagnostic()
        .wrap_err("failed to write HTTP response")?;
    Ok(())
}

impl ControllerState {
    async fn attach(&mut self, sandbox_id: String) -> Result<Manifest> {
        if sandbox_id.trim().is_empty() {
            bail!("sandboxId is required");
        }
        if self.config.max_attachments != 1 {
            bail!("this MVP controller currently supports exactly one active attachment");
        }

        self.require_gateway_mtls()?;
        self.stop_runtime();

        let output_dir = self.config.output_base.join(&sandbox_id);
        let attachment = attachment_for(&sandbox_id, &output_dir, "Materializing");
        self.active_attachment = Some(attachment);
        self.phase = "Materializing".to_string();
        self.write_manifest("Materializing")?;

        info!(sandbox_id = %sandbox_id, output_dir = %output_dir.display(), "materializing DPU attachment");
        fs::create_dir_all(output_dir.join("opa"))
            .into_diagnostic()
            .wrap_err("failed to create DPU attachment state directory")?;

        run_dpu_control_agent(DpuControlAgentConfig {
            openshell_endpoint: self.config.openshell_endpoint.clone(),
            sandbox_id: sandbox_id.clone(),
            output_dir: output_dir.clone(),
            poll_interval: Duration::from_secs(30),
            oneshot: true,
        })
        .await
        .wrap_err("failed to materialize DPU runtime state")?;

        self.apply_protected_ovs_intent(&output_dir)?;
        self.start_opa(&output_dir).await?;
        self.start_proxy(&output_dir).await?;

        self.active_attachment = Some(attachment_for(&sandbox_id, &output_dir, "Ready"));
        self.phase = "Ready".to_string();
        self.write_manifest("Ready")?;
        info!(sandbox_id = %sandbox_id, "DPU attachment is ready");
        self.manifest("Ready")
    }

    fn detach(&mut self, sandbox_id: &str) -> Result<()> {
        match &self.active_attachment {
            Some(active) if active.sandbox_id == sandbox_id => {
                info!(sandbox_id, "detaching DPU attachment");
                self.stop_runtime();
                self.active_attachment = None;
                self.phase = "Ready".to_string();
                self.write_manifest("Ready")?;
                Ok(())
            }
            Some(active) => bail!(
                "requested attachment '{}' is not active; active attachment is '{}'",
                sandbox_id,
                active.sandbox_id
            ),
            None => Ok(()),
        }
    }

    fn require_gateway_mtls(&self) -> Result<()> {
        if !self.config.openshell_endpoint.starts_with("https://") {
            return Ok(());
        }
        for (label, path) in [
            ("Gateway CA certificate", &self.config.tls_ca),
            ("Gateway client certificate", &self.config.tls_cert),
            ("Gateway client key", &self.config.tls_key),
        ] {
            if !path.is_file() {
                bail!(
                    "{} not found at {}. Mount or sync the gateway mTLS bundle before attachment.",
                    label,
                    path.display()
                );
            }
        }
        Ok(())
    }

    fn stop_runtime(&mut self) {
        stop_child("proxy", &mut self.proxy_child);
        stop_child("opa", &mut self.opa_child);
    }

    async fn start_opa(&mut self, output_dir: &Path) -> Result<()> {
        let policy_path = output_dir.join("opa/policy.rego");
        let data_path = output_dir.join("opa/data.json");
        info!(addr = %self.config.opa_addr, "starting DPU OPA");
        let child = Command::new(&self.config.opa_bin)
            .arg("run")
            .arg("--server")
            .arg("--addr")
            .arg(&self.config.opa_addr)
            .arg(&policy_path)
            .arg(&data_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to start {}", self.config.opa_bin.display()))?;
        self.opa_child = Some(child);
        wait_for_tcp(&self.config.opa_addr, Duration::from_secs(20))
            .await
            .wrap_err("OPA did not become reachable")?;
        Ok(())
    }

    async fn start_proxy(&mut self, output_dir: &Path) -> Result<()> {
        let credentials_path = output_dir.join("credentials.json");
        let ca_path = output_dir.join("openshell-dpu-ca.crt");
        info!(
            listen = %self.config.proxy_listen,
            tls_mitm = self.config.dpu_tls_mitm,
            "starting OpenShell DPU proxy"
        );
        let mut command = Command::new(&self.config.proxy_bin);
        command
            .arg("--mode")
            .arg("tcp")
            .arg("--listen")
            .arg(&self.config.proxy_listen)
            .arg("--opa-url")
            .arg(format!("http://{}", self.config.opa_addr))
            .arg("--credentials")
            .arg(&credentials_path)
            .arg("--ca-cert-out")
            .arg(&ca_path)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if !self.config.dpu_tls_mitm {
            command.arg("--disable-tls-mitm");
        }

        let child = command
            .spawn()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to start {}", self.config.proxy_bin.display()))?;
        self.proxy_child = Some(child);
        wait_for_tcp(&self.config.proxy_listen, Duration::from_secs(20))
            .await
            .wrap_err("DPU proxy did not become reachable")?;
        if self.config.dpu_tls_mitm {
            wait_for_file(&ca_path, Duration::from_secs(10))
                .await
                .wrap_err("DPU proxy CA certificate was not created")?;
        }
        Ok(())
    }

    fn apply_protected_ovs_intent(&self, output_dir: &Path) -> Result<()> {
        if !self.config.apply_ovs_intent {
            info!("skipping OVS intent application");
            return Ok(());
        }

        let intent_path = output_dir.join("ovs-protected-path.json");
        let raw = fs::read_to_string(&intent_path)
            .into_diagnostic()
            .wrap_err("failed to read OVS protected-path intent")?;
        let data: serde_json::Value = serde_json::from_str(&raw)
            .into_diagnostic()
            .wrap_err("invalid OVS intent JSON")?;
        let bridge = json_string(&data, "bridge")?;
        let in_port_name = json_string(&data, "in_port_name")?;
        let proto = json_string(&data, "proto")?;
        let dst_ip = json_string(&data, "dst_ip")?;
        let dst_port = json_u64(&data, "dst_port")?;
        let priority = json_u64(&data, "priority")?;
        let action = json_string(&data, "action")?;

        let ofport_output = Command::new("ovs-vsctl")
            .arg("get")
            .arg("Interface")
            .arg(&in_port_name)
            .arg("ofport")
            .output()
            .into_diagnostic()
            .wrap_err("failed to resolve OVS interface ofport")?;
        if !ofport_output.status.success() {
            bail!(
                "ovs-vsctl failed while resolving ofport for {}",
                in_port_name
            );
        }
        let ofport = String::from_utf8_lossy(&ofport_output.stdout)
            .trim()
            .trim_matches('"')
            .to_string();
        if ofport.is_empty() {
            bail!("empty OVS ofport for {}", in_port_name);
        }

        let strict_match = format!(
            "priority={priority},{proto},in_port={ofport},nw_dst={dst_ip},tp_dst={dst_port}"
        );
        let _ = Command::new("ovs-ofctl")
            .arg("--strict")
            .arg("del-flows")
            .arg(&bridge)
            .arg(&strict_match)
            .status();

        match action.as_str() {
            "allow" => info!("protected proxy is allowed by policy; deny override removed"),
            "drop" => {
                let status = Command::new("ovs-ofctl")
                    .arg("add-flow")
                    .arg(&bridge)
                    .arg(format!("{strict_match},actions=drop"))
                    .status()
                    .into_diagnostic()
                    .wrap_err("failed to add OVS drop flow")?;
                if !status.success() {
                    bail!("ovs-ofctl add-flow failed for protected-path intent");
                }
            }
            other => bail!("unsupported OVS protected-path action '{}'", other),
        }
        Ok(())
    }

    fn manifest(&self, phase: &str) -> Result<Manifest> {
        let (proxy_host, proxy_port) = split_host_port(&self.config.proxy_listen)?;
        let mut sandbox_env = BTreeMap::new();
        sandbox_env.insert(
            "OPENSHELL_UPSTREAM_HTTP_PROXY".to_string(),
            self.config.proxy_listen.clone(),
        );
        let attachments = self.active_attachment.iter().cloned().collect::<Vec<_>>();
        Ok(Manifest {
            api_version: "openshell.ai/v1alpha1",
            kind: "EgressBackendManifest",
            metadata: Metadata {
                name: self.config.backend_name.clone(),
                backend: "bluefield",
                dpu_host: hostname(),
            },
            spec: Spec {
                mode: "shared",
                proxy: ProxySpec {
                    scheme: "http",
                    host: proxy_host.clone(),
                    port: proxy_port,
                    listen: self.config.proxy_listen.clone(),
                    tls_inspection: self.config.dpu_tls_mitm,
                },
                control: ControlSpec {
                    openshell_endpoint: self.config.openshell_endpoint.clone(),
                    mtls_required: self.config.openshell_endpoint.starts_with("https://"),
                    tls_server_name: self.config.tls_server_name.clone(),
                    attachment_api: AttachmentApiSpec {
                        transport: "dpu-local-http",
                        listen: self.config.control_addr.clone(),
                        url: format!("http://{}", self.config.control_addr),
                    },
                },
                datapath: DatapathSpec {
                    protected_gateway_cidr: self.config.protected_gateway_cidr.clone(),
                    protected_gateway_ip: proxy_host,
                    guest_ip: self.config.guest_ip.clone(),
                    guest_ip_cidr: self.config.guest_ip_cidr.clone(),
                    pod_cidr: self.config.pod_cidr.clone(),
                    gateway_mac: self.config.gateway_mac.clone(),
                    bridge: self.config.bridge.clone(),
                    vf_representor: self.config.vf_representor.clone(),
                    sf_representor: self.config.sf_representor.clone(),
                    sf_app_device: self.config.sf_app_device.clone(),
                    ingress_mode: self.config.ingress_mode.clone(),
                },
                capabilities: Capabilities {
                    l4_policy: vec!["ovs"],
                    l7_inspection: vec!["tls-termination", "http-request-parse"],
                    credential_owner: vec!["dpu", "host"],
                    policy_runtime: vec!["opa"],
                    trust_export: vec!["ca-pem"],
                    attachment_mode: vec!["single"],
                    attachment_api: vec!["localhost-http"],
                },
                requirements: Requirements {
                    sandbox_env,
                    sandbox_trust: SandboxTrust {
                        ca_bundle_source: "dpu-attachment",
                    },
                    host: HostRequirements {
                        requires_protected_vf: true,
                        requires_vf_bridge: true,
                    },
                },
            },
            attachments,
            status: Status {
                ready: phase == "Ready",
                phase: phase.to_string(),
                version: "0.1.0",
                max_attachments: self.config.max_attachments,
                current_attachments: usize::from(self.active_attachment.is_some()),
                apply_ovs_intent: self.config.apply_ovs_intent,
                last_updated: utc_now(),
            },
        })
    }

    fn write_manifest(&self, phase: &str) -> Result<()> {
        let manifest = self.manifest(phase)?;
        let yaml = serde_yml::to_string(&manifest).into_diagnostic()?;
        let json = serde_json::to_string_pretty(&manifest).into_diagnostic()?;
        write_atomic(&self.config.manifest_yaml, yaml.as_bytes())?;
        write_atomic(&self.config.manifest_json, json.as_bytes())?;
        info!(manifest = %self.config.manifest_yaml.display(), phase, "exported backend manifest");
        Ok(())
    }
}

fn attachment_for(sandbox_id: &str, output_dir: &Path, phase: &str) -> Attachment {
    Attachment {
        sandbox_id: sandbox_id.to_string(),
        output_dir: path_string(output_dir),
        ca_path: path_string(&output_dir.join("openshell-dpu-ca.crt")),
        state_path: path_string(&output_dir.join("state.json")),
        ovs_intent_path: path_string(&output_dir.join("ovs-protected-path.json")),
        phase: phase.to_string(),
    }
}

fn stop_child(name: &str, child: &mut Option<Child>) {
    if let Some(mut child) = child.take() {
        if let Err(error) = child.kill() {
            warn!(process = name, error = %error, "failed to signal child process");
        }
        if let Err(error) = child.wait() {
            warn!(process = name, error = %error, "failed to wait for child process");
        }
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(8192);
    let mut temp = [0_u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut temp).await.into_diagnostic()?;
        if n == 0 {
            bail!("connection closed before HTTP headers");
        }
        buffer.extend_from_slice(&temp[..n]);
        if buffer.len() > 1024 * 1024 {
            bail!("HTTP request too large");
        }
        if let Some(pos) = find_header_end(&buffer) {
            header_end = pos;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| miette!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| miette!("missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| miette!("missing HTTP path"))?
        .to_string();

    let mut content_length = 0_usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .into_diagnostic()
                    .wrap_err("invalid Content-Length")?;
            }
        }
    }

    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let n = stream.read(&mut temp).await.into_diagnostic()?;
        if n == 0 {
            bail!("connection closed before HTTP body completed");
        }
        buffer.extend_from_slice(&temp[..n]);
    }
    let body = buffer[body_start..body_start + content_length].to_vec();
    Ok(HttpRequest { method, path, body })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn http_json<T: Serialize>(status: u16, value: T) -> String {
    let body = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"serialization failed\"}".to_string());
    http_response(status, "application/json", body)
}

fn http_response(status: u16, content_type: &str, body: String) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("timed out waiting for TCP listener at {}", addr)
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if path.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("timed out waiting for {}", path.display())
}

fn write_atomic(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("manifest")
    ));
    fs::write(&tmp, content)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)).into_diagnostic()?;
    fs::rename(&tmp, path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

fn parse_boolish(raw: &str, name: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => bail!("{} must be boolean-like, got '{}'", name, other),
    }
}

fn split_host_port(listen: &str) -> Result<(String, u16)> {
    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| miette!("listen address '{}' must be host:port", listen))?;
    let port = port
        .parse::<u16>()
        .into_diagnostic()
        .wrap_err("invalid proxy listen port")?;
    Ok((host.to_string(), port))
}

fn json_string(data: &serde_json::Value, key: &str) -> Result<String> {
    data.get(key)
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| miette!("missing string field '{}' in OVS intent", key))
}

fn json_u64(data: &serde_json::Value, key: &str) -> Result<u64> {
    data.get(key)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| miette!("missing integer field '{}' in OVS intent", key))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn utc_now() -> String {
    match Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "1970-01-01T00:00:00Z".to_string(),
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}
