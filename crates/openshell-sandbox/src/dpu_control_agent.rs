// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! DPU control-plane agent for the BF3 managed proxy MVP.
//!
//! The agent pulls effective sandbox policy and provider environment from the
//! OpenShell server, compiles a DPU-local OPA bundle for destination-based
//! enforcement, emits protected-path OVS rule intent for the BF3 MVP, writes
//! local runtime state, and reports policy load status.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::proto::{PolicySource, SandboxPolicy as ProtoSandboxPolicy};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::grpc_client::{CachedOpenShellClient, SettingsPollResult};

const DPU_PROXY_POLICY: &str = include_str!("../data/dpu-proxy-policy.rego");
const PROTECTED_PROXY_BRIDGE: &str = "ovsbr1";
const PROTECTED_PROXY_VF_REP: &str = "pf0vf0";
const PROTECTED_PROXY_IP: &str = "10.99.2.1";
const PROTECTED_PROXY_PORT: u16 = 3128;
const PROTECTED_PROXY_PRIORITY: u16 = 300;
const PROTECTED_PROXY_PROTO: &str = "tcp";

#[derive(Debug, Clone)]
pub struct DpuControlAgentConfig {
    pub openshell_endpoint: String,
    pub sandbox_id: String,
    pub output_dir: PathBuf,
    pub poll_interval: Duration,
    pub oneshot: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct AllowedDestination {
    host: String,
    ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DpuOpaData {
    allowed_destinations: Vec<AllowedDestination>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProtectedPathAction {
    Allow,
    Drop,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ProtectedPathRuleIntent {
    bridge: String,
    in_port_name: String,
    proto: String,
    dst_ip: String,
    dst_port: u16,
    priority: u16,
    action: ProtectedPathAction,
    reason: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct AppliedState {
    sandbox_id: String,
    version: u32,
    policy_hash: String,
    config_revision: u64,
    policy_source: String,
    global_policy_version: u32,
    provider_env_hash: String,
    allowed_destination_count: usize,
    ignored_binary_rules: usize,
    skipped_hostless_endpoints: usize,
    skipped_invalid_ports: usize,
    protected_proxy_action: String,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompiledPolicy {
    data: DpuOpaData,
    ignored_binary_rules: usize,
    skipped_hostless_endpoints: usize,
    skipped_invalid_ports: usize,
    protected_proxy_allowed: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Default)]
struct CompiledDestinationAccumulator {
    ports: BTreeSet<u16>,
    allowed_ips: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimePaths {
    base: PathBuf,
    opa_dir: PathBuf,
    opa_policy: PathBuf,
    opa_data: PathBuf,
    credentials: PathBuf,
    ovs_protected_path: PathBuf,
    state: PathBuf,
}

impl RuntimePaths {
    fn new(base: PathBuf) -> Self {
        let opa_dir = base.join("opa");
        Self {
            opa_policy: opa_dir.join("policy.rego"),
            opa_data: opa_dir.join("data.json"),
            credentials: base.join("credentials.json"),
            ovs_protected_path: base.join("ovs-protected-path.json"),
            state: base.join("state.json"),
            base,
            opa_dir,
        }
    }
}

struct RemoteRuntime {
    settings: SettingsPollResult,
    provider_env: HashMap<String, String>,
    provider_env_hash: String,
}

pub async fn run_dpu_control_agent(config: DpuControlAgentConfig) -> Result<()> {
    let client = CachedOpenShellClient::connect(&config.openshell_endpoint)
        .await
        .wrap_err("failed to connect DPU control agent to OpenShell")?;
    let paths = RuntimePaths::new(config.output_dir.clone());
    ensure_layout(&paths)?;

    let mut last_config_revision: Option<u64> = None;
    let mut last_provider_hash = String::new();

    loop {
        let remote = match pull_remote_runtime(&client, &config.sandbox_id).await {
            Ok(remote) => remote,
            Err(error) => {
                if config.oneshot {
                    return Err(error);
                }
                warn!(
                    sandbox_id = %config.sandbox_id,
                    error = %error,
                    "DPU control agent sync failed; keeping last-known-good state"
                );
                tokio::time::sleep(config.poll_interval).await;
                continue;
            }
        };

        let unchanged = Some(remote.settings.config_revision) == last_config_revision
            && remote.provider_env_hash == last_provider_hash;

        if unchanged {
            debug!(
                sandbox_id = %config.sandbox_id,
                config_revision = remote.settings.config_revision,
                "DPU control agent state unchanged"
            );
        } else {
            match apply_remote_runtime(&client, &config.sandbox_id, &paths, remote).await {
                Ok(applied) => {
                    info!(
                        sandbox_id = %config.sandbox_id,
                        config_revision = applied.config_revision,
                        policy_hash = %applied.policy_hash,
                        allowed_destinations = applied.allowed_destination_count,
                        warnings = applied.warnings.len(),
                        "DPU control agent applied runtime state"
                    );
                    last_config_revision = Some(applied.config_revision);
                    last_provider_hash = applied.provider_env_hash;
                }
                Err(error) => {
                    if config.oneshot {
                        return Err(error);
                    }
                    warn!(
                        sandbox_id = %config.sandbox_id,
                        error = %error,
                        "DPU control agent sync failed; keeping last-known-good state"
                    );
                }
            }
        }

        if config.oneshot {
            return Ok(());
        }

        tokio::time::sleep(config.poll_interval).await;
    }
}

async fn pull_remote_runtime(
    client: &CachedOpenShellClient,
    sandbox_id: &str,
) -> Result<RemoteRuntime> {
    let settings = client
        .poll_settings(sandbox_id)
        .await
        .wrap_err("failed to fetch sandbox settings")?;
    let provider_env = client
        .fetch_provider_environment(sandbox_id)
        .await
        .wrap_err("failed to fetch provider environment")?;
    let provider_env_hash = hash_provider_env(&provider_env)?;

    Ok(RemoteRuntime {
        settings,
        provider_env,
        provider_env_hash,
    })
}

async fn apply_remote_runtime(
    client: &CachedOpenShellClient,
    sandbox_id: &str,
    paths: &RuntimePaths,
    remote: RemoteRuntime,
) -> Result<AppliedState> {
    match apply_runtime_files(
        sandbox_id,
        &remote.settings,
        &remote.provider_env,
        &remote.provider_env_hash,
        paths,
    ) {
        Ok(state) => {
            maybe_report_policy_status(client, sandbox_id, &remote.settings, true, "").await;
            Ok(state)
        }
        Err(error) => {
            maybe_report_policy_status(
                client,
                sandbox_id,
                &remote.settings,
                false,
                &error.to_string(),
            )
            .await;
            Err(error)
        }
    }
}

async fn maybe_report_policy_status(
    client: &CachedOpenShellClient,
    sandbox_id: &str,
    settings: &SettingsPollResult,
    loaded: bool,
    error_msg: &str,
) {
    if settings.version == 0 || settings.policy_source != PolicySource::Sandbox {
        return;
    }

    if let Err(error) = client
        .report_policy_status(sandbox_id, settings.version, loaded, error_msg)
        .await
    {
        warn!(
            sandbox_id = %sandbox_id,
            version = settings.version,
            error = %error,
            "DPU control agent failed to report policy status"
        );
    }
}

fn apply_runtime_files(
    sandbox_id: &str,
    settings: &SettingsPollResult,
    provider_env: &HashMap<String, String>,
    provider_env_hash: &str,
    paths: &RuntimePaths,
) -> Result<AppliedState> {
    let compiled = compile_dpu_policy(settings.policy.as_ref());
    let protected_path = build_protected_path_rule_intent(&compiled);
    let state = AppliedState {
        sandbox_id: sandbox_id.to_string(),
        version: settings.version,
        policy_hash: settings.policy_hash.clone(),
        config_revision: settings.config_revision,
        policy_source: policy_source_name(settings.policy_source),
        global_policy_version: settings.global_policy_version,
        provider_env_hash: provider_env_hash.to_string(),
        allowed_destination_count: compiled.data.allowed_destinations.len(),
        ignored_binary_rules: compiled.ignored_binary_rules,
        skipped_hostless_endpoints: compiled.skipped_hostless_endpoints,
        skipped_invalid_ports: compiled.skipped_invalid_ports,
        protected_proxy_action: protected_path.action.as_str().to_string(),
        warnings: compiled.warnings.clone(),
    };

    write_string_atomic(&paths.opa_policy, DPU_PROXY_POLICY, 0o644)?;
    write_json_atomic(&paths.opa_data, &compiled.data, 0o644)?;
    write_json_atomic(&paths.credentials, provider_env, 0o600)?;
    write_json_atomic(&paths.ovs_protected_path, &protected_path, 0o644)?;
    write_json_atomic(&paths.state, &state, 0o600)?;

    Ok(state)
}

fn ensure_layout(paths: &RuntimePaths) -> Result<()> {
    fs::create_dir_all(&paths.base)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", paths.base.display()))?;
    fs::create_dir_all(&paths.opa_dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", paths.opa_dir.display()))?;
    Ok(())
}

fn compile_dpu_policy(policy: Option<&ProtoSandboxPolicy>) -> CompiledPolicy {
    let Some(policy) = policy else {
        return CompiledPolicy {
            data: DpuOpaData {
                allowed_destinations: Vec::new(),
            },
            ignored_binary_rules: 0,
            skipped_hostless_endpoints: 0,
            skipped_invalid_ports: 0,
            protected_proxy_allowed: false,
            warnings: vec![
                "No sandbox policy returned; DPU proxy policy compiled as deny-all".to_string(),
            ],
        };
    };

    let mut destinations: BTreeMap<String, CompiledDestinationAccumulator> = BTreeMap::new();
    let mut warnings = BTreeSet::new();
    let mut ignored_binary_rules = 0usize;
    let mut skipped_hostless_endpoints = 0usize;
    let mut skipped_invalid_ports = 0usize;

    for (policy_key, rule) in &policy.network_policies {
        if !rule.binaries.is_empty() {
            ignored_binary_rules += 1;
            warnings.insert(format!(
                "Policy '{policy_key}' has binary-scoped rules; DPU proxy MVP ignores binary matching and compiles destination union only"
            ));
        }

        for endpoint in &rule.endpoints {
            let host = endpoint.host.trim();
            if host.is_empty() {
                skipped_hostless_endpoints += 1;
                warnings.insert(format!(
                    "Skipped hostless endpoint in policy '{policy_key}' because the DPU proxy MVP matches explicit destination hosts only"
                ));
                continue;
            }

            let mut normalized_ports = BTreeSet::new();
            let ports_iter = if endpoint.ports.is_empty() {
                if endpoint.port > 0 {
                    vec![endpoint.port]
                } else {
                    Vec::new()
                }
            } else {
                endpoint.ports.clone()
            };

            for port in ports_iter {
                if port == 0 || port > u16::MAX.into() {
                    skipped_invalid_ports += 1;
                    warnings.insert(format!(
                        "Skipped invalid port '{port}' for endpoint '{host}' in policy '{policy_key}'"
                    ));
                    continue;
                }
                normalized_ports.insert(port as u16);
            }

            if normalized_ports.is_empty() {
                skipped_invalid_ports += 1;
                warnings.insert(format!(
                    "Skipped endpoint '{host}' in policy '{policy_key}' because it had no valid ports"
                ));
                continue;
            }

            let destination = destinations.entry(host.to_string()).or_default();
            destination.ports.extend(normalized_ports);
            destination
                .allowed_ips
                .extend(endpoint.allowed_ips.iter().cloned());
        }
    }

    let allowed_destinations = destinations
        .into_iter()
        .map(|(host, destination)| AllowedDestination {
            host,
            ports: destination.ports.into_iter().collect(),
            allowed_ips: destination.allowed_ips.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    let protected_proxy_allowed = allowed_destinations.iter().any(|destination| {
        destination.host == PROTECTED_PROXY_IP
            && destination.ports.contains(&PROTECTED_PROXY_PORT)
    });

    if !protected_proxy_allowed {
        warnings.insert(format!(
            "Protected proxy endpoint {}:{} is absent from the sandbox policy; the DPU protected path will be blocked on {} via {}",
            PROTECTED_PROXY_IP,
            PROTECTED_PROXY_PORT,
            PROTECTED_PROXY_BRIDGE,
            PROTECTED_PROXY_VF_REP,
        ));
    }

    CompiledPolicy {
        data: DpuOpaData {
            allowed_destinations,
        },
        ignored_binary_rules,
        skipped_hostless_endpoints,
        skipped_invalid_ports,
        protected_proxy_allowed,
        warnings: warnings.into_iter().collect(),
    }
}

fn build_protected_path_rule_intent(compiled: &CompiledPolicy) -> ProtectedPathRuleIntent {
    let (action, reason) = if compiled.protected_proxy_allowed {
        (
            ProtectedPathAction::Allow,
            format!(
                "Protected proxy endpoint {}:{} is present in the sandbox policy; remove any high-priority deny override and leave the baseline forwarding path on {} in place",
                PROTECTED_PROXY_IP, PROTECTED_PROXY_PORT, PROTECTED_PROXY_BRIDGE
            ),
        )
    } else {
        (
            ProtectedPathAction::Drop,
            format!(
                "Protected proxy endpoint {}:{} is absent from the sandbox policy; install a high-priority deny override on {} ingress {}",
                PROTECTED_PROXY_IP,
                PROTECTED_PROXY_PORT,
                PROTECTED_PROXY_BRIDGE,
                PROTECTED_PROXY_VF_REP,
            ),
        )
    };

    ProtectedPathRuleIntent {
        bridge: PROTECTED_PROXY_BRIDGE.to_string(),
        in_port_name: PROTECTED_PROXY_VF_REP.to_string(),
        proto: PROTECTED_PROXY_PROTO.to_string(),
        dst_ip: PROTECTED_PROXY_IP.to_string(),
        dst_port: PROTECTED_PROXY_PORT,
        priority: PROTECTED_PROXY_PRIORITY,
        action,
        reason,
    }
}

fn hash_provider_env(provider_env: &HashMap<String, String>) -> Result<String> {
    let canonical: BTreeMap<&str, &str> = provider_env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let json = serde_json::to_vec(&canonical)
        .into_diagnostic()
        .wrap_err("failed to serialize provider environment for hashing")?;
    let mut hasher = Sha256::new();
    hasher.update(&json);
    Ok(format!("{:x}", hasher.finalize()))
}

fn policy_source_name(source: PolicySource) -> String {
    match source {
        PolicySource::Sandbox => "sandbox".to_string(),
        PolicySource::Global => "global".to_string(),
        PolicySource::Unspecified => "unspecified".to_string(),
    }
}

impl ProtectedPathAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Drop => "drop",
        }
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let json = serde_json::to_string_pretty(value)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to serialize {}", path.display()))?;
    write_string_atomic(path, &json, mode)
}

fn write_string_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| miette::miette!("path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {}", parent.display()))?;

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write {}", tmp_path.display()))?;
    set_mode(&tmp_path, mode)?;
    fs::rename(&tmp_path, path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to move {} into place", path.display()))?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};
    use regorus::Value;

    fn endpoint(host: &str, ports: &[u32]) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.to_string(),
            port: 0,
            protocol: String::new(),
            tls: String::new(),
            enforcement: String::new(),
            access: String::new(),
            rules: Vec::new(),
            allowed_ips: Vec::new(),
            ports: ports.to_vec(),
        }
    }

    #[test]
    fn compile_policy_merges_hosts_and_ports() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "api".to_string(),
            NetworkPolicyRule {
                name: "api".to_string(),
                endpoints: vec![
                    endpoint("api.openai.com", &[443]),
                    endpoint("api.openai.com", &[8443]),
                ],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));

        assert_eq!(
            compiled.data.allowed_destinations,
            vec![AllowedDestination {
                host: "api.openai.com".to_string(),
                ports: vec![443, 8443],
                allowed_ips: Vec::new(),
            }]
        );
        assert!(compiled.warnings.is_empty());
    }

    #[test]
    fn compile_policy_skips_hostless_endpoints_and_records_warning() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "cidr-only".to_string(),
            NetworkPolicyRule {
                name: "cidr-only".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: String::new(),
                    port: 443,
                    protocol: String::new(),
                    tls: String::new(),
                    enforcement: String::new(),
                    access: String::new(),
                    rules: Vec::new(),
                    allowed_ips: vec!["10.0.0.0/8".to_string()],
                    ports: Vec::new(),
                }],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));

        assert!(compiled.data.allowed_destinations.is_empty());
        assert_eq!(compiled.skipped_hostless_endpoints, 1);
        assert!(compiled
            .warnings
            .iter()
            .any(|warning| warning.contains("hostless endpoint")));
    }

    #[test]
    fn compile_policy_marks_binary_rules_ignored() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "binary-scoped".to_string(),
            NetworkPolicyRule {
                name: "binary-scoped".to_string(),
                endpoints: vec![endpoint("example.com", &[443])],
                binaries: vec![openshell_core::proto::NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    harness: false,
                }],
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));

        assert_eq!(compiled.ignored_binary_rules, 1);
        assert!(compiled
            .warnings
            .iter()
            .any(|warning| warning.contains("ignores binary matching")));
    }

    #[test]
    fn compile_policy_preserves_allowed_ips_union_per_host() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "nvidia".to_string(),
            NetworkPolicyRule {
                name: "nvidia".to_string(),
                endpoints: vec![
                    NetworkEndpoint {
                        host: "inference-api.nvidia.com".to_string(),
                        port: 0,
                        protocol: String::new(),
                        tls: String::new(),
                        enforcement: String::new(),
                        access: String::new(),
                        rules: Vec::new(),
                        allowed_ips: vec!["10.48.202.0/24".to_string()],
                        ports: vec![443],
                    },
                    NetworkEndpoint {
                        host: "inference-api.nvidia.com".to_string(),
                        port: 0,
                        protocol: String::new(),
                        tls: String::new(),
                        enforcement: String::new(),
                        access: String::new(),
                        rules: Vec::new(),
                        allowed_ips: vec!["10.48.203.0/24".to_string()],
                        ports: vec![443],
                    },
                ],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));

        assert_eq!(
            compiled.data.allowed_destinations,
            vec![AllowedDestination {
                host: "inference-api.nvidia.com".to_string(),
                ports: vec![443],
                allowed_ips: vec!["10.48.202.0/24".to_string(), "10.48.203.0/24".to_string()],
            }]
        );
    }

    #[test]
    fn compile_policy_marks_protected_proxy_allowed_when_present() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "dpu_proxy".to_string(),
            NetworkPolicyRule {
                name: "dpu_proxy".to_string(),
                endpoints: vec![endpoint(PROTECTED_PROXY_IP, &[PROTECTED_PROXY_PORT.into()])],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));
        let intent = build_protected_path_rule_intent(&compiled);

        assert!(compiled.protected_proxy_allowed);
        assert_eq!(intent.action, ProtectedPathAction::Allow);
        assert_eq!(intent.bridge, PROTECTED_PROXY_BRIDGE);
        assert_eq!(intent.in_port_name, PROTECTED_PROXY_VF_REP);
        assert_eq!(intent.dst_ip, PROTECTED_PROXY_IP);
        assert_eq!(intent.dst_port, PROTECTED_PROXY_PORT);
    }

    #[test]
    fn compile_policy_blocks_protected_proxy_when_absent() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "upstream".to_string(),
            NetworkPolicyRule {
                name: "upstream".to_string(),
                endpoints: vec![endpoint("api.openai.com", &[443])],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));
        let intent = build_protected_path_rule_intent(&compiled);

        assert!(!compiled.protected_proxy_allowed);
        assert_eq!(intent.action, ProtectedPathAction::Drop);
        assert!(compiled
            .warnings
            .iter()
            .any(|warning| warning.contains("Protected proxy endpoint")));
    }

    #[test]
    fn dpu_policy_rego_exposes_matched_endpoint_config_with_allowed_ips() {
        let mut policy = SandboxPolicy::default();
        policy.network_policies.insert(
            "nvidia".to_string(),
            NetworkPolicyRule {
                name: "nvidia".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "inference-api.nvidia.com".to_string(),
                    port: 0,
                    protocol: String::new(),
                    tls: String::new(),
                    enforcement: String::new(),
                    access: String::new(),
                    rules: Vec::new(),
                    allowed_ips: vec!["10.48.202.0/24".to_string()],
                    ports: vec![443],
                }],
                binaries: Vec::new(),
            },
        );

        let compiled = compile_dpu_policy(Some(&policy));
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("policy.rego".into(), DPU_PROXY_POLICY.into())
            .unwrap();
        engine
            .add_data_json(&serde_json::to_string(&compiled.data).unwrap())
            .unwrap();
        engine
            .set_input_json(
                &serde_json::json!({
                    "destination_host": "inference-api.nvidia.com",
                    "destination_port": 443,
                })
                .to_string(),
            )
            .unwrap();

        let allowed = engine.eval_rule("data.openshell.allow".into()).unwrap();
        assert_eq!(allowed, Value::from(true));

        let endpoint = engine
            .eval_rule("data.openshell.matched_endpoint_config".into())
            .unwrap();
        let allowed_ips = match endpoint {
            Value::Object(map) => match map.get(&Value::from("allowed_ips")) {
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| match item {
                        Value::String(value) => value.to_string(),
                        other => panic!("unexpected allowed_ips item: {other:?}"),
                    })
                    .collect::<Vec<_>>(),
                other => panic!("unexpected allowed_ips field: {other:?}"),
            },
            other => panic!("unexpected endpoint config: {other:?}"),
        };

        assert_eq!(allowed_ips, vec!["10.48.202.0/24".to_string()]);
    }
}
