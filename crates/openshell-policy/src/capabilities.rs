// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_core::proto::{
    L7Allow, L7QueryMatcher, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule,
    SandboxPolicy,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CAPABILITIES_DIR: &str = "capabilities";

const PROFILE_RESTRICTED: &[&str] = &[];
const PROFILE_MEDIUM_DEV: &[&str] = &["github_readonly", "pypi_install"];
const PROFILE_MEDIUM_API: &[&str] = &["discord_getme", "telegram_send_only"];
const PROFILE_OPEN: &[&str] = &[
    "github_readonly",
    "pypi_install",
    "discord_getme",
    "discord_send",
    "telegram_send_only",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityDefinition {
    pub id: String,
    pub title: String,
    pub risk: RiskLevel,
    pub description: String,
    pub policy_name: String,
    pub constraints: Vec<String>,
    pub recommended_usage: Vec<String>,
    pub rule: NetworkPolicyRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFile {
    id: String,
    title: String,
    #[serde(default)]
    risk: RiskLevel,
    #[serde(default)]
    description: String,
    policy_name: String,
    #[serde(default)]
    constraints: Vec<String>,
    #[serde(default)]
    recommended_usage: Vec<String>,
    block: CapabilityRuleDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<CapabilityEndpointDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    binaries: Vec<CapabilityBinaryDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityEndpointDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    port: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<CapabilityL7RuleDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityL7RuleDef {
    allow: CapabilityL7AllowDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityL7AllowDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    query: BTreeMap<String, CapabilityQueryMatcherDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CapabilityQueryMatcherDef {
    Glob(String),
    Any(CapabilityQueryAnyDef),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityQueryAnyDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityBinaryDef {
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLint {
    pub code: String,
    pub rule_name: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RiskFinding {
    pub rule_name: String,
    pub level: RiskLevel,
    pub summary: String,
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskReport {
    pub overall_risk: RiskLevel,
    pub findings: Vec<RiskFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskChange {
    pub rule_name: String,
    pub before: RiskLevel,
    pub after: RiskLevel,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskDelta {
    pub before: RiskReport,
    pub after: RiskReport,
    pub introduced: Vec<RiskFinding>,
    pub removed: Vec<RiskFinding>,
    pub changed: Vec<RiskChange>,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

fn capability_rule_to_proto(policy_name: &str, rule: CapabilityRuleDef) -> NetworkPolicyRule {
    NetworkPolicyRule {
        name: if rule.name.is_empty() {
            policy_name.to_string()
        } else {
            rule.name
        },
        endpoints: rule
            .endpoints
            .into_iter()
            .map(|endpoint| {
                let normalized_ports = if !endpoint.ports.is_empty() {
                    endpoint.ports
                } else if endpoint.port > 0 {
                    vec![endpoint.port]
                } else {
                    vec![]
                };
                NetworkEndpoint {
                    host: endpoint.host,
                    port: normalized_ports.first().copied().unwrap_or(0),
                    ports: normalized_ports,
                    protocol: endpoint.protocol,
                    tls: endpoint.tls,
                    enforcement: endpoint.enforcement,
                    access: endpoint.access,
                    rules: endpoint
                        .rules
                        .into_iter()
                        .map(|rule| L7Rule {
                            allow: Some(L7Allow {
                                method: rule.allow.method,
                                path: rule.allow.path,
                                command: rule.allow.command,
                                query: rule
                                    .allow
                                    .query
                                    .into_iter()
                                    .map(|(key, matcher)| {
                                        let proto = match matcher {
                                            CapabilityQueryMatcherDef::Glob(glob) => {
                                                L7QueryMatcher { glob, any: vec![] }
                                            }
                                            CapabilityQueryMatcherDef::Any(any) => L7QueryMatcher {
                                                glob: String::new(),
                                                any: any.any,
                                            },
                                        };
                                        (key, proto)
                                    })
                                    .collect(),
                            }),
                        })
                        .collect(),
                    allowed_ips: endpoint.allowed_ips,
                }
            })
            .collect(),
        binaries: rule
            .binaries
            .into_iter()
            .map(|binary| NetworkBinary {
                path: binary.path,
                ..Default::default()
            })
            .collect(),
    }
}

pub fn parse_capability_definition(yaml: &str) -> Result<CapabilityDefinition> {
    let raw: CapabilityFile = serde_yaml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("failed to parse capability YAML")?;
    Ok(CapabilityDefinition {
        id: raw.id,
        title: raw.title,
        risk: raw.risk,
        description: raw.description,
        policy_name: raw.policy_name.clone(),
        constraints: raw.constraints,
        recommended_usage: raw.recommended_usage,
        rule: capability_rule_to_proto(&raw.policy_name, raw.block),
    })
}

pub fn load_capability_definition(path: &Path) -> Result<CapabilityDefinition> {
    let yaml = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read capability from {}", path.display()))?;
    parse_capability_definition(&yaml)
}

pub fn load_capability_catalog(dir: &Path) -> Result<HashMap<String, CapabilityDefinition>> {
    let mut entries = fs::read_dir(dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read capability directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to enumerate capability directory {}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());

    let mut catalog = HashMap::new();
    for entry in entries {
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let capability = load_capability_definition(&path)?;
        catalog.insert(capability.id.clone(), capability);
    }
    Ok(catalog)
}

pub fn list_profiles() -> &'static [&'static str] {
    &["restricted", "medium-dev", "medium-api", "open"]
}

pub fn profile_capability_ids(profile: &str) -> Option<&'static [&'static str]> {
    match profile {
        "restricted" => Some(PROFILE_RESTRICTED),
        "medium-dev" => Some(PROFILE_MEDIUM_DEV),
        "medium-api" => Some(PROFILE_MEDIUM_API),
        "open" => Some(PROFILE_OPEN),
        _ => None,
    }
}

fn normalized_ports(endpoint: &NetworkEndpoint) -> Vec<u32> {
    let mut ports = if endpoint.ports.is_empty() {
        if endpoint.port == 0 {
            Vec::new()
        } else {
            vec![endpoint.port]
        }
    } else {
        endpoint.ports.clone()
    };
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn same_endpoint(lhs: &NetworkEndpoint, rhs: &NetworkEndpoint) -> bool {
    lhs.host.eq_ignore_ascii_case(&rhs.host) && normalized_ports(lhs) == normalized_ports(rhs)
}

fn merge_endpoint(existing: &mut NetworkEndpoint, incoming: &NetworkEndpoint) {
    if existing.port == 0 {
        existing.port = incoming.port;
    }
    if existing.ports.is_empty() && !incoming.ports.is_empty() {
        existing.ports = incoming.ports.clone();
    }
    if existing.protocol.is_empty() {
        existing.protocol = incoming.protocol.clone();
    }
    if existing.tls.is_empty() {
        existing.tls = incoming.tls.clone();
    }
    if existing.enforcement.is_empty() {
        existing.enforcement = incoming.enforcement.clone();
    }
    if existing.access.is_empty() {
        existing.access = incoming.access.clone();
    }
    for rule in &incoming.rules {
        if !existing.rules.contains(rule) {
            existing.rules.push(rule.clone());
        }
    }
    for ip in &incoming.allowed_ips {
        if !existing.allowed_ips.contains(ip) {
            existing.allowed_ips.push(ip.clone());
        }
    }
}

fn merge_network_rule(existing: &mut NetworkPolicyRule, incoming: &NetworkPolicyRule) {
    if existing.name.is_empty() {
        existing.name = incoming.name.clone();
    }
    for binary in &incoming.binaries {
        if !existing.binaries.iter().any(|candidate| candidate.path == binary.path) {
            existing.binaries.push(binary.clone());
        }
    }
    for endpoint in &incoming.endpoints {
        if let Some(existing_endpoint) = existing
            .endpoints
            .iter_mut()
            .find(|candidate| same_endpoint(candidate, endpoint))
        {
            merge_endpoint(existing_endpoint, endpoint);
        } else {
            existing.endpoints.push(endpoint.clone());
        }
    }
}

pub fn add_capability(policy: &mut SandboxPolicy, capability: &CapabilityDefinition) {
    if let Some(existing) = policy.network_policies.get_mut(&capability.policy_name) {
        merge_network_rule(existing, &capability.rule);
    } else {
        policy
            .network_policies
            .insert(capability.policy_name.clone(), capability.rule.clone());
    }
}

pub fn replace_capability(policy: &mut SandboxPolicy, capability: &CapabilityDefinition) {
    policy
        .network_policies
        .insert(capability.policy_name.clone(), capability.rule.clone());
}

pub fn remove_capability(policy: &mut SandboxPolicy, capability: &CapabilityDefinition) -> bool {
    policy.network_policies.remove(&capability.policy_name).is_some()
}

pub fn apply_profile(
    policy: &mut SandboxPolicy,
    profile: &str,
    catalog: &HashMap<String, CapabilityDefinition>,
) -> Result<()> {
    let Some(capability_ids) = profile_capability_ids(profile) else {
        return Err(miette!("unknown profile '{profile}'"));
    };
    for capability_id in capability_ids {
        let capability = catalog
            .get(*capability_id)
            .ok_or_else(|| miette!("profile '{profile}' references unknown capability '{capability_id}'"))?;
        add_capability(policy, capability);
    }
    Ok(())
}

fn is_http_like_protocol(protocol: &str) -> bool {
    matches!(
        protocol.to_ascii_lowercase().as_str(),
        "http" | "https" | "rest"
    )
}

fn mutating_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

fn wildcard_host(host: &str) -> bool {
    host.contains('*')
}

fn arbitrary_internet(host: &str) -> bool {
    matches!(host, "*" | "**" | "*.*")
}

fn messaging_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.contains("discord.com")
        || host.contains("discordapp.com")
        || host.contains("api.telegram.org")
        || host.contains("slack.com")
}

fn powerful_network_binary(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path);
    matches!(
        basename,
        "curl" | "wget" | "bash" | "sh" | "python" | "python3" | "node" | "uv" | "pip"
    )
}

fn summarize_rule_risk(rule_name: &str, rule: &NetworkPolicyRule) -> RiskFinding {
    let mut level = RiskLevel::Low;
    let mut signals = Vec::new();

    for binary in &rule.binaries {
        if powerful_network_binary(&binary.path) {
            level = level.max(RiskLevel::High);
            signals.push(format!("powerful network binary: {}", binary.path));
        }
    }

    for endpoint in &rule.endpoints {
        if arbitrary_internet(&endpoint.host) {
            level = RiskLevel::Critical;
            signals.push(format!("arbitrary internet host pattern: {}", endpoint.host));
        } else if wildcard_host(&endpoint.host) {
            level = level.max(RiskLevel::High);
            signals.push(format!("wildcard host: {}", endpoint.host));
        }

        if messaging_host(&endpoint.host) {
            level = level.max(RiskLevel::High);
            signals.push(format!("messaging API host: {}", endpoint.host));
        }

        if endpoint.access.eq_ignore_ascii_case("full") {
            level = level.max(RiskLevel::High);
            signals.push("full endpoint access".to_string());
        }

        if is_http_like_protocol(&endpoint.protocol)
            && endpoint.rules.is_empty()
            && endpoint.access.is_empty()
        {
            level = level.max(RiskLevel::Medium);
            signals.push("transport allowed without REST constraints".to_string());
        }

        for l7_rule in &endpoint.rules {
            let Some(allow) = &l7_rule.allow else {
                continue;
            };

            if allow.method.is_empty() || allow.method == "*" {
                level = level.max(RiskLevel::Medium);
                signals.push("any HTTP method allowed".to_string());
            }

            if allow.path.is_empty()
                || allow.path == "*"
                || allow.path == "**"
                || allow.path == "/**"
            {
                level = level.max(RiskLevel::High);
                signals.push("broad REST path constraint".to_string());
            }

            if mutating_method(&allow.method)
                && (allow.path.is_empty()
                    || allow.path == "*"
                    || allow.path == "**"
                    || allow.path == "/**")
            {
                level = level.max(RiskLevel::High);
                signals.push(format!("mutating method with broad path: {}", allow.method));
            }
        }
    }

    let summary = if signals.is_empty() {
        "bounded rule".to_string()
    } else {
        signals.join("; ")
    };

    RiskFinding {
        rule_name: rule_name.to_string(),
        level,
        summary,
        signals,
    }
}

pub fn analyze_policy_risk(policy: &SandboxPolicy) -> RiskReport {
    let mut findings: Vec<_> = policy
        .network_policies
        .iter()
        .map(|(rule_name, rule)| summarize_rule_risk(rule_name, rule))
        .collect();
    findings.sort_by(|lhs, rhs| lhs.rule_name.cmp(&rhs.rule_name));

    let overall_risk = findings
        .iter()
        .map(|finding| finding.level)
        .max()
        .unwrap_or(RiskLevel::Low);

    RiskReport {
        overall_risk,
        findings,
    }
}

pub fn show_risk_delta(before: &SandboxPolicy, after: &SandboxPolicy) -> RiskDelta {
    let before_report = analyze_policy_risk(before);
    let after_report = analyze_policy_risk(after);

    let before_map: HashMap<_, _> = before_report
        .findings
        .iter()
        .map(|finding| (finding.rule_name.clone(), finding.clone()))
        .collect();
    let after_map: HashMap<_, _> = after_report
        .findings
        .iter()
        .map(|finding| (finding.rule_name.clone(), finding.clone()))
        .collect();

    let mut introduced = after_map
        .iter()
        .filter_map(|(rule_name, finding)| {
            (!before_map.contains_key(rule_name)).then_some(finding.clone())
        })
        .collect::<Vec<_>>();
    introduced.sort_by(|lhs, rhs| lhs.rule_name.cmp(&rhs.rule_name));

    let mut removed = before_map
        .iter()
        .filter_map(|(rule_name, finding)| (!after_map.contains_key(rule_name)).then_some(finding.clone()))
        .collect::<Vec<_>>();
    removed.sort_by(|lhs, rhs| lhs.rule_name.cmp(&rhs.rule_name));

    let mut changed = after_map
        .iter()
        .filter_map(|(rule_name, after_finding)| {
            let before_finding = before_map.get(rule_name)?;
            (before_finding.level != after_finding.level
                || before_finding.summary != after_finding.summary)
                .then(|| RiskChange {
                    rule_name: rule_name.clone(),
                    before: before_finding.level,
                    after: after_finding.level,
                    summary: after_finding.summary.clone(),
                })
        })
        .collect::<Vec<_>>();
    changed.sort_by(|lhs, rhs| lhs.rule_name.cmp(&rhs.rule_name));

    RiskDelta {
        before: before_report,
        after: after_report,
        introduced,
        removed,
        changed,
    }
}

pub fn lint_policy(policy: &SandboxPolicy) -> Vec<PolicyLint> {
    let mut lints = Vec::new();

    for (rule_name, rule) in &policy.network_policies {
        for endpoint in &rule.endpoints {
            if wildcard_host(&endpoint.host) {
                lints.push(PolicyLint {
                    code: "wildcard-domain".to_string(),
                    rule_name: Some(rule_name.clone()),
                    message: format!("rule '{rule_name}' uses wildcard host '{}'", endpoint.host),
                });
            }

            if endpoint.access.eq_ignore_ascii_case("full") {
                lints.push(PolicyLint {
                    code: "over-broad-access".to_string(),
                    rule_name: Some(rule_name.clone()),
                    message: format!("rule '{rule_name}' grants full endpoint access"),
                });
            }

            if is_http_like_protocol(&endpoint.protocol)
                && endpoint.rules.is_empty()
                && endpoint.access.is_empty()
            {
                lints.push(PolicyLint {
                    code: "missing-rest-constraints".to_string(),
                    rule_name: Some(rule_name.clone()),
                    message: format!(
                        "rule '{rule_name}' allows {} traffic without method/path constraints",
                        endpoint.protocol
                    ),
                });
            }

            for l7_rule in &endpoint.rules {
                let Some(allow) = &l7_rule.allow else {
                    continue;
                };
                if allow.path.is_empty()
                    || allow.path == "*"
                    || allow.path == "**"
                    || allow.path == "/**"
                {
                    lints.push(PolicyLint {
                        code: "broad-rest-path".to_string(),
                        rule_name: Some(rule_name.clone()),
                        message: format!("rule '{rule_name}' has a broad REST path matcher"),
                    });
                }
            }
        }

        for binary in &rule.binaries {
            if binary.path.is_empty() || !binary.path.starts_with('/') {
                lints.push(PolicyLint {
                    code: "unknown-binary".to_string(),
                    rule_name: Some(rule_name.clone()),
                    message: format!(
                        "rule '{rule_name}' uses a non-absolute binary path '{}'",
                        binary.path
                    ),
                });
            }
        }
    }

    lints
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{FilesystemPolicy, ProcessPolicy};

    fn default_policy() -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/sandbox".into()],
            }),
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        }
    }

    fn github_capability() -> CapabilityDefinition {
        parse_capability_definition(
            r#"
id: github_readonly
title: GitHub read-only API
risk: low
description: Allow GET requests to api.github.com.
policy_name: github_readonly
constraints:
  - HTTPS only
recommended_usage:
  - Read repository metadata
block:
  endpoints:
    - host: api.github.com
      port: 443
      protocol: https
      access: read-only
  binaries:
    - path: /usr/bin/curl
"#,
        )
        .expect("capability should parse")
    }

    #[test]
    fn add_capability_merges_into_policy() {
        let mut policy = default_policy();
        let capability = github_capability();

        add_capability(&mut policy, &capability);

        assert!(policy.network_policies.contains_key("github_readonly"));
        let rule = &policy.network_policies["github_readonly"];
        assert_eq!(rule.endpoints[0].host, "api.github.com");
    }

    #[test]
    fn replace_capability_overwrites_existing_rule() {
        let mut policy = default_policy();
        let mut capability = github_capability();
        add_capability(&mut policy, &capability);

        capability.rule.binaries = vec![NetworkBinary {
            path: "/usr/bin/git".to_string(),
            ..Default::default()
        }];
        replace_capability(&mut policy, &capability);

        let rule = &policy.network_policies["github_readonly"];
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/git");
    }

    #[test]
    fn remove_capability_deletes_rule() {
        let mut policy = default_policy();
        let capability = github_capability();
        add_capability(&mut policy, &capability);

        assert!(remove_capability(&mut policy, &capability));
        assert!(!policy.network_policies.contains_key("github_readonly"));
    }

    #[test]
    fn apply_profile_adds_expected_capabilities() {
        let mut policy = default_policy();
        let mut catalog = HashMap::new();
        catalog.insert("github_readonly".to_string(), github_capability());
        catalog.insert(
            "pypi_install".to_string(),
            parse_capability_definition(
                r#"
id: pypi_install
title: PyPI install
risk: medium
description: Allow package downloads.
policy_name: pypi_install
block:
  endpoints:
    - host: pypi.org
      port: 443
      protocol: https
    - host: files.pythonhosted.org
      port: 443
      protocol: https
  binaries:
    - path: /usr/bin/uv
"#,
            )
            .expect("pypi capability should parse"),
        );

        apply_profile(&mut policy, "medium-dev", &catalog).expect("profile should apply");

        assert!(policy.network_policies.contains_key("github_readonly"));
        assert!(policy.network_policies.contains_key("pypi_install"));
    }

    #[test]
    fn lint_policy_flags_broad_rules() {
        let policy = SandboxPolicy {
            network_policies: [(
                "danger".to_string(),
                NetworkPolicyRule {
                    name: "danger".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "*.example.com".to_string(),
                        port: 443,
                        protocol: "https".to_string(),
                        access: "full".to_string(),
                        rules: vec![L7Rule {
                            allow: Some(L7Allow {
                                method: "POST".to_string(),
                                path: "/**".to_string(),
                                ..Default::default()
                            }),
                        }],
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "curl".to_string(),
                        ..Default::default()
                    }],
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let codes = lint_policy(&policy)
            .into_iter()
            .map(|lint| lint.code)
            .collect::<Vec<_>>();
        assert!(codes.contains(&"wildcard-domain".to_string()));
        assert!(codes.contains(&"over-broad-access".to_string()));
        assert!(codes.contains(&"broad-rest-path".to_string()));
        assert!(codes.contains(&"unknown-binary".to_string()));
    }

    #[test]
    fn show_risk_delta_reports_introduced_and_changed_risk() {
        let before = SandboxPolicy::default();
        let after = SandboxPolicy {
            network_policies: [(
                "discord_send".to_string(),
                NetworkPolicyRule {
                    name: "discord_send".to_string(),
                    endpoints: vec![NetworkEndpoint {
                        host: "discord.com".to_string(),
                        port: 443,
                        protocol: "https".to_string(),
                        access: "full".to_string(),
                        ..Default::default()
                    }],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".to_string(),
                        ..Default::default()
                    }],
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let delta = show_risk_delta(&before, &after);
        assert_eq!(delta.before.overall_risk, RiskLevel::Low);
        assert_eq!(delta.after.overall_risk, RiskLevel::High);
        assert_eq!(delta.introduced.len(), 1);
        assert_eq!(delta.introduced[0].rule_name, "discord_send");
    }
}
