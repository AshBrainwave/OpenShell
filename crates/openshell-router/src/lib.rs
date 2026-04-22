// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod backend;
pub mod config;
mod mock;

pub use backend::{
    ProxyResponse, StreamingProxyResponse, ValidatedEndpoint, ValidationFailure,
    ValidationFailureKind, verify_backend_endpoint,
};
use config::{ResolvedRoute, RouterConfig};
use tracing::info;

const UPSTREAM_HTTP_PROXY_ENV: &str = "OPENSHELL_UPSTREAM_HTTP_PROXY";

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("route not found for route '{0}'")]
    RouteNotFound(String),
    #[error("no compatible route for protocol '{0}'")]
    NoCompatibleRoute(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("upstream protocol error: {0}")]
    UpstreamProtocol(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug)]
pub struct Router {
    routes: Vec<ResolvedRoute>,
    client: reqwest::Client,
}

impl Router {
    pub fn new() -> Result<Self, RouterError> {
        let client = build_http_client()?;
        Ok(Self {
            routes: Vec::new(),
            client,
        })
    }

    pub fn from_config(config: &RouterConfig) -> Result<Self, RouterError> {
        let resolved = config.resolve_routes()?;
        let mut router = Self::new()?;
        router.routes = resolved;
        Ok(router)
    }

    /// Proxy a raw HTTP request to the first compatible route from `candidates`.
    ///
    /// Filters candidates by `source_protocol` compatibility (exact match against
    /// one of the route's `protocols`), then forwards to the first match.
    pub async fn proxy_with_candidates(
        &self,
        source_protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
        candidates: &[ResolvedRoute],
    ) -> Result<ProxyResponse, RouterError> {
        let normalized_source = source_protocol.trim().to_ascii_lowercase();
        let route = candidates
            .iter()
            .find(|r| r.protocols.iter().any(|p| p == &normalized_source))
            .ok_or_else(|| RouterError::NoCompatibleRoute(source_protocol.to_string()))?;

        info!(
            protocols = %route.protocols.join(","),
            endpoint = %route.endpoint,
            method = %method,
            path = %path,
            "routing proxy inference request"
        );

        if mock::is_mock_route(route) {
            info!(endpoint = %route.endpoint, "returning mock response");
            return Ok(mock::mock_response(route, &normalized_source));
        }

        backend::proxy_to_backend(
            &self.client,
            route,
            &normalized_source,
            method,
            path,
            headers,
            body,
        )
        .await
    }

    /// Streaming variant of [`proxy_with_candidates`](Self::proxy_with_candidates).
    ///
    /// Returns response headers immediately without buffering the body.
    /// The caller streams body chunks via [`StreamingProxyResponse::response`].
    pub async fn proxy_with_candidates_streaming(
        &self,
        source_protocol: &str,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: bytes::Bytes,
        candidates: &[ResolvedRoute],
    ) -> Result<StreamingProxyResponse, RouterError> {
        let normalized_source = source_protocol.trim().to_ascii_lowercase();
        let route = candidates
            .iter()
            .find(|r| r.protocols.iter().any(|p| p == &normalized_source))
            .ok_or_else(|| RouterError::NoCompatibleRoute(source_protocol.to_string()))?;

        info!(
            protocols = %route.protocols.join(","),
            endpoint = %route.endpoint,
            method = %method,
            path = %path,
            "routing proxy inference request (streaming)"
        );

        if mock::is_mock_route(route) {
            info!(endpoint = %route.endpoint, "returning mock response (buffered)");
            let buffered = mock::mock_response(route, &normalized_source);
            return Ok(StreamingProxyResponse::from_buffered(buffered));
        }

        backend::proxy_to_backend_streaming(
            &self.client,
            route,
            &normalized_source,
            method,
            path,
            headers,
            body,
        )
        .await
    }
}

fn build_http_client() -> Result<reqwest::Client, RouterError> {
    let mut builder = reqwest::Client::builder();

    if let Some(proxy_url) = upstream_https_proxy_url_from_env()? {
        info!(
            upstream_http_proxy = %proxy_url,
            "router configured HTTPS upstream proxy"
        );
        let proxy = reqwest::Proxy::https(&proxy_url).map_err(|e| {
            RouterError::Internal(format!(
                "failed to configure HTTPS upstream proxy from {UPSTREAM_HTTP_PROXY_ENV}: {e}"
            ))
        })?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| RouterError::Internal(format!("failed to build HTTP client: {e}")))
}

fn upstream_https_proxy_url_from_env() -> Result<Option<String>, RouterError> {
    match std::env::var(UPSTREAM_HTTP_PROXY_ENV) {
        Ok(raw) => normalize_upstream_proxy_url(&raw),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(RouterError::Internal(format!(
            "{UPSTREAM_HTTP_PROXY_ENV} contains invalid unicode"
        ))),
    }
}

fn normalize_upstream_proxy_url(raw: &str) -> Result<Option<String>, RouterError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let parsed = reqwest::Url::parse(&candidate).map_err(|e| {
        RouterError::Internal(format!(
            "invalid {UPSTREAM_HTTP_PROXY_ENV} value '{trimmed}': {e}"
        ))
    })?;

    match parsed.scheme() {
        "http" | "https" => Ok(Some(parsed.to_string())),
        other => Err(RouterError::Internal(format!(
            "unsupported {UPSTREAM_HTTP_PROXY_ENV} scheme '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{RouteConfig, RouterConfig};

    fn test_config() -> RouterConfig {
        RouterConfig {
            routes: vec![RouteConfig {
                name: "inference.local".to_string(),
                endpoint: "http://localhost:8000/v1".to_string(),
                model: "meta/llama-3.1-8b-instruct".to_string(),
                provider_type: None,
                protocols: vec!["openai_chat_completions".to_string()],
                api_key: Some("test-key".to_string()),
                api_key_env: None,
            }],
        }
    }

    #[test]
    fn router_resolves_routes_from_config() {
        let router = Router::from_config(&test_config()).unwrap();
        assert_eq!(router.routes.len(), 1);
        assert_eq!(router.routes[0].protocols, vec!["openai_chat_completions"]);
    }

    #[test]
    fn config_missing_api_key_returns_error() {
        let config = RouterConfig {
            routes: vec![RouteConfig {
                name: "inference.local".to_string(),
                endpoint: "http://localhost".to_string(),
                model: "test-model".to_string(),
                provider_type: None,
                protocols: vec!["openai_chat_completions".to_string()],
                api_key: None,
                api_key_env: None,
            }],
        };
        let err = Router::from_config(&config).unwrap_err();
        assert!(matches!(err, RouterError::Internal(_)));
    }

    #[test]
    fn normalize_upstream_proxy_url_adds_http_scheme() {
        let proxy = normalize_upstream_proxy_url("10.99.2.1:3128")
            .unwrap()
            .expect("proxy url");
        assert_eq!(proxy, "http://10.99.2.1:3128/");
    }

    #[test]
    fn normalize_upstream_proxy_url_preserves_scheme() {
        let proxy = normalize_upstream_proxy_url("https://proxy.example:8443")
            .unwrap()
            .expect("proxy url");
        assert_eq!(proxy, "https://proxy.example:8443/");
    }

    #[test]
    fn normalize_upstream_proxy_url_rejects_bad_scheme() {
        let err = normalize_upstream_proxy_url("socks5://proxy.example:1080").unwrap_err();
        assert!(matches!(err, RouterError::Internal(_)));
        assert!(err.to_string().contains("unsupported"));
    }
}
