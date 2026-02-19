//! LLM manager for provider credentials and HTTP client.
//!
//! The manager is intentionally simple — it holds API keys, an HTTP client,
//! and shared rate limit state. Routing decisions (which model for which
//! process) live on the agent's RoutingConfig, not here.

use crate::config::LlmConfig;
use crate::error::{LlmError, Result};
use anyhow::Context as _;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

const OPENAI_DEFAULT_CHAT_COMPLETIONS_ENDPOINT: &str = "https://api.openai.com/v1/chat/completions";

/// Manages LLM provider clients and tracks rate limit state.
pub struct LlmManager {
    config: LlmConfig,
    http_client: reqwest::Client,
    /// Models currently in rate limit cooldown, with the time they were limited.
    rate_limited: Arc<RwLock<HashMap<String, Instant>>>,
}

impl LlmManager {
    /// Create a new LLM manager with the given configuration.
    pub async fn new(config: LlmConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .with_context(|| "failed to build HTTP client")?;

        Ok(Self {
            config,
            http_client,
            rate_limited: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get the appropriate API key for a provider.
    pub fn get_api_key(&self, provider: &str) -> Result<String> {
        match provider {
            "anthropic" => self
                .config
                .anthropic_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("anthropic".into()).into()),
            "openai" => self
                .config
                .openai_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("openai".into()).into()),
            "nvidia" => self
                .config
                .nvidia_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("nvidia".into()).into()),
            "openrouter" => self
                .config
                .openrouter_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("openrouter".into()).into()),
            "zhipu" => self
                .config
                .zhipu_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("zhipu".into()).into()),
            "groq" => self
                .config
                .groq_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("groq".into()).into()),
            "together" => self
                .config
                .together_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("together".into()).into()),
            "fireworks" => self
                .config
                .fireworks_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("fireworks".into()).into()),
            "deepseek" => self
                .config
                .deepseek_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("deepseek".into()).into()),
            "xai" => self
                .config
                .xai_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("xai".into()).into()),
            "mistral" => self
                .config
                .mistral_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("mistral".into()).into()),
            "ollama" => self
                .config
                .ollama_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("ollama".into()).into()),
            "opencode-zen" => self
                .config
                .opencode_zen_key
                .clone()
                .ok_or_else(|| LlmError::MissingProviderKey("opencode-zen".into()).into()),
            _ => Err(LlmError::UnknownProvider(provider.into()).into()),
        }
    }

    /// Get configured Ollama base URL, if provided.
    pub fn ollama_base_url(&self) -> Option<String> {
        self.config.ollama_base_url.clone()
    }

    /// Get the HTTP client.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Resolve the OpenAI-compatible chat completions endpoint.
    ///
    /// If `llm.openai_base_url` is configured, this method appends
    /// `/chat/completions` unless the URL already points to that endpoint.
    pub fn openai_chat_completions_endpoint(&self) -> String {
        normalize_openai_chat_completions_endpoint(self.config.openai_base_url.as_deref())
    }

    /// Resolve a model name to provider and model components.
    /// Format: "provider/model-name" or just "model-name" (defaults to anthropic).
    pub fn resolve_model(&self, model_name: &str) -> Result<(String, String)> {
        if let Some((provider, model)) = model_name.split_once('/') {
            Ok((provider.to_string(), model.to_string()))
        } else {
            Ok(("anthropic".into(), model_name.into()))
        }
    }

    /// Record that a model hit a rate limit.
    pub async fn record_rate_limit(&self, model_name: &str) {
        self.rate_limited
            .write()
            .await
            .insert(model_name.to_string(), Instant::now());
        tracing::warn!(model = %model_name, "model rate limited, entering cooldown");
    }

    /// Check if a model is currently in rate limit cooldown.
    pub async fn is_rate_limited(&self, model_name: &str, cooldown_secs: u64) -> bool {
        let map = self.rate_limited.read().await;
        if let Some(limited_at) = map.get(model_name) {
            limited_at.elapsed().as_secs() < cooldown_secs
        } else {
            false
        }
    }

    /// Clean up expired rate limit entries.
    pub async fn cleanup_rate_limits(&self, cooldown_secs: u64) {
        self.rate_limited
            .write()
            .await
            .retain(|_, limited_at| limited_at.elapsed().as_secs() < cooldown_secs);
    }
}

fn normalize_openai_chat_completions_endpoint(base_url: Option<&str>) -> String {
    let Some(base_url) = base_url.map(str::trim).filter(|url| !url.is_empty()) else {
        return OPENAI_DEFAULT_CHAT_COMPLETIONS_ENDPOINT.to_string();
    };

    if base_url.ends_with("/chat/completions") {
        return base_url.to_string();
    }

    let trimmed_base = base_url.trim_end_matches('/');
    format!("{trimmed_base}/chat/completions")
}
