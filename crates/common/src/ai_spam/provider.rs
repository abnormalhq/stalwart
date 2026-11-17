/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use crate::ai_spam::{config::ValidatedConfig, input::SYSTEM_PROMPT};
use futures::StreamExt;
use serde::Deserialize;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub const MAX_RESPONSE_BYTES: usize = 2048;
pub const PROVIDER_DEADLINE: Duration = Duration::from_millis(1500);

pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ModelResult, ProviderError>> + Send + 'a>>;

pub trait Provider: Send + Sync {
    fn classify<'a>(&'a self, input: &'a str) -> ProviderFuture<'a>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Verdict {
    Spam,
    Ham,
    Uncertain,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ModelResult {
    pub verdict: Verdict,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProviderError {
    Transport,
    InvalidResponse,
    OversizedResponse,
}

pub struct HttpProvider {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    model: String,
    credential: Option<Arc<crate::ai_spam::config::ProviderCredential>>,
}

impl HttpProvider {
    pub(crate) fn new(config: &ValidatedConfig) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(PROVIDER_DEADLINE)
            .resolve_to_addrs(&config.host, &config.sockets)
            .build()
            .map_err(|_| ProviderError::Transport)?;
        Ok(Self {
            client,
            endpoint: config.endpoint.clone(),
            model: config.model.clone(),
            credential: config.credential.clone(),
        })
    }

    async fn request(&self, input: &str) -> Result<ModelResult, ProviderError> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": input }
            ],
            "max_tokens": 128,
            "stream": false
        });
        let body = serde_json::to_vec(&body).map_err(|_| ProviderError::InvalidResponse)?;
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(credential) = self.credential.as_ref() {
            request = request.bearer_auth(credential.expose_to_provider());
        }
        let response = request.send().await.map_err(|_| ProviderError::Transport)?;
        if !response.status().is_success() {
            return Err(ProviderError::InvalidResponse);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ProviderError::OversizedResponse);
        }

        let mut stream = response.bytes_stream();
        let mut bytes = Vec::with_capacity(MAX_RESPONSE_BYTES);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| ProviderError::Transport)?;
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ProviderError::OversizedResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_response(&bytes)
    }
}

impl Provider for HttpProvider {
    fn classify<'a>(&'a self, input: &'a str) -> ProviderFuture<'a> {
        Box::pin(self.request(input))
    }
}

#[derive(Deserialize)]
struct Envelope {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Choice {
    message: AssistantMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct AssistantMessage {
    role: String,
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct Usage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelOutput {
    verdict: OutputVerdict,
    confidence: u8,
}

#[derive(Deserialize)]
enum OutputVerdict {
    #[serde(rename = "spam")]
    Spam,
    #[serde(rename = "ham")]
    Ham,
    #[serde(rename = "uncertain")]
    Uncertain,
}

pub(crate) fn parse_response(bytes: &[u8]) -> Result<ModelResult, ProviderError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProviderError::OversizedResponse);
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| ProviderError::InvalidResponse)?;
    if envelope.choices.len() != 1 {
        return Err(ProviderError::InvalidResponse);
    }
    let choice = &envelope.choices[0];
    if choice.message.role != "assistant"
        || choice
            .message
            .tool_calls
            .as_ref()
            .is_some_and(|calls| !calls.is_empty())
        || choice
            .finish_reason
            .as_deref()
            .is_some_and(|reason| reason != "stop")
    {
        return Err(ProviderError::InvalidResponse);
    }
    if let Some(usage) = envelope.usage {
        if usage.prompt_tokens.is_some_and(|value| value > 4096)
            || usage.completion_tokens.is_some_and(|value| value > 128)
            || usage.total_tokens.is_some_and(|value| value > 4224)
        {
            return Err(ProviderError::InvalidResponse);
        }
    }
    let content = choice
        .message
        .content
        .as_deref()
        .ok_or(ProviderError::InvalidResponse)?;
    let output: ModelOutput =
        serde_json::from_str(content).map_err(|_| ProviderError::InvalidResponse)?;
    if output.confidence > 100 {
        return Err(ProviderError::InvalidResponse);
    }
    let verdict = match output.verdict {
        OutputVerdict::Spam => Verdict::Spam,
        OutputVerdict::Ham => Verdict::Ham,
        OutputVerdict::Uncertain => Verdict::Uncertain,
    };
    Ok(ModelResult {
        verdict,
        confidence: output.confidence,
    })
}
