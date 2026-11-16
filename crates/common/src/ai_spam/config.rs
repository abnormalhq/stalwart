/*
 * SPDX-License-Identifier: AGPL-3.0-only
 */

use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub const MAX_SCORE_CAP: u8 = 5;
pub const MAX_INPUT_TOKENS: u64 = 4096;
pub const MAX_OUTPUT_TOKENS: u64 = 128;
pub const TOKENIZER_OVERHEAD_TOKENS: usize = 512;
pub const MAX_FOUNDATION_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointMode {
    External,
    Private,
    Loopback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataScope {
    SubjectAndInlinePlainText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pricing {
    pub input_micros_per_million_tokens: u64,
    pub output_micros_per_million_tokens: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budgets {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
}

#[derive(Clone, Debug)]
pub struct OperatorConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub endpoint_mode: EndpointMode,
    pub approved_ips: Vec<IpAddr>,
    pub model: String,
    pub server_id: String,
    pub revision: u64,
    pub credential_ref_id: Option<String>,
    pub credential_epoch: Option<u64>,
    pub data_scope: DataScope,
    pub billing_period: String,
    pub pricing: Option<Pricing>,
    pub budgets: Budgets,
    pub score_cap: u8,
    pub external_consent_fingerprint: Option<String>,
}

pub struct ProviderCredential {
    reference_id: String,
    epoch: u64,
    secret: String,
}

impl ProviderCredential {
    pub fn from_resolved_secret(
        reference_id: String,
        epoch: u64,
        secret: String,
    ) -> Option<Arc<Self>> {
        (!reference_id.is_empty()
            && (8..=64).contains(&reference_id.len())
            && reference_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            && (1..=MAX_FOUNDATION_INTEGER).contains(&epoch)
            && !secret.is_empty()
            && secret.len() <= 4096)
            .then(|| {
                Arc::new(Self {
                    reference_id,
                    epoch,
                    secret,
                })
            })
    }

    pub(crate) fn expose_to_provider(&self) -> &str {
        &self.secret
    }
}

impl fmt::Debug for ProviderCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCredential([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConfigError {
    InvalidEndpoint,
    InvalidModel,
    InvalidIdentity,
    InvalidPeriod,
    InvalidAllowlist,
    InvalidBudget,
    InvalidScoreCap,
}

pub struct RuntimeConfig {
    enabled: bool,
    validated: Option<ValidatedConfig>,
}

impl RuntimeConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            validated: None,
        }
    }

    pub fn unready() -> Self {
        Self {
            enabled: true,
            validated: None,
        }
    }

    pub fn from_operator(
        config: OperatorConfig,
        credential: Option<Arc<ProviderCredential>>,
    ) -> Result<Self, ConfigError> {
        if !config.enabled {
            return Ok(Self::disabled());
        }

        let endpoint =
            canonical_endpoint(&config.endpoint, config.endpoint_mode, &config.approved_ips)?;
        if config.model.is_empty()
            || config.model.len() > 128
            || tokenizer_for_model(&config.model).is_none()
            || !config
                .model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        {
            return Err(ConfigError::InvalidModel);
        }
        if config.server_id.is_empty()
            || config.server_id.len() > 128
            || !config
                .server_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || !(1..=MAX_FOUNDATION_INTEGER).contains(&config.revision)
        {
            return Err(ConfigError::InvalidIdentity);
        }
        if !valid_period(&config.billing_period) {
            return Err(ConfigError::InvalidPeriod);
        }
        if !(1..=MAX_SCORE_CAP).contains(&config.score_cap) {
            return Err(ConfigError::InvalidScoreCap);
        }

        let Some(pricing) = config.pricing else {
            return Ok(Self::unready());
        };
        let Some(max_cost) = reserved_cost(pricing) else {
            return Err(ConfigError::InvalidBudget);
        };
        if config.budgets.requests == 0
            || config.budgets.input_tokens < MAX_INPUT_TOKENS
            || config.budgets.output_tokens < MAX_OUTPUT_TOKENS
            || config.budgets.cost_micros < max_cost
        {
            return Ok(Self::unready());
        }
        if pricing.input_micros_per_million_tokens > MAX_FOUNDATION_INTEGER
            || pricing.output_micros_per_million_tokens > MAX_FOUNDATION_INTEGER
            || config.budgets.requests > MAX_FOUNDATION_INTEGER
            || config.budgets.input_tokens > MAX_FOUNDATION_INTEGER
            || config.budgets.output_tokens > MAX_FOUNDATION_INTEGER
            || config.budgets.cost_micros > MAX_FOUNDATION_INTEGER
        {
            return Err(ConfigError::InvalidBudget);
        }
        match (
            &config.credential_ref_id,
            config.credential_epoch,
            credential.as_ref(),
        ) {
            (Some(reference_id), Some(epoch), Some(resolved))
                if reference_id == &resolved.reference_id
                    && *epoch == resolved.epoch
                    && *epoch <= MAX_FOUNDATION_INTEGER => {}
            (None, None, None) => {}
            _ => return Ok(Self::unready()),
        }

        let consent = consent_fingerprint(
            &endpoint.canonical,
            &config.model,
            config.data_scope,
            &config.server_id,
            config.revision,
        );
        if config.endpoint_mode != EndpointMode::Loopback
            && config.external_consent_fingerprint.as_deref() != Some(consent.as_str())
        {
            return Ok(Self::unready());
        }

        Ok(Self {
            enabled: true,
            validated: Some(ValidatedConfig {
                endpoint: endpoint.url,
                canonical_endpoint: endpoint.canonical,
                host: endpoint.host,
                sockets: endpoint.sockets,
                model: config.model,
                server_id: config.server_id,
                billing_period: config.billing_period,
                pricing,
                budgets: config.budgets,
                score_cap: config.score_cap,
                credential,
            }),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn is_ready(&self) -> bool {
        self.validated.is_some()
    }

    pub(crate) fn validated(&self) -> Option<&ValidatedConfig> {
        self.validated.as_ref()
    }
}

pub(crate) struct ValidatedConfig {
    pub endpoint: Url,
    pub canonical_endpoint: String,
    pub host: String,
    pub sockets: Vec<SocketAddr>,
    pub model: String,
    pub server_id: String,
    pub billing_period: String,
    pub pricing: Pricing,
    pub budgets: Budgets,
    pub score_cap: u8,
    pub credential: Option<Arc<ProviderCredential>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenizerContract {
    Cl100k,
    O200k,
}

pub fn tokenizer_for_model(model: &str) -> Option<TokenizerContract> {
    match model {
        "gpt-3.5-turbo" | "gpt-4" | "gpt-4-turbo" => Some(TokenizerContract::Cl100k),
        "gpt-4o" | "gpt-4o-mini" | "gpt-4.1" | "gpt-4.1-mini" | "gpt-4.1-nano" => {
            Some(TokenizerContract::O200k)
        }
        _ => None,
    }
}

impl fmt::Debug for ValidatedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedConfig")
            .field("endpoint", &self.canonical_endpoint)
            .field("model", &self.model)
            .field("server_id", &self.server_id)
            .field("billing_period", &self.billing_period)
            .field("score_cap", &self.score_cap)
            .field("credential", &self.credential)
            .finish()
    }
}

struct CanonicalEndpoint {
    url: Url,
    canonical: String,
    host: String,
    sockets: Vec<SocketAddr>,
}

fn canonical_endpoint(
    value: &str,
    mode: EndpointMode,
    approved_ips: &[IpAddr],
) -> Result<CanonicalEndpoint, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidEndpoint)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with("/chat/completions")
    {
        return Err(ConfigError::InvalidEndpoint);
    }

    match (mode, url.scheme()) {
        (EndpointMode::External | EndpointMode::Private, "https") => {}
        (EndpointMode::Loopback, "https" | "http") => {}
        _ => return Err(ConfigError::InvalidEndpoint),
    }

    let (host, sockets) = validate_operator_ips(&url, mode, approved_ips)?;
    if matches!(
        host.as_str(),
        "metadata.google.internal" | "metadata.azure.internal" | "instance-data.ec2.internal"
    ) {
        return Err(ConfigError::InvalidEndpoint);
    }
    let canonical = url.as_str().to_owned();
    Ok(CanonicalEndpoint {
        url,
        canonical,
        host,
        sockets,
    })
}

pub(crate) fn validate_operator_ips(
    url: &Url,
    mode: EndpointMode,
    approved_ips: &[IpAddr],
) -> Result<(String, Vec<SocketAddr>), ConfigError> {
    let raw_host = url.host_str().ok_or(ConfigError::InvalidEndpoint)?;
    let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
        &raw_host[1..raw_host.len() - 1]
    } else if raw_host.contains('[') || raw_host.contains(']') {
        return Err(ConfigError::InvalidEndpoint);
    } else {
        raw_host
    }
    .to_ascii_lowercase();
    let literal_ip = host.parse::<IpAddr>().ok();
    if mode == EndpointMode::Loopback {
        if let Some(ip) = literal_ip {
            if !is_loopback_ip(ip) {
                return Err(ConfigError::InvalidAllowlist);
            }
        } else if host != "localhost" {
            return Err(ConfigError::InvalidAllowlist);
        }
    }
    if approved_ips.is_empty() || approved_ips.len() > 8 {
        return Err(ConfigError::InvalidAllowlist);
    }
    let port = url
        .port_or_known_default()
        .ok_or(ConfigError::InvalidEndpoint)?;
    let mut sockets = Vec::with_capacity(approved_ips.len());
    for ip in approved_ips {
        let valid = match mode {
            EndpointMode::External => is_public_ip(*ip),
            EndpointMode::Private => is_private_ip(*ip),
            EndpointMode::Loopback => is_loopback_ip(*ip),
        };
        if !valid || sockets.iter().any(|socket: &SocketAddr| socket.ip() == *ip) {
            return Err(ConfigError::InvalidAllowlist);
        }
        sockets.push(SocketAddr::new(*ip, port));
    }
    if let Some(host_ip) = literal_ip {
        if !approved_ips.contains(&host_ip) {
            return Err(ConfigError::InvalidAllowlist);
        }
    }
    if mode == EndpointMode::Loopback && !approved_ips.iter().all(|ip| is_loopback_ip(*ip)) {
        return Err(ConfigError::InvalidAllowlist);
    }
    Ok((host, sockets))
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip
            .to_ipv4()
            .map_or_else(|| ip.is_loopback(), |mapped| mapped.is_loopback()),
    }
}

pub fn consent_fingerprint(
    canonical_endpoint: &str,
    model: &str,
    data_scope: DataScope,
    server_id: &str,
    revision: u64,
) -> String {
    let mut hash = Sha256::new();
    let revision = revision.to_string();
    for value in [
        canonical_endpoint.as_bytes(),
        model.as_bytes(),
        match data_scope {
            DataScope::SubjectAndInlinePlainText => b"subject-inline-plain-text",
        },
        server_id.as_bytes(),
        revision.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    format!("{:x}", hash.finalize())
}

pub(crate) fn reserved_cost(pricing: Pricing) -> Option<u64> {
    let input = (u128::from(MAX_INPUT_TOKENS)
        .checked_mul(u128::from(pricing.input_micros_per_million_tokens))?
        .checked_add(999_999)?)
        / 1_000_000;
    let output = (u128::from(MAX_OUTPUT_TOKENS)
        .checked_mul(u128::from(pricing.output_micros_per_million_tokens))?
        .checked_add(999_999)?)
        / 1_000_000;
    u64::try_from(input.checked_add(output)?).ok()
}

fn valid_period(period: &str) -> bool {
    let bytes = period.as_bytes();
    let month = period.get(5..).and_then(|value| value.parse::<u8>().ok());
    bytes.len() == 7
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && month.is_some_and(|value| (1..=12).contains(&value))
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => private_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4() {
                return private_ipv4(mapped);
            }
            ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && ip.to_string() != "fd00:ec2::254"
        }
    }
}

fn private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() && !ip.is_link_local() && !ip.is_unspecified()
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4() {
                return public_ipv4(mapped);
            }
            let value = u128::from(ip);
            let in_global_unicast = value >> 125 == 1;
            let documentation = value >> 96 == 0x2001_0db8 || value >> 108 == 0x3fff0;
            let special_2001 = value >> 105 == 0x100080;
            let six_to_four = value >> 112 == 0x2002;
            let nat64_well_known = value >> 32 == 0x0064_ff9b_0000_0000_0000_0000;
            let nat64_local = value >> 80 == 0x0064_ff9b_0001;
            in_global_unicast
                && !documentation
                && !special_2001
                && !six_to_four
                && !nat64_well_known
                && !nat64_local
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && !ip.is_unique_local()
                && ip.to_string() != "fd00:ec2::254"
        }
    }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != Ipv4Addr::BROADCAST
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        && !(a == 255 && d == 255)
}
