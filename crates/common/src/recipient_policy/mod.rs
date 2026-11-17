// SPDX-License-Identifier: AGPL-3.0-only

mod store;

use crate::{Server, mail_capabilities::TenantServerScope};
use ::store::Store;
use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use store::RecipientPolicyStore;

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const MAX_COMMAND_BYTES: usize = 16 * 1024;
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipientPolicyState {
    Reserved,
    Active,
    Disabled,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyActor {
    User,
    Admin,
    Operator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientPolicyCommand {
    pub schema_version: u32,
    pub scope: TenantServerScope,
    pub remote_account_id: String,
    pub account_generation: u64,
    pub domain: String,
    pub address: String,
    pub revision: u64,
    pub state: RecipientPolicyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientPolicyAcknowledgment {
    pub schema_version: u32,
    pub address: String,
    pub scope: TenantServerScope,
    pub remote_account_id: String,
    pub account_generation: u64,
    pub revision: u64,
    pub digest: String,
    pub state: RecipientPolicyState,
    pub acknowledged_at: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RecipientPolicyConfig {
    /// Persist as an installation latch; keep RCPT enforcement active after first enable so tombstones remain enforced.
    pub enforcement_enabled: bool,
}

impl RecipientPolicyConfig {
    fn require_enabled(&self) -> Result<(), RecipientPolicyError> {
        if self.enforcement_enabled {
            Ok(())
        } else {
            Err(RecipientPolicyError::Disabled)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecipientPolicyRecord {
    pub schema_version: u32,
    pub address: String,
    pub scope: TenantServerScope,
    pub remote_account_id: String,
    pub account_generation: u64,
    pub domain: String,
    pub revision: u64,
    pub state: RecipientPolicyState,
    pub disabled_by: Option<PolicyActor>,
    pub expires_at: Option<u64>,
    pub digest: String,
    pub acknowledgment: RecipientPolicyAcknowledgment,
}

#[derive(Debug, Clone)]
pub struct TrustedRecipientPolicyContext {
    scope: TenantServerScope,
    remote_account_id: String,
    account_generation: u64,
    allowed_domains: BTreeSet<String>,
    enabled: bool,
    actor: PolicyActor,
}

impl Default for TrustedRecipientPolicyContext {
    fn default() -> Self {
        Self {
            scope: TenantServerScope {
                tenant_id: String::new(),
                server_id: String::new(),
                placement_generation: 0,
                server_generation: 0,
            },
            remote_account_id: String::new(),
            account_generation: 0,
            allowed_domains: BTreeSet::new(),
            enabled: false,
            actor: PolicyActor::User,
        }
    }
}

impl TrustedRecipientPolicyContext {
    pub fn new(
        scope: TenantServerScope,
        remote_account_id: String,
        account_generation: u64,
        allowed_domains: impl IntoIterator<Item = String>,
        enabled: bool,
        actor: PolicyActor,
    ) -> Result<Self, RecipientPolicyError> {
        let allowed_domains: BTreeSet<String> = allowed_domains.into_iter().collect();
        if !scope.is_valid()
            || remote_account_id.trim().is_empty()
            || account_generation == 0
            || allowed_domains.is_empty()
            || allowed_domains.iter().any(|domain| !valid_domain(domain))
        {
            return Err(RecipientPolicyError::InvalidCommand);
        }
        Ok(Self {
            scope,
            remote_account_id,
            account_generation,
            allowed_domains,
            enabled,
            actor,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientDecision {
    NotManaged,
    Reject,
    ContinueToAliasCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientPolicyError {
    Disabled,
    InvalidCommand,
    InvalidSignature,
    StaleTimestamp,
    UntrustedScope,
    RevisionConflict,
    Tombstoned,
    AdminDisabled,
    TemporaryFailure,
}

impl fmt::Display for RecipientPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Disabled => "Recipient policy enforcement is disabled",
            Self::InvalidCommand => "Invalid recipient policy command",
            Self::InvalidSignature => "Invalid recipient policy signature",
            Self::StaleTimestamp => "Recipient policy timestamp is outside the accepted window",
            Self::UntrustedScope => "Recipient policy scope is not authorized",
            Self::RevisionConflict => "Recipient policy revision conflict",
            Self::Tombstoned => "Recipient address is a permanent tombstone",
            Self::AdminDisabled => {
                "Administrator-disabled recipient cannot be re-enabled by a user"
            }
            Self::TemporaryFailure => "Recipient policy storage is unavailable",
        })
    }
}

impl std::error::Error for RecipientPolicyError {}

pub(super) fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && !domain.is_empty()
        && domain.is_ascii()
        && domain == domain.to_ascii_lowercase()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub(super) fn valid_address(address: &str) -> bool {
    if address.len() > 320 || !address.is_ascii() || address != address.to_ascii_lowercase() {
        return false;
    }
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.contains('@')
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
        && valid_domain(domain)
}

pub(super) fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_signature(signature: &str) -> Result<[u8; 32], RecipientPolicyError> {
    if signature.len() != 64 {
        return Err(RecipientPolicyError::InvalidSignature);
    }
    let mut decoded = [0u8; 32];
    for (index, chunk) in signature.as_bytes().chunks_exact(2).enumerate() {
        let high = (chunk[0] as char).to_digit(16);
        let low = (chunk[1] as char).to_digit(16);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(RecipientPolicyError::InvalidSignature);
        };
        if chunk.iter().any(u8::is_ascii_uppercase) {
            return Err(RecipientPolicyError::InvalidSignature);
        }
        decoded[index] = ((high << 4) | low) as u8;
    }
    Ok(decoded)
}

fn authenticate_raw_command(
    raw_body: &[u8],
    timestamp: &str,
    signature: &str,
    secret_key: &[u8],
    now: u64,
) -> Result<(RecipientPolicyCommand, String), RecipientPolicyError> {
    if raw_body.is_empty() || raw_body.len() > MAX_COMMAND_BYTES || secret_key.len() < 32 {
        return Err(RecipientPolicyError::InvalidCommand);
    }
    if timestamp.is_empty()
        || timestamp.len() > 20
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RecipientPolicyError::StaleTimestamp);
    }
    let timestamp_value = timestamp
        .parse::<u64>()
        .map_err(|_| RecipientPolicyError::StaleTimestamp)?;
    if timestamp_value.to_string() != timestamp
        || now.abs_diff(timestamp_value) > MAX_CLOCK_SKEW_SECONDS
    {
        return Err(RecipientPolicyError::StaleTimestamp);
    }

    let signature = decode_signature(signature)?;
    let mut signed = Vec::with_capacity(timestamp.len() + 1 + raw_body.len());
    signed.extend_from_slice(timestamp.as_bytes());
    signed.push(b'\n');
    signed.extend_from_slice(raw_body);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key);
    hmac::verify(&key, &signed, &signature).map_err(|_| RecipientPolicyError::InvalidSignature)?;

    let command: RecipientPolicyCommand =
        serde_json::from_slice(raw_body).map_err(|_| RecipientPolicyError::InvalidCommand)?;
    let digest = hex(&Sha256::digest(raw_body));
    Ok((command, digest))
}

fn authorize_command(
    command: &RecipientPolicyCommand,
    trusted: &TrustedRecipientPolicyContext,
) -> Result<(), RecipientPolicyError> {
    if !trusted.enabled {
        return Err(RecipientPolicyError::Disabled);
    }
    let max_generation = crate::mail_capabilities::MAX_SAFE_JS_INTEGER;
    if command.schema_version != POLICY_SCHEMA_VERSION
        || !command.scope.is_valid()
        || command.scope != trusted.scope
        || command.remote_account_id != trusted.remote_account_id
        || command.account_generation != trusted.account_generation
        || !(1..=max_generation).contains(&command.account_generation)
        || !(1..=max_generation).contains(&command.revision)
        || !valid_domain(&command.domain)
        || !valid_address(&command.address)
        || command.address.rsplit_once('@').map(|(_, domain)| domain)
            != Some(command.domain.as_str())
        || !trusted.allowed_domains.contains(&command.domain)
        || command
            .expires_at
            .is_some_and(|expiry| expiry > max_generation)
        || (command.state == RecipientPolicyState::Reserved && command.expires_at.is_some())
    {
        return Err(RecipientPolicyError::UntrustedScope);
    }
    Ok(())
}

fn apply_transition(
    current: Option<RecipientPolicyRecord>,
    command: &RecipientPolicyCommand,
    digest: &str,
    actor: PolicyActor,
    acknowledged_at: u64,
) -> Result<RecipientPolicyRecord, RecipientPolicyError> {
    if !valid_address(&command.address) || digest.len() != 64 {
        return Err(RecipientPolicyError::InvalidCommand);
    }

    if let Some(current) = current {
        if current.address != command.address
            || current.scope != command.scope
            || current.remote_account_id != command.remote_account_id
            || current.account_generation != command.account_generation
            || current.domain != command.domain
        {
            return Err(RecipientPolicyError::UntrustedScope);
        }
        if current.revision == command.revision && current.digest == digest {
            return Ok(current);
        }
        if current.state == RecipientPolicyState::Deleted {
            return Err(RecipientPolicyError::Tombstoned);
        }
        if command.revision != current.revision.saturating_add(1) {
            return Err(RecipientPolicyError::RevisionConflict);
        }
        if current.state == RecipientPolicyState::Disabled
            && matches!(
                current.disabled_by,
                Some(PolicyActor::Admin | PolicyActor::Operator)
            )
            && actor == PolicyActor::User
        {
            return Err(RecipientPolicyError::AdminDisabled);
        }
        if current.state == RecipientPolicyState::Reserved
            && !matches!(
                command.state,
                RecipientPolicyState::Active | RecipientPolicyState::Deleted
            )
        {
            return Err(RecipientPolicyError::RevisionConflict);
        }
        if command.state == RecipientPolicyState::Reserved {
            return Err(RecipientPolicyError::RevisionConflict);
        }
    } else if command.revision != 1
        || command.state != RecipientPolicyState::Reserved
        || command.expires_at.is_some()
    {
        return Err(RecipientPolicyError::RevisionConflict);
    }

    let disabled_by = (command.state == RecipientPolicyState::Disabled).then_some(actor);
    let acknowledgment = RecipientPolicyAcknowledgment {
        schema_version: POLICY_SCHEMA_VERSION,
        address: command.address.clone(),
        scope: command.scope.clone(),
        remote_account_id: command.remote_account_id.clone(),
        account_generation: command.account_generation,
        revision: command.revision,
        digest: digest.to_string(),
        state: command.state,
        acknowledged_at,
    };
    Ok(RecipientPolicyRecord {
        schema_version: POLICY_SCHEMA_VERSION,
        address: command.address.clone(),
        scope: command.scope.clone(),
        remote_account_id: command.remote_account_id.clone(),
        account_generation: command.account_generation,
        domain: command.domain.clone(),
        revision: command.revision,
        state: command.state,
        disabled_by,
        expires_at: command.expires_at,
        digest: digest.to_string(),
        acknowledgment,
    })
}

pub async fn apply_signed_command(
    config: &RecipientPolicyConfig,
    server: &Server,
    trusted: &TrustedRecipientPolicyContext,
    secret_key: &[u8],
    raw_body: &[u8],
    timestamp: &str,
    signature: &str,
    now: u64,
) -> Result<RecipientPolicyAcknowledgment, RecipientPolicyError> {
    config.require_enabled()?;
    if !trusted.enabled {
        return Err(RecipientPolicyError::Disabled);
    }
    let (command, digest) =
        authenticate_raw_command(raw_body, timestamp, signature, secret_key, now)?;
    authorize_command(&command, trusted)?;
    RecipientPolicyStore::apply(server.store(), &command, &digest, trusted.actor, now).await
}

pub async fn recipient_decision(
    config: &RecipientPolicyConfig,
    store: &Store,
    address: &str,
    current_account: Option<&crate::mail_capabilities::ScopedMailAccount>,
    now: u64,
) -> Result<RecipientDecision, RecipientPolicyError> {
    config.require_enabled()?;
    let normalized_address = address.to_ascii_lowercase();
    if !valid_address(&normalized_address) {
        return Ok(RecipientDecision::NotManaged);
    }
    let Some(record) = RecipientPolicyStore::read(store, &normalized_address).await? else {
        return Ok(RecipientDecision::NotManaged);
    };
    Ok(decide_record(
        Some(&record),
        &normalized_address,
        current_account,
        now,
    ))
}

fn decide_record(
    record: Option<&RecipientPolicyRecord>,
    address: &str,
    current_account: Option<&crate::mail_capabilities::ScopedMailAccount>,
    now: u64,
) -> RecipientDecision {
    let Some(record) = record else {
        return RecipientDecision::NotManaged;
    };
    if record.address != address
        || record.domain
            != address
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or_default()
    {
        return RecipientDecision::Reject;
    }
    match record.state {
        RecipientPolicyState::Reserved
        | RecipientPolicyState::Disabled
        | RecipientPolicyState::Deleted => {
            return RecipientDecision::Reject;
        }
        RecipientPolicyState::Active
            if record
                .expires_at
                .is_some_and(|expires_at| expires_at <= now) =>
        {
            return RecipientDecision::Reject;
        }
        RecipientPolicyState::Active => {}
    }
    if let Some(current_account) = current_account {
        if !current_account.is_valid()
            || record.scope != current_account.scope()
            || record.remote_account_id != current_account.account_id
            || record.account_generation != current_account.account_generation
        {
            return RecipientDecision::Reject;
        }
    }
    RecipientDecision::ContinueToAliasCheck
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> TenantServerScope {
        TenantServerScope {
            tenant_id: "tenant-a".to_string(),
            server_id: "server-a".to_string(),
            placement_generation: 3,
            server_generation: 2,
        }
    }

    fn trusted(actor: PolicyActor, enabled: bool) -> TrustedRecipientPolicyContext {
        TrustedRecipientPolicyContext::new(
            scope(),
            "account-a".to_string(),
            5,
            ["example.test".to_string()],
            enabled,
            actor,
        )
        .unwrap()
    }

    fn command(revision: u64, state: RecipientPolicyState) -> RecipientPolicyCommand {
        RecipientPolicyCommand {
            schema_version: POLICY_SCHEMA_VERSION,
            scope: scope(),
            remote_account_id: "account-a".to_string(),
            account_generation: 5,
            domain: "example.test".to_string(),
            address: "masked@example.test".to_string(),
            revision,
            state,
            expires_at: None,
        }
    }

    fn transition(
        current: Option<RecipientPolicyRecord>,
        command: &RecipientPolicyCommand,
        digest: &str,
        actor: PolicyActor,
        acknowledged_at: u64,
    ) -> Result<RecipientPolicyRecord, RecipientPolicyError> {
        apply_transition(current, command, digest, actor, acknowledged_at)
    }

    fn signed_body(
        command: &RecipientPolicyCommand,
        key: &[u8],
        timestamp: &str,
    ) -> (Vec<u8>, String) {
        let body = serde_json::to_vec(command).unwrap();
        let mut message = timestamp.as_bytes().to_vec();
        message.push(b'\n');
        message.extend_from_slice(&body);
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let signature = hex(hmac::sign(&key, &message).as_ref());
        (body, signature)
    }

    #[test]
    fn rejects_untrusted_scope_account_generation_and_domain() {
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.scope.tenant_id = "tenant-b".to_string();
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.scope.server_id = "server-b".to_string();
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.scope.placement_generation += 1;
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.remote_account_id = "account-b".to_string();
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.account_generation += 1;
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        let mut value = command(1, RecipientPolicyState::Reserved);
        value.domain = "elsewhere.test".to_string();
        assert_eq!(
            authorize_command(&value, &trusted(PolicyActor::User, true)),
            Err(RecipientPolicyError::UntrustedScope)
        );
        assert_eq!(
            authorize_command(
                &command(1, RecipientPolicyState::Reserved),
                &trusted(PolicyActor::User, false)
            ),
            Err(RecipientPolicyError::Disabled)
        );
    }

    #[tokio::test]
    async fn disabled_enforcement_fails_closed_without_a_store() {
        assert_eq!(
            recipient_decision(
                &RecipientPolicyConfig::default(),
                &::store::Store::None,
                "ordinary@example.test",
                None,
                10,
            )
            .await,
            Err(RecipientPolicyError::Disabled)
        );
    }

    #[test]
    fn default_config_cannot_acknowledge_policy_installation() {
        assert_eq!(
            RecipientPolicyConfig::default().require_enabled(),
            Err(RecipientPolicyError::Disabled)
        );
    }

    #[test]
    fn authenticates_bounded_raw_json_with_timestamp_and_hmac() {
        let key = [7u8; 32];
        let timestamp = "1700000000";
        let (body, signature) =
            signed_body(&command(1, RecipientPolicyState::Reserved), &key, timestamp);
        let (parsed, digest) =
            authenticate_raw_command(&body, timestamp, &signature, &key, 1_700_000_000).unwrap();
        assert_eq!(parsed, command(1, RecipientPolicyState::Reserved));
        assert_eq!(digest, hex(&Sha256::digest(&body)));
        assert_eq!(
            authenticate_raw_command(&body, timestamp, &signature, &key, 1_700_000_301),
            Err(RecipientPolicyError::StaleTimestamp)
        );
        assert_eq!(
            authenticate_raw_command(&body, timestamp, &signature, &key, 1_700_000_000 - 301),
            Err(RecipientPolicyError::StaleTimestamp)
        );
        assert_eq!(
            authenticate_raw_command(&body, timestamp, &signature, &key, 1_700_000_000),
            Ok((parsed, digest))
        );
    }

    #[test]
    fn revisions_are_idempotent_and_reject_reuse_with_different_content() {
        let reserve = command(1, RecipientPolicyState::Reserved);
        let first = transition(
            None,
            &reserve,
            "a".repeat(64).as_str(),
            PolicyActor::User,
            10,
        )
        .unwrap();
        let replay = transition(
            Some(first.clone()),
            &reserve,
            &first.digest,
            PolicyActor::User,
            20,
        )
        .unwrap();
        assert_eq!(replay, first);
        assert_eq!(
            transition(
                Some(first),
                &reserve,
                "b".repeat(64).as_str(),
                PolicyActor::User,
                20
            ),
            Err(RecipientPolicyError::RevisionConflict)
        );
    }

    #[test]
    fn deleted_addresses_are_tombstones_and_admin_disable_has_precedence() {
        let reserved = transition(
            None,
            &command(1, RecipientPolicyState::Reserved),
            &"a".repeat(64),
            PolicyActor::User,
            10,
        )
        .unwrap();
        assert_eq!(
            decide_record(Some(&reserved), "masked@example.test", None, 10),
            RecipientDecision::Reject
        );
        let deleted = transition(
            Some(reserved),
            &command(2, RecipientPolicyState::Deleted),
            &"b".repeat(64),
            PolicyActor::User,
            11,
        )
        .unwrap();
        assert_eq!(
            decide_record(Some(&deleted), "masked@example.test", None, 12),
            RecipientDecision::Reject
        );
        assert_eq!(
            transition(
                Some(deleted),
                &command(3, RecipientPolicyState::Active),
                &"c".repeat(64),
                PolicyActor::Admin,
                12
            ),
            Err(RecipientPolicyError::Tombstoned)
        );

        let reserved = transition(
            None,
            &command(1, RecipientPolicyState::Reserved),
            &"a".repeat(64),
            PolicyActor::User,
            10,
        )
        .unwrap();
        let active = transition(
            Some(reserved),
            &command(2, RecipientPolicyState::Active),
            &"b".repeat(64),
            PolicyActor::User,
            11,
        )
        .unwrap();
        let disabled = transition(
            Some(active),
            &command(3, RecipientPolicyState::Disabled),
            &"c".repeat(64),
            PolicyActor::Admin,
            12,
        )
        .unwrap();
        assert_eq!(
            decide_record(Some(&disabled), "masked@example.test", None, 12),
            RecipientDecision::Reject
        );
        assert_eq!(
            transition(
                Some(disabled),
                &command(4, RecipientPolicyState::Active),
                &"d".repeat(64),
                PolicyActor::User,
                13
            ),
            Err(RecipientPolicyError::AdminDisabled)
        );
    }

    #[test]
    fn expiry_boundary_and_ordinary_recipient_decisions_fail_closed_without_bypassing_alias_checks()
    {
        let reserved = transition(
            None,
            &command(1, RecipientPolicyState::Reserved),
            &"a".repeat(64),
            PolicyActor::User,
            10,
        )
        .unwrap();
        let mut active_command = command(2, RecipientPolicyState::Active);
        active_command.expires_at = Some(100);
        let active = transition(
            Some(reserved),
            &active_command,
            &"b".repeat(64),
            PolicyActor::User,
            11,
        )
        .unwrap();
        let account = crate::mail_capabilities::ScopedMailAccount {
            tenant_id: "tenant-a".to_string(),
            server_id: "server-a".to_string(),
            placement_generation: 3,
            server_generation: 2,
            account_id: "account-a".to_string(),
            account_generation: 5,
        };
        assert_eq!(
            decide_record(Some(&active), "masked@example.test", Some(&account), 99),
            RecipientDecision::ContinueToAliasCheck
        );
        assert_eq!(
            decide_record(Some(&active), "masked@example.test", Some(&account), 100),
            RecipientDecision::Reject
        );
        assert_eq!(
            decide_record(Some(&active), "masked@example.test", None, 99),
            RecipientDecision::ContinueToAliasCheck
        );
        assert_eq!(
            decide_record(None, "ordinary@example.test", None, 100),
            RecipientDecision::NotManaged
        );
        let mut stale_account = account.clone();
        stale_account.account_generation += 1;
        assert_eq!(
            decide_record(
                Some(&active),
                "masked@example.test",
                Some(&stale_account),
                99
            ),
            RecipientDecision::Reject
        );
    }
}
