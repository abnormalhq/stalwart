// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MailModule {
    Isolation,
    Scim,
    Telemetry,
    Retention,
    Storage,
    AiSpam,
    Customization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleRevisionState {
    Disabled,
    Pending,
    Applied,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantServerScope {
    pub tenant_id: String,
    pub server_id: String,
    pub placement_generation: u64,
    pub server_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopedMailAccount {
    pub tenant_id: String,
    pub server_id: String,
    pub placement_generation: u64,
    pub server_generation: u64,
    pub account_id: String,
    pub account_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyAcknowledgment {
    pub scope: TenantServerScope,
    pub module: MailModule,
    pub schema_version: u32,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub desired_digest: String,
    pub applied_digest: String,
    pub enabled: bool,
    pub state: ModuleRevisionState,
    pub acknowledged_at: String,
}

impl TenantServerScope {
    pub fn is_valid(&self) -> bool {
        valid_identifier(&self.tenant_id)
            && valid_identifier(&self.server_id)
            && valid_generation(self.placement_generation)
            && valid_generation(self.server_generation)
    }
}

impl ScopedMailAccount {
    pub fn is_valid(&self) -> bool {
        valid_identifier(&self.tenant_id)
            && valid_identifier(&self.server_id)
            && valid_generation(self.placement_generation)
            && valid_generation(self.server_generation)
            && valid_identifier(&self.account_id)
            && valid_generation(self.account_generation)
    }

    pub fn scope(&self) -> TenantServerScope {
        TenantServerScope {
            tenant_id: self.tenant_id.clone(),
            server_id: self.server_id.clone(),
            placement_generation: self.placement_generation,
            server_generation: self.server_generation,
        }
    }
}

impl PolicyAcknowledgment {
    pub fn is_current(
        &self,
        current_scope: &TenantServerScope,
        current_module: MailModule,
        desired_revision: u64,
        desired_digest: &str,
    ) -> bool {
        current_scope.is_valid()
            && self.scope.is_valid()
            && self.scope == *current_scope
            && self.module == current_module
            && self.schema_version == SCHEMA_VERSION
            && valid_generation(desired_revision)
            && self.desired_revision == desired_revision
            && self.applied_revision == self.desired_revision
            && valid_digest(desired_digest)
            && self.desired_digest == desired_digest
            && valid_digest(&self.desired_digest)
            && self.applied_digest == self.desired_digest
            && self.enabled
            && self.state == ModuleRevisionState::Applied
            && valid_identifier(&self.acknowledged_at)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim()
}

fn valid_generation(value: u64) -> bool {
    (1..=MAX_SAFE_JS_INTEGER).contains(&value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    fn acknowledgment() -> PolicyAcknowledgment {
        PolicyAcknowledgment {
            scope: scope(),
            module: MailModule::Retention,
            schema_version: SCHEMA_VERSION,
            desired_revision: 4,
            applied_revision: 4,
            desired_digest: "a".repeat(64),
            applied_digest: "a".repeat(64),
            enabled: true,
            state: ModuleRevisionState::Applied,
            acknowledged_at: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    #[test]
    fn modules_and_contracts_serialize_with_the_shared_json_shape() {
        for (module, name) in [
            (MailModule::Isolation, "isolation"),
            (MailModule::Scim, "scim"),
            (MailModule::Telemetry, "telemetry"),
            (MailModule::Retention, "retention"),
            (MailModule::Storage, "storage"),
            (MailModule::AiSpam, "ai-spam"),
            (MailModule::Customization, "customization"),
        ] {
            assert_eq!(
                serde_json::to_string(&module).unwrap(),
                format!("\"{name}\"")
            );
        }
        let value = serde_json::to_value(ScopedMailAccount {
            tenant_id: "tenant-a".to_string(),
            server_id: "server-a".to_string(),
            placement_generation: 3,
            server_generation: 2,
            account_id: "remote-a".to_string(),
            account_generation: 5,
        })
        .unwrap();
        assert_eq!(value["tenantId"], "tenant-a");
        assert_eq!(value["accountId"], "remote-a");
        assert_eq!(value["accountGeneration"], 5);
    }

    #[test]
    fn unknown_fields_and_invalid_scopes_are_rejected() {
        let mut scope_json = serde_json::to_value(scope()).unwrap();
        scope_json["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TenantServerScope>(scope_json).is_err());

        let mut account_json = serde_json::to_value(ScopedMailAccount {
            tenant_id: "tenant-a".to_string(),
            server_id: "server-a".to_string(),
            placement_generation: 3,
            server_generation: 2,
            account_id: "remote-a".to_string(),
            account_generation: 5,
        })
        .unwrap();
        account_json["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ScopedMailAccount>(account_json).is_err());

        let mut acknowledgment_json = serde_json::to_value(acknowledgment()).unwrap();
        acknowledgment_json["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PolicyAcknowledgment>(acknowledgment_json).is_err());

        let mut invalid = scope();
        invalid.placement_generation = MAX_SAFE_JS_INTEGER + 1;
        assert!(!invalid.is_valid());
        invalid.placement_generation = 1;
        invalid.tenant_id = " tenant-a".to_string();
        assert!(!invalid.is_valid());
    }

    #[test]
    fn acknowledgment_requires_enabled_current_revision_and_generation() {
        let acknowledgment = acknowledgment();
        assert!(acknowledgment.is_current(&scope(), MailModule::Retention, 4, &"a".repeat(64)));
        assert!(!acknowledgment.is_current(&scope(), MailModule::Retention, 5, &"a".repeat(64)));

        let mut stale_scope = scope();
        stale_scope.placement_generation += 1;
        assert!(!acknowledgment.is_current(
            &stale_scope,
            MailModule::Retention,
            4,
            &"a".repeat(64)
        ));

        assert!(!acknowledgment.is_current(&scope(), MailModule::Storage, 4, &"a".repeat(64)));
        assert!(!acknowledgment.is_current(&scope(), MailModule::Retention, 4, &"b".repeat(64)));

        let mut stale_applied_revision = acknowledgment.clone();
        stale_applied_revision.applied_revision = 3;
        assert!(!stale_applied_revision.is_current(
            &scope(),
            MailModule::Retention,
            4,
            &"a".repeat(64)
        ));

        let mut disabled = acknowledgment;
        disabled.enabled = false;
        disabled.state = ModuleRevisionState::Disabled;
        assert!(!disabled.is_current(&scope(), MailModule::Retention, 4, &"a".repeat(64)));
    }

    #[test]
    fn unsupported_schema_and_malformed_digests_fail_closed() {
        let mut unsupported = acknowledgment();
        unsupported.schema_version = SCHEMA_VERSION + 1;
        assert!(!unsupported.is_current(&scope(), MailModule::Retention, 4, &"a".repeat(64)));

        let mut acknowledgment = acknowledgment();
        acknowledgment.desired_digest = "A".repeat(64);
        assert!(!acknowledgment.is_current(&scope(), MailModule::Retention, 4, &"A".repeat(64)));
    }
}
