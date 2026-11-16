# Stalwart v1.1.1 Community update

This is a selective Community port of upstream v1.1.1 (`3adead91f3c87e7415b58c9ed8e6ec05a5dda521`) on the Abnormal debranding baseline. It is not a wholesale upstream merge. Upstream copyright and license notices remain in place; newly adopted masked-address source is taken from the official dual-licensed v1.1.1 files with their AGPL/SEL headers intact.

## Masked addresses

The official codec and registry representation are included for compatibility, but native masked-address routing is not available in this Community update. `common::network::masked::MASKED_ADDRESS_ROUTING_AVAILABLE` is a server-owned literal `false`; it has no environment, configuration, or feature override. Both native routing call sites use `parse_for_routing`, which returns before decoding or registry access while the gate is closed. JMAP get, query, and set requests are rejected with `Forbidden` before dispatch.

The Community `schema_oss.json.gz` and matching hash are refreshed from the pinned v1.1.1 OSS artifact served by the non-Enterprise HTTP path. It includes `MaskedEmail` metadata; that metadata does not make the object available through JMAP or routing. The mixed Enterprise `schema.json.gz` and hash are not changed.

Existing directory and explicit Mail aliases are not rewritten, rejected, or changed by native masked-address decoding. No stored aliases are migrated. Keep the native feature disabled until Console adaptation and isolation validation receive separate review.

Changing the false constant alone is not a complete or approved activation path. The following Abnormal policy and lifecycle work remains excluded and needs separate design, review, and validation before activation:

- Console integration and isolation validation for native masked-address creation and management.
- OAuth scope and authorization policy for users, administrators, and object creation.
- Product quota/configuration integration, including account/tenant scope and limits.
- Cache invalidation for masked-object updates, disablement, expiry, and deletion.
- Account/object cleanup and ownership handling for deletion, transfer, or loss of access.
- Abnormal store key-path adaptation plus persistence and compatibility checks.
- Recipient/address-format policy, including the pending Mail 14/27 decision; this port selects neither format.
- End-to-end validation across supported storage backends and restart/import scenarios.

Imported or pre-existing native objects cannot activate routing while the gate remains false. The upstream schema/object mapping and quota-check code are carried but remain unreachable through Community JMAP while the guard is closed. This port does not provide Abnormal-specific OAuth scopes, quota/configuration lifecycle, cache invalidation, account cleanup, or store-key adaptation; no native provider is exposed or activated.

## Configuration migration

Upstream v1.1.1 changes the Netcup DNS API to key-only authentication. Existing Netcup configurations using a customer number, API key ID, and password need migration to the new API key field before using that provider.

## Preserved and deferred licensing boundaries

The still-SEL `crates/common/src/enterprise/mod.rs`, `crates/common/src/enterprise/masked.rs`, and `crates/smtp/src/queue/tenant.rs` remain untouched. Existing still-SEL snippets remain byte-for-byte as they were on the Abnormal baseline; scheduler SEL changes are excluded. Mixed generated schema changes are selective rather than whole-file replacements. Only the `itip_add_uninvited_attendee` / `ItipOrigin` forwarded-invitation interface and its paired email-ingest integration remain deferred. The independent RSVP-preservation fix in `crates/groupware/src/scheduling/inbound.rs` and first-RRULE-wins fix in `crates/groupware/src/calendar/itip.rs` are included.

The v1.1.1 update does not modify the Mail repository, rewrite stored aliases, or change the Mail 14/27 policy.
