# Stalwart v1.1.1 Community update

This is a selective Community port of upstream v1.1.1 (`3adead91f3c87e7415b58c9ed8e6ec05a5dda521`) on the Abnormal debranding baseline. It is not a wholesale upstream merge. Upstream copyright and license notices remain in place; newly adopted masked-address source is taken from the official dual-licensed v1.1.1 files with their AGPL/SEL headers intact.

## Masked addresses

The official codec and registry representation are included for compatibility, but native masked-address routing is not available in this Community update. `common::network::masked::MASKED_ADDRESS_ROUTING_AVAILABLE` is a server-owned literal `false`; it has no environment, configuration, or feature override. Both native routing call sites use `parse_for_routing`, which returns before decoding or registry access while the gate is closed. JMAP get, query, and set requests are rejected with `Forbidden` before dispatch.

The Community `schema_oss.json.gz` and matching hash are refreshed from the pinned v1.1.1 OSS artifact served by the non-Enterprise HTTP path. It includes `MaskedEmail` metadata; that metadata does not make the object available through JMAP or routing. The mixed Enterprise `schema.json.gz` and hash are not changed.

Existing directory and explicit Mail aliases are not rewritten, rejected, or changed by native masked-address decoding. No stored aliases are migrated. Keep the native feature disabled until Console adaptation and isolation validation receive separate review.

The upstream Community source parity now includes OAuth `SETTINGS` permission mapping, `max_masked_addresses` quota configuration, masked-object account-destroy cleanup, and `MaskedEmail` keys in the `Directory` subspace (`common/src/auth/oauth/scope.rs`, `common/src/config/mailstore/email.rs`, `services/src/task_manager/tasks/destroy_account.rs`, and `store/src/write/key.rs`). Focused tests cover these mappings and SQLite key persistence across reopen. These source changes do not open JMAP dispatch or masked-address routing.

Changing the false constant alone is not a complete or approved activation path. The following Abnormal policy and lifecycle work remains excluded and needs separate design, review, and validation before activation:

- Console integration and isolation validation for native masked-address creation and management.
- Abnormal-specific authorization policy for users, administrators, and object creation; the upstream scope mapping is source parity only.
- Product quota policy and configuration lifecycle, including account/tenant scope and limits; upstream max-quota mapping is present, but no product limit is selected here.
- Cache invalidation for masked-object updates, disablement, expiry, and deletion. Tenant-only invalidation changes remain in their SEL snippet and were not applied.
- Ownership handling for transfer or loss of access; account-destroy cleanup parity alone does not settle those policies.
- Recipient/address-format policy, including the pending Mail 14/27 decision; this port selects neither format.
- End-to-end lifecycle validation across supported storage backends and restart/import scenarios; only the key persistence mapping was exercised with SQLite.

Imported or pre-existing native objects cannot activate routing while the gate remains false. JMAP masked get/query/set remain forbidden before dispatch, and no native provider or alias rewriting is exposed or activated.

## Configuration migration

Upstream v1.1.1 changes the Netcup DNS API to key-only authentication. Existing Netcup configurations using a customer number, API key ID, and password need migration to the new API key field before using that provider.

## Preserved and deferred licensing boundaries

The still-SEL `crates/common/src/enterprise/mod.rs`, `crates/common/src/enterprise/masked.rs`, and `crates/smtp/src/queue/tenant.rs` remain untouched. Existing still-SEL snippets remain byte-for-byte as they were on the Abnormal baseline; scheduler and tenant-only cache-invalidation SEL changes are excluded. The four lifecycle parity files above retain their old SEL blocks unchanged alongside Community-only branches. Mixed generated schema changes are selective rather than whole-file replacements. The `itip_add_uninvited_attendee` / `ItipOrigin` forwarding interface and paired email-ingest origin mapping are ported; local SQLite integration tests call `Server.itip_ingest` and cover forwarding, rejection guards, duplicate-UID behavior, and normal invitation/RSVP processing. The RSVP-preservation and first-RRULE-wins fixes remain included.

## Pinned release-delta inventory

This inventory compares the worktree semantically with pinned upstream `3adead91f3c87e7415b58c9ed8e6ec05a5dda521`; changed-path counts are not treated as evidence of omitted work.

- Production code in `crates/calcard/`, `crates/imap-proto/`, `crates/email/src/cache/`, `crates/email/src/message/ingest.rs`, and `crates/store/src/query/log.rs` is upstream-identical, including the iTIP ingest-origin hunk. The current email-ingest diff is test-only integration coverage for Submission-versus-Delivery MIME propagation; Server iTIP integration asserts rejected UIDs persist no documents and a duplicate UID remains a single unchanged document. These paths are not pending production ports.
- IMAP production-source differences are the existing debranding in `crates/imap/src/lib.rs`, `crates/imap/src/op/capability.rs`, and `crates/imap/src/op/logout.rs`. `crates/imap/src/core/view.rs` contains Community regression tests, and this update adds local wire coverage; no omitted IMAP protocol hunk is identified. SMTP differences are debranding in `crates/smtp/src/inbound/data.rs` and `crates/smtp/src/inbound/spawn.rs`, plus the retained SEL-only tenant implementation in `crates/smtp/src/queue/tenant.rs`; these are not missing AGPL ports.
- The masked-address schema and lifecycle work is Community-only, with the existing Enterprise snippets retained. JMAP masked get/query/set and native address resolution remain closed by the Community gate; the surrounding source differences in `crates/jmap/src/registry/`, `crates/common/src/cache/principals.rs`, `crates/common/src/network/mta.rs`, and `crates/registry/src/schema/` are gate/licensing adaptations, not authorization to activate routing. Tenant-only cache invalidation and scheduler changes remain excluded as SEL-only.
- The pinned release adds `crates/dav/src/common/create.rs` with `CreateLock` / `CreateLockHandler` (`AGPL-3.0-only OR LicenseRef-SEL`). The worktree file at that path is a fork-authored durable `DavCreateFence` implementation, not an exact port of the pinned file. Treat this as a known source-parity replacement/delta; this step did not merge the upstream `CreateLock` API into the fence implementation. The pinned file has no `SPDX-SnippetBegin` blocks, and no claim is made that the local implementation came from that upstream file.
- `crates/common/src/network/masked.rs` is derived from the pinned upstream file with the literal-false routing gate retained; the local `crates/spam-filter/src/analysis/image_size.rs` is fork-authored and absent from the pinned release. `crates/common/src/test_utils.rs` and `crates/imap/src/core/wire_tests.rs` are local test infrastructure, not upstream imports. These files are not represented as pinned source ports.
- The raw-byte ordered audit compared every changed `SPDX-SnippetBegin` block in the worktree against both `abnormal/main` and `HEAD`: 35 files contained such snippets, all baseline blocks remained byte-identical and in order, and no new SEL snippet was found. The source review found no other omitted AGPL release hunk in the path groups listed above; it is a scoped parity inventory, not a complete legal opinion on every upstream diff hunk.

The v1.1.1 update does not modify the Mail repository, rewrite stored aliases, or change the Mail 14/27 policy.

## DAV fenced create scope

Calendar, card, and file DAV PUT/MKCOL/COPY/MOVE destination creates now use a durable generation fence keyed by owner account and `SyncCollection`, read before forced primary revalidation and asserted in the final resource batch. The monotonic marker is stored in the `System` subspace and must never be cleared when a resource or account is retired; retaining it avoids an ABA window if a name is later reused. Normal/full backups include the `Data` family, which includes `System`, and restore the stored key/value records. A selective backup that omits `Data` does not preserve these markers and is not a complete DAV namespace backup. These guarantees apply only to writers that use the fence: older binaries and JMAP name writers do not participate, so no mixed old/new writer safety or global cross-protocol uniqueness is claimed. The shared fence contracts (first-writer collision and rollback, delayed stale rejection, reopen/recreate persistence, namespace isolation, and overflow) run on SQLite, RocksDB, and opt-in PostgreSQL; the Community CI runs RocksDB on an isolated path and PostgreSQL through a service mapped only to loopback. MySQL was not tested locally because no server binaries are installed. SQLite request tests also cover retry-time `If` reevaluation, concurrent Calendar/Card/File PUT races, exact File PUT versus COPY/MOVE/MKCOL collision outcomes, and successful unrelated-path retries.

## Shared DAV and iTIP creation generation

The reusable primary-store groupware generation primitive keeps the existing DAV marker key bytes and `System` subspace namespace: the unchanged DAV prefix, owner account ID, and `SyncCollection` value. Calendar DAV creates and normal/forwarded iTIP event creates use the same Calendar generation. Each iTIP path reads its generation before its UID lookup; event creation appends the generation assertion and increment to the same atomic batch as the event, log, quota, and notification writes. The existing assertion retry re-runs the UID lookup, so a same-UID forwarded race leaves one event while different UIDs can both succeed after retry. Event deletion does not clear the generation, but the marker is not a permanent UID reservation: a deleted UID can be created again.

Atomic `BatchBuilder` mode suppresses automatic and explicit soft commit-point splits from initial construction; fenced work therefore reaches one native backend transaction. Backend hard transaction limits are unchanged and are not bypassed; a backend limit failure fails the batch atomically. The default builder retains its existing soft-split behavior. This is scoped to participating DAV and iTIP creation writers only; it does not establish JMAP-global UID uniqueness or mixed-version/JMAP writer safety. Default-calendar creation continues to use its existing compare-and-set assertion.
