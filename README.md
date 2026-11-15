# Abnormal Mail Server

Abnormal Mail Server is an Abnormal-owned Community build and debranding fork of [Stalwart Mail Server](https://github.com/stalwartlabs/stalwart). The upstream base is tag **v1.1.0**, commit **e7cde9b3fac32d2a254ef782efec56f2373ec5d4**. The fork repository is [abnormalhq/stalwart](https://github.com/abnormalhq/stalwart).

**Fork modification date: 2026-11-16.**

This repository preserves the upstream executable and crate name `stalwart`, existing configuration and storage formats, and all Stalwart protocol namespaces and API identifiers. It does not claim that the upstream project's Enterprise code or SEL-covered files have been relicensed.

## Community build

The locked-dependency Community build is:

```sh
./build-community.sh
```

The script uses `--locked --release -p stalwart --no-default-features` and the explicit Community feature set:

```text
sqlite postgres mysql rocks s3 redis keep azure nats
```

Build prerequisites are a Rust stable toolchain that supports edition 2024 (Rust 1.85 or later; locked dependencies may require a newer release), a C/C++ build toolchain, and libclang development libraries for the RocksDB bindgen dependency. Python 3.11 or later is needed only for the asset generation/check scripts. `Cargo.lock` pins Rust dependency versions; it does not pin the compiler, native tools or libraries, or Python/zlib, and this project does not claim bit-identical builds.

It rejects extra Cargo arguments so an invocation cannot accidentally add `enterprise` or `--all-features`. The resulting executable remains `target/release/stalwart`. Use your deployment's existing configuration path and data stores:

```sh
./target/release/stalwart --help
./target/release/stalwart --config /path/to/your/config.json
```

The `.min` and `.min.gz` filenames are retained for the server's existing embedded-asset paths. `scripts/generate-ui-assets.py` creates the HTML copies and gzip files from checked-in sources without minifying JavaScript or CSS; it also updates the 12-character UI asset hash and substitutes that hash in packaged login and RSVP pages. Use `python3 scripts/generate-ui-assets.py --check` to verify generated files with the local Python/zlib toolchain.

Docker build recipes also use locked dependencies and Community-only features. This repository does not publish container images or deploy binaries.

## What is preserved

- Existing JMAP, IMAP, SMTP, POP3, ManageSieve, and DAV protocol identifiers.
- The `/jmap` endpoint, management namespace `urn:stalwart:jmap`, standard JMAP URNs, and existing methods such as `x:MtaMilter/get`, `x:MtaMilter/set`, and `x:Action/set`.
- The `stalwart` process/package name.
- Upstream copyright statements, SPDX headers, license texts, and SEL snippets.
- Upstream documentation and project acknowledgements where applicable.

## Branding scope and separately loaded admin UI

This fork debrands the server's built-in login and calendar RSVP pages, the Community calendar-email fallback logo, and the server protocol banners changed by the neutral-greetings patch. It does not currently rebrand the separate administrative web UI.

When the registry has no application object, `crates/common/src/manager/defaults.rs` inserts a default application named `Stalwart Web Interface`, with URL prefixes `/admin` and `/account`, and points it at `https://github.com/stalwartlabs/webui/releases/download/v2/webui.zip`. That UI is a separately downloaded artifact, not bundled in this server source/build, and remains upstream-branded. The [`stalwartlabs/webui`](https://github.com/stalwartlabs/webui) project is distinct from the archived `stalwartlabs/webadmin` repository. This fork has not changed the bootstrap URL or defaults.

The current `stalwartlabs/webui` README describes its source as dual-licensed under AGPL-3.0 and SEL, but its README says SELv1 while the checked-in `LICENSES/LicenseRef-SEL.txt` is SELv2. The AGPL option permits modifications to files that are AGPL-covered or dual-licensed when the AGPL option is selected, subject to its notice and source obligations. That does not itself grant trademark rights; file-level licensing and the rights to use or alter Stalwart marks/logos in the separate UI have not been established here. Rebranding that UI needs a separate source/asset and trademark review.

## Enterprise migration blockers

Community builds do not include the SEL-only Enterprise feature set. Before migrating any existing server, inspect its actual configuration and data; do not assume these features are unused:

- **Tenant isolation:** Enterprise tenant filtering is not provided by the Community build. MailHQ workspace authorization is an application-layer boundary, not a replacement for server-side Stalwart tenant filtering. A deployment that relies on Stalwart tenants must design and validate an isolation replacement before migration.
- **Sharded blob storage:** the SEL-only sharded backend is not available in the Community build. S3 or another Community backend is not a drop-in replacement; plan and verify data migration before changing storage.
- **SCIM:** MailHQ has an application-owned, workspace-scoped SCIM Users flow that provisions mailboxes. Its documented implementation does not provide SCIM Groups and is not a drop-in replacement for arbitrary clients provisioned directly against Stalwart's Enterprise SCIM endpoint. Configure identity providers to use the appropriate MailHQ endpoint only after validating the integration.
- **Telemetry:** MailHQ reads Community Prometheus metrics at `/metrics/prometheus` and uses application queue-status fallbacks. This does not provide parity with Enterprise `Metric`/`Trace` history or tracing.

These notes describe known integration paths, not a claim that the Community alternatives have feature parity. Runtime server configuration has not been inspected by this repository.

## License and corresponding source

The upstream source tree is mixed-license: many files are dual-licensed `AGPL-3.0-only OR LicenseRef-SEL`, and some files/snippets are SEL-only. The Community build disables the Enterprise feature and excludes the SEL-only SCIM dependency from its active feature graph; this does **not** relicense the whole source tree. Preserve all SEL notices and snippets and do not use this build as a way to bypass Enterprise licensing. Review each file's SPDX notice and `LICENSES/` before modifying or redistributing source.

The Community artifact is intended to use the AGPL-3.0-only option for the applicable dual-licensed code. This statement is not a claim that every file in the checkout is AGPL. The upstream v1.1.0 notices remain in place; copyright in those materials remains with Stalwart Labs LLC and the applicable contributors.

Operators distributing a modified version or making it available for remote network interaction must meet the applicable AGPL obligations, including the corresponding-source offer in §13. Provide users of each running deployment with access to the **exact corresponding source** for that build, including the source revision, fork modifications, build scripts and installation information required by the license. The source link on the built-in login and RSVP pages points to this fork, but each operator is responsible for ensuring that it identifies the exact source corresponding to the deployed binary and remains accessible.

The fork is provided without warranty, as stated by the applicable license. See [AGPL-3.0-only](LICENSES/AGPL-3.0-only.txt), [SELv2](LICENSES/LicenseRef-SEL.txt), and the retained file-level license notices.

## Contributing, support, and security

Fork-specific issues and pull requests belong in [abnormalhq/stalwart](https://github.com/abnormalhq/stalwart), not the upstream Stalwart repository. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Do not send fork reports to Stalwart Labs or its support channels.

For security-sensitive reports, use GitHub's private vulnerability reporting for this repository if available. Do not post vulnerability details in a public issue. This fork does not publish a support email address; see [SECURITY.md](SECURITY.md) for the reporting policy.

## Upstream provenance and acknowledgements

This fork is derived from Stalwart v1.1.0. Stalwart Labs LLC and the upstream contributors retain their original copyright and attribution. Upstream documentation and release history remain available at [stalwartlabs/stalwart](https://github.com/stalwartlabs/stalwart); consult it as upstream documentation, not as a guarantee that every instruction applies to this fork.

The original Stalwart project acknowledged support from the [NGI0 Entrust Fund](https://nlnet.nl/entrust) and [NGI Zero Core](https://nlnet.nl/NGI0/), established by [NLnet](https://nlnet.nl/) with European Commission support. Those acknowledgements concern upstream work and do not imply endorsement of this fork.

© 2020 Stalwart Labs LLC and contributors for the upstream material; Abnormal's fork modifications retain their respective notices.
