# Abnormal Mail Server

Abnormal Mail Server is an Abnormal-owned Community build and debranding fork of [Stalwart Mail Server](https://github.com/stalwartlabs/stalwart). The upstream update is tag **v1.1.1**, commit **3adead91f3c87e7415b58c9ed8e6ec05a5dda521**, selectively ported onto the Abnormal Community baseline. The fork repository is [abnormalhq/stalwart](https://github.com/abnormalhq/stalwart).

> **v1.1.1 scope:** This is a selective Community port, not a complete upstream merge. See [UPGRADE-v1.1.1.md](UPGRADE-v1.1.1.md) for included changes, exclusions, migrations, and disabled features.

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

The approved release workflow packages the immutable release source with the Dockerfile from its reviewed workflow revision and a locked, Community-only Linux amd64 build. It publishes that image to GHCR; see [CONTRIBUTING.md](CONTRIBUTING.md) for its checks and backfill procedure. It does not deploy binaries or change package visibility.

## What is preserved

- Existing JMAP, IMAP, SMTP, POP3, ManageSieve, and DAV protocol identifiers.
- The `/jmap` endpoint, management namespace `urn:stalwart:jmap`, standard JMAP URNs, and existing methods such as `x:MtaMilter/get`, `x:MtaMilter/set`, and `x:Action/set`.
- The `stalwart` process/package name.
- Upstream copyright statements, SPDX headers, license texts, and SEL snippets.
- Upstream documentation and project acknowledgements where applicable.

## Admin and account entry routes

This fork uses the existing Abnormal Console at [console.abnormalhq.com](https://console.abnormalhq.com/) rather than loading the upstream Stalwart WebUI. The server no longer inserts a default WebUI application. Top-level `/admin` and `/account` paths are reserved: GET and HEAD requests redirect to the configured `http.redirectRoot` destination; other methods receive 405 with `Allow: GET, HEAD`. The server root uses the same redirect behavior.

The schema's existing `/account` default and legacy relative `redirectRoot` values under `/admin` or `/account` (including nested paths, query strings, and fragments) normalize to `https://console.abnormalhq.com/`. Absolute URLs and non-root root-relative destinations are preserved. Relative destinations such as `webmail/` or `./webmail/` are anchored at the server root (`/webmail/`), not relative to `/admin` or `/account`. Dot segments are normalized before checking the destination: a resulting `/admin`, `/account`, or `/` maps to Console to avoid redirect loops. If a configured destination has no fragment, the redirect adds an empty fragment so browsers do not inherit the previous page's fragment. The incoming request path and query are never appended. A `None` redirect target leaves the root unredirected and makes GET/HEAD requests to `/admin` and `/account` return 404; other methods return 405. Operators may configure another entry destination.

An upgrade does not delete existing Application registry records or cached bundles. Their `/admin` and `/account` mounts are ignored; other prefixes continue to be served, including unreserved prefixes on a mixed application. These redirects are navigation only: the Console has separate authentication, does not reuse Stalwart sessions, passwords, or OAuth tokens, and is not claimed to provide feature parity with Stalwart's former WebUI. The server's built-in login, device authorization, OAuth, and calendar RSVP routes are unchanged.

## Enterprise migration blockers

Community builds do not include the SEL-only Enterprise feature set. Before migrating any existing server, inspect its actual configuration and data; do not assume these features are unused:

- **Tenant isolation:** Enterprise tenant filtering is not provided by the Community build. MailHQ workspace authorization is an application-layer boundary, not a replacement for server-side Stalwart tenant filtering. A deployment that relies on Stalwart tenants must design and validate an isolation replacement before migration.
- **Sharded blob storage:** the SEL-only sharded backend is not available in the Community build. S3 or another Community backend is not a drop-in replacement; plan and verify data migration before changing storage.
- **SCIM:** MailHQ has an application-owned, workspace-scoped SCIM Users flow that provisions mailboxes. Its documented implementation does not provide SCIM Groups and is not a drop-in replacement for arbitrary clients provisioned directly against Stalwart's Enterprise SCIM endpoint. Configure identity providers to use the appropriate MailHQ endpoint only after validating the integration.
- **Telemetry:** MailHQ reads Community Prometheus metrics at `/metrics/prometheus` and uses application queue-status fallbacks. This does not provide parity with Enterprise `Metric`/`Trace` history or tracing.

These notes describe known integration paths, not a claim that the Community alternatives have feature parity. Runtime server configuration has not been inspected by this repository.

## License and corresponding source

The upstream source tree is mixed-license: many files are dual-licensed `AGPL-3.0-only OR LicenseRef-SEL`, and some files/snippets are SEL-only. The Community build disables the Enterprise feature and excludes the SEL-only SCIM dependency from its active feature graph; this does **not** relicense the whole source tree. Preserve all SEL notices and snippets and do not use this build as a way to bypass Enterprise licensing. Review each file's SPDX notice and `LICENSES/` before modifying or redistributing source.

The Community artifact is intended to use the AGPL-3.0-only option for the applicable dual-licensed code. This statement is not a claim that every file in the checkout is AGPL. The upstream v1.1.1 notices remain in place; copyright in those materials remains with Stalwart Labs LLC and the applicable contributors.

Operators distributing a modified version or making it available for remote network interaction must meet the applicable AGPL obligations, including the corresponding-source offer in §13. Provide users of each running deployment with access to the **exact corresponding source** for that build, including the source revision, fork modifications, build scripts and installation information required by the license. The source link on the built-in login and RSVP pages points to this fork, but each operator is responsible for ensuring that it identifies the exact source corresponding to the deployed binary and remains accessible.

The fork is provided without warranty, as stated by the applicable license. See [AGPL-3.0-only](LICENSES/AGPL-3.0-only.txt), [SELv2](LICENSES/LicenseRef-SEL.txt), and the retained file-level license notices.

## Contributing, support, and security

Fork-specific issues and pull requests belong in [abnormalhq/stalwart](https://github.com/abnormalhq/stalwart), not the upstream Stalwart repository. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Do not send fork reports to Stalwart Labs or its support channels.

For security-sensitive reports, use GitHub's private vulnerability reporting for this repository if available. Do not post vulnerability details in a public issue. This fork does not publish a support email address; see [SECURITY.md](SECURITY.md) for the reporting policy.

## Upstream provenance and acknowledgements

This fork is updated from Stalwart v1.1.1. Stalwart Labs LLC and the upstream contributors retain their original copyright and attribution. Upstream documentation and release history remain available at [stalwartlabs/stalwart](https://github.com/stalwartlabs/stalwart); consult it as upstream documentation, not as a guarantee that every instruction applies to this fork.

The original Stalwart project acknowledged support from the [NGI0 Entrust Fund](https://nlnet.nl/entrust) and [NGI Zero Core](https://nlnet.nl/NGI0/), established by [NLnet](https://nlnet.nl/) with European Commission support. Those acknowledgements concern upstream work and do not imply endorsement of this fork.

© 2020 Stalwart Labs LLC and contributors for the upstream material; Abnormal's fork modifications retain their respective notices.
