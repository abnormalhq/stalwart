# Contributing to Abnormal Mail Server

Thank you for considering a contribution. This repository is the Abnormal-owned fork at [abnormalhq/stalwart](https://github.com/abnormalhq/stalwart). Fork-specific work should be discussed and submitted here; do not open issues, pull requests, or security reports against upstream Stalwart.

## Scope

- Keep the supported build Community-only. Do not enable the `enterprise` feature or `--all-features`, and do not modify SEL-only files or SPDX snippets.
- Preserve upstream copyright/license notices and existing configuration, storage, executable, and protocol identifiers unless a separately reviewed compatibility plan approves a change.
- Keep `/admin` and `/account` as configurable Console redirect entry points; do not restore the upstream WebUI bootstrap or imply SSO or feature parity.
- Keep changes focused and include regression coverage for changed behavior.
- Do not add image publishing or deployment automation without explicit project approval.

## Local workflow

Use the fixed Community build entrypoint:

```sh
./build-community.sh
```

The Community PR workflow runs the following checks after installing Python, Rust, and libclang:

```sh
python3 scripts/generate-ui-assets.py --check
python3 scripts/check-community.py
cargo check --locked -p stalwart --no-default-features --features "sqlite postgres mysql rocks s3 redis keep azure nats"
cargo test --locked -p common --no-default-features community_
cargo test --locked --manifest-path crates/http/Cargo.toml --no-default-features community_redirect_tests
cargo test --locked -p spam-filter --no-default-features analysis::image_size::tests
cargo test --locked -p spam-filter --no-default-features analysis::html::image_size_tests
```

## Releases

Release Please runs on pushes to `main` and opens a synchronized release PR from Conventional Commits. Use `fix:` for patch releases, `feat:` for minor releases, and `!` or a `BREAKING CHANGE:` footer for major releases. The initial changelog is bootstrapped from the `v1.1.0` tag at `e7cde9b3fac32d2a254ef782efec56f2373ec5d4`, so earlier inherited history is excluded.

Release PRs update the root version, the 36 direct workspace crate manifests, and `Cargo.lock`; fork release notes are written to `CHANGELOG-fork.md`, separate from the upstream reference `CHANGELOG.md`. Cargo may remove the `x-release-please-version` comments when regenerating `Cargo.lock`; restore them only on the 36 direct local package version lines and local-qualified dependency references. Do not annotate `event_macro` or registry records. Run `python3 scripts/check-release-please.py` to verify coverage before merging; the merge creates the version tag and GitHub release.

GitHub suppresses pull-request workflow runs for PRs created with the default `GITHUB_TOKEN`. Before merging a Release Please PR, manually run **Community PR CI** from the Actions tab and select that release PR's branch for `workflow_dispatch`. If a `RELEASE_PLEASE_TOKEN` secret is already configured, the release workflow can use it instead to enable PR-triggered checks; no token is required for the default setup.

Read the applicable upstream documentation for code conventions, but treat upstream support and contribution policies as applying to the upstream repository only.

## Submitting changes

Open a pull request against the Abnormal fork. Explain the user-visible change, compatibility impact, license scope, and the regression checks included. Do not request an upstream PR or contact Stalwart Labs on behalf of this fork.

By submitting code, you confirm that you have the right to contribute it and agree that your contributions to AGPL-eligible fork code are made available under AGPL-3.0-only. Do not submit code or modifications covered only by SEL.

## Reports

Use this repository's GitHub issues for non-sensitive fork bugs and requests. For vulnerabilities, follow [SECURITY.md](SECURITY.md); do not put sensitive details in a public issue or send them to upstream.
