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
cargo test --locked -p http@1.1.0 --no-default-features community_redirect_tests
cargo test --locked -p spam-filter --no-default-features analysis::image_size::tests
cargo test --locked -p spam-filter --no-default-features analysis::html::image_size_tests
```

Read the applicable upstream documentation for code conventions, but treat upstream support and contribution policies as applying to the upstream repository only.

## Submitting changes

Open a pull request against the Abnormal fork. Explain the user-visible change, compatibility impact, license scope, and the regression checks included. Do not request an upstream PR or contact Stalwart Labs on behalf of this fork.

By submitting code, you confirm that you have the right to contribute it and agree that your contributions to AGPL-eligible fork code are made available under AGPL-3.0-only. Do not submit code or modifications covered only by SEL.

## Reports

Use this repository's GitHub issues for non-sensitive fork bugs and requests. For vulnerabilities, follow [SECURITY.md](SECURITY.md); do not put sensitive details in a public issue or send them to upstream.
