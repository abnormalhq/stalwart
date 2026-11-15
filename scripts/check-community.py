#!/usr/bin/env python3
"""Check fork branding, compatibility identifiers, and Community feature gates."""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import subprocess
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMUNITY_FEATURES = "sqlite postgres mysql rocks s3 redis keep azure nats"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def read(path: str) -> str:
    return (ROOT / path).read_text()


def cargo_tree(*args: str) -> str:
    result = subprocess.run(
        ["cargo", "tree", "--locked", "-p", "stalwart", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def require_no_enterprise_feature(tree: str, label: str) -> None:
    require(not re.search(r'feature "enterprise"', tree),
            f"{label} feature graph activates Enterprise.")


def check_enterprise_feature_guard() -> None:
    synthetic_tree = 'stalwart v1.1.0\n└── feature "enterprise"\n'
    try:
        require_no_enterprise_feature(synthetic_tree, "Synthetic")
    except SystemExit as error:
        require(error.code == "Synthetic feature graph activates Enterprise.",
                "Enterprise feature-tree guard rejected synthetic input for an unexpected reason.")
    else:
        raise SystemExit("Enterprise feature-tree guard accepted a synthetic Enterprise feature.")


def main() -> None:
    main_manifest = tomllib.loads(read("crates/main/Cargo.toml"))
    http_manifest = tomllib.loads(read("crates/http/Cargo.toml"))
    defaults = main_manifest["features"]["default"]
    require("enterprise" not in defaults, "Enterprise must not be a default feature.")
    require(main_manifest["dependencies"]["scim"].get("optional") is True, "Main SCIM dependency must be optional.")
    require(http_manifest["dependencies"]["scim"].get("optional") is True, "HTTP SCIM dependency must be optional.")
    http_enterprise = http_manifest["features"]["enterprise"]
    require("dep:scim" in http_enterprise and "scim/enterprise" in http_enterprise,
            "HTTP Enterprise feature must explicitly enable SCIM.")

    build_script = read("build-community.sh")
    require("--locked" in build_script and "--no-default-features" in build_script,
            "Community build entrypoint must use locked, no-default-features mode.")
    build_features = re.search(r'--features "([^"]+)"', build_script)
    require(build_features is not None and build_features.group(1) == COMMUNITY_FEATURES,
            "Community build feature set changed unexpectedly.")
    require('"$@"' not in build_script and "--all-features" not in build_script,
            "Community build entrypoint must not accept feature overrides.")
    bootstrap_defaults = read("crates/common/src/manager/defaults.rs")
    require(
        "ObjectType::Application" not in bootstrap_defaults
        and "Stalwart Web Interface" not in bootstrap_defaults
        and "webui.zip" not in bootstrap_defaults,
        "Upstream WebUI must not be inserted by server bootstrap defaults.",
    )
    for dockerfile in ("Dockerfile", "Dockerfile.build"):
        for line in read(dockerfile).splitlines():
            if re.search(r"\bcargo (?:chef cook|build|zigbuild)\b", line):
                require("--locked" in line, f"Docker compile command is not locked: {line.strip()}")
                require("enterprise" not in line, f"Docker compile command enables Enterprise: {line.strip()}")

    check_enterprise_feature_guard()
    print("Synthetic Enterprise feature-tree guard rejection passed.")
    default_tree = cargo_tree("-e", "features")
    require_no_enterprise_feature(default_tree, "Default Stalwart")
    scim_package = r"\bscim v[^\n]*[/\\]crates[/\\]scim(?:\)|$)"
    require(not re.search(scim_package, default_tree),
            "Default Stalwart feature graph includes the SEL-only crates/scim package.")
    community_tree = cargo_tree("-e", "features", "--no-default-features", "--features", COMMUNITY_FEATURES)
    require_no_enterprise_feature(community_tree, "Explicit Community")
    require(not re.search(scim_package, community_tree),
            "Community feature graph includes the SEL-only crates/scim package.")

    ui_hash = read("resources/html-templates/ui.hash").strip()
    require(re.fullmatch(r"[0-9a-f]{12}", ui_hash) is not None, "ui.hash must be 12 lowercase hex characters.")
    request_source = read("crates/http/src/request.rs")
    require("UI_ASSET_PREFIX" in request_source and "ui.hash" in request_source,
            "HTTP asset routing no longer reads ui.hash.")
    for route in (".strip_prefix(UI_ASSET_PREFIX)", '".css" =>', '".js" =>'):
        require(route in request_source, f"HTTP hashed-asset route is missing: {route}")
    for asset in ("login.html", "calendar-rsvp.html"):
        compressed = (ROOT / f"resources/html-templates/{asset}.min.gz").read_bytes()
        page = gzip.decompress(compressed)
        require(f"ui-{ui_hash}.css".encode() in page, f"{asset} CSS reference does not match ui.hash.")
        require(f"ui-{ui_hash}.js".encode() in page, f"{asset} JS reference does not match ui.hash.")
        require(b"ui-HASH" not in page, f"{asset} contains an unresolved UI hash placeholder.")
        source = read(f"resources/html-templates/{asset}")
        for marker in (
            "Source code",
            "https://github.com/abnormalhq/stalwart",
            "https://www.gnu.org/licenses/agpl-3.0.html",
            "No warranty",
            "modified by abnormalhq",
        ):
            require(marker in source, f"{asset} is missing required source-offer notice: {marker}")

    login = read("resources/html-templates/login.html")
    for contract in (
        'id="login-form"',
        'id="username"',
        'name="username"',
        'id="password"',
        'name="password"',
        'id="otp"',
        'name="otp"',
        'id="device-code"',
        'name="device-code"',
    ):
        require(contract in login, f"Login form contract changed: {contract}")

    ui = read("resources/html-templates/ui.js")
    require('aria-label="Abnormal Mail"' in ui, "Fallback UI logo needs an accessible product label.")
    require('aria-label="Stalwart"' not in ui, "Legacy Stalwart fallback logo remains in the UI source.")
    require("loadLogo" in ui and "currentColor" in ui, "Custom-logo fallback or theme-aware wordmark is missing.")
    logo_source = (ROOT / "resources/html-templates/abnormal-mail-logo.png.b64").read_bytes()
    require(logo_source.endswith(b"\r\n"), "Calendar fallback base64 must end with CRLF.")
    logo_content = logo_source[:-2]
    unfolded_logo = logo_content.replace(b"\r\n", b"")
    require(b"\r" not in unfolded_logo and b"\n" not in unfolded_logo,
            "Calendar fallback base64 must use CRLF line endings only.")
    logo_lines = logo_content.split(b"\r\n")
    require(all(0 < len(line) <= 76 for line in logo_lines),
            "Calendar fallback base64 lines must be 1 to 76 characters.")
    require(all(len(line) == 76 for line in logo_lines[:-1]),
            "Calendar fallback base64 lines before the last must be 76 characters.")
    try:
        logo = base64.b64decode(b"".join(logo_lines), validate=True)
    except (binascii.Error, ValueError) as error:
        raise SystemExit("Calendar fallback base64 is invalid.") from error
    require(logo.startswith(b"\x89PNG\r\n\x1a\n"), "Calendar fallback logo is not a PNG.")
    wordmark = read("resources/html-templates/abnormal-mail-logo.svg")
    require('aria-label="Abnormal Mail"' in wordmark and "Abnormal Mail</text>" in wordmark,
            "Calendar fallback logo source must be an Abnormal Mail wordmark.")
    require("abnormal-mail-logo.png.b64" in read("crates/common/src/lib.rs"),
            "Calendar fallback logo source is not wired into the Community build.")

    for workflow in (
        ".github/workflows/auto-close-issues.yml",
        ".github/workflows/auto-close-prs.yml",
        ".github/workflows/auto-redirect-discussions.yml",
        ".github/workflows/ci-retry.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/scorecard.yml",
        ".github/workflows/trivy.yml",
    ):
        require("github.repository == 'stalwartlabs/stalwart'" in read(workflow),
                f"Inherited upstream-only workflow is not repository-gated: {workflow}")
    community_ci = read(".github/workflows/community-pr.yml")
    require("contents: read" in community_ci and "write" not in community_ci,
            "Community PR CI must use read-only permissions.")

    capabilities = read("crates/jmap-proto/src/request/capability.rs")
    for urn in (
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail",
        "urn:stalwart:jmap",
    ):
        require(urn in capabilities, f"Protocol URN changed or missing: {urn}")

    print("Community brand, source-offer, login contract, URN, hash-route, and feature-gate checks passed.")


if __name__ == "__main__":
    main()
