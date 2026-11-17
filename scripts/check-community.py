#!/usr/bin/env python3
"""Check fork branding, compatibility identifiers, and Community feature gates."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
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


def check_masked_address_gate() -> None:
    masked = read("crates/common/src/network/masked.rs")
    require(
        re.search(r"pub const MASKED_ADDRESS_ROUTING_AVAILABLE: bool = false;", masked) is not None,
        "Native masked-address routing must remain server-disabled by a literal false gate.",
    )
    wrapper = re.search(r"pub fn parse_for_routing\(.*?\n    }", masked, re.DOTALL)
    require(wrapper is not None, "Masked-address routing parser is missing.")
    require(
        wrapper.group(0).index("MASKED_ADDRESS_ROUTING_AVAILABLE")
        < wrapper.group(0).index("Self::parse(local_part)"),
        "Masked-address routing must check availability before decoding.",
    )

    for path in (
        "crates/common/src/network/mta.rs",
        "crates/common/src/cache/principals.rs",
    ):
        source = read(path)
        require(
            "MaskedAddress::parse_for_routing(local_part.as_ref())" in source,
            f"Masked routing must handle borrowed and owned local parts: {path}",
        )
        parser = source.find("MaskedAddress::parse_for_routing(")
        registry = source.find(".object::<MaskedEmail>", parser)
        require(parser >= 0 and registry > parser, f"Masked routing call is missing or reordered: {path}")
        gate = source.rfind('#[cfg(not(feature = "enterprise"))]', 0, parser)
        require(gate >= 0 and parser - gate < 1000, f"Community-only masked routing gate is missing: {path}")

    availability = read("crates/jmap/src/registry/mod.rs")
    for required in (
        "ObjectType::MaskedEmail",
        "MASKED_ADDRESS_ROUTING_AVAILABLE",
        "trc::JmapEvent::Forbidden",
    ):
        require(required in availability, f"Community MaskedEmail availability guard is missing: {required}")
    for path in (
        "crates/jmap/src/registry/get.rs",
        "crates/jmap/src/registry/query.rs",
        "crates/jmap/src/registry/set.rs",
    ):
        source = read(path)
        guard = source.find("self.assert_enterprise_object(object_type)?;")
        dispatch = source.find("match object_type", guard)
        require(guard >= 0 and dispatch > guard, f"Registry access guard must precede dispatch: {path}")


def check_community_schema_contract() -> None:
    compressed = (ROOT / "resources/schema/schema_oss.json.gz").read_bytes()
    checksum = read("resources/schema/schema_oss.json.sha256").strip()
    expected_checksum = base64.urlsafe_b64encode(hashlib.sha256(compressed).digest()).decode().rstrip("=")
    require(checksum == expected_checksum, "Community OSS schema checksum does not match its compressed asset.")

    schema = json.loads(gzip.decompress(compressed))
    fields = schema.get("fields", {})
    netcup = fields.get("x:DnsServerNetcup", {}).get("properties", {})
    require("apiKey" in netcup, "Community OSS schema is missing the Netcup apiKey field.")
    require(
        not {"apiKeyId", "customerNumber", "password"}.intersection(netcup),
        "Community OSS schema still advertises obsolete Netcup authentication fields.",
    )

    for object_name in ("x:DmarcTroubleshoot", "x:SpamClassify"):
        mail_from = fields.get(object_name, {}).get("properties", {}).get("mailFrom", {})
        require(
            mail_from.get("type", {}).get("nullable") is True,
            f"Community OSS schema must mark {object_name}.mailFrom nullable.",
        )

    parameters = schema.get("enums", {}).get("SpamClassifyParameters", [])
    require(
        [parameter.get("name") for parameter in parameters]
        == ["bit7", "bit8Mime", "binaryMime", "smtpUtf8"],
        "Community OSS schema has an incorrect SpamClassifyParameters enum.",
    )
    bit8_mime = next(parameter for parameter in parameters if parameter.get("name") == "bit8Mime")
    require(
        bit8_mime.get("label") == "8-bit MIME message content",
        "Community OSS schema has an incorrect bit8Mime label.",
    )


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
    check_masked_address_gate()
    check_community_schema_contract()
    print("Synthetic Enterprise feature-tree guard rejection passed.")
    print("Community OSS schema checksum and v1.1.1 contract checks passed.")
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
    ):
        require(not (ROOT / workflow).exists(),
                f"Upstream-only release/triage workflow must stay removed: {workflow}")
    for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        name = workflow.relative_to(ROOT)
        source = workflow.read_text()
        require("stalwartlabs/stalwart" not in source,
                f"Workflow still targets the upstream repository: {name}")
        require("github.repository == 'abnormalhq/stalwart'" in source,
                f"Workflow is not gated to the fork repository: {name}")
    community_ci = read(".github/workflows/community-pr.yml")
    require("contents: read" in community_ci and "write" not in community_ci,
            "Community PR CI must use read-only permissions.")
    require(
        (
            "pull_request:\n    branches: [main, "
            "devin/1794818404-capability-foundation]"
        )
        in community_ci,
        "Community PR CI must run for pull requests targeting main and the capability foundation branch.",
    )
    require(
        "push:\n    branches: [main]" in community_ci,
        "Community push CI must remain restricted to main.",
    )

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
