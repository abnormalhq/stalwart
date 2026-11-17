#!/usr/bin/env python3
"""Check Release Please's Cargo.lock annotation coverage."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = "x-release-please-version"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


metadata = json.loads(
    subprocess.run(
        ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
)
release_manifest = json.loads((ROOT / ".release-please-manifest.json").read_text())
release_version = (ROOT / ".release-please-version").read_text().strip()
require(set(release_manifest) == {"."}, "Release Please manifest must contain only the root component.")
require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.-]+)?", release_version) is not None,
        ".release-please-version must contain a semantic version.")
require(release_manifest["."] == release_version, "Release Please manifest and version file are out of sync.")

workspace_ids = set(metadata["workspace_members"])
workspace_packages = [package for package in metadata["packages"] if package["id"] in workspace_ids]
direct_packages = {}
outside_glob = set()

for package in workspace_packages:
    manifest = Path(package["manifest_path"]).relative_to(ROOT).as_posix()
    if re.fullmatch(r"crates/[^/]+/Cargo.toml", manifest):
        require(package["name"] not in direct_packages, f"Duplicate direct workspace package: {package['name']}")
        direct_packages[package["name"]] = package
    else:
        outside_glob.add(package["name"])

require(bool(direct_packages), "No direct workspace packages match crates/*/Cargo.toml.")
require(outside_glob == {"event_macro"}, f"Workspace packages outside the configured glob: {sorted(outside_glob)}")
require(
    {package["version"] for package in direct_packages.values()} == {release_version},
    "Direct workspace package versions must match the Release Please version file.",
)

versioned_path_dependencies = [
    f"{package['name']} -> {dependency['name']} ({dependency['req']})"
    for package in workspace_packages
    for dependency in package.get("dependencies", [])
    if dependency.get("path") and dependency.get("req") not in (None, "*")
]
require(
    not versioned_path_dependencies,
    "Add Release Please updates for local path dependency version constraints: "
    + ", ".join(versioned_path_dependencies),
)

local_versions = {(name, package["version"]) for name, package in direct_packages.items()}
local_refs = {f"{name} {version}" for name, version in local_versions}
lock_lines = (ROOT / "Cargo.lock").read_text().splitlines()
marked_lines = set()
found_packages = set()
qualified_refs = 0
starts = [index for index, line in enumerate(lock_lines) if line == "[[package]]"]

for position, start in enumerate(starts):
    end = starts[position + 1] if position + 1 < len(starts) else len(lock_lines)
    block = lock_lines[start + 1 : end]
    name_match = next((re.fullmatch(r'name = "([^"]+)"', line) for line in block if line.startswith("name = ")), None)
    version_match = next((re.fullmatch(r'version = "([^"]+)".*', line) for line in block if line.startswith("version = ")), None)
    require(name_match is not None and version_match is not None, "Malformed package record in Cargo.lock.")
    name, version = name_match.group(1), version_match.group(1)
    has_source = any(line.startswith("source = ") for line in block)
    is_local = not has_source and (name, version) in local_versions

    for offset, line in enumerate(block, start + 1):
        if is_local and line.startswith("version = "):
            require(MARKER in line, f"Missing Release Please marker for local package {name} {version}.")
            found_packages.add(name)
            marked_lines.add(offset)

        if line.startswith("dependencies = ["):
            dependency_end = next(
                (index for index in range(offset + 1, end) if lock_lines[index].strip() == "]"),
                end,
            )
            for dependency_index in range(offset + 1, dependency_end):
                dependency = re.match(r'\s*"([^"]+)"', lock_lines[dependency_index])
                if dependency and dependency.group(1) in local_refs:
                    require(
                        MARKER in lock_lines[dependency_index],
                        f"Missing Release Please marker for local lock reference {dependency.group(1)}.",
                    )
                    qualified_refs += 1
                    marked_lines.add(dependency_index)

require(found_packages == set(direct_packages), f"Missing local Cargo.lock records: {sorted(set(direct_packages) - found_packages)}")
for index, line in enumerate(lock_lines):
    if MARKER in line:
        require(index in marked_lines, f"Unexpected Release Please marker in Cargo.lock at line {index + 1}.")

print(
    f"Release Please Cargo.lock coverage passed: {len(direct_packages)} direct workspace packages, "
    f"{qualified_refs} qualified local dependency references; no versioned path dependencies."
)
