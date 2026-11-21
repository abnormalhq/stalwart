#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


REPOSITORY = "abnormalhq/stalwart"
IMAGE = "ghcr.io/abnormalhq/stalwart"
IMAGE_SOURCE = "https://github.com/abnormalhq/stalwart"
WORKFLOWS = ("community-pr.yml", "trivy.yml")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


class PublishError(RuntimeError):
    pass


def validate_tag(tag):
    if not isinstance(tag, str) or not tag.startswith("v") or not VERSION_RE.fullmatch(tag[1:]):
        raise PublishError("tag must be a strict vMAJOR.MINOR.PATCH release tag")
    return tag[1:]


def validate_release(release, tag, expected_sha=None):
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        raise PublishError("GitHub Release does not match the requested tag")
    if release.get("draft") is not False:
        raise PublishError("GitHub Release must be published, not a draft")
    if release.get("prerelease") is not False:
        raise PublishError("GitHub Release must not be a prerelease")
    if expected_sha:
        if not SHA_RE.fullmatch(expected_sha):
            raise PublishError("expected SHA must be a full 40-character commit SHA")
    return True


def validate_expected_sha(expected_sha, resolved_sha):
    if expected_sha and (
        not SHA_RE.fullmatch(expected_sha) or expected_sha.lower() != resolved_sha.lower()
    ):
        raise PublishError("expected SHA does not match the resolved release tag")


def validate_tag_snapshot(snapshot, expected_ref_oid, expected_peeled_oid, expected_sha):
    ref_oid, peeled_oid, resolved_sha = snapshot
    if (
        ref_oid != expected_ref_oid.lower()
        or peeled_oid != expected_peeled_oid.lower()
        or resolved_sha != expected_sha.lower()
    ):
        raise PublishError("release tag changed after it was resolved")


def parse_registry_tag_state(status, body):
    if status == 200:
        return "exists"
    if status == 404:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        errors = payload.get("errors", []) if isinstance(payload, dict) else []
        codes = {item.get("code") for item in errors if isinstance(item, dict)}
        if codes and codes <= {"MANIFEST_UNKNOWN", "NAME_UNKNOWN"}:
            return "absent"
    raise PublishError("registry read was not a definitive existing/absent result; refusing to publish")


def workflow_run_state(runs, expected_sha):
    matching = [
        run
        for run in runs
        if isinstance(run, dict)
        and str(run.get("head_sha", "")).lower() == expected_sha.lower()
        and run.get("event") in ("push", "workflow_dispatch")
        and run.get("head_branch") == "main"
    ]
    if not matching:
        return "pending", None
    failed = next(
        (
            run
            for run in matching
            if run.get("status") == "completed" and run.get("conclusion") != "success"
        ),
        None,
    )
    if failed:
        return "failure", failed
    pending = next((run for run in matching if run.get("status") != "completed"), None)
    if pending:
        return "pending", pending
    return "success", matching[0]


def verify_image_metadata(version_output, labels, os_name, architecture, version, sha, source=IMAGE_SOURCE):
    if not re.search(r"(?<![\w.])v?" + re.escape(version) + r"(?![\w.])", version_output):
        raise PublishError("image --version output does not match the release version")
    if os_name != "linux" or architecture != "amd64":
        raise PublishError("image platform must be linux/amd64")
    expected = {
        "org.opencontainers.image.source": source,
        "org.opencontainers.image.revision": sha,
        "org.opencontainers.image.version": version,
    }
    for name, value in expected.items():
        if not isinstance(labels, dict) or labels.get(name) != value:
            raise PublishError("image OCI label does not match: " + name)
    return True


def _http(request, timeout=30):
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read()
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        raise PublishError("network request failed: " + str(getattr(error, "reason", error)))


def _json_response(status, body, label):
    if status != 200:
        raise PublishError(label + " returned HTTP " + str(status))
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PublishError(label + " returned invalid JSON")


def github_api_json(path, token):
    if not token:
        raise PublishError("GITHUB_TOKEN is required to verify release and workflow checks")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "abnormalhq-stalwart-community-image-publisher",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    status, _, body = _http(request)
    return _json_response(status, body, "GitHub API request")


def get_release(tag, token):
    quoted_tag = urllib.parse.quote(tag, safe="")
    return github_api_json("/releases/tags/" + quoted_tag, token)


def get_workflow_runs(workflow, sha, token):
    query = urllib.parse.urlencode({"head_sha": sha, "per_page": "100"})
    payload = github_api_json(
        "/actions/workflows/" + urllib.parse.quote(workflow, safe="") + "/runs?" + query,
        token,
    )
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise PublishError("GitHub Actions API did not return workflow runs for " + workflow)
    return runs


def check_required_workflows(sha, token, fetch_runs=None):
    fetch = fetch_runs or get_workflow_runs
    for workflow in WORKFLOWS:
        state, run = workflow_run_state(fetch(workflow, sha, token), sha)
        if state != "success":
            url = run.get("html_url", "") if run else ""
            raise PublishError(
                workflow
                + " is not a successful main push/dispatch on release SHA "
                + sha
                + (": " + url if url else "")
            )


def wait_for_checks(
    sha,
    token,
    timeout_seconds=5400,
    poll_seconds=30,
    fetch_runs=None,
    clock=None,
    sleeper=None,
):
    fetch = fetch_runs or get_workflow_runs
    now = clock or time.monotonic
    sleep = sleeper or time.sleep
    started = now()
    last_report = None
    while True:
        states = []
        for workflow in WORKFLOWS:
            runs = fetch(workflow, sha, token)
            state, run = workflow_run_state(runs, sha)
            states.append((workflow, state, run))
            if state == "failure":
                url = run.get("html_url", "") if run else ""
                raise PublishError(
                    workflow + " failed on release SHA " + sha + (": " + url if url else "")
                )
        if all(state == "success" for _, state, _ in states):
            for workflow, _, run in states:
                print(workflow + ": success " + (run.get("html_url", "") if run else ""))
            return
        report = tuple(
            (workflow, state, run.get("id") if run else None) for workflow, state, run in states
        )
        if report != last_report:
            for workflow, state, run in states:
                print(
                    workflow
                    + ": "
                    + state
                    + (" " + run.get("html_url", "") if run and run.get("html_url") else "")
                )
            last_report = report
        elapsed = now() - started
        if elapsed >= timeout_seconds:
            pending = ", ".join(workflow for workflow, state, _ in states if state != "success")
            raise PublishError(
                "timed out waiting for successful exact-SHA checks ("
                + pending
                + ") on "
                + sha
                + "; inspect those existing Actions runs. This workflow does not dispatch or rerun checks."
            )
        sleep(min(poll_seconds, max(0, timeout_seconds - elapsed)))


def run_git(args, cwd):
    result = subprocess.run(["git"] + args, cwd=str(cwd), text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise PublishError("git " + " ".join(args) + " failed: " + result.stderr.strip())
    return result.stdout.strip()


def remote_tag_snapshot(tag, cwd):
    ref = "refs/tags/" + tag
    output = run_git(
        ["ls-remote", "https://github.com/" + REPOSITORY + ".git", ref, ref + "^{}"],
        cwd,
    )
    values = {}
    for line in output.splitlines():
        fields = line.split("\t", 1)
        if len(fields) == 2 and fields[1] in (ref, ref + "^{}"):
            if not SHA_RE.fullmatch(fields[0]):
                raise PublishError("remote release tag returned an invalid object ID")
            values[fields[1]] = fields[0].lower()
    if ref not in values:
        raise PublishError("release tag does not exist on the repository remote")
    peeled = values.get(ref + "^{}", "")
    return values[ref], peeled, peeled or values[ref]


def source_commit(source_dir):
    head = run_git(["rev-parse", "HEAD"], source_dir).lower()
    if not SHA_RE.fullmatch(head):
        raise PublishError("source checkout did not resolve to a full commit SHA")
    return head


def ensure_ancestor(sha, trusted_dir, ref="refs/remotes/origin/main"):
    main_sha = run_git(["rev-parse", ref], trusted_dir).lower()
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, main_sha],
        cwd=str(trusted_dir),
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PublishError("release commit is not verified as an ancestor of current main")
    return main_sha


def fetch_current_main(trusted_dir):
    ref = "refs/remotes/origin/ghcr-publish-main"
    run_git(
        ["fetch", "--no-tags", "origin", "+refs/heads/main:" + ref],
        trusted_dir,
    )
    return ref


def main_package_version(source_dir):
    cargo = (Path(source_dir) / "crates/main/Cargo.toml").read_text(encoding="utf-8")
    section = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", cargo)
    if not section:
        raise PublishError("crates/main/Cargo.toml has no [package] section")
    version = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*(?:#.*)?$', section.group(1))
    if not version:
        raise PublishError("crates/main/Cargo.toml has no literal package version")
    return version.group(1)


def validate_version_files(source_dir, tag):
    version = validate_tag(tag)
    state = (Path(source_dir) / ".release-please-version").read_text(encoding="utf-8").strip()
    cargo_version = main_package_version(source_dir)
    if not VERSION_RE.fullmatch(state) or state != version or cargo_version != version:
        raise PublishError("release tag, .release-please-version, and crates/main Cargo version must match")
    return version


def verify_main_context():
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    ref = os.environ.get("GITHUB_REF", "")
    if repository != REPOSITORY or ref != "refs/heads/main":
        raise PublishError("image publishing is allowed only from abnormalhq/stalwart on refs/heads/main")


def write_outputs(values):
    output = os.environ.get("GITHUB_OUTPUT")
    lines = [key + "=" + str(value) for key, value in values.items()]
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def resolve_release_inputs(args):
    verify_main_context()
    trusted_dir = Path(args.trusted_dir).resolve()
    version = validate_tag(args.tag)
    tag_ref_oid, tag_peeled_oid, source_sha = remote_tag_snapshot(args.tag, trusted_dir)
    validate_expected_sha(args.expected_sha, source_sha)
    token = os.environ.get("GITHUB_TOKEN", "")
    validate_release(get_release(args.tag, token), args.tag, args.expected_sha or None)
    ensure_ancestor(source_sha, trusted_dir, fetch_current_main(trusted_dir))
    write_outputs(
        {
            "tag": args.tag,
            "version": version,
            "sha": source_sha,
            "tag_ref_oid": tag_ref_oid,
            "tag_peeled_oid": tag_peeled_oid,
        }
    )


def validate_source_inputs(args):
    verify_main_context()
    version = validate_tag(args.tag)
    if not SHA_RE.fullmatch(args.sha):
        raise PublishError("resolved release SHA must be a full commit SHA")
    source_dir = Path(args.source_dir).resolve()
    trusted_dir = Path(args.trusted_dir).resolve()
    source_sha = source_commit(source_dir)
    if source_sha != args.sha.lower():
        raise PublishError("source checkout does not match the resolved release commit")
    validate_tag_snapshot(
        remote_tag_snapshot(args.tag, trusted_dir),
        args.tag_ref_oid.lower(),
        args.tag_peeled_oid.lower(),
        source_sha,
    )
    if validate_version_files(source_dir, args.tag) != version:
        raise PublishError("release tag, root version, and main Cargo version do not match")
    ensure_ancestor(source_sha, trusted_dir, fetch_current_main(trusted_dir))
    token = os.environ.get("GITHUB_TOKEN", "")
    wait_for_checks(source_sha, token, args.timeout_seconds, args.poll_seconds)
    write_outputs(
        {
            "tag": args.tag,
            "version": version,
            "sha": source_sha,
            "tag_ref_oid": args.tag_ref_oid,
            "tag_peeled_oid": args.tag_peeled_oid,
        }
    )


def revalidate_release(args):
    verify_main_context()
    version = validate_tag(args.tag)
    if not SHA_RE.fullmatch(args.sha):
        raise PublishError("resolved release SHA must be a full commit SHA")
    source_dir = Path(args.source_dir).resolve()
    trusted_dir = Path(args.trusted_dir).resolve()
    if source_commit(source_dir) != args.sha.lower():
        raise PublishError("release source checkout changed before publication")
    validate_tag_snapshot(
        remote_tag_snapshot(args.tag, trusted_dir),
        args.tag_ref_oid.lower(),
        args.tag_peeled_oid.lower(),
        args.sha.lower(),
    )
    token = os.environ.get("GITHUB_TOKEN", "")
    validate_release(get_release(args.tag, token), args.tag, args.sha)
    if validate_version_files(source_dir, args.tag) != version:
        raise PublishError("release version changed before publication")
    ensure_ancestor(args.sha.lower(), trusted_dir, fetch_current_main(trusted_dir))
    check_required_workflows(args.sha.lower(), token)


def registry_token(username, password, realm, service, scope):
    parsed = urllib.parse.urlparse(realm)
    if parsed.scheme != "https" or parsed.hostname != "ghcr.io":
        raise PublishError("registry authentication challenge used an untrusted token endpoint")
    expected_scope = "repository:" + IMAGE.split("/", 1)[1] + ":pull"
    if service != "ghcr.io" or scope != expected_scope:
        raise PublishError("registry authentication challenge requested an unexpected scope")
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query.update({"service": service, "scope": scope})
    token_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))
    credential = base64.b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        token_url,
        headers={"Authorization": "Basic " + credential, "Accept": "application/json"},
    )
    status, _, body = _http(request)
    payload = _json_response(status, body, "GHCR read-token request")
    token = payload.get("token") or payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise PublishError("GHCR did not return a read token")
    return token


def authenticated_manifest(tag, username, password):
    url = "https://ghcr.io/v2/" + IMAGE.split("/", 1)[1] + "/manifests/" + urllib.parse.quote(tag, safe="")
    scope = "repository:" + IMAGE.split("/", 1)[1] + ":pull"
    token = registry_token(username, password, "https://ghcr.io/token", "ghcr.io", scope)
    request = urllib.request.Request(
        url,
        headers={"Accept": ACCEPT, "Authorization": "Bearer " + token},
    )
    return _http(request)


def registry_credentials():
    username = os.environ.get("GITHUB_ACTOR", "")
    password = os.environ.get("GITHUB_TOKEN", "")
    if not username or not password:
        raise PublishError("GITHUB_ACTOR and GITHUB_TOKEN are required for authenticated GHCR reads")
    return username, password


def check_registry_tag(args):
    validate_tag(args.tag)
    username, password = registry_credentials()
    status, _, body = authenticated_manifest(args.tag, username, password)
    state = parse_registry_tag_state(status, body)
    if state == "exists":
        raise PublishError("GHCR tag " + args.tag + " already exists; refusing to overwrite it")
    print("GHCR tag " + args.tag + " is absent; no push has occurred")


def registry_digest(tag, username, password):
    status, headers, body = authenticated_manifest(tag, username, password)
    if parse_registry_tag_state(status, body) != "exists":
        raise PublishError("published GHCR tag is not readable")
    digest = headers.get("Docker-Content-Digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PublishError("GHCR manifest response has no valid Docker-Content-Digest")
    actual = "sha256:" + hashlib.sha256(body).hexdigest()
    if actual != digest:
        raise PublishError("GHCR manifest body does not match Docker-Content-Digest")
    return digest


def get_digest(args):
    validate_tag(args.tag)
    username, password = registry_credentials()
    digest = registry_digest(args.tag, username, password)
    write_outputs({"digest": digest})


def verify_image(args):
    image_ref = args.image_ref
    run = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "/usr/local/bin/stalwart", image_ref, "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if run.returncode != 0:
        raise PublishError("image --version smoke test failed: " + (run.stderr.strip() or str(run.returncode)))
    version_output = (run.stdout + run.stderr).strip()
    inspect = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{json .}}", image_ref],
        text=True,
        capture_output=True,
        check=False,
    )
    if inspect.returncode != 0:
        raise PublishError("docker image inspect failed: " + inspect.stderr.strip())
    try:
        metadata = json.loads(inspect.stdout)
        if isinstance(metadata, list):
            metadata = metadata[0]
    except (IndexError, json.JSONDecodeError):
        raise PublishError("docker image inspect returned invalid image metadata")
    labels = (metadata.get("Config") or {}).get("Labels") or {}
    verify_image_metadata(
        version_output,
        labels,
        metadata.get("Os"),
        metadata.get("Architecture"),
        args.version,
        args.sha,
    )
    if args.write_summary:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
        if not summary_path:
            raise PublishError("GITHUB_STEP_SUMMARY is required for the publication summary")
        version_text = " ".join(version_output.split()).replace("`", "'")
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(
                "## Community image published and verified\n\n"
                + "- Image: `" + IMAGE + ":" + args.tag + "`\n"
                + "- Platform: `linux/amd64`\n"
                + "- Digest: `" + args.digest + "`\n"
                + "- Pull by immutable digest: `docker pull " + IMAGE + "@" + args.digest + "`\n"
                + "- Version check: `" + version_text + "`\n"
                + "- OCI labels: source, revision, and version match the release\n"
            )
    print("verified " + image_ref + " as linux/amd64 " + args.version)


def build_parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    tag = commands.add_parser("validate-tag")
    tag.add_argument("--tag", required=True)

    resolve = commands.add_parser("resolve-tag")
    resolve.add_argument("--tag", required=True)
    resolve.add_argument("--expected-sha", default="")
    resolve.add_argument("--trusted-dir", required=True)

    validate = commands.add_parser("validate-source")
    validate.add_argument("--tag", required=True)
    validate.add_argument("--sha", required=True)
    validate.add_argument("--tag-ref-oid", required=True)
    validate.add_argument("--tag-peeled-oid", default="")
    validate.add_argument("--source-dir", required=True)
    validate.add_argument("--trusted-dir", required=True)
    validate.add_argument("--timeout-seconds", type=int, default=5400)
    validate.add_argument("--poll-seconds", type=int, default=30)

    check = commands.add_parser("check-registry-tag")
    check.add_argument("--tag", required=True)

    revalidate = commands.add_parser("revalidate")
    revalidate.add_argument("--tag", required=True)
    revalidate.add_argument("--sha", required=True)
    revalidate.add_argument("--tag-ref-oid", required=True)
    revalidate.add_argument("--tag-peeled-oid", default="")
    revalidate.add_argument("--source-dir", required=True)
    revalidate.add_argument("--trusted-dir", required=True)

    digest = commands.add_parser("get-digest")
    digest.add_argument("--tag", required=True)

    image = commands.add_parser("verify-image")
    image.add_argument("--image-ref", required=True)
    image.add_argument("--tag", required=True)
    image.add_argument("--version", required=True)
    image.add_argument("--sha", required=True)
    image.add_argument("--digest", default="")
    image.add_argument("--write-summary", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-tag":
            print(validate_tag(args.tag))
        elif args.command == "resolve-tag":
            resolve_release_inputs(args)
        elif args.command == "validate-source":
            validate_source_inputs(args)
        elif args.command == "check-registry-tag":
            check_registry_tag(args)
        elif args.command == "revalidate":
            revalidate_release(args)
        elif args.command == "get-digest":
            get_digest(args)
        elif args.command == "verify-image":
            verify_image(args)
        else:
            raise PublishError("unsupported command")
    except (PublishError, OSError, ValueError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
