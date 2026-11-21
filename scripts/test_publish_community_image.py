import argparse
import json
import unittest
import urllib.parse
from unittest import mock

import publish_community_image as publisher
from publish_community_image import (
    PublishError,
    parse_registry_tag_state,
    validate_expected_sha,
    validate_release,
    validate_tag,
    validate_tag_snapshot,
    verify_image_metadata,
    workflow_run_state,
)


SHA = "a" * 40


class PublishGuardTests(unittest.TestCase):
    def test_strict_release_tag(self):
        self.assertEqual(validate_tag("v1.2.0"), "1.2.0")
        for tag in ("1.2.0", "v1.2", "v1.2.0-rc.1", "v1.2.0+build", "v1.2.0/other"):
            with self.subTest(tag=tag), self.assertRaises(PublishError):
                validate_tag(tag)

    def test_release_must_be_published_and_stable(self):
        release = {"tag_name": "v1.2.0", "draft": False, "prerelease": False}
        self.assertTrue(validate_release(release, "v1.2.0", SHA))
        for update in ({"draft": True}, {"prerelease": True}, {"tag_name": "v1.2.1"}):
            with self.subTest(update=update), self.assertRaises(PublishError):
                validate_release(dict(release, **update), "v1.2.0", SHA)

    def test_missing_workflow_is_pending_and_failure_is_terminal(self):
        self.assertEqual(workflow_run_state([], SHA), ("pending", None))
        wrong_sha = [{"head_sha": "b" * 40, "event": "push", "head_branch": "main", "status": "completed", "conclusion": "success"}]
        self.assertEqual(workflow_run_state(wrong_sha, SHA), ("pending", None))
        manual_run = [{"head_sha": SHA, "event": "workflow_dispatch", "head_branch": "main", "status": "completed", "conclusion": "success"}]
        self.assertEqual(workflow_run_state(manual_run, SHA)[0], "success")
        pull_request = [{"head_sha": SHA, "event": "pull_request", "head_branch": "main", "status": "completed", "conclusion": "success"}]
        self.assertEqual(workflow_run_state(pull_request, SHA), ("pending", None))
        foreign_branch = [{"head_sha": SHA, "event": "push", "head_branch": "feature", "status": "completed", "conclusion": "success"}]
        self.assertEqual(workflow_run_state(foreign_branch, SHA), ("pending", None))
        failed = [{"head_sha": SHA, "event": "push", "head_branch": "main", "status": "completed", "conclusion": "failure"}]
        self.assertEqual(workflow_run_state(failed, SHA)[0], "failure")

    def test_any_failed_exact_sha_run_blocks_publication(self):
        runs = [
            {"head_sha": SHA, "event": "push", "head_branch": "main", "status": "completed", "conclusion": "failure", "created_at": "2026-01-01T00:00:00Z"},
            {"head_sha": SHA, "event": "push", "head_branch": "main", "status": "completed", "conclusion": "success", "created_at": "2026-01-02T00:00:00Z"},
        ]
        state, run = workflow_run_state(runs, SHA)
        self.assertEqual(state, "failure")
        self.assertEqual(run["conclusion"], "failure")

    def test_workflow_history_filters_events_and_paginates_past_mixed_runs(self):
        def read_history(old_push_conclusion):
            calls = []

            def api(path, _token):
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                event = query["event"][0]
                page = int(query["page"][0])
                calls.append((event, page))
                if event == "push" and page == 1:
                    runs = [
                        {
                            "head_sha": SHA,
                            "event": "schedule",
                            "head_branch": "main",
                            "status": "completed",
                            "conclusion": "success",
                        }
                        for _ in range(100)
                    ]
                    return {"total_count": 101, "workflow_runs": runs}
                if event == "push" and page == 2:
                    return {
                        "total_count": 101,
                        "workflow_runs": [
                            {
                                "head_sha": SHA,
                                "event": "push",
                                "head_branch": "main",
                                "status": "completed",
                                "conclusion": old_push_conclusion,
                            }
                        ],
                    }
                if event == "workflow_dispatch" and page == 1:
                    return {
                        "total_count": 1,
                        "workflow_runs": [
                            {
                                "head_sha": SHA,
                                "event": "workflow_dispatch",
                                "head_branch": "main",
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ],
                    }
                self.fail("unexpected workflow run page: " + repr((event, page)))

            with mock.patch.object(publisher, "github_api_json", side_effect=api):
                runs = publisher.get_workflow_runs("community-pr.yml", SHA, "token")
            return runs, calls

        failed_runs, calls = read_history("failure")
        self.assertEqual(workflow_run_state(failed_runs, SHA)[0], "failure")
        self.assertEqual(calls, [("push", 1), ("push", 2), ("workflow_dispatch", 1)])
        successful_runs, _ = read_history("success")
        self.assertEqual(workflow_run_state(successful_runs, SHA)[0], "success")

    def test_workflow_history_truncation_cap_and_api_errors_fail_closed(self):
        with mock.patch.object(
            publisher,
            "github_api_json",
            return_value={"total_count": 1001, "workflow_runs": []},
        ):
            with self.assertRaisesRegex(PublishError, "1000-run result cap"):
                publisher.get_workflow_runs("community-pr.yml", SHA, "token")

        with mock.patch.object(
            publisher,
            "github_api_json",
            return_value={"total_count": 101, "workflow_runs": [{} for _ in range(99)]},
        ):
            with self.assertRaisesRegex(PublishError, "truncated"):
                publisher.get_workflow_runs("community-pr.yml", SHA, "token")

        with mock.patch.object(
            publisher,
            "github_api_json",
            side_effect=PublishError("GitHub API returned HTTP 403"),
        ):
            with self.assertRaisesRegex(PublishError, "HTTP 403"):
                publisher.get_workflow_runs("community-pr.yml", SHA, "token")

    def test_missing_checks_timeout_and_pre_push_recheck_fail_closed(self):
        fetch_none = lambda *_: []
        with self.assertRaisesRegex(PublishError, "timed out waiting"):
            publisher.wait_for_checks(SHA, "token", timeout_seconds=0, poll_seconds=0, fetch_runs=fetch_none)
        with self.assertRaisesRegex(PublishError, "not a successful"):
            publisher.check_required_workflows(SHA, "token", fetch_runs=fetch_none)

    def test_expected_sha_mismatch_with_mocked_tag_resolution(self):
        args = argparse.Namespace(tag="v1.2.0", expected_sha="b" * 40, trusted_dir="trusted")
        with mock.patch.object(publisher, "verify_main_context"):
            with mock.patch.object(publisher, "remote_tag_snapshot", return_value=(SHA, "", SHA)):
                with mock.patch.object(publisher, "get_release") as get_release:
                    with self.assertRaisesRegex(PublishError, "expected SHA does not match"):
                        publisher.resolve_release_inputs(args)
                    get_release.assert_not_called()

    def test_moved_tag_rejected_with_mocked_remote_snapshot(self):
        moved = "b" * 40
        args = argparse.Namespace(
            tag="v1.2.0",
            sha=SHA,
            tag_ref_oid=SHA,
            tag_peeled_oid="",
            source_dir="source",
            trusted_dir="trusted",
        )
        with mock.patch.object(publisher, "verify_main_context"):
            with mock.patch.object(publisher, "source_commit", return_value=SHA):
                with mock.patch.object(publisher, "remote_tag_snapshot", return_value=(moved, "", moved)):
                    with mock.patch.object(publisher, "get_release") as get_release:
                        with self.assertRaisesRegex(PublishError, "release tag changed"):
                            publisher.revalidate_release(args)
                        get_release.assert_not_called()

    def test_tag_snapshot_and_expected_sha_are_immutable(self):
        validate_expected_sha(SHA, SHA)
        with self.assertRaisesRegex(PublishError, "expected SHA"):
            validate_expected_sha("b" * 40, SHA)
        validate_tag_snapshot((SHA, "", SHA), SHA, "", SHA)
        with self.assertRaisesRegex(PublishError, "tag changed"):
            validate_tag_snapshot(("b" * 40, "", "b" * 40), SHA, "", SHA)

    def test_registry_existing_and_definitive_absence(self):
        self.assertEqual(parse_registry_tag_state(200, b"{}"), "exists")
        body = json.dumps({"errors": [{"code": "MANIFEST_UNKNOWN"}]}).encode()
        self.assertEqual(parse_registry_tag_state(404, body), "absent")
        body = json.dumps({"errors": [{"code": "NAME_UNKNOWN"}]}).encode()
        self.assertEqual(parse_registry_tag_state(404, body), "absent")
        mixed_errors = json.dumps({"errors": [{"code": "MANIFEST_UNKNOWN"}, {"code": "UNAUTHORIZED"}]}).encode()
        with self.assertRaises(PublishError):
            parse_registry_tag_state(404, mixed_errors)

    def test_existing_registry_tag_refuses_push(self):
        args = argparse.Namespace(tag="v1.2.0")
        with mock.patch.object(publisher, "registry_credentials", return_value=("actor", "token")):
            with mock.patch.object(publisher, "authenticated_manifest", return_value=(200, {}, b"{}")):
                with self.assertRaisesRegex(PublishError, "already exists"):
                    publisher.check_registry_tag(args)

    def test_registry_manifest_read_uses_authenticated_token_without_network(self):
        with mock.patch.object(publisher, "registry_token", return_value="read-token") as token:
            with mock.patch.object(publisher, "_http", return_value=(404, {}, b"{}")) as http:
                publisher.authenticated_manifest("v1.2.0", "actor", "secret")
        token.assert_called_once_with(
            "actor",
            "secret",
            "https://ghcr.io/token",
            "ghcr.io",
            "repository:abnormalhq/stalwart:pull",
        )
        request = http.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer read-token")

    def test_registry_auth_and_unclassified_failures_fail_closed(self):
        for status, body in (
            (401, b"unauthorized"),
            (403, b"denied"),
            (404, b"not found"),
            (404, b'{"errors":[{"code":"UNAUTHORIZED"}]}'),
            (500, b"server error"),
        ):
            with self.subTest(status=status, body=body), self.assertRaises(PublishError):
                parse_registry_tag_state(status, body)

    def test_image_version_platform_and_oci_labels_must_match(self):
        labels = {
            "org.opencontainers.image.source": "https://github.com/abnormalhq/stalwart",
            "org.opencontainers.image.revision": SHA,
            "org.opencontainers.image.version": "1.2.0",
        }
        self.assertTrue(verify_image_metadata("1.2.0\n", labels, "linux", "amd64", "1.2.0", SHA))
        with self.assertRaises(PublishError):
            verify_image_metadata("1.2.1", labels, "linux", "amd64", "1.2.0", SHA)
        with self.assertRaises(PublishError):
            verify_image_metadata("1.2.0", labels, "linux", "arm64", "1.2.0", SHA)
        with self.assertRaises(PublishError):
            verify_image_metadata("1.2.0", dict(labels, **{"org.opencontainers.image.revision": "b" * 40}), "linux", "amd64", "1.2.0", SHA)


if __name__ == "__main__":
    unittest.main()
