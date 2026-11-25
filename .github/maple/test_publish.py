#!/usr/bin/env python3
"""Tests for publish.py. Run: python3 -m unittest discover -s .github/maple -p 'test_*.py'"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import publish

VERSION, UPSTREAM = "0.17.0-maple.1", "0.17.0"
REKOR, VERIFY = publish.CRATES
GIT_ENV = {
    "PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def dependency(name, req, kind=None, path="/workspace/crates/x"):
    return {"name": name, "req": req, "kind": kind, "path": path}


def metadata(**changes):
    """cargo metadata for a correct publish branch, with one field of it changed."""
    packages = {
        REKOR: {"name": REKOR, "version": VERSION, "publish": None, "dependencies": [
            dependency("sigstore-types", f"={UPSTREAM}"),
            dependency("serde", "^1.0", path=None)]},
        VERIFY: {"name": VERIFY, "version": VERSION, "publish": None, "dependencies": [
            dependency(REKOR, f"={VERSION}"),
            dependency("sigstore-bundle", f"={UPSTREAM}"),
            dependency("sigstore-sign", "*", kind="dev")]},
        "sigstore-types": {"name": "sigstore-types", "version": UPSTREAM, "publish": None, "dependencies": []},
    }
    for name, package in changes.items():
        packages[name.replace("_", "-")] = package
    return {"packages": list(packages.values())}


class TagTests(unittest.TestCase):
    def test_a_maple_tag_names_the_crate_version_and_the_upstream_release(self):
        self.assertEqual(publish.tagged_version(f"refs/tags/maple-v{VERSION}"), (VERSION, UPSTREAM))

    def test_other_refs_are_refused(self):
        for ref in ("refs/tags/maple-v0.17.0", "refs/tags/v0.17.0-maple.1", "refs/tags/maple-v0.17.0-maple.0",
                    "refs/tags/maple-v0.17-maple.1", "refs/heads/maple/0.17-publish",
                    "refs/tags/maple-v0.17.0-maple.1-rc1", ""):
            with self.subTest(ref=ref), self.assertRaises(publish.Refused):
                publish.tagged_version(ref)


class PublishBranchTests(unittest.TestCase):
    HEADS = {"maple/0.17": "b" * 40, "maple/0.17-publish": "a" * 40, "maple/0.16": "d" * 40,
             "maple/0.16-publish": "c" * 40}

    def branch(self, sha="a" * 40, heads=None, parents=("b" * 40,), upstream=UPSTREAM):
        return publish.publish_branch(sha, self.HEADS if heads is None else heads, list(parents), upstream)

    def test_the_head_of_a_publish_branch_one_commit_on_its_release_branch_is_accepted(self):
        self.assertEqual(self.branch(), ("maple/0.17-publish", "maple/0.17"))

    def test_a_release_branch_named_after_the_full_upstream_version_is_accepted(self):
        heads = {"maple/0.17.1": "b" * 40, "maple/0.17.1-publish": "a" * 40}
        self.assertEqual(self.branch(heads=heads, upstream="0.17.1"), ("maple/0.17.1-publish", "maple/0.17.1"))

    def test_a_commit_that_is_not_a_publish_branch_head_is_refused(self):
        for sha in ("b" * 40, "e" * 40):  # the release branch head, and a commit on no branch
            with self.subTest(sha=sha), self.assertRaisesRegex(publish.Refused, "not the head"):
                self.branch(sha=sha)

    def test_more_than_the_one_rename_commit_is_refused(self):
        with self.assertRaisesRegex(publish.Refused, "exactly one commit"):
            self.branch(parents=("f" * 40,))  # the parent is not the release branch head

    def test_a_release_branch_that_moved_after_the_publish_branch_was_built_is_refused(self):
        with self.assertRaisesRegex(publish.Refused, "exactly one commit"):
            self.branch(heads={**self.HEADS, "maple/0.17": "9" * 40})

    def test_a_merge_commit_is_refused(self):
        with self.assertRaisesRegex(publish.Refused, "exactly one commit"):
            self.branch(parents=("b" * 40, "d" * 40))

    def test_a_tag_for_another_release_line_is_refused(self):
        with self.assertRaisesRegex(publish.Refused, "not the publish branch for upstream 0.18.0"):
            self.branch(upstream="0.18.0")

    def test_a_publish_branch_without_its_release_branch_is_refused(self):
        with self.assertRaisesRegex(publish.Refused, "does not exist"):
            self.branch(heads={"maple/0.17-publish": "a" * 40})

    def test_two_publish_branches_at_the_same_commit_are_refused(self):
        with self.assertRaisesRegex(publish.Refused, "exactly one"):
            self.branch(heads={**self.HEADS, "maple/0.16-publish": "a" * 40})


class RemoteHeadsTests(unittest.TestCase):
    """The branch heads and parents come from Git as the workflow reads them."""

    def git(self, cwd, *arguments):
        return subprocess.run(["git", *arguments], cwd=cwd, env=GIT_ENV, check=True, text=True,
                              capture_output=True).stdout.strip()

    def test_heads_are_read_from_the_remote_and_the_parent_from_the_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            origin, work = Path(temporary, "origin"), Path(temporary, "work")
            origin.mkdir()
            self.git(origin, "init", "--quiet", "--initial-branch", "main")
            self.git(origin, "commit", "--quiet", "--allow-empty", "-m", "upstream release")
            self.git(origin, "switch", "--quiet", "-c", "maple/0.17")
            self.git(origin, "commit", "--quiet", "--allow-empty", "-m", "our change")
            base = self.git(origin, "rev-parse", "HEAD")
            self.git(origin, "switch", "--quiet", "-c", "maple/0.17-publish")
            self.git(origin, "commit", "--quiet", "--allow-empty", "-m", "rename")
            head = self.git(origin, "rev-parse", "HEAD")
            self.git(temporary, "clone", "--quiet", str(origin), str(work))
            # A branch that exists only in this checkout must not count.
            self.git(work, "branch", "maple/9.9-publish", head)
            previous = os.getcwd()
            os.chdir(work)
            self.addCleanup(os.chdir, previous)
            environment = dict(os.environ)
            os.environ.update(GIT_ENV)
            self.addCleanup(lambda: (os.environ.clear(), os.environ.update(environment)))
            heads = publish.maple_heads()
            self.assertEqual(heads, {"maple/0.17": base, "maple/0.17-publish": head})
            parents = publish.output("git", "rev-list", "--parents", "-n", "1", head).split()[1:]
            self.assertEqual(publish.publish_branch(head, heads, parents, UPSTREAM),
                             ("maple/0.17-publish", "maple/0.17"))


class ManifestTests(unittest.TestCase):
    def refused(self, pattern, **changes):
        with self.assertRaisesRegex(publish.Refused, pattern):
            publish.check_manifests(metadata(**changes), VERSION, UPSTREAM)

    def package(self, name, **fields):
        correct = {package["name"]: package for package in metadata()["packages"]}[name]
        return {**correct, **fields}

    def test_the_publish_branch_manifests_are_accepted(self):
        publish.check_manifests(metadata(), VERSION, UPSTREAM)

    def test_a_crate_at_another_version_than_the_tag_is_refused(self):
        self.refused("is at 0.17.0-maple.2", maple_sigstore_rekor=self.package(REKOR, version="0.17.0-maple.2"))

    def test_a_missing_crate_is_refused(self):
        without = {"packages": [p for p in metadata()["packages"] if p["name"] != VERIFY]}
        with self.assertRaisesRegex(publish.Refused, "not a package"):
            publish.check_manifests(without, VERSION, UPSTREAM)

    def test_a_crate_that_forbids_publishing_is_refused(self):
        self.refused("does not allow", maple_sigstore_verify=self.package(VERIFY, publish=[]))

    def test_an_unmodified_sibling_must_be_pinned_to_the_upstream_release(self):
        loose = self.package(REKOR, dependencies=[dependency("sigstore-types", "^0.17.0")])
        self.refused("sigstore-types at exactly 0.17.0", maple_sigstore_rekor=loose)

    def test_the_renamed_sibling_must_be_pinned_to_this_version(self):
        loose = self.package(VERIFY, dependencies=[dependency(REKOR, f"={UPSTREAM}")])
        self.refused(f"{REKOR} at exactly {VERSION}", maple_sigstore_verify=loose)

    def test_verify_must_depend_on_rekor(self):
        self.refused("does not depend", maple_sigstore_verify=self.package(VERIFY, dependencies=[]))

    def test_no_other_crate_may_carry_a_maple_name_or_version(self):
        self.refused("maple-sigstore-tsa", maple_sigstore_tsa={
            "name": "maple-sigstore-tsa", "version": VERSION, "publish": None, "dependencies": []})
        self.refused("sigstore-types", sigstore_types={
            "name": "sigstore-types", "version": VERSION, "publish": None, "dependencies": []})


class Registry:
    """A stand-in index and upload: what is served, what was uploaded, and when uploads appear."""

    def __init__(self, served, appears_after=0, upload_status=0, accepts=True):
        self.served = {name: set(versions) if versions is not None else None for name, versions in served.items()}
        self.appears_after, self.upload_status, self.accepts = appears_after, upload_status, accepts
        self.uploads, self.pending, self.slept = [], {}, 0

    def versions(self, name):
        if name in self.pending:
            self.pending[name] -= 1
            if self.pending[name] < 0:
                del self.pending[name]
                self.served[name] = (self.served[name] or set()) | {VERSION}
        versions = self.served.get(name)
        return None if versions is None else set(versions)

    def upload(self, name):
        # Cargo refuses to package verify until the index serves the rekor version it pins.
        if name == VERIFY and VERSION not in (self.served.get(REKOR) or ()):
            raise AssertionError("verify was uploaded before the index served rekor")
        self.uploads.append(name)
        if self.accepts:
            self.pending[name] = self.appears_after
        return self.upload_status

    def sleep(self, seconds):
        self.slept += seconds

    def publish(self, token="token"):
        publish.publish(VERSION, {"CARGO_REGISTRY_TOKEN": token}, self.versions, self.upload, self.sleep)


class RegistryStateTests(unittest.TestCase):
    def state(self, served):
        return publish.registry_state(VERSION, Registry(served).versions)

    def test_crates_that_were_never_published_need_the_bootstrap_token(self):
        self.assertEqual(self.state({REKOR: None, VERIFY: None}), ([REKOR, VERIFY], "bootstrap"))

    def test_a_rerun_after_only_the_first_upload_publishes_the_second(self):
        self.assertEqual(self.state({REKOR: {VERSION}, VERIFY: None}), ([VERIFY], "bootstrap"))

    def test_a_later_version_of_existing_crates_uses_trusted_publishing(self):
        earlier = {"0.16.0-maple.1"}
        self.assertEqual(self.state({REKOR: earlier, VERIFY: earlier}), ([REKOR, VERIFY], "trusted"))

    def test_nothing_is_left_when_both_are_published(self):
        self.assertEqual(self.state({REKOR: {VERSION}, VERIFY: {VERSION}}), ([], "none"))


class PublishTests(unittest.TestCase):
    def test_rekor_is_uploaded_first_and_verify_only_once_the_index_serves_it(self):
        registry = Registry({REKOR: None, VERIFY: None}, appears_after=3)
        registry.publish()
        self.assertEqual(registry.uploads, [REKOR, VERIFY])
        self.assertGreaterEqual(registry.slept, 2 * 3 * publish.POLL_SECONDS)

    def test_a_crate_that_is_already_served_is_not_uploaded_again(self):
        registry = Registry({REKOR: {VERSION}, VERIFY: None})
        registry.publish()
        self.assertEqual(registry.uploads, [VERIFY])

    def test_nothing_is_uploaded_when_both_are_served(self):
        registry = Registry({REKOR: {VERSION}, VERIFY: {VERSION}})
        registry.publish(token="")
        self.assertEqual(registry.uploads, [])

    def test_an_upload_that_cargo_reports_as_failed_but_the_index_serves_counts_as_published(self):
        registry = Registry({REKOR: None, VERIFY: None}, upload_status=101)
        registry.publish()
        self.assertEqual(registry.uploads, [REKOR, VERIFY])

    def test_a_refused_upload_stops_before_the_second_crate(self):
        registry = Registry({REKOR: None, VERIFY: None}, upload_status=101, accepts=False)
        with self.assertRaisesRegex(publish.Refused, "not in the crates.io index"):
            registry.publish()
        self.assertEqual(registry.uploads, [REKOR])
        self.assertLessEqual(registry.slept, publish.SERVED_AFTER_FAILURE)

    def test_an_accepted_upload_the_index_never_serves_fails_the_job(self):
        registry = Registry({REKOR: None, VERIFY: None}, accepts=False)
        with self.assertRaisesRegex(publish.Refused, "not in the crates.io index"):
            registry.publish()
        self.assertEqual(registry.uploads, [REKOR])

    def test_no_upload_is_attempted_without_a_credential(self):
        registry = Registry({REKOR: None, VERIFY: None})
        with self.assertRaisesRegex(publish.Refused, "No crates.io credential"):
            registry.publish(token="")
        self.assertEqual(registry.uploads, [])

    def test_an_index_error_while_waiting_is_retried(self):
        registry = Registry({REKOR: {VERSION}, VERIFY: None})
        calls = iter([OSError("reset"), None, {VERSION}])

        def versions(name):
            answer = next(calls)
            if isinstance(answer, OSError):
                raise answer
            return answer

        self.assertTrue(publish.wait_until_served(VERIFY, VERSION, 60, versions, registry.sleep))


if __name__ == "__main__":
    unittest.main()
