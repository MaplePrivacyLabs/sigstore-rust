#!/usr/bin/env python3
"""Release the two crates this fork changes. MAPLE.md describes the process.

  plan     Check that the tagged commit may be released and say which crates
           crates.io does not have yet. Uses no credential.
  publish  Repeat that check, then upload the missing crates in dependency
           order, waiting for the registry index between them.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Dependency order: maple-sigstore-verify pins maple-sigstore-rekor exactly, so
# it cannot be packaged until that version is in the index. Nothing else in the
# workspace is ever published from this fork.
CRATES = ("maple-sigstore-rekor", "maple-sigstore-verify")
TAG = re.compile(r"refs/tags/maple-v(((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))-maple\.[1-9]\d*)\Z")
INDEX = "https://index.crates.io"
USER_AGENT = "maple-sigstore-publish (https://github.com/MaplePrivacyLabs/sigstore-rust)"
POLL_SECONDS = 10
# How long to wait for an uploaded version to be served. Cargo's own wait can
# end early, and an upload can succeed even when Cargo reports a failure.
SERVED_AFTER_SUCCESS = 15 * 60
SERVED_AFTER_FAILURE = 3 * 60


class Refused(Exception):
    """The release must not go ahead. The message says why."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def output(*command):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True).stdout


# --- Which commit may be released -------------------------------------------


def tagged_version(ref):
    """The crate version and the upstream release a maple-v tag names."""
    match = TAG.fullmatch(ref)
    require(match, "This run is not for a tag named maple-v<upstream version>-maple.<n>")
    return match.group(1), match.group(2)


def maple_heads(remote="origin"):
    """Branch heads under maple/, read from the remote and not from this checkout."""
    heads = {}
    for line in output("git", "ls-remote", "--heads", remote, "refs/heads/maple/*").splitlines():
        sha, ref = line.split()
        heads[ref.removeprefix("refs/heads/")] = sha
    return heads


def publish_branch(sha, heads, parents, upstream):
    """The maple/<release>-publish branch whose head is this commit.

    The commit must be that head, and its only parent must be the head of
    maple/<release>: the reviewed changes plus the one rename commit, nothing else.
    """
    at_head = sorted(name for name, head in heads.items() if name.endswith("-publish") and head == sha)
    require(len(at_head) == 1, "The tagged commit is not the head of exactly one maple/<release>-publish branch")
    branch = at_head[0]
    base = branch.removesuffix("-publish")
    release = base.removeprefix("maple/")
    require(release in (upstream, upstream.rpartition(".")[0]),
            f"{branch} is not the publish branch for upstream {upstream}")
    require(base in heads, f"{base} does not exist")
    require(parents == [heads[base]], f"{branch} must be exactly one commit on top of the head of {base}")
    return branch, base


def check_manifests(metadata, version, upstream):
    """The two crates carry the tagged version and pin their workspace siblings exactly."""
    packages = {package["name"]: package for package in metadata["packages"]}
    for name in CRATES:
        require(name in packages, f"{name} is not a package in this workspace")
        package = packages[name]
        require(package["version"] == version, f"{name} is at {package['version']}, but the tag says {version}")
        require(package.get("publish") in (None, ["crates-io"]), f"{name} does not allow publishing to crates.io")
        for dependency in package["dependencies"]:
            # A path means a crate of this workspace. Dev-dependencies never reach a consumer.
            if dependency.get("path") is None or dependency.get("kind") == "dev":
                continue
            expected = f"={version}" if dependency["name"] in CRATES else f"={upstream}"
            require(dependency["req"] == expected,
                    f"{name} must depend on {dependency['name']} at exactly {expected[1:]}, not {dependency['req']}")
    require(any(dependency["name"] == CRATES[0] and dependency.get("kind") is None
                for dependency in packages[CRATES[1]]["dependencies"]),
            f"{CRATES[1]} does not depend on {CRATES[0]}")
    renamed = sorted(name for name, package in packages.items()
                     if name not in CRATES and ("maple" in name or "maple" in package["version"]))
    require(not renamed, f"Only {' and '.join(CRATES)} may carry a Maple name or version, not {', '.join(renamed)}")


# --- What crates.io already has ---------------------------------------------


def index_versions(name):
    """Every version the sparse index serves for a crate, or None if it has never been published."""
    request = urllib.request.Request(f"{INDEX}/{name[:2]}/{name[2:4]}/{name}", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            lines = response.read().decode().splitlines()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    return {json.loads(line)["vers"] for line in lines if line.strip()}


def plan(environ, versions=index_versions):
    """Check the release commit, then return its version, the crates still missing and how to authenticate."""
    version, upstream = tagged_version(environ.get("GITHUB_REF", ""))
    sha = environ["GITHUB_SHA"]
    parents = output("git", "rev-list", "--parents", "-n", "1", sha).split()[1:]
    branch, base = publish_branch(sha, maple_heads(), parents, upstream)
    check_manifests(json.loads(output("cargo", "metadata", "--no-deps", "--format-version", "1", "--locked")),
                    version, upstream)
    print(f"{sha} is the head of {branch}, one commit on top of {base}.")
    return (version, *registry_state(version, versions))


def registry_state(version, versions):
    """The crates not yet published at this version, and the credential the upload needs.

    crates.io accepts trusted publishing only for a crate that already exists,
    so a crate's first version needs the bootstrap token.
    """
    served = {name: versions(name) for name in CRATES}
    missing = [name for name in CRATES if version not in (served[name] or ())]
    for name in CRATES:
        print(f"{name} {version}: {'to publish' if name in missing else 'already on crates.io'}")
    if not missing:
        return missing, "none"
    return missing, "bootstrap" if any(served[name] is None for name in missing) else "trusted"


# --- Uploading ----------------------------------------------------------------


def cargo_publish(name):
    # --no-verify: the check job built, tested and dry-ran this commit without a
    # credential. Building here would run dependency build scripts next to the token.
    return subprocess.run(["cargo", "publish", "--locked", "--no-verify", "-p", name]).returncode


def wait_until_served(name, version, seconds, versions=index_versions, sleep=time.sleep):
    """True once the index serves this version; False if it has not after the given time."""
    for attempt in range(seconds // POLL_SECONDS + 1):
        if attempt:
            sleep(POLL_SECONDS)
        try:
            if version in (versions(name) or ()):
                return True
        except OSError as error:
            print(f"Reading the index for {name} failed ({error}); trying again.")
    return False


def publish(version, environ, versions=index_versions, upload=cargo_publish, sleep=time.sleep):
    """Upload each crate the index lacks, in order, and wait for it to be served before the next."""
    for name in CRATES:
        if version in (versions(name) or ()):
            print(f"{name} {version} is already on crates.io; skipping it.")
            continue
        require(environ.get("CARGO_REGISTRY_TOKEN"),
                f"No crates.io credential for {name}. A crate's first version needs CRATES_BOOTSTRAP_TOKEN in the "
                "maple-crates environment; later versions need its trusted publisher entry on crates.io.")
        status = upload(name)
        wait = SERVED_AFTER_SUCCESS if status == 0 else SERVED_AFTER_FAILURE
        require(wait_until_served(name, version, wait, versions, sleep),
                f"{name} {version} is not in the crates.io index (cargo publish exited with {status}). "
                "Nothing after it was uploaded. Rerun this job once the cause is fixed.")
        print(f"{name} {version} is published and served by the index.")


def github_output(environ, **values):
    if environ.get("GITHUB_OUTPUT"):
        with open(environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.writelines(f"{key}={value}\n" for key, value in values.items())


def main(argv, environ):
    require(len(argv) == 2 and argv[1] in ("plan", "publish"), "Usage: publish.py plan|publish")
    version, missing, auth = plan(environ)
    if argv[1] == "plan":
        github_output(environ, version=version, missing=" ".join(missing), auth=auth)
    elif missing:
        publish(version, environ)
    else:
        print("Both crates are already published at this version. Nothing to do.")


if __name__ == "__main__":
    try:
        main(sys.argv, os.environ)
    except Refused as refusal:
        sys.exit(f"Refused: {refusal}")
