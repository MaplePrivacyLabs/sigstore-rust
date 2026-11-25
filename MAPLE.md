# The Maple fork of sigstore-rust

This repository is a fork of
[sigstore/sigstore-rust](https://github.com/sigstore/sigstore-rust). Maple
uses it to verify release statements signed with an ECDSA P-384 key and logged
in Rekor v2, which the upstream release cannot do yet. This file says which
branch is which and why. It exists only on the Maple branches.

## What the fork changes

Three things, in two crates (`sigstore-rekor` and `sigstore-verify`). Every
other crate is unmodified upstream.

1. **P-384 Rekor v2 entries verify.** Upstream assumed SHA-256 and knew only
   the P-256 key details. Offered upstream as
   [sigstore/sigstore-rust#375](https://github.com/sigstore/sigstore-rust/pull/375).
2. **A checkpoint can be required to come from the entry's own log**, with
   `require_checkpoint_log_binding()`. It is opt-in, so the default behaves as
   upstream does. Not offered upstream.
3. **A managed-key test corpus** under `test-vectors/managed-key/`, shared
   with the browser fork. Not offered upstream.

## Branches

| Branch | Starts from | Holds | Rewritten? |
| --- | --- | --- | --- |
| `main` | upstream `main` | A mirror of upstream. Nothing of Maple's. | Fast-forwarded only |
| `maple/<release>`, for example `maple/0.17` | The upstream release tag | The three changes above, as their own commits, this file, and the publish workflow | Never, once something pins a commit on it |
| `maple/<release>-publish` | `maple/<release>` | Exactly one commit: the crate renames | Rebuilt whenever `maple/<release>` moves |
| `upstream/p384-rekor-v2` | upstream `main` | One commit, the P-384 fix alone: the pull request above | Rebased as upstream asks |
| `maple/p384-rekor-v2`, `maple/p384-rekor-v2-publish` | The 0.16.0 tag | The same work on upstream 0.16.0 | Frozen; see below |

### Why two starting points

The Maple branch starts from an upstream **release tag**, because the crates
Maple does not change come from crates.io at exactly that release, and the two
renamed crates must match them.

The upstream branch starts from upstream **`main`**, because that is what the
maintainers review, and it carries only what they have been asked to take. It
is a sibling of the Maple branch, not its base. Both hold the same P-384 fix.

### Why the renames are their own branch

crates.io refuses a crate that depends on a Git repository, so a crate that
uses this fork cannot be published unless the fork's crates are on crates.io
too. They cannot be published under upstream's names. `maple/<release>-publish`
renames the two changed crates:

- `sigstore-rekor` to `maple-sigstore-rekor`
- `sigstore-verify` to `maple-sigstore-verify`

The library names stay `sigstore_rekor` and `sigstore_verify`, so no source
changes, and the other crates are pinned to exactly the upstream release. The
renames live in one commit on their own branch so the Maple branch stays a
plain diff against upstream and the renames can be redone mechanically.

Versions are the upstream version with a Maple suffix, for example
`0.17.0-maple.1`. Raise the last number to publish a fix on the same upstream
release.

### The frozen 0.16.0 branches

`maple/p384-rekor-v2` is pinned by commit from elsewhere. Rewriting it would
remove a commit that builds depend on, so it stays as it is until nothing
pins it. Do new work on `maple/<release>`.

## Moving to a new upstream release

1. Create `maple/<new release>` from the previous Maple branch and rebase it
   onto the new upstream release tag: `git rebase --onto <new tag> <old tag>`.
   Drop any commit upstream has taken.
2. Run the whole test suite, including the corpus
   (`test-vectors/managed-key/README.md` says how) and upstream's conformance
   vectors.
3. Rebuild `maple/<new release>-publish` as one commit on top: the two
   renames, their versions, and the exact pins on the other crates.
4. `cargo publish --dry-run -p maple-sigstore-rekor -p maple-sigstore-verify`:
   both in one command, since `maple-sigstore-verify` depends on a
   `maple-sigstore-rekor` that is not in the registry yet.
5. Update this file's table.
6. Publish, as described below.

The publish workflow and its script are commits on the Maple branch, so the
rebase in step 1 carries them to the new release line. Nothing in them names
a release.

## Publishing to crates.io

`.github/workflows/maple-publish.yml` publishes `maple-sigstore-rekor` and
then `maple-sigstore-verify`, and nothing else. To release:

1. Make sure `maple/<release>-publish` is rebuilt on the current head of
   `maple/<release>` and both crates carry the version to release.
2. Tag that branch head `maple-v<version>`, for example
   `maple-v0.17.0-maple.1`, and push the tag.
3. The `check` job refuses unless the tagged commit is the head of a
   `maple/<release>-publish` branch, exactly one commit on top of
   `maple/<release>`, with manifests that match the tag. It then runs the
   workspace tests and a dry run.
4. The `publish` job waits for a reviewer in the `maple-crates` environment,
   repeats the check, uploads `maple-sigstore-rekor`, waits until the
   crates.io index serves it, and uploads `maple-sigstore-verify`.

A rerun is safe. A crate the index already serves at this version is skipped,
and when both are there the run says so and asks for no approval. To redo a
release after a fix, rebuild the publish branch with the next build number
and push a new tag; a published version can never be replaced.

### Credentials

crates.io allows trusted publishing only for a crate that already exists.

- **A crate's first version** is uploaded with an API token held as the
  `CRATES_BOOTSTRAP_TOKEN` secret of the `maple-crates` environment, never as
  a repository secret. Scope it to publishing new crates named
  `maple-sigstore-*`, give it a short expiry, and delete the secret and
  revoke the token once both crates exist.
- **Every later version** uses trusted publishing. Each crate needs its own
  entry on crates.io (crate Settings, Trusted Publishing): repository
  `MaplePrivacyLabs/sigstore-rust`, workflow `maple-publish.yml`, environment
  `maple-crates`.

The workflow picks the method from what the index serves; there is nothing to
select.

### The workflows inherited from upstream

Upstream's own workflows come with every branch, including `release-plz.yml`,
which releases upstream's crates on a push to `main`. They cannot publish from
this fork: it holds no repository secret, upstream's crates trust only
upstream's repository, and the two Maple crates trust only
`maple-publish.yml` in `maple-crates`.

As a second guard, this repository has an environment named `crates-io`, the
one `release-plz.yml` asks for, that no branch or tag is allowed to use, so
that job cannot start here. Keep both guards: never give `crates-io` an
allowed ref or a secret, and never point a crate's trusted publisher at it.
GitHub lists `release-plz.yml` under Actions only after a push to `main` has
run it once; disable it there when it appears.

## When the fork can go away

Once an upstream release verifies P-384 Rekor v2 entries and offers the
checkpoint binding, a consumer can return to the upstream crates and stop
publishing these. Until then the corpus is the test that an upstream release
is good enough.
