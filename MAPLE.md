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
| `maple/<release>`, for example `maple/0.17` | The upstream release tag | The three changes above, as their own commits, and this file | Never, once something pins a commit on it |
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
4. `cargo publish --dry-run` both renamed crates, `maple-sigstore-rekor`
   first, since `maple-sigstore-verify` depends on it.
5. Update this file's table.

## When the fork can go away

Once an upstream release verifies P-384 Rekor v2 entries and offers the
checkpoint binding, a consumer can return to the upstream crates and stop
publishing these. Until then the corpus is the test that an upstream release
is good enough.
