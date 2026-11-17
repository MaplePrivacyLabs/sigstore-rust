# Managed-key DSSE / Rekor v2 / RFC 3161 test vectors

Accept and reject vectors for verifying a DSSE in-toto bundle signed with a
managed (non-certificate) key, logged in Rekor v2 as a `hashedrekord` 0.0.2
entry and timestamped by an RFC 3161 authority. They cover P-384 (the case this
library previously rejected), P-256 regressions, and the binding of each piece
of evidence to the signature. The statements are synthetic.

`manifest.json` lists every vector. For each one it records:

- source and parent;
- the single mutation made;
- the expected library outcome, with and without `require_checkpoint_log_binding()`;
- for rejections, the expected error category and message, and a language-neutral
  reason code (see [Reason codes](#reason-codes));
- the outcome under the strict profile in [PROFILE.md](PROFILE.md), with the clause
  and reason code for rejections;
- the outcome the pinned Cosign gives.

`crates/sigstore-verify/tests/managed_key_corpus.rs` asserts all of this. A
vector that fails for a reason other than the recorded one fails the test.

The official sigstore-conformance vectors are vendored separately in
`../sigstore-conformance` and run by `tests/conformance_vectors.rs`. This corpus
only adds what that suite lacks: no conformance vector uses P-384, or a managed
key with a Rekor v2 entry and a DSSE envelope.

## Layout

| Path | Contents |
| --- | --- |
| `sources/r1`, `r2`, `r3` | Real bundles from the pinned Cosign: P-384, a second P-384 key and statement, and P-256. Each comes with the key, the artifact named by the statement subject, the statement and `provenance.json`. |
| `sources/trusted_root.*.json` | Sigstore production trusted root (TUF snapshot) and staging root; the staging root is used only for its timestamp authority. |
| `generate.py` | Derives every other file from `sources/`. |
| `vectors/<id>/bundle.sigstore.json` | The vectors. |
| `roots/production.json` | Production root, for the real bundles and their mutations. |
| `roots/production-staging-tsa.json` | Production root with the staging timestamp authority: an untrusted-timestamp case. |
| `roots/test.json` | Synthetic test logs (see below) plus the production timestamp authority. |
| `keys/`, `artifacts/` | Verification key and artifact referenced by each vector. |
| `check-cosign.py` | Re-checks the recorded Cosign outcomes with a Cosign binary. |

## How the vectors were made

**Positives** (`category: positive`, `source.kind: real`) were produced by real
tooling: Cosign v3.1.4 `attest-blob` with a throwaway key and an explicit signing
configuration naming one Rekor v2 log (`log2025-1.rekor.sigstore.dev`) and
Sigstore's timestamp authority. Each was accepted by the log and verified by
Cosign v3.1.4 with `--use-signed-timestamps`. `provenance.json` records the log
index and time. The throwaway private keys were deleted after signing.

**Negatives** are each one documented mutation of an accepted parent. The test
checks that the parent is accepted, so the mutation is the only cause of the
failure. Where a mutation would otherwise be stopped by an earlier, unrelated
check, the matching evidence is moved with it, so the vector reaches the check
it targets. For example, a substituted signature carries its own timestamp. The
manifest records each such dependent change.

**Re-logged vectors.** Changing a log entry body invalidates its inclusion proof,
so a body mutation alone would only ever test the Merkle proof. To reach the
key-details, digest and binding checks behind it, `generate.py` puts the
(mutated) body into a synthetic two-leaf tree and signs a checkpoint with a test
log key from `roots/test.json`. The unmutated re-logged parents
(`p384-relogged`, `p256-relogged`) are accepted by both this library and Cosign
with that root. That shows the re-logging itself is correct, so the body change
is the only difference in each child.

**Test logs.**
- Two Ed25519 Rekor v2 logs, A and B, are identified by their signed-note key ID.
- One ECDSA P-256 Rekor v1 log, as Rekor v1 uses, is identified by SHA-256 of its key and signs with RFC 6979 deterministic nonces.

Their private keys are derived from fixed public strings in `generate.py`. They
are test-only and must never be trusted outside `roots/test.json`.
`p384-rekor1-dsse-synthetic` uses the v1 test log to give a P-384 signature a
Rekor v1 `dsse` 0.0.1 entry with inclusion proof, checkpoint and SET. Cosign
accepts it against the test root. It is synthetic: no public Rekor v1 entry was
made.

**Categories.**
- `standard-negative`: rejected by this library and by Cosign.
- `binding-negative`: accepted by default, rejected with checkpoint-to-log binding.
- `profile-negative`: targets a requirement of the stricter profile in PROFILE.md and cites its clause. The profile rejects every such vector. The library's own outcome is recorded per mode and is usually acceptance, but some of these vectors are also rejected by the library for another reason (for example a missing media type, an invalid added SET, or a `null` integratedTime). Read each vector's expected outcomes rather than inferring them from the category.

`cosign: null` marks cases Cosign is not expected to judge.

## Reason codes

Every rejection in the manifest carries a `code`, so a verifier written in
another language can check that it rejects each vector for the same reason
without matching this library's error messages. The codes name the first check
that fails. For the strict profile, a clause checked before library
verification has its own code; a rejection by library verification (MK-7
timestamp failures and MK-8) carries the code of the library error with
checkpoint-to-log binding on.

| Code | The vector is rejected because |
| --- | --- |
| `bundle-malformed` | the bundle does not parse as a valid bundle |
| `duplicate-json-key` | a JSON object repeats a member name (MK-4) |
| `conflicting-oneof` | two variants of one protobuf `oneof` are present (MK-4) |
| `media-type-unsupported` | the media type is missing or not an accepted version (MK-1) |
| `tlog-entry-count` | there is not exactly one transparency log entry (MK-5) |
| `tlog-entry-kind` | the entry is not a Rekor v2 `hashedrekord` 0.0.2 entry (MK-5) |
| `integrated-time-present` | the entry has an `integratedTime` member (MK-6) |
| `inclusion-promise-present` | the entry has an `inclusionPromise` member (MK-6) |
| `timestamp-count` | there is not exactly one RFC 3161 timestamp (MK-7) |
| `dsse-signature-invalid` | the DSSE signature does not verify with the verification key |
| `inclusion-proof-missing` | the entry has no inclusion proof |
| `inclusion-proof-invalid` | the inclusion proof does not lead to the checkpoint's root hash |
| `inclusion-promise-missing` | an inclusion promise is required and absent |
| `inclusion-promise-invalid` | the inclusion promise (SET) does not verify |
| `checkpoint-origin-mismatch` | the checkpoint origin is not the entry's log |
| `checkpoint-signature-invalid` | the checkpoint has no valid signature from the (entry's) log |
| `tlog-key-details-mismatch` | the logged key details do not match the logged key |
| `tlog-digest-algorithm-mismatch` | the logged digest algorithm does not match the key details |
| `tlog-digest-malformed` | the logged digest has the wrong length for its algorithm |
| `tlog-digest-mismatch` | the logged digest is not the digest of the signed content |
| `tlog-key-mismatch` | the logged public key is not the verification key |
| `tlog-signature-mismatch` | the logged signature is not the bundle's signature |
| `timestamp-signature-invalid` | the timestamp's signature does not verify |
| `timestamp-untrusted-authority` | the timestamp was not signed by a trusted timestamp authority |
| `timestamp-message-mismatch` | the timestamp covers a different signature |

`generate.py` assigns library codes from the error messages and asserts that
each message maps to exactly one code.

## Regenerating and checking

```sh
python3 generate.py            # rewrite vectors/, roots/, keys/, artifacts/, manifest.json
python3 generate.py --check    # fail if a fresh generation differs from the committed files
unshare -rn python3 check-cosign.py /path/to/cosign-v3.1.4   # recorded Cosign outcomes
cargo test -p sigstore-verify --test managed_key_corpus
```

`generate.py` needs Python 3 and the OpenSSL 3.2+ command line. It is
deterministic.

Copies of this directory used elsewhere should be taken from one generation and
kept byte-identical. Compare `manifest.json` and the vector files by digest.
