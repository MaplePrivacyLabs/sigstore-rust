# Vendored sigstore-conformance bundle-verification vectors

`bundle-verify/` is an unmodified copy of `test/assets/bundle-verify` from
[sigstore/sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
at the commit pinned below, the same commit the CI `conformance` job uses
(release v0.0.29). sigstore-conformance is licensed under Apache-2.0, as is this
repository.

```text
repository: https://github.com/sigstore/sigstore-conformance
commit:     21533cde107c734ebc153c3e3a24d75fc9811a36 (v0.0.29)
path:       test/assets/bundle-verify
```

`crates/sigstore-verify/tests/conformance_vectors.rs` runs every vector through
the library API, following the rules in `bundle-verify/README.md`: a directory
whose name ends in `_fail` must be rejected, every other one accepted; `key.pub`
selects managed-key verification, otherwise the `identity` and `issuer` files (or
the suite's defaults) select keyless verification; `trusted_root.json` replaces
the embedded production root. Each vector is verified from the artifact bytes and
from its SHA-256 digest, as the suite's harness does.

To update, replace `bundle-verify/` with the directory from the new commit, update
the commit above and the pin in `.github/workflows/ci.yml` together, and check
`diff -r` against a fresh checkout shows no difference.
