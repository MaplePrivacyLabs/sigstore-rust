#!/usr/bin/env python3
"""Check the manifest's recorded Cosign outcomes with a Cosign binary.

For every vector whose `cosign` field is "accept" or "reject", runs

    cosign verify-blob-attestation --bundle B --key K --trusted-root R \
        --use-signed-timestamps --type <statement predicateType> ARTIFACT

and compares the exit status with the recorded outcome. Vectors with
`"cosign": null` are profile-only cases Cosign is not expected to judge and are
skipped. Verification uses only the given files; run it without network access
(for example under `unshare -rn`) to be sure.

usage: check-cosign.py COSIGN
"""
import base64
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def predicate_type(bundle_path):
    try:
        with open(bundle_path, encoding="utf-8") as f:
            payload = base64.b64decode(json.load(f)["dsseEnvelope"]["payload"])
        return json.loads(payload)["predicateType"]
    except (ValueError, KeyError):
        return "unknown"


def main(cosign):
    with open(os.path.join(HERE, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    mismatches = 0
    for v in manifest["vectors"]:
        want = v["cosign"]
        if want is None:
            continue
        path = lambda field: os.path.join(HERE, v[field])  # noqa: E731
        r = subprocess.run(
            [cosign, "verify-blob-attestation", "--bundle", path("bundle"), "--key", path("key"),
             "--trusted-root", path("trusted_root"), "--use-signed-timestamps",
             "--type", predicate_type(path("bundle")), path("artifact")],
            capture_output=True, text=True)
        got = "accept" if r.returncode == 0 else "reject"
        detail = (r.stderr.strip().splitlines() or [""])[-1][:160]
        status = "ok" if got == want else "MISMATCH"
        mismatches += got != want
        print(f"{status:8} {v['id']}: recorded {want}, cosign {got}  {detail}")
    print(f"{mismatches} mismatches")
    return 1 if mismatches else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
