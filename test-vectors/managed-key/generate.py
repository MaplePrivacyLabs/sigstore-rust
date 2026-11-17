#!/usr/bin/env python3
"""Generate the managed-key P-384 / Rekor v2 test vectors and their manifest.

Inputs are the real bundles in `sources/` (produced by the pinned Cosign; see
README.md) and the trusted roots in `sources/`. Every other vector is derived
from them here, deterministically: Python's standard library plus the OpenSSL
command line (Ed25519 signatures, which are deterministic).

    python3 generate.py            write vectors/, roots/, keys/, artifacts/, manifest.json
    python3 generate.py --check    regenerate into a temporary directory and fail if
                                   anything differs from the committed files

The synthetic transparency logs ("test logs") used for re-logged entries are
signed with keys derived from fixed public strings. They exist only in
`roots/test.json` and must never be trusted for anything else.
"""

import base64
import copy
import filecmp
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = os.path.join(HERE, "sources")
OUTPUTS = ("vectors", "roots", "keys", "artifacts", "manifest.json")

# Fixed timestamps for synthetic material (seconds since the epoch).
TEST_LOG_START = "2026-01-01T00:00:00Z"
V1_INTEGRATED_TIME = 1794873600  # 2026-11-17T00:00:00Z

ERR_CHECKPOINT = "TransparencyLog.Checkpoint"


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    return base64.b64decode(text)


def sha256(data):
    return hashlib.sha256(data).digest()


def canonical(obj):
    """Compact JSON with sorted keys, as Rekor canonicalizes entry bodies."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def pae(payload_type, payload):
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


# ---------------------------------------------------------------------------
# Synthetic Ed25519 transparency logs
# ---------------------------------------------------------------------------

ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
# SEC1 ECPrivateKey for P-256 without the optional public key; OpenSSL derives it.
P256_SEC1_PREFIX = bytes.fromhex("30310201010420")
P256_SEC1_SUFFIX = bytes.fromhex("a00a06082a8648ce3d030107")


class TestLog:
    """A synthetic log with a deterministic key.

    Rekor v2 test logs use Ed25519 and are identified by their signed-note key
    ID, SHA-256(origin || "\n" || 0x01 || raw public key). The Rekor v1 test
    log uses ECDSA P-256, as Rekor v1 does, and is identified by SHA-256 of
    its DER public key; its signatures use RFC 6979 deterministic nonces
    (OpenSSL 3.2 or later).
    """

    def __init__(self, workdir, name, host, v1=False):
        self.host = host
        self.base_url = f"https://{host}"
        self.origin = f"{host} - 1" if v1 else host
        self.v1 = v1
        seed = sha256(f"sigstore-rust test vectors: {name} (test-only key, never trust)".encode())
        self.key_path = os.path.join(workdir, f"{name}.pem")
        if v1:
            der_path = os.path.join(workdir, f"{name}.der")
            with open(der_path, "wb") as f:
                f.write(P256_SEC1_PREFIX + seed + P256_SEC1_SUFFIX)
            openssl(["ec", "-inform", "DER", "-in", der_path, "-out", self.key_path])
            self.spki = openssl(["ec", "-in", self.key_path, "-pubout", "-outform", "DER"])
            self.log_id = sha256(self.spki)
            self.key_details = "PKIX_ECDSA_P256_SHA_256"
        else:
            with open(self.key_path, "w") as f:
                f.write("-----BEGIN PRIVATE KEY-----\n" + b64(ED25519_PKCS8_PREFIX + seed)
                        + "\n-----END PRIVATE KEY-----\n")
            self.spki = openssl(["pkey", "-in", self.key_path, "-pubout", "-outform", "DER"])
            self.log_id = sha256(host.encode() + b"\n\x01" + self.spki[-32:])
            self.key_details = "PKIX_ED25519"

    def sign(self, message):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(message)
            path = f.name
        try:
            args = ["pkeyutl", "-sign", "-inkey", self.key_path, "-rawin", "-in", path]
            if self.v1:
                args += ["-digest", "sha256", "-pkeyopt", "nonce-type:1"]
            return openssl(args)
        finally:
            os.unlink(path)

    def signature_line(self, note_body, name=None):
        sig = self.log_id[:4] + self.sign(note_body.encode())
        return f"\u2014 {name or self.host} {b64(sig)}\n"

    def trusted_root_entry(self):
        return {
            "baseUrl": self.base_url,
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": b64(self.spki),
                "keyDetails": self.key_details,
                "validFor": {"start": TEST_LOG_START},
            },
            "logId": {"keyId": b64(self.log_id)},
        }


def openssl(args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


FILLER_LEAF = b"sigstore-rust test vectors: filler leaf 0"


def leaf_hash(data):
    return sha256(b"\x00" + data)


def tree_for(body):
    """A two-leaf tree whose second leaf is `body`: (root, proof hashes)."""
    left = leaf_hash(FILLER_LEAF)
    root = sha256(b"\x01" + left + leaf_hash(body))
    return root, [left]


def note_body(origin, size, root):
    return f"{origin}\n{size}\n{b64(root)}\n"


def relog(entry, body, log, signers=None, origin=None):
    """Put `body` at index 1 of a two-leaf tree in `log` and sign the checkpoint.

    `signers` lists (log, name) pairs whose signature lines are appended, in
    order (default: the log under its own origin). `origin` overrides the
    origin written in the checkpoint body.
    """
    entry = copy.deepcopy(entry)
    root, hashes = tree_for(body)
    text = note_body(origin or log.origin, 2, root)
    lines = "".join(
        signer.signature_line(text, name) for signer, name in (signers or [(log, log.host)])
    )
    entry["logIndex"] = "1"
    entry["logId"] = {"keyId": b64(log.log_id)}
    entry["canonicalizedBody"] = b64(body)
    entry["inclusionProof"] = {
        "logIndex": "1",
        "rootHash": b64(root),
        "treeSize": "2",
        "hashes": [b64(h) for h in hashes],
        "checkpoint": {"envelope": text + "\n" + lines},
    }
    return entry


# ---------------------------------------------------------------------------
# Vector bookkeeping
# ---------------------------------------------------------------------------


def accept():
    return {"result": "accept"}


def reject(error, message):
    return {"result": "reject", "error": error, "message": message}


def profile_reject(clause, reason):
    return {"result": "reject", "clause": clause, "reason": reason}


class Corpus:
    def __init__(self, out):
        self.out = out
        self.vectors = []
        self.ids = set()

    def add(self, vid, bundle, *, description, category, source, parent, mutation, key, artifact,
            root, library, binding=None, profile=None, cosign, raw=None):
        assert vid not in self.ids, vid
        assert category in ("positive", "standard-negative", "binding-negative", "profile-negative")
        self.ids.add(vid)
        if parent is not None:
            assert parent in self.ids, f"{vid}: parent {parent} must be defined first"
        path = f"vectors/{vid}/bundle.sigstore.json"
        os.makedirs(os.path.join(self.out, "vectors", vid), exist_ok=True)
        with open(os.path.join(self.out, path), "w", encoding="utf-8") as f:
            f.write(raw if raw is not None else json.dumps(bundle, indent=2) + "\n")
        binding = binding or library
        if profile is None:
            profile = accept() if library["result"] == "accept" and binding["result"] == "accept" else None
        assert profile is not None, f"{vid}: profile expectation required"
        self.vectors.append({
            "id": vid,
            "description": description,
            "category": category,
            "bundle": path,
            "trusted_root": f"roots/{root}.json",
            "key": f"keys/{key}.pub",
            "artifact": f"artifacts/{artifact}.bin",
            "source": source,
            "parent": parent,
            "mutation": mutation,
            "expected": {
                "library": library,
                "library_checkpoint_log_binding": binding,
                "profile": profile,
            },
            "cosign": cosign,
        })


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate(out):
    work = tempfile.mkdtemp()
    try:
        _generate(out, work)
    finally:
        shutil.rmtree(work)


def _generate(out, work):
    for name in OUTPUTS:
        path = os.path.join(out, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.exists(path):
            os.unlink(path)
    for d in ("roots", "keys", "artifacts"):
        os.makedirs(os.path.join(out, d))

    runs = {}
    for run in ("r1", "r2", "r3"):
        src = os.path.join(SOURCES, run)
        runs[run] = {
            "bundle": load_json(os.path.join(src, "bundle.sigstore.json")),
            "provenance": load_json(os.path.join(src, "provenance.json")),
        }
        shutil.copyfile(os.path.join(src, "key.pub"), os.path.join(out, "keys", f"{run}.pub"))
        shutil.copyfile(os.path.join(src, "artifact.bin"), os.path.join(out, "artifacts", f"{run}.bin"))

    # Trusted roots.
    production = load_json(os.path.join(SOURCES, "trusted_root.production.json"))
    staging = load_json(os.path.join(SOURCES, "trusted_root.staging.json"))
    log_a = TestLog(work, "test-log-a", "test-log-a.rekor.example.com")
    log_b = TestLog(work, "test-log-b", "test-log-b.rekor.example.com")
    log_v1 = TestLog(work, "test-log-v1", "test-log-v1.rekor.example.com", v1=True)
    test_root = {
        "mediaType": production["mediaType"],
        "tlogs": [log_a.trusted_root_entry(), log_b.trusted_root_entry(), log_v1.trusted_root_entry()],
        "certificateAuthorities": [],
        "ctlogs": [],
        "timestampAuthorities": copy.deepcopy(production["timestampAuthorities"]),
    }
    untrusted_tsa = copy.deepcopy(production)
    untrusted_tsa["timestampAuthorities"] = copy.deepcopy(staging["timestampAuthorities"])
    for name, root in (("production", production), ("test", test_root),
                       ("production-staging-tsa", untrusted_tsa)):
        with open(os.path.join(out, "roots", f"{name}.json"), "w", encoding="utf-8") as f:
            f.write(json.dumps(root, indent=2) + "\n")

    c = Corpus(out)
    r1, r2, r3 = (runs[r]["bundle"] for r in ("r1", "r2", "r3"))

    def real(run):
        p = runs[run]["provenance"]
        return {"kind": "real", "detail": p["detail"]}

    derived = {"kind": "derived", "detail": "single documented mutation of the parent, made by generate.py"}
    relogged = {"kind": "derived", "detail": "parent's log entry re-logged in a synthetic test log (roots/test.json) by generate.py"}

    def entry(b):
        return b["verificationMaterial"]["tlogEntries"][0]

    def body_of(b):
        return json.loads(unb64(entry(b)["canonicalizedBody"]))

    # ---- Real positives -------------------------------------------------
    c.add("p384-rekor2-dsse-tsa", r1, description="P-384 managed key, DSSE in-toto statement, Rekor v2 hashedrekord 0.0.2 entry, RFC 3161 timestamp",
          category="positive", source=real("r1"), parent=None, mutation=None, key="r1", artifact="r1",
          root="production", library=accept(), cosign="accept")
    c.add("p384-rekor2-dsse-tsa-second-key", r2, description="Second P-384 positive: different key and statement",
          category="positive", source=real("r2"), parent=None, mutation=None, key="r2", artifact="r2",
          root="production", library=accept(), cosign="accept")
    c.add("p256-rekor2-dsse-tsa", r3, description="P-256 managed key, DSSE, Rekor v2, RFC 3161 timestamp",
          category="positive", source=real("r3"), parent=None, mutation=None, key="r3", artifact="r3",
          root="production", library=accept(), cosign="accept")

    # Checkpoint witness lines are neither verified nor required.
    b = copy.deepcopy(r1)
    cp = entry(b)["inclusionProof"]["checkpoint"]["envelope"]
    head, sigs = cp.split("\n\n", 1)
    lines = [l for l in sigs.split("\n") if l]
    log_line = [l for l in lines if l.split(" ")[1] == head.split("\n")[0]]
    assert len(log_line) == 1 and len(lines) > 1, "expected one log signature plus witness lines"
    entry(b)["inclusionProof"]["checkpoint"]["envelope"] = head + "\n\n" + log_line[0] + "\n"
    c.add("p384-checkpoint-witnesses-removed", b, description="Checkpoint keeps only the log's own signature line",
          category="positive", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="remove every witness cosignature line from the checkpoint", key="r1", artifact="r1",
          root="production", library=accept(), cosign="accept")
    b = copy.deepcopy(r1)
    others = [l for l in lines if l not in log_line]
    entry(b)["inclusionProof"]["checkpoint"]["envelope"] = head + "\n\n" + "\n".join(others + log_line) + "\n"
    c.add("p384-checkpoint-log-signature-last", b, description="Log signature line after the witness lines",
          category="positive", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="move the log's signature line after the witness cosignature lines", key="r1", artifact="r1",
          root="production", library=accept(), cosign="accept")

    # ---- Standard negatives on the real P-384 bundle ----------------------
    b = copy.deepcopy(r1)
    statement = json.loads(unb64(b["dsseEnvelope"]["payload"]))
    pcr0 = statement["predicate"]["measurements"]["PCR0"]
    statement["predicate"]["measurements"]["PCR0"] = ("0" if pcr0[0] != "0" else "1") + pcr0[1:]
    b["dsseEnvelope"]["payload"] = b64(json.dumps(statement, indent=2).encode() + b"\n")
    c.add("p384-payload-pcr-tampered", b, description="Signed statement altered: one PCR0 digit changed",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="change the first hex digit of predicate.measurements.PCR0 in the DSSE payload",
          key="r1", artifact="r1", root="production",
          library=reject("SignatureInvalid", "DSSE signature verification failed"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    b["dsseEnvelope"]["signatures"][0]["sig"] = r2["dsseEnvelope"]["signatures"][0]["sig"]
    b["verificationMaterial"]["timestampVerificationData"] = copy.deepcopy(r2["verificationMaterial"]["timestampVerificationData"])
    c.add("p384-signature-substituted", b, description="DSSE signature replaced by another key's valid signature over another statement, with that signature's own timestamp",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="replace the DSSE signature and the RFC 3161 timestamp with those of p384-rekor2-dsse-tsa-second-key",
          key="r1", artifact="r1", root="production",
          library=reject("SignatureInvalid", "DSSE signature verification failed"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    b["verificationMaterial"]["publicKey"]["hint"] = r2["verificationMaterial"]["publicKey"]["hint"]
    c.add("p384-verified-with-other-key", b, description="Bundle checked against a different approved key (e.g. another environment's), with that key's hint",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="set publicKey.hint to the second key's hint and verify with the second key",
          key="r2", artifact="r1", root="production",
          library=reject("SignatureInvalid", "DSSE signature verification failed"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    proof = entry(b)["inclusionProof"]
    h = bytearray(unb64(proof["hashes"][0]))
    h[0] ^= 1
    proof["hashes"][0] = b64(bytes(h))
    c.add("p384-inclusion-proof-corrupted", b, description="One inclusion proof hash altered",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="flip the low bit of the first byte of inclusionProof.hashes[0]",
          key="r1", artifact="r1", root="production",
          library=reject("TransparencyLog.InclusionProof", "inclusion proof verification failed"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    del entry(b)["inclusionProof"]
    c.add("p384-inclusion-proof-removed", b, description="The only log entry has no inclusion proof",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="remove inclusionProof from the log entry",
          key="r1", artifact="r1", root="production",
          library=reject("Bundle", "bundle must have an inclusion proof"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    cp = entry(b)["inclusionProof"]["checkpoint"]["envelope"]
    head, sigs = cp.split("\n\n", 1)
    origin = head.split("\n")[0]
    new_lines = []
    for l in sigs.split("\n"):
        if l and l.split(" ")[1] == origin:
            raw = bytearray(unb64(l.split(" ")[2]))
            raw[-1] ^= 1
            l = f"— {origin} {b64(bytes(raw))}"
        new_lines.append(l)
    entry(b)["inclusionProof"]["checkpoint"]["envelope"] = head + "\n\n" + "\n".join(new_lines)
    c.add("p384-checkpoint-signature-corrupted", b, description="The log's checkpoint signature altered",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="flip the low bit of the last byte of the log's checkpoint signature",
          key="r1", artifact="r1", root="production",
          library=reject(ERR_CHECKPOINT, "No valid Rekor signature found on checkpoint"),
          binding=reject(ERR_CHECKPOINT, "checkpoint has no valid signature from the entry's log"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    cp = entry(b)["inclusionProof"]["checkpoint"]["envelope"]
    head, sigs = cp.split("\n\n", 1)
    origin = head.split("\n")[0]
    kept = [l for l in sigs.split("\n") if l and l.split(" ")[1] != origin]
    entry(b)["inclusionProof"]["checkpoint"]["envelope"] = head + "\n\n" + "\n".join(kept) + "\n"
    c.add("p384-checkpoint-log-signature-removed", b, description="Checkpoint carries only witness cosignatures",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="remove the log's own signature line from the checkpoint, keeping the witness lines",
          key="r1", artifact="r1", root="production",
          library=reject(ERR_CHECKPOINT, "No matching Rekor key found for checkpoint signature"),
          binding=reject(ERR_CHECKPOINT, "checkpoint has no valid signature from the entry's log"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    cp = entry(b)["inclusionProof"]["checkpoint"]["envelope"]
    cp_lines = cp.split("\n")
    root_bytes = bytearray(unb64(cp_lines[2]))
    root_bytes[0] ^= 1
    cp_lines[2] = b64(bytes(root_bytes))
    entry(b)["inclusionProof"]["checkpoint"]["envelope"] = "\n".join(cp_lines)
    c.add("p384-checkpoint-root-hash-altered", b, description="Checkpoint root hash altered (signature no longer covers it)",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="flip the low bit of the first byte of the checkpoint root hash",
          key="r1", artifact="r1", root="production",
          library=reject("TransparencyLog.InclusionProof", "inclusion proof verification failed"),
          profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    b = copy.deepcopy(r1)
    v1_production = [t for t in production["tlogs"] if t["baseUrl"] == "https://rekor.sigstore.dev"]
    assert len(v1_production) == 1
    entry(b)["logId"] = {"keyId": v1_production[0]["logId"]["keyId"]}
    c.add("p384-entry-names-another-trusted-log", b, description="Entry's log ID points at another log in the trusted root (Rekor v1 production); the checkpoint is still the real one from log2025-1",
          category="binding-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="set logId.keyId to the trusted root's rekor.sigstore.dev log ID",
          key="r1", artifact="r1", root="production",
          library=accept(),
          binding=reject(ERR_CHECKPOINT, "does not match the entry's log \"rekor.sigstore.dev\""),
          profile=profile_reject("MK-8", "checkpoint is not from the entry's log"), cosign="reject")

    b = copy.deepcopy(r1)
    tok = bytearray(unb64(b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"]))
    tok[-1] ^= 1
    b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"] = b64(bytes(tok))
    c.add("p384-timestamp-tampered", b, description="RFC 3161 timestamp token altered",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="flip the low bit of the last byte of the timestamp token (its signature)",
          key="r1", artifact="r1", root="production",
          library=reject("Timestamp.Invalid", "Failed to verify timestamp signature: Verification error: ECDSA_P384_SHA256 signature invalid"),
          profile=profile_reject("MK-7", "the timestamp does not verify"), cosign="reject")

    c.add("p384-timestamp-untrusted-authority", r1, description="Unmodified bundle checked against a trusted root whose timestamp authority is a different one (Sigstore staging)",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="trusted root only: replace timestampAuthorities with the staging root's",
          key="r1", artifact="r1", root="production-staging-tsa",
          library=reject("Timestamp.Invalid", "CMS signer does not match any trusted TSA certificate"),
          profile=profile_reject("MK-7", "the timestamp does not verify"), cosign="reject")

    b = copy.deepcopy(r1)
    b["verificationMaterial"]["timestampVerificationData"] = copy.deepcopy(r2["verificationMaterial"]["timestampVerificationData"])
    c.add("p384-timestamp-from-other-signature", b, description="A valid timestamp from the same authority, but over a different signature",
          category="standard-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="replace the RFC 3161 timestamp with p384-rekor2-dsse-tsa-second-key's",
          key="r1", artifact="r1", root="production",
          library=reject("Timestamp.Invalid", "Timestamp message hash mismatch"),
          profile=profile_reject("MK-7", "the timestamp does not verify"), cosign="reject")

    # ---- Profile-only negatives -----------------------------------------
    b = copy.deepcopy(r1)
    b["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": []}
    c.add("p384-timestamp-removed", b, description="No RFC 3161 timestamp",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="empty timestampVerificationData.rfc3161Timestamps",
          key="r1", artifact="r1", root="production", library=accept(),
          profile=profile_reject("MK-7", "exactly one timestamp is required"), cosign="reject")

    b = copy.deepcopy(r1)
    ts = b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
    ts.append(copy.deepcopy(ts[0]))
    c.add("p384-timestamp-duplicated", b, description="The same timestamp twice",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="append a second copy of the RFC 3161 timestamp",
          key="r1", artifact="r1", root="production", library=accept(),
          profile=profile_reject("MK-7", "exactly one timestamp is required"), cosign=None)

    b = copy.deepcopy(r1)
    b["verificationMaterial"]["tlogEntries"].append(copy.deepcopy(entry(r1)))
    c.add("p384-tlog-entry-duplicated", b, description="The same log entry twice",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="append a second copy of the log entry",
          key="r1", artifact="r1", root="production", library=accept(),
          profile=profile_reject("MK-5", "exactly one log entry is required"), cosign=None)

    b = copy.deepcopy(r1)
    extra = copy.deepcopy(entry(r1))
    del extra["inclusionProof"]
    b["verificationMaterial"]["tlogEntries"].append(extra)
    c.add("p384-extra-entry-without-proof", b, description="A second, proofless copy of the log entry (the library requires a proof on at least one entry, not on each)",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="append a copy of the log entry without its inclusion proof",
          key="r1", artifact="r1", root="production",
          library=accept(),
          profile=profile_reject("MK-5", "exactly one log entry is required"), cosign=None)

    b = copy.deepcopy(r1)
    entry(b)["integratedTime"] = str(V1_INTEGRATED_TIME)
    c.add("p384-rekor2-integrated-time-added", b, description="Rekor v2 entry carrying an (unauthenticated) integratedTime",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation=f"add integratedTime {V1_INTEGRATED_TIME} to the log entry",
          key="r1", artifact="r1", root="production", library=accept(),
          profile=profile_reject("MK-6", "no integrated time is allowed"), cosign=None)

    # The field must be absent, whatever its value.
    for suffix, value, shown, library in (
            ("zero-string", "0", '"0"', accept()),
            ("zero-number", 0, "0", accept()),
            ("null", None, "null", reject("Parse", "invalid type: null, expected a protobuf int64"))):
        b = copy.deepcopy(r1)
        entry(b)["integratedTime"] = value
        c.add(f"p384-rekor2-integrated-time-{suffix}", b,
              description=f"Rekor v2 entry carrying integratedTime {shown}: present, though zero or null",
              category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
              mutation=f"add integratedTime {shown} to the log entry",
              key="r1", artifact="r1", root="production", library=library,
              profile=profile_reject("MK-6", "no integrated time field is allowed"), cosign=None)

    b = copy.deepcopy(r1)
    entry(b)["inclusionPromise"] = {"signedEntryTimestamp": b64(b"\x30\x00")}
    c.add("p384-rekor2-inclusion-promise-added", b, description="Rekor v2 entry carrying an inclusion promise (SET)",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="add an inclusionPromise with an empty signature to the log entry",
          key="r1", artifact="r1", root="production",
          library=reject("TransparencyLog.InclusionPromise", "SET verification failed"),
          profile=profile_reject("MK-6", "no inclusion promise is allowed"), cosign=None)

    b = copy.deepcopy(r1)
    b["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.2"
    c.add("p384-media-type-v0.2", b, description="Media type relabelled as bundle v0.2",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="set mediaType to the v0.2 media type",
          key="r1", artifact="r1", root="production", library=accept(),
          profile=profile_reject("MK-1", "only the v0.3 media type is accepted"), cosign=None)

    b = copy.deepcopy(r1)
    del b["mediaType"]
    c.add("p384-media-type-missing", b, description="No media type",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="remove mediaType", key="r1", artifact="r1", root="production",
          library=reject("Bundle", "bundles must have an inclusion promise"),
          profile=profile_reject("MK-1", "only the v0.3 media type is accepted"), cosign=None)

    text = json.dumps(r1, indent=2) + "\n"
    signed_env = '  "dsseEnvelope": ' + json.dumps(r1["dsseEnvelope"], indent=2).replace("\n", "\n  ")
    assert signed_env in text
    dup = text.replace(signed_env, signed_env + ',\n  "dsseEnvelope": ' + json.dumps(r2["dsseEnvelope"]), 1)
    assert dup != text
    c.add("p384-duplicate-dsse-envelope-key", None, raw=dup, description="Bundle JSON with the dsseEnvelope member twice: the signed envelope first, another key's envelope and statement second. This library keeps the first; a parser that keeps the last would read the other statement",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="insert a second dsseEnvelope member (the second key's envelope) after the original one",
          key="r1", artifact="r1", root="production",
          library=accept(),
          profile=profile_reject("MK-4", "duplicate JSON keys are rejected"), cosign=None)

    b = copy.deepcopy(r1)
    b["messageSignature"] = {"messageDigest": {"algorithm": "SHA2_256", "digest": b64(sha256(b""))},
                             "signature": r1["dsseEnvelope"]["signatures"][0]["sig"]}
    c.add("p384-conflicting-content", b, description="Both a DSSE envelope and a message signature",
          category="profile-negative", source=derived, parent="p384-rekor2-dsse-tsa",
          mutation="add a messageSignature member beside dsseEnvelope",
          key="r1", artifact="r1", root="production",
          library=accept(),
          profile=profile_reject("MK-4", "conflicting content variants are rejected"), cosign=None)

    # ---- Re-logged parents and entry-body negatives ----------------------
    def relogged_vector(vid, parent_bundle, parent_id, key, artifact, description):
        bb = copy.deepcopy(parent_bundle)
        body = unb64(entry(bb)["canonicalizedBody"])
        bb["verificationMaterial"]["tlogEntries"][0] = relog(entry(bb), body, log_a)
        c.add(vid, bb, description=description, category="positive", source=relogged, parent=parent_id,
              mutation="re-log the unchanged entry body at index 1 of a two-leaf tree in test log A",
              key=key, artifact=artifact, root="test", library=accept(), cosign="accept")
        return bb

    p384_relogged = relogged_vector("p384-relogged", r1, "p384-rekor2-dsse-tsa", "r1", "r1",
                                    "The real P-384 entry, unchanged, in synthetic test log A")
    p256_relogged = relogged_vector("p256-relogged", r3, "p256-rekor2-dsse-tsa", "r3", "r3",
                                    "The real P-256 entry, unchanged, in synthetic test log A")

    def body_vector(vid, parent_bundle, parent_id, key, artifact, change, description, mutation, library):
        bb = copy.deepcopy(parent_bundle)
        body = body_of(bb)
        change(body["spec"]["hashedRekordV002"])
        bb["verificationMaterial"]["tlogEntries"][0] = relog(entry(bb), canonical(body), log_a)
        c.add(vid, bb, description=description, category="standard-negative", source=derived,
              parent=parent_id, mutation=mutation + "; re-log the changed body in test log A",
              key=key, artifact=artifact, root="test", library=library,
              profile=profile_reject("MK-8", "library verification fails"), cosign="reject")

    env1 = r1["dsseEnvelope"]
    pae1 = pae(env1["payloadType"], unb64(env1["payload"]))
    env3 = r3["dsseEnvelope"]
    pae3 = pae(env3["payloadType"], unb64(env3["payload"]))

    def set_(path, value):
        def change(spec):
            node = spec
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = value
        return change

    def combine(*changes):
        def change(spec):
            for ch in changes:
                ch(spec)
        return change

    body_vector("p384-key-details-p256", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["signature", "verifier", "keyDetails"], "PKIX_ECDSA_P256_SHA_256"),
                "P-384 key logged with P-256 key details",
                "set keyDetails to PKIX_ECDSA_P256_SHA_256",
                reject("TransparencyLog.EntryMismatch", "key details PKIX_ECDSA_P256_SHA_256 do not match its EcdsaP384 key"))
    body_vector("p256-key-labelled-p384", p256_relogged, "p256-relogged", "r3", "r3",
                combine(set_(["signature", "verifier", "keyDetails"], "PKIX_ECDSA_P384_SHA_384"),
                        set_(["data", "algorithm"], "SHA2_384"),
                        set_(["data", "digest"], b64(hashlib.sha384(pae3).digest()))),
                "Wrong curve: a P-256 key logged as P-384, with an otherwise consistent SHA-384 digest of the PAE",
                "set keyDetails to PKIX_ECDSA_P384_SHA_384, algorithm to SHA2_384 and digest to SHA-384(PAE)",
                reject("TransparencyLog.EntryMismatch", "key details PKIX_ECDSA_P384_SHA_384 do not match its EcdsaP256 key"))
    body_vector("p384-digest-algorithm-sha256", p384_relogged, "p384-relogged", "r1", "r1",
                combine(set_(["data", "algorithm"], "SHA2_256"),
                        set_(["data", "digest"], b64(sha256(pae1)))),
                "P-384 entry carrying SHA-256 of the PAE",
                "set algorithm to SHA2_256 and digest to SHA-256(PAE)",
                reject("TransparencyLog.EntryMismatch", "digest algorithm SHA2_256 does not match key details PKIX_ECDSA_P384_SHA_384"))
    body_vector("p384-digest-truncated", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["data", "digest"], b64(hashlib.sha384(pae1).digest()[:32])),
                "SHA2_384 digest truncated to 32 bytes",
                "truncate the logged digest to its first 32 bytes",
                reject("TransparencyLog.MalformedEntry", "SHA2_384 digest is 32 bytes, expected 48"))
    flipped = bytearray(hashlib.sha384(pae1).digest())
    flipped[0] ^= 1
    body_vector("p384-digest-altered", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["data", "digest"], b64(bytes(flipped))),
                "Logged digest altered",
                "flip the low bit of the first byte of the logged digest",
                reject("ArtifactMismatch", "artifact hash mismatch for hashedrekord entry"))
    body_vector("p384-digest-of-payload", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["data", "digest"], b64(hashlib.sha384(unb64(env1["payload"])).digest())),
                "SHA-384 of the payload alone instead of the PAE",
                "set the logged digest to SHA-384(payload)",
                reject("ArtifactMismatch", "artifact hash mismatch for hashedrekord entry"))
    r2_key = body_of(r2)["spec"]["hashedRekordV002"]["signature"]["verifier"]["publicKey"]["rawBytes"]
    body_vector("p384-logged-key-substituted", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["signature", "verifier", "publicKey", "rawBytes"], r2_key),
                "Entry logs a different P-384 key than the one verifying the signature",
                "set the logged public key to the second key",
                reject("TransparencyLog.EntryMismatch", "public key in Rekor entry does not match managed key"))
    body_vector("p384-logged-signature-substituted", p384_relogged, "p384-relogged", "r1", "r1",
                set_(["signature", "content"], r2["dsseEnvelope"]["signatures"][0]["sig"]),
                "Entry logs a different signature than the bundle's",
                "set the logged signature to the second bundle's signature",
                reject("TransparencyLog.EntryMismatch", "DSSE signature in bundle does not match signature in Rekor entry"))

    # ---- Checkpoint-to-log binding on the test logs ---------------------
    bb = copy.deepcopy(p384_relogged)
    body = unb64(entry(bb)["canonicalizedBody"])
    bb["verificationMaterial"]["tlogEntries"][0] = relog(entry(bb), body, log_a, signers=[(log_b, log_a.host)])
    c.add("p384-checkpoint-signed-by-other-trusted-log", bb,
          description="Entry names test log A; its checkpoint (origin A) is signed only by test log B, which is also trusted",
          category="binding-negative", source=derived, parent="p384-relogged",
          mutation="replace the checkpoint signature with one by test log B's key (B's key hint)",
          key="r1", artifact="r1", root="test", library=accept(),
          binding=reject(ERR_CHECKPOINT, "checkpoint has no valid signature from the entry's log"),
          profile=profile_reject("MK-8", "checkpoint is not from the entry's log"), cosign="reject")
    bb = copy.deepcopy(p384_relogged)
    bb["verificationMaterial"]["tlogEntries"][0] = relog(entry(bb), body, log_a, origin=log_b.origin)
    c.add("p384-checkpoint-origin-other-log", bb,
          description="Checkpoint signed by test log A's key but with test log B's origin",
          category="binding-negative", source=derived, parent="p384-relogged",
          mutation="write test log B's origin into the checkpoint body (signed by A)",
          key="r1", artifact="r1", root="test", library=accept(),
          binding=reject(ERR_CHECKPOINT, "checkpoint origin \"test-log-b.rekor.example.com\" does not match the entry's log \"test-log-a.rekor.example.com\""),
          profile=profile_reject("MK-8", "checkpoint is not from the entry's log"), cosign="reject")

    # ---- Synthetic Rekor v1 entry for the P-384 regression --------------
    bb = copy.deepcopy(r1)
    key_pem = open(os.path.join(SOURCES, "r1", "key.pub"), "rb").read()
    env = bb["dsseEnvelope"]
    envelope_json = canonical({"payload": env["payload"], "payloadType": env["payloadType"],
                               "signatures": [{"keyid": "", "sig": env["signatures"][0]["sig"]}]})
    v1_body = canonical({
        "apiVersion": "0.0.1", "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": sha256(envelope_json).hex()},
            "payloadHash": {"algorithm": "sha256", "value": sha256(unb64(env["payload"])).hex()},
            "signatures": [{"signature": env["signatures"][0]["sig"], "verifier": b64(key_pem)}],
        },
    })
    v1_entry = relog({}, v1_body, log_v1, signers=[(log_v1, log_v1.host)])
    set_payload = canonical({"body": b64(v1_body), "integratedTime": V1_INTEGRATED_TIME,
                             "logID": log_v1.log_id.hex(), "logIndex": 1})
    v1_entry = {
        "logIndex": "1",
        "logId": v1_entry["logId"],
        "kindVersion": {"kind": "dsse", "version": "0.0.1"},
        "integratedTime": str(V1_INTEGRATED_TIME),
        "inclusionPromise": {"signedEntryTimestamp": b64(log_v1.sign(set_payload))},
        "inclusionProof": v1_entry["inclusionProof"],
        "canonicalizedBody": v1_entry["canonicalizedBody"],
    }
    bb["verificationMaterial"]["tlogEntries"] = [v1_entry]
    c.add("p384-rekor1-dsse-synthetic", bb,
          description="The real P-384 DSSE signature and timestamp with a synthetic Rekor v1 dsse 0.0.1 entry (inclusion proof, checkpoint and SET from test log v1)",
          category="profile-negative", source={"kind": "synthetic", "detail": "Rekor v1 entry built by generate.py; no public Rekor v1 run was made"},
          parent="p384-rekor2-dsse-tsa",
          mutation="replace the Rekor v2 entry with a synthetic Rekor v1 dsse 0.0.1 entry for the same envelope",
          key="r1", artifact="r1", root="test", library=accept(),
          profile=profile_reject("MK-5", "Rekor v1 entries are rejected"), cosign="accept")

    # ---- Same binding behaviour on the real P-256 bundle ----------------
    b = copy.deepcopy(r3)
    entry(b)["logId"] = {"keyId": v1_production[0]["logId"]["keyId"]}
    c.add("p256-entry-names-another-trusted-log", b, description="P-256 counterpart of p384-entry-names-another-trusted-log (also verifiable by releases without P-384 support)",
          category="binding-negative", source=derived, parent="p256-rekor2-dsse-tsa",
          mutation="set logId.keyId to the trusted root's rekor.sigstore.dev log ID",
          key="r3", artifact="r3", root="production", library=accept(),
          binding=reject(ERR_CHECKPOINT, "does not match the entry's log \"rekor.sigstore.dev\""),
          profile=profile_reject("MK-8", "checkpoint is not from the entry's log"), cosign="reject")

    manifest = {
        "description": "Managed-key DSSE / Rekor v2 / RFC 3161 test vectors. See README.md and PROFILE.md.",
        "generator": "generate.py",
        "sources": {run: runs[run]["provenance"] for run in runs},
        "test_logs": {log.host: {"origin": log.origin, "log_id": b64(log.log_id),
                                 "rekor_api": 1 if log.v1 else 2} for log in (log_a, log_b, log_v1)},
        "vectors": c.vectors,
    }
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(c.vectors)} vectors")


def check():
    tmp = tempfile.mkdtemp()
    try:
        generate(tmp)
        diffs = []
        for name in OUTPUTS:
            a, b = os.path.join(HERE, name), os.path.join(tmp, name)
            if os.path.isdir(b):
                cmp = filecmp.dircmp(a, b)
                stack = [cmp]
                while stack:
                    d = stack.pop()
                    diffs += [os.path.join(d.left, x) for x in d.left_only + d.right_only + d.diff_files + d.funny_files]
                    for sub in d.subdirs.values():
                        stack.append(sub)
            elif not os.path.exists(a) or not filecmp.cmp(a, b, shallow=False):
                diffs.append(a)
        if diffs:
            print("generated files differ from the committed ones:\n  " + "\n  ".join(diffs), file=sys.stderr)
            sys.exit(1)
        print("committed vectors match a fresh generation")
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif sys.argv[1:] == []:
        generate(HERE)
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
