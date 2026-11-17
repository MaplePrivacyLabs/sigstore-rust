//! Managed-key DSSE / Rekor v2 / RFC 3161 corpus in `test-vectors/managed-key`.
//!
//! Every vector in `manifest.json` is verified with `PublicKeyVerificationPolicy`
//! (transparency log checks on), with and without checkpoint-to-log binding.
//! The outcome must match the manifest: an accepted vector must verify, and a
//! rejected one must fail with the recorded error category and message. A
//! vector failing for any other reason is a test failure.
//!
//! Vectors also carry the expected outcome under the strict profile described in
//! `test-vectors/managed-key/PROFILE.md`. The [`profile`] module below is a
//! test-only reference implementation of that profile, so that profile-only
//! negatives (most of which this library accepts) are also checked to fail for
//! the clause they cite. It is not part of the library.

use serde_json::Value;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, DerPublicKey};
use sigstore_verify::{verify, PublicKeyVerificationPolicy};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/managed-key")
}

struct Vector {
    id: String,
    raw: String,
    key: DerPublicKey,
    artifact: Vec<u8>,
    root: TrustedRoot,
}

fn load(spec: &Value) -> Vector {
    let dir = corpus_dir();
    let path = |field: &str| dir.join(spec[field].as_str().unwrap());
    Vector {
        id: spec["id"].as_str().unwrap().to_string(),
        raw: fs::read_to_string(path("bundle")).unwrap(),
        key: DerPublicKey::from_pem(&fs::read_to_string(path("key")).unwrap()).unwrap(),
        artifact: fs::read(path("artifact")).unwrap(),
        root: TrustedRoot::from_file(path("trusted_root")).unwrap(),
    }
}

/// The library outcome: `Ok` or (error category, message).
type Outcome = Result<(), (String, String)>;

fn verify_library(v: &Vector, bind_checkpoint: bool) -> Outcome {
    let bundle = Bundle::from_json(&v.raw).map_err(|e| ("Parse".to_string(), e.to_string()))?;
    let mut policy = PublicKeyVerificationPolicy::new(v.key.clone());
    if bind_checkpoint {
        policy = policy.require_checkpoint_log_binding();
    }
    verify(
        Artifact::from(v.artifact.as_slice()),
        &bundle,
        &policy,
        &v.root,
    )
    .map(|_| ())
    .map_err(|e| (category(&e), e.to_string()))
}

/// `Variant` or `Variant.Inner` for the nested error enums, from their Debug
/// form, e.g. `TransparencyLog.Checkpoint`.
fn category(error: &sigstore_verify::Error) -> String {
    let debug = format!("{error:?}");
    let name = |s: &str| {
        s.split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap()
            .to_string()
    };
    let outer = name(&debug);
    match outer.as_str() {
        "TransparencyLog" | "Timestamp" | "Certificate" => {
            format!("{outer}.{}", name(&debug[outer.len() + 1..]))
        }
        _ => outer,
    }
}

fn check(expected: &Value, actual: &Outcome) -> Result<(), String> {
    match (expected["result"].as_str().unwrap(), actual) {
        ("accept", Ok(())) => Ok(()),
        ("reject", Err((category, message))) => {
            let want_category = expected["error"].as_str().unwrap();
            let want_message = expected["message"].as_str().unwrap();
            if category == want_category && message.contains(want_message) {
                Ok(())
            } else {
                Err(format!(
                    "expected {want_category} containing {want_message:?}, got {category}: {message}"
                ))
            }
        }
        (want, got) => Err(format!("expected {want}, got {got:?}")),
    }
}

#[test]
fn managed_key_corpus() {
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(corpus_dir().join("manifest.json")).unwrap())
            .unwrap();
    let specs = manifest["vectors"].as_array().unwrap();
    assert!(specs.len() >= 40, "corpus unexpectedly small");
    let by_id: HashMap<&str, &Value> = specs
        .iter()
        .map(|s| (s["id"].as_str().unwrap(), s))
        .collect();

    let mut failures = Vec::new();
    for spec in specs {
        let v = load(spec);
        let expected = &spec["expected"];

        // Each negative is a mutation of a parent that is itself accepted.
        if let Some(parent) = spec["parent"].as_str() {
            let parent = by_id
                .get(parent)
                .unwrap_or_else(|| panic!("{}: unknown parent {parent}", v.id));
            for mode in ["library", "library_checkpoint_log_binding"] {
                if parent["expected"][mode]["result"] != "accept" {
                    failures.push(format!(
                        "{}: parent {} is not accepted ({mode})",
                        v.id, parent["id"]
                    ));
                }
            }
        }

        for (mode, bind) in [("library", false), ("library_checkpoint_log_binding", true)] {
            if let Err(e) = check(&expected[mode], &verify_library(&v, bind)) {
                failures.push(format!("{} [{mode}]: {e}", v.id));
            }
        }

        let actual = profile::check(&v);
        let want = &expected["profile"];
        let ok = match (want["result"].as_str().unwrap(), &actual) {
            ("accept", Ok(())) => true,
            ("reject", Err(clause)) => *clause == want["clause"].as_str().unwrap(),
            _ => false,
        };
        if !ok {
            failures.push(format!(
                "{} [profile]: expected {want}, got {actual:?}",
                v.id
            ));
        }

        if spec["category"] == "profile-negative" && expected["profile"]["result"] != "reject" {
            failures.push(format!(
                "{}: profile-negative must be rejected by the profile",
                v.id
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures.join("\n")
    );
}

/// Vectors that target different timestamp checks (a corrupted token, an
/// untrusted authority, a token over another signature) must each record a
/// reason that the others' actual errors do not satisfy, so that one of them
/// failing for another's reason is caught.
#[test]
fn timestamp_negatives_record_distinct_reasons() {
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(corpus_dir().join("manifest.json")).unwrap())
            .unwrap();
    let cases: Vec<(String, Value, Outcome)> = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|spec| {
            spec["category"] == "standard-negative"
                && spec["expected"]["library"]["error"]
                    .as_str()
                    .is_some_and(|e| e.starts_with("Timestamp."))
        })
        .map(|spec| {
            let v = load(spec);
            let actual = verify_library(&v, false);
            (v.id, spec["expected"]["library"].clone(), actual)
        })
        .collect();
    assert!(
        cases.len() >= 3,
        "expected at least three timestamp negatives"
    );
    for (id, expected, actual) in &cases {
        assert!(check(expected, actual).is_ok(), "{id}: {actual:?}");
        for (other, _, other_actual) in &cases {
            if other != id {
                assert!(
                    check(expected, other_actual).is_err(),
                    "{id}'s expected reason also matches {other}'s error {other_actual:?}"
                );
            }
        }
    }
}

/// Test-only reference implementation of `PROFILE.md`.
mod profile {
    use super::*;
    use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

    const MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

    /// The first clause the vector violates, or `Ok` if it satisfies them all.
    pub(super) fn check(v: &Vector) -> Result<(), &'static str> {
        // MK-4: no duplicate member names anywhere in the JSON.
        serde_json::from_str::<NoDuplicateKeys>(&v.raw).map_err(|_| "MK-4")?;
        let json: Value = serde_json::from_str(&v.raw).map_err(|_| "MK-4")?;

        // MK-4: one variant per oneof: content and verification material.
        let material = &json["verificationMaterial"];
        let contents = ["messageSignature", "dsseEnvelope"];
        let variants = ["publicKey", "certificate", "x509CertificateChain"];
        if contents.iter().filter(|k| json.get(**k).is_some()).count() > 1
            || variants
                .iter()
                .filter(|k| material.get(**k).is_some())
                .count()
                > 1
        {
            return Err("MK-4");
        }
        // MK-1: exactly the v0.3 media type.
        if json["mediaType"] != MEDIA_TYPE {
            return Err("MK-1");
        }
        // MK-2: the verification material is a public key (hint), nothing else.
        if material.get("publicKey").is_none() {
            return Err("MK-2");
        }
        // MK-3: a DSSE envelope with exactly one signature.
        let signatures = json["dsseEnvelope"]["signatures"].as_array();
        if signatures.is_none_or(|s| s.len() != 1) {
            return Err("MK-3");
        }
        // MK-5: exactly one log entry, a Rekor v2 hashedrekord 0.0.2 entry.
        let entries = material["tlogEntries"].as_array().map_or(&[][..], |e| e);
        if entries.len() != 1
            || entries[0]["kindVersion"]["kind"] != "hashedrekord"
            || entries[0]["kindVersion"]["version"] != "0.0.2"
        {
            return Err("MK-5");
        }
        // MK-6: no integratedTime and no inclusionPromise member, whatever
        // its value (zero and null included).
        if entries[0].get("integratedTime").is_some()
            || entries[0].get("inclusionPromise").is_some()
        {
            return Err("MK-6");
        }
        // MK-7: exactly one RFC 3161 timestamp.
        let timestamps = material["timestampVerificationData"]["rfc3161Timestamps"].as_array();
        if timestamps.is_none_or(|t| t.len() != 1) {
            return Err("MK-7");
        }
        // MK-7 / MK-8: library verification with log checks and checkpoint
        // binding; a timestamp failure is MK-7.
        match verify_library(v, true) {
            Ok(()) => Ok(()),
            Err((category, _)) if category.starts_with("Timestamp.") => Err("MK-7"),
            Err(_) => Err("MK-8"),
        }
    }

    /// Deserializes any JSON value, failing on a repeated member name.
    struct NoDuplicateKeys;

    impl<'de> Deserialize<'de> for NoDuplicateKeys {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(NoDuplicateKeysVisitor)
        }
    }

    struct NoDuplicateKeysVisitor;

    impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
        type Value = NoDuplicateKeys;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON without duplicate member names")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut seen = std::collections::HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate member {key:?}"
                    )));
                }
                map.next_value::<NoDuplicateKeys>()?;
            }
            Ok(NoDuplicateKeys)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
            Ok(NoDuplicateKeys)
        }

        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(NoDuplicateKeys)
        }
    }
}
