//! Managed-key DSSE / Rekor v2 / RFC 3161 corpus in `test-vectors/managed-key`.
//!
//! Every vector in `manifest.json` is verified with `PublicKeyVerificationPolicy`
//! (transparency log checks on), with and without checkpoint-to-log binding.
//! The outcome must match the manifest: an accepted vector must verify, and a
//! rejected one must fail with the recorded error category and message. A
//! vector failing for any other reason is a test failure.
//!
//! Vectors also carry the expected outcome under the managed-key profile in
//! `test-vectors/managed-key/PROFILE.md`. The [`profile`] module below is a
//! test-only reference implementation of that profile, so that profile-only
//! negatives (most of which this library accepts) are also checked to fail for
//! the clause they cite. It is not part of the library.

use serde::Deserialize;
use serde_json::Value;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, DerPublicKey};
use sigstore_verify::{verify, PublicKeyVerificationPolicy};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct Manifest {
    vectors: Vec<VectorSpec>,
}

#[derive(Deserialize)]
struct VectorSpec {
    id: String,
    bundle: PathBuf,
    key: PathBuf,
    artifact: PathBuf,
    trusted_root: PathBuf,
    parent: Option<String>,
    category: String,
    expected: Expectations,
}

#[derive(Deserialize)]
struct Expectations {
    library: ExpectedLibrary,
    library_checkpoint_log_binding: ExpectedLibrary,
    profile: ExpectedProfile,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum ExpectedLibrary {
    Accept,
    Reject { error: String, message: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum ExpectedProfile {
    Accept,
    Reject { clause: String },
}

#[derive(Clone, Copy, Debug)]
enum CheckpointBinding {
    Default,
    Required,
}

impl CheckpointBinding {
    const ALL: [Self; 2] = [Self::Default, Self::Required];

    fn expected(self, spec: &VectorSpec) -> &ExpectedLibrary {
        match self {
            Self::Default => &spec.expected.library,
            Self::Required => &spec.expected.library_checkpoint_log_binding,
        }
    }

    fn policy(self, key: DerPublicKey) -> PublicKeyVerificationPolicy {
        let policy = PublicKeyVerificationPolicy::new(key);
        match self {
            Self::Default => policy,
            Self::Required => policy.require_checkpoint_log_binding(),
        }
    }
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/managed-key")
}

fn manifest() -> Manifest {
    serde_json::from_str(&fs::read_to_string(corpus_dir().join("manifest.json")).unwrap()).unwrap()
}

struct Vector {
    id: String,
    bundle_json: String,
    key: DerPublicKey,
    artifact: Vec<u8>,
    root: TrustedRoot,
}

fn load(spec: &VectorSpec) -> Vector {
    let dir = corpus_dir();
    Vector {
        id: spec.id.clone(),
        bundle_json: fs::read_to_string(dir.join(&spec.bundle)).unwrap(),
        key: DerPublicKey::from_pem(&fs::read_to_string(dir.join(&spec.key)).unwrap()).unwrap(),
        artifact: fs::read(dir.join(&spec.artifact)).unwrap(),
        root: TrustedRoot::from_file(dir.join(&spec.trusted_root)).unwrap(),
    }
}

/// The library outcome: `Ok` or (error category, message).
type Outcome = Result<(), (String, String)>;

fn verify_library(vector: &Vector, binding: CheckpointBinding) -> Outcome {
    let bundle = Bundle::from_json(&vector.bundle_json)
        .map_err(|error| ("Parse".to_string(), error.to_string()))?;
    verify(
        Artifact::from(vector.artifact.as_slice()),
        &bundle,
        &binding.policy(vector.key.clone()),
        &vector.root,
    )
    .map(|_| ())
    .map_err(|error| (category(&error), error.to_string()))
}

/// `Variant` or `Variant.Inner` for nested errors, e.g. `TransparencyLog.Checkpoint`.
/// These Debug names are the Rust error vocabulary recorded by the corpus;
/// language-neutral reason codes are separate manifest fields.
fn category(error: &sigstore_verify::Error) -> String {
    let debug = format!("{error:?}");
    let name = |text: &str| {
        text.split(|character: char| !character.is_alphanumeric())
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

fn check(expected: &ExpectedLibrary, actual: &Outcome) -> Result<(), String> {
    match (expected, actual) {
        (ExpectedLibrary::Accept, Ok(())) => Ok(()),
        (ExpectedLibrary::Reject { error, message }, Err((actual_category, actual_message))) => {
            if actual_category == error && actual_message.contains(message) {
                Ok(())
            } else {
                Err(format!(
                    "expected {error} containing {message:?}, got {actual_category}: {actual_message}"
                ))
            }
        }
        (expected, actual) => Err(format!("expected {expected:?}, got {actual:?}")),
    }
}

fn check_parent(spec: &VectorSpec, by_id: &HashMap<&str, &VectorSpec>, failures: &mut Vec<String>) {
    if let Some(parent_id) = &spec.parent {
        let parent = by_id
            .get(parent_id.as_str())
            .unwrap_or_else(|| panic!("{}: unknown parent {parent_id}", spec.id));
        for binding in CheckpointBinding::ALL {
            if !matches!(binding.expected(parent), ExpectedLibrary::Accept) {
                failures.push(format!(
                    "{}: parent {} is not accepted ({binding:?})",
                    spec.id, parent.id
                ));
            }
        }
    }
}

fn check_library(spec: &VectorSpec, vector: &Vector, failures: &mut Vec<String>) {
    for binding in CheckpointBinding::ALL {
        if let Err(error) = check(binding.expected(spec), &verify_library(vector, binding)) {
            failures.push(format!("{} [{binding:?}]: {error}", vector.id));
        }
    }
}

fn check_profile(spec: &VectorSpec, vector: &Vector, failures: &mut Vec<String>) {
    let actual = profile::check(vector);
    let expected = &spec.expected.profile;
    let matches = match (expected, &actual) {
        (ExpectedProfile::Accept, Ok(())) => true,
        (ExpectedProfile::Reject { clause }, Err(actual_clause)) => {
            clause.as_str() == *actual_clause
        }
        _ => false,
    };
    if !matches {
        failures.push(format!(
            "{} [profile]: expected {expected:?}, got {actual:?}",
            vector.id
        ));
    }
    if spec.category == "profile-negative" && !matches!(expected, ExpectedProfile::Reject { .. }) {
        failures.push(format!(
            "{}: profile-negative must be rejected by the profile",
            vector.id
        ));
    }
}

#[test]
fn managed_key_corpus() {
    let manifest = manifest();
    let specs = &manifest.vectors;
    assert_eq!(specs.len(), 56, "unexpected number of corpus vectors");
    let by_id = specs.iter().map(|spec| (spec.id.as_str(), spec)).collect();
    let mut failures = Vec::new();
    for spec in specs {
        let vector = load(spec);
        // Each negative is a mutation of a parent that is itself accepted.
        check_parent(spec, &by_id, &mut failures);
        check_library(spec, &vector, &mut failures);
        check_profile(spec, &vector, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures.join("\n")
    );
}

/// Timestamp negatives must have distinct reasons, so a failure at the wrong
/// timestamp check cannot satisfy the vector's expectation.
#[test]
fn timestamp_negatives_record_distinct_reasons() {
    let manifest = manifest();
    let cases: Vec<_> = manifest
        .vectors
        .iter()
        .filter(|spec| {
            spec.category == "standard-negative"
                && matches!(&spec.expected.library, ExpectedLibrary::Reject { error, .. }
                    if error.starts_with("Timestamp."))
        })
        .map(|spec| {
            (
                spec,
                verify_library(&load(spec), CheckpointBinding::Default),
            )
        })
        .collect();
    assert!(
        cases.len() >= 3,
        "expected at least three timestamp negatives"
    );
    for (spec, actual) in &cases {
        let expected = &spec.expected.library;
        assert!(check(expected, actual).is_ok(), "{}: {actual:?}", spec.id);
        for (other, other_actual) in &cases {
            if other.id != spec.id {
                assert!(
                    check(expected, other_actual).is_err(),
                    "{}'s expected reason also matches {}'s error {other_actual:?}",
                    spec.id,
                    other.id
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
    pub(super) fn check(vector: &Vector) -> Result<(), &'static str> {
        // MK-4: no duplicate member names anywhere in the JSON.
        serde_json::from_str::<NoDuplicateKeys>(&vector.bundle_json).map_err(|_| "MK-4")?;
        let json: Value = serde_json::from_str(&vector.bundle_json).map_err(|_| "MK-4")?;

        // MK-4: one variant per oneof: content and verification material.
        let material = &json["verificationMaterial"];
        let contents = ["messageSignature", "dsseEnvelope"];
        let variants = ["publicKey", "certificate", "x509CertificateChain"];
        if count_present(&json, &contents) > 1 || count_present(material, &variants) > 1 {
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
        // MK-3: a DSSE envelope with exactly one signature, or a messageSignature.
        let dsse_ok = json["dsseEnvelope"]["signatures"]
            .as_array()
            .is_some_and(|s| s.len() == 1);
        let blob_ok = json["messageSignature"].is_object();
        if !dsse_ok && !blob_ok {
            return Err("MK-3");
        }
        // MK-5: exactly one log entry, a Rekor v2 hashedrekord 0.0.2 entry.
        let entries = material["tlogEntries"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
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
        match verify_library(vector, CheckpointBinding::Required) {
            Ok(()) => Ok(()),
            Err((category, _)) if category.starts_with("Timestamp.") => Err("MK-7"),
            Err(_) => Err("MK-8"),
        }
    }

    fn count_present(object: &Value, keys: &[&str]) -> usize {
        keys.iter()
            .filter(|key| object.get(**key).is_some())
            .count()
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
