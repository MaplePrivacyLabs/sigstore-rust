//! Library-level run of the pinned sigstore-conformance bundle-verification
//! vectors vendored in `test-vectors/sigstore-conformance` (see its README).
//!
//! The rules follow the suite's `bundle-verify/README.md`: a directory whose
//! name ends in `_fail` must be rejected and every other one accepted. Each
//! vector is verified from the artifact bytes and from its SHA-256 digest, and
//! with and without checkpoint-to-log binding, which must not change any
//! outcome.

use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_types::{Artifact, Bundle, DerPublicKey};
use sigstore_verify::{verify, Policy, PublicKeyVerificationPolicy, VerificationPolicy};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
const DEFAULT_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/sigstore-conformance/bundle-verify")
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Verify one vector; `Err` carries the verifier's (or loader's) error.
fn verify_vector(dir: &Path, digest_only: bool, bind_checkpoint: bool) -> Result<(), String> {
    let bundle = fs::read_to_string(dir.join("bundle.sigstore.json")).map_err(|e| e.to_string())?;
    let bundle = Bundle::from_json(&bundle).map_err(|e| format!("bundle: {e}"))?;
    let root = if dir.join("trusted_root.json").exists() {
        TrustedRoot::from_file(dir.join("trusted_root.json")).map_err(|e| e.to_string())?
    } else {
        TrustedRoot::from_embedded(SigstoreInstance::PublicGood).map_err(|e| e.to_string())?
    };
    let policy: Box<dyn Policy> = if dir.join("key.pub").exists() {
        let pem = fs::read_to_string(dir.join("key.pub")).map_err(|e| e.to_string())?;
        let key = DerPublicKey::from_pem(&pem).map_err(|e| format!("key: {e}"))?;
        let policy = PublicKeyVerificationPolicy::new(key);
        Box::new(if bind_checkpoint {
            policy.require_checkpoint_log_binding()
        } else {
            policy
        })
    } else {
        let identity =
            read_trimmed(&dir.join("identity")).unwrap_or_else(|| DEFAULT_IDENTITY.into());
        let issuer = read_trimmed(&dir.join("issuer")).unwrap_or_else(|| DEFAULT_ISSUER.into());
        let policy = VerificationPolicy::new(identity, issuer);
        Box::new(if bind_checkpoint {
            policy.require_checkpoint_log_binding()
        } else {
            policy
        })
    };
    let artifact_path = if dir.join("artifact").exists() {
        dir.join("artifact")
    } else {
        dir.join("../a.txt")
    };
    let bytes = fs::read(artifact_path).map_err(|e| e.to_string())?;
    let artifact = if digest_only {
        Artifact::from(sigstore_crypto::sha256(&bytes))
    } else {
        Artifact::from(bytes.as_slice())
    };
    verify(artifact, &bundle, policy.as_ref(), &root)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn pinned_conformance_bundle_vectors() {
    let mut dirs: Vec<PathBuf> = fs::read_dir(vectors_dir())
        .expect("vendored conformance vectors")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    assert_eq!(dirs.len(), 67, "unexpected number of vendored vectors");
    let expected_failures = dirs
        .iter()
        .filter(|dir| dir.to_string_lossy().ends_with("_fail"))
        .count();
    assert_eq!(expected_failures, 48, "unexpected number of _fail vectors");

    let mut failures = Vec::new();
    for dir in &dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let should_fail = name.ends_with("_fail");
        for digest_only in [false, true] {
            for bind_checkpoint in [false, true] {
                let outcome = verify_vector(dir, digest_only, bind_checkpoint);
                if outcome.is_err() != should_fail {
                    failures.push(format!(
                        "{name} (digest={digest_only}, checkpoint binding={bind_checkpoint}): {outcome:?}"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "conformance failures:\n{}",
        failures.join("\n")
    );
}
