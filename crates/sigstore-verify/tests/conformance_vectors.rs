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

const VENDORED_VECTORS: usize = 67;
const FAIL_VECTORS: usize = 48;

const DEFAULT_IDENTITY: &str = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main";
const DEFAULT_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Clone, Copy, Debug)]
enum ArtifactInput {
    Bytes,
    Digest,
}

#[derive(Clone, Copy, Debug)]
enum CheckpointBinding {
    Default,
    Required,
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/sigstore-conformance/bundle-verify")
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn trusted_root(dir: &Path) -> Result<TrustedRoot, String> {
    if dir.join("trusted_root.json").exists() {
        TrustedRoot::from_file(dir.join("trusted_root.json")).map_err(|e| e.to_string())
    } else {
        TrustedRoot::from_embedded(SigstoreInstance::PublicGood).map_err(|e| e.to_string())
    }
}

fn policy(dir: &Path, binding: CheckpointBinding) -> Result<Box<dyn Policy>, String> {
    let policy: Box<dyn Policy> = if dir.join("key.pub").exists() {
        let pem = fs::read_to_string(dir.join("key.pub")).map_err(|e| e.to_string())?;
        let key = DerPublicKey::from_pem(&pem).map_err(|e| format!("key: {e}"))?;
        let policy = PublicKeyVerificationPolicy::new(key);
        Box::new(match binding {
            CheckpointBinding::Default => policy,
            CheckpointBinding::Required => policy.require_checkpoint_log_binding(),
        })
    } else {
        let identity =
            read_trimmed(&dir.join("identity")).unwrap_or_else(|| DEFAULT_IDENTITY.into());
        let issuer = read_trimmed(&dir.join("issuer")).unwrap_or_else(|| DEFAULT_ISSUER.into());
        let policy = VerificationPolicy::new(identity, issuer);
        Box::new(match binding {
            CheckpointBinding::Default => policy,
            CheckpointBinding::Required => policy.require_checkpoint_log_binding(),
        })
    };
    Ok(policy)
}

fn artifact_bytes(dir: &Path) -> Result<Vec<u8>, String> {
    let artifact_path = if dir.join("artifact").exists() {
        dir.join("artifact")
    } else {
        // The suite shares a.txt when a vector has no dedicated artifact.
        dir.join("../a.txt")
    };
    fs::read(artifact_path).map_err(|e| e.to_string())
}

/// Verify one vector; loader and verifier errors retain the suite's rejection semantics.
fn verify_vector(
    dir: &Path,
    input: ArtifactInput,
    binding: CheckpointBinding,
) -> Result<(), String> {
    let bundle = fs::read_to_string(dir.join("bundle.sigstore.json")).map_err(|e| e.to_string())?;
    let bundle = Bundle::from_json(&bundle).map_err(|e| format!("bundle: {e}"))?;
    let root = trusted_root(dir)?;
    let policy = policy(dir, binding)?;
    let bytes = artifact_bytes(dir)?;
    let artifact = match input {
        ArtifactInput::Bytes => Artifact::from(bytes.as_slice()),
        ArtifactInput::Digest => Artifact::from(sigstore_crypto::sha256(&bytes)),
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
    assert_eq!(
        dirs.len(),
        VENDORED_VECTORS,
        "unexpected number of vendored vectors"
    );
    let expected_failures = dirs
        .iter()
        .filter(|dir| dir.to_string_lossy().ends_with("_fail"))
        .count();
    assert_eq!(
        expected_failures, FAIL_VECTORS,
        "unexpected number of _fail vectors"
    );

    let mut failures = Vec::new();
    for dir in &dirs {
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        let should_fail = name.ends_with("_fail");
        for input in [ArtifactInput::Bytes, ArtifactInput::Digest] {
            for binding in [CheckpointBinding::Default, CheckpointBinding::Required] {
                let outcome = verify_vector(dir, input, binding);
                if outcome.is_err() != should_fail {
                    failures.push(format!(
                        "{name} ({input:?}, checkpoint binding={binding:?}): {outcome:?}"
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
