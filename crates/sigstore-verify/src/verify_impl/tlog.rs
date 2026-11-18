//! Transparency log verification
//!
//! This module handles verification of transparency log entries including
//! checkpoint verification and SET (Signed Entry Timestamp) verification.

use crate::error::{Error, Result};
use serde::Serialize;
use sigstore_crypto::Checkpoint;
use sigstore_crypto::Keyring;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::bundle::InclusionProof;
use sigstore_types::{Bundle, KindVersion, Sha256Hash, SignatureBytes, TransparencyLogEntry};
use std::collections::HashMap;

/// Verify transparency log entries (checkpoints, Merkle inclusion proofs and SETs)
///
/// For every tlog entry this cryptographically verifies (via
/// [`verify_entry_inclusion`]):
/// - the Merkle inclusion proof of the entry's canonicalized body against
///   the proof's root hash (if an inclusion proof is present),
/// - the checkpoint signature with the Rekor keys from the trusted root,
///   and that the checkpoint's root hash matches the proof's root hash,
/// - the inclusion promise (SET), if present.
///
/// It also validates the entry's integrated time against the certificate
/// validity window and the current time.
///
/// # Arguments
/// * `bundle` - The bundle containing transparency log entries
/// * `rekor_keys` - Trusted root for cryptographic verification
/// * `checkpoint_binding` - If set, each checkpoint must also be signed by
///   the entry's own log (see [`RekorLogs`])
/// * `not_before` - Certificate validity start time (Unix timestamp)
/// * `not_after` - Certificate validity end time (Unix timestamp)
pub(crate) fn verify_tlog_entries(
    bundle: &Bundle,
    rekor_keys: &Keyring,
    checkpoint_binding: Option<&RekorLogs>,
    not_before: jiff::Timestamp,
    not_after: jiff::Timestamp,
) -> Result<Option<jiff::Timestamp>> {
    let mut integrated_time_result: Option<jiff::Timestamp> = None;

    for entry in &bundle.verification_material.tlog_entries {
        // Verify Merkle inclusion proof, checkpoint signature and SET
        verify_entry_inclusion(entry, rekor_keys, checkpoint_binding)?;

        // Only a Rekor v1 SET authenticates integratedTime. An inclusion proof
        // authenticates the body, not this separate timestamp field.
        let is_rekor_v2 = entry.kind_version == KindVersion::HashedRekordV002;
        if !is_rekor_v2 && entry.inclusion_promise.is_some() {
            if let Some(time) = entry.integrated_time {
                validate_integrated_time(time, jiff::Timestamp::now(), not_before, not_after)?;
                integrated_time_result = Some(earliest(integrated_time_result, time));
            }
        }
    }

    Ok(integrated_time_result)
}

/// The earlier of an optional time and `time`: the earliest log integration
/// is the strongest proof of when the signature existed.
pub(crate) fn earliest(current: Option<jiff::Timestamp>, time: jiff::Timestamp) -> jiff::Timestamp {
    current.map_or(time, |current| current.min(time))
}

/// Validate an entry's integrated time: it must not be in the future and
/// must fall within the certificate validity window.
fn validate_integrated_time(
    time: jiff::Timestamp,
    now: jiff::Timestamp,
    not_before: jiff::Timestamp,
    not_after: jiff::Timestamp,
) -> Result<()> {
    validate_integrated_time_not_in_future(time, now)?;

    // Check that integrated time is within certificate validity period
    if time < not_before {
        return Err(Error::integrated_time(format!(
            "integrated time {} is before certificate validity (not_before: {})",
            time, not_before
        )));
    }

    if time > not_after {
        return Err(Error::integrated_time(format!(
            "integrated time {} is after certificate validity (not_after: {})",
            time, not_after
        )));
    }

    Ok(())
}

pub(crate) fn validate_integrated_time_not_in_future(
    time: jiff::Timestamp,
    now: jiff::Timestamp,
) -> Result<()> {
    if time > now {
        return Err(Error::integrated_time(format!(
            "integrated time {} is in the future (current time: {})",
            time, now
        )));
    }
    Ok(())
}

/// Cryptographically verify the log-inclusion material of a single tlog entry.
///
/// This performs all per-entry transparency log crypto checks:
/// - If an inclusion proof is present:
///   - verifies the Merkle inclusion proof, i.e. that the leaf hash of the
///     entry's canonicalized body hashes up to the authenticated root, and
///   - verifies the checkpoint signature against a Rekor key from the trusted
///     root (see [`verify_checkpoint`]). Rekor v1 additionally requires its
///     duplicated proof root to match the checkpoint root.
/// - If an inclusion promise (SET) is present, verifies it against the
///   Rekor key for the entry's log ID (see [`verify_set`]).
///
/// Time-related checks (integrated time vs. certificate validity) are not
/// performed here; see [`verify_tlog_entries`].
///
/// With `checkpoint_binding`, the checkpoint must be signed by the entry's
/// own log rather than by any trusted Rekor key (see
/// [`verify_checkpoint_from_entry_log`]).
pub(crate) fn verify_entry_inclusion(
    entry: &TransparencyLogEntry,
    rekor_keys: &Keyring,
    checkpoint_binding: Option<&RekorLogs>,
) -> Result<()> {
    if let Some(ref inclusion_proof) = entry.inclusion_proof {
        verify_merkle_inclusion(entry, inclusion_proof)?;
        match checkpoint_binding {
            None => verify_checkpoint(
                inclusion_proof.checkpoint.envelope(),
                inclusion_proof,
                is_rekor_v2(entry),
                rekor_keys,
            )?,
            Some(logs) => {
                verify_checkpoint_from_entry_log(entry, inclusion_proof, rekor_keys, logs)?
            }
        }
    }

    if entry.inclusion_promise.is_some() {
        verify_set(entry, rekor_keys)?;
    }

    Ok(())
}

/// Verify the Merkle inclusion proof of a tlog entry.
///
/// Computes the leaf hash of the entry's canonicalized body and verifies
/// that, combined with the proof hashes, it reproduces the expected root
/// hash. Rekor v2 takes the index, tree size, and root from the top-level entry
/// and signed checkpoint rather than unauthenticated duplicate proof fields.
/// The checkpoint signature check authenticates the selected root.
fn verify_merkle_inclusion(entry: &TransparencyLogEntry, proof: &InclusionProof) -> Result<()> {
    let (leaf_index, tree_size, root_hash) = if is_rekor_v2(entry) {
        let checkpoint = proof.checkpoint.checkpoint().ok_or_else(|| {
            Error::checkpoint("Rekor v2 inclusion proof has no checkpoint".to_string())
        })?;
        let leaf_index = entry.log_index.get();
        (leaf_index, checkpoint.tree_size(), *checkpoint.root_hash())
    } else {
        let leaf_index = proof.log_index.get();
        let tree_size = proof.tree_size;
        (leaf_index, tree_size, proof.root_hash)
    };

    let leaf_hash = sigstore_merkle::hash_leaf(entry.canonicalized_body.as_bytes());

    sigstore_merkle::verify_inclusion_proof(
        &leaf_hash,
        leaf_index,
        tree_size,
        &proof.hashes,
        &root_hash,
    )
    .map_err(|e| Error::inclusion_proof(format!("inclusion proof verification failed: {}", e)))
}

/// Verify a checkpoint signature using the trusted root
pub fn verify_checkpoint(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    is_v2: bool,
    rekor_keys: &Keyring,
) -> Result<()> {
    let checkpoint = parse_checkpoint(checkpoint_envelope, inclusion_proof, is_v2)?;

    // A checkpoint can contain log and witness signatures. TrustedRoot keeps
    // validity metadata alongside each parsed verification key. Four-byte
    // checkpoint hints may collide, so try every matching key and do not let
    // an invalid matching signature suppress a later valid log signature.

    let message = checkpoint.signed_data();
    let now = jiff::Timestamp::now();
    let mut found_matching_key = false;
    for sig in checkpoint.signatures() {
        for key in rekor_keys.keys_by_hint(&sig.key_id, now) {
            found_matching_key = true;
            if key.verify(message, &sig.signature).is_ok() {
                return Ok(());
            }
        }
    }

    let message = if found_matching_key {
        "No valid Rekor signature found on checkpoint"
    } else {
        "No matching Rekor key found for checkpoint signature"
    };
    Err(Error::checkpoint(message.to_string()))
}

/// Parse the signed note and check Rekor v1's duplicated root hash.
fn parse_checkpoint(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    is_v2: bool,
) -> Result<Checkpoint> {
    // Parse the checkpoint (signed note)
    let checkpoint = Checkpoint::from_text(checkpoint_envelope)
        .map_err(|e| Error::checkpoint(format!("Failed to parse checkpoint: {}", e)))?;

    // Rekor v1 requires internal consistency with its duplicate proof root.
    // Rekor v2 explicitly treats that field as unauthenticated and ignores it.
    let checkpoint_root_hash = checkpoint.root_hash();
    let proof_root_hash = &inclusion_proof.root_hash;

    if !is_v2 && checkpoint_root_hash.as_bytes() != proof_root_hash.as_bytes() {
        return Err(Error::checkpoint(format!(
            "Checkpoint root hash mismatch: expected {}, got {}",
            checkpoint_root_hash.to_hex(),
            proof_root_hash.to_hex()
        )));
    }

    Ok(checkpoint)
}

/// The trusted Rekor logs, by log ID, with the checkpoint origin each one
/// signs under.
///
/// Used when a policy binds checkpoints to the entry's own log. Without that
/// binding, [`verify_checkpoint`] accepts a checkpoint signed by any trusted
/// Rekor key, even one belonging to a different log than the entry's.
pub(crate) struct RekorLogs {
    origins: HashMap<Sha256Hash, Option<String>>,
}

impl RekorLogs {
    pub(crate) fn new(trusted_root: &TrustedRoot) -> Result<Self> {
        let mut origins = HashMap::new();
        for log in &trusted_root.tlogs {
            let id = Sha256Hash::try_from(log.log_id.key_id.as_bytes())?;
            origins.insert(id, log_origin(&log.base_url));
        }
        Ok(Self { origins })
    }

    /// The expected checkpoint origin for this log ID.
    fn origin(&self, log_id: &Sha256Hash) -> Option<&str> {
        self.origins
            .get(log_id)
            .and_then(|origin| origin.as_deref())
    }
}

/// The origin a Rekor v2 log signs its checkpoints under: the host of its base
/// URL, as sigstore-go derives it.
///
/// The URL must parse as an absolute `http` or `https` URL with a host and no
/// user info. Its port and path are ignored. Domain names are normalized by
/// URL parsing (lower case, IDNA to ASCII), and an IPv6 address is returned
/// without brackets. Returns `None` for anything else, which makes
/// checkpoint-to-log binding fail for a Rekor v2 entry of that log.
fn log_origin(base_url: &str) -> Option<String> {
    let url = url::Url::parse(base_url).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    match url.host()? {
        url::Host::Domain(domain) if !domain.is_empty() => Some(domain.to_string()),
        url::Host::Domain(_) => None,
        url::Host::Ipv4(address) => Some(address.to_string()),
        url::Host::Ipv6(address) => Some(address.to_string()),
    }
}

/// Verify an entry's checkpoint and require that it was signed by the log the
/// entry names.
///
/// The checkpoint must carry a valid signature from the trusted key whose log
/// ID equals the entry's log ID. Signature lines from other keys, such as
/// witness cosignatures, are ignored; they are neither verified nor required.
/// For Rekor v2 the checkpoint origin, and the name on the log's signature
/// line, must also equal the origin of that log (the host of its base URL).
/// Rekor v1 origins carry a tree ID that the trusted root does not record, so
/// only the signing key is bound for them.
fn verify_checkpoint_from_entry_log(
    entry: &TransparencyLogEntry,
    inclusion_proof: &InclusionProof,
    rekor_keys: &Keyring,
    logs: &RekorLogs,
) -> Result<()> {
    let is_v2 = is_rekor_v2(entry);
    let checkpoint = parse_checkpoint(
        inclusion_proof.checkpoint.envelope(),
        inclusion_proof,
        is_v2,
    )?;

    let log_id = Sha256Hash::try_from(entry.log_id.key_id.as_bytes())
        .map_err(|e| Error::malformed_entry(format!("invalid Rekor log ID: {e}")))?;
    let key = rekor_keys
        .key_started_by(&log_id, jiff::Timestamp::now())
        .ok_or_else(|| Error::unknown_log(entry.log_id.key_id.to_string()))?;

    let origin = if is_v2 {
        let origin = logs.origin(&log_id).ok_or_else(|| {
            Error::checkpoint(format!(
                "trusted root has no valid base URL for the entry's log {}",
                entry.log_id.key_id
            ))
        })?;
        if checkpoint.origin() != origin {
            return Err(Error::checkpoint(format!(
                "checkpoint origin {:?} does not match the entry's log {:?}",
                checkpoint.origin(),
                origin
            )));
        }
        Some(origin)
    } else {
        None
    };

    const KEY_HINT_LEN: usize = 4;
    let hint = &log_id.as_bytes()[..KEY_HINT_LEN];
    let message = checkpoint.signed_data();
    let signed_by_log = checkpoint.signatures().iter().any(|sig| {
        sig.key_id.as_bytes() == hint
            && origin.is_none_or(|origin| sig.name == origin)
            && key.verify(message, &sig.signature).is_ok()
    });
    if signed_by_log {
        Ok(())
    } else {
        Err(Error::checkpoint(format!(
            "checkpoint has no valid signature from the entry's log {}",
            entry.log_id.key_id
        )))
    }
}

fn is_rekor_v2(entry: &TransparencyLogEntry) -> bool {
    entry.kind_version == KindVersion::HashedRekordV002
}

#[derive(Serialize)]
struct RekorPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

/// Verify SET (Signed Entry Timestamp)
pub fn verify_set(entry: &TransparencyLogEntry, rekor_keys: &Keyring) -> Result<()> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(Error::inclusion_promise("Missing inclusion promise".into()))?;

    // Find the key for the log ID. When the entry carries an integrated
    // time, require the log key's validity window to cover it: an entry must
    // have been integrated while the log key was valid.
    let decoded_key_id = entry.log_id.key_id.as_bytes();
    let key_id = Sha256Hash::try_from(decoded_key_id)
        .map_err(|e| Error::malformed_entry(format!("invalid Rekor log ID: {e}")))?;
    let keyring = rekor_keys;
    let log_key = if let Some(integrated_ts) = entry.integrated_time {
        keyring.key_at(&key_id, integrated_ts).ok_or_else(|| {
            Error::inclusion_promise(format!(
                "No log key valid at integrated time {} for log ID {}",
                integrated_ts, entry.log_id.key_id
            ))
        })?
    } else {
        keyring
            .key_started_by(&key_id, jiff::Timestamp::now())
            .ok_or_else(|| Error::unknown_log(entry.log_id.key_id.to_string()))?
    };

    // Construct the payload (base64-encoded body)
    let body = entry.canonicalized_body.to_base64();
    let log_index = entry.log_index.as_i64();

    // Log ID for payload must be hex encoded
    let log_id_hex = hex::encode(decoded_key_id);

    let payload = RekorPayload {
        body,
        // The SET payload is wire-format Rekor V1 JSON, where "absent" is
        // the proto3 default of 0.
        integrated_time: entry.integrated_time.map_or(0, |ts| ts.as_second()),
        log_index,
        log_id: log_id_hex,
    };

    let canonical_json = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| Error::inclusion_promise(format!("Canonicalization failed: {}", e)))?;

    // Get signature bytes from signed timestamp
    let signature = SignatureBytes::new(promise.signed_entry_timestamp.as_bytes().to_vec());

    log_key
        .verify(&canonical_json, &signature)
        .map_err(|e| Error::inclusion_promise(format!("SET verification failed: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(seconds: i64) -> jiff::Timestamp {
        jiff::Timestamp::from_second(seconds).unwrap()
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn test_integrated_time_in_future_rejected() {
        // Even one second in the future must be rejected.
        let err = validate_integrated_time(ts(NOW + 1), ts(NOW), ts(NOW - 600), ts(NOW + 600))
            .unwrap_err();
        assert!(err.to_string().contains("is in the future"));
    }

    #[test]
    fn test_integrated_time_at_now_accepted() {
        assert!(validate_integrated_time(ts(NOW), ts(NOW), ts(NOW - 600), ts(NOW + 600)).is_ok());
    }
    mod checkpoint_log_binding {
        use super::*;
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use sigstore_crypto::{KeyPair, VerificationKey};

        const ORIGIN_A: &str = "log-a.example.com";
        const ORIGIN_B: &str = "log-b.example.com";
        const BODY: &[u8] = br#"{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{}}"#;

        struct Log {
            key: KeyPair,
            id: Sha256Hash,
            origin: &'static str,
        }

        impl Log {
            fn new(origin: &'static str) -> Self {
                Self {
                    key: KeyPair::generate_ecdsa_p256().unwrap(),
                    id: sigstore_crypto::sha256(origin.as_bytes()),
                    origin,
                }
            }

            /// A signature line for `note` under `name` with this log's key.
            fn sign(&self, name: &str, note: &str) -> String {
                let mut sig = self.id.as_bytes()[..4].to_vec();
                sig.extend_from_slice(self.key.sign(note.as_bytes()).unwrap().as_bytes());
                format!("\u{2014} {name} {}\n", STANDARD.encode(sig))
            }
        }

        struct Fixture {
            log_a: Log,
            log_b: Log,
            keyring: Keyring,
            logs: RekorLogs,
        }

        impl Fixture {
            fn new() -> Self {
                let log_a = Log::new(ORIGIN_A);
                let log_b = Log::new(ORIGIN_B);
                let mut keyring = Keyring::new();
                let mut origins = HashMap::new();
                for log in [&log_a, &log_b] {
                    let key =
                        VerificationKey::from_spki(&log.key.public_key_der().unwrap()).unwrap();
                    keyring.add_key(log.id, key);
                    origins.insert(log.id, Some(log.origin.to_string()));
                }
                Self {
                    log_a,
                    log_b,
                    keyring,
                    logs: RekorLogs { origins },
                }
            }

            /// The checkpoint note body for a one-leaf tree holding `BODY`.
            fn note(origin: &str) -> String {
                let root = sigstore_merkle::hash_leaf(BODY);
                format!("{origin}\n1\n{}\n", STANDARD.encode(root.as_bytes()))
            }

            /// A Rekor v2 entry naming `log_id`, with `checkpoint` as its
            /// signed note.
            fn entry(log_id: &Sha256Hash, checkpoint: &str) -> TransparencyLogEntry {
                let root = sigstore_merkle::hash_leaf(BODY);
                serde_json::from_value(serde_json::json!({
                    "logIndex": "0",
                    "logId": {"keyId": STANDARD.encode(log_id.as_bytes())},
                    "kindVersion": {"kind": "hashedrekord", "version": "0.0.2"},
                    "canonicalizedBody": STANDARD.encode(BODY),
                    "inclusionProof": {
                        "logIndex": "0",
                        "rootHash": STANDARD.encode(root.as_bytes()),
                        "treeSize": "1",
                        "hashes": [],
                        "checkpoint": {"envelope": checkpoint},
                    },
                }))
                .unwrap()
            }

            fn verify_default(&self, entry: &TransparencyLogEntry) -> Result<()> {
                verify_entry_inclusion(entry, &self.keyring, None)
            }

            fn verify_with_binding(&self, entry: &TransparencyLogEntry) -> Result<()> {
                verify_entry_inclusion(entry, &self.keyring, Some(&self.logs))
            }
        }

        fn assert_checkpoint_error(result: Result<()>, expected: &str) {
            match result {
                Err(Error::TransparencyLog(crate::error::TransparencyLogError::Checkpoint(m)))
                    if m.contains(expected) => {}
                other => panic!("expected checkpoint error containing {expected:?}, got {other:?}"),
            }
        }

        #[test]
        fn test_own_log_signature_passes_either_way() {
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_A);
            let entry = Fixture::entry(
                &logs.log_a.id,
                &format!("{note}\n{}", logs.log_a.sign(ORIGIN_A, &note)),
            );
            logs.verify_default(&entry).unwrap();
            logs.verify_with_binding(&entry).unwrap();
        }

        #[test]
        fn test_witness_and_other_log_lines_are_ignored_when_the_log_signed() {
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_A);
            let witness = Log::new("witness.example.org");
            let checkpoint = format!(
                "{note}\n{}{}{}",
                witness.sign(witness.origin, &note),
                logs.log_b.sign(ORIGIN_B, &note),
                logs.log_a.sign(ORIGIN_A, &note),
            );
            let entry = Fixture::entry(&logs.log_a.id, &checkpoint);
            logs.verify_default(&entry).unwrap();
            logs.verify_with_binding(&entry).unwrap();
        }

        #[test]
        fn test_checkpoint_from_another_trusted_log_is_rejected_only_with_binding() {
            // Accepted by default, as in earlier releases; rejected when the
            // checkpoint must come from the entry's own log.
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_A);
            let entry = Fixture::entry(
                &logs.log_a.id,
                &format!("{note}\n{}", logs.log_b.sign(ORIGIN_A, &note)),
            );
            logs.verify_default(&entry).unwrap();
            assert_checkpoint_error(
                logs.verify_with_binding(&entry),
                "checkpoint has no valid signature from the entry's log",
            );
        }

        #[test]
        fn test_checkpoint_origin_must_be_the_entry_logs() {
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_B);
            let entry = Fixture::entry(
                &logs.log_a.id,
                &format!("{note}\n{}", logs.log_a.sign(ORIGIN_B, &note)),
            );
            logs.verify_default(&entry).unwrap();
            assert_checkpoint_error(
                logs.verify_with_binding(&entry),
                "checkpoint origin \"log-b.example.com\" does not match the entry's log \"log-a.example.com\"",
            );
        }

        #[test]
        fn test_log_signature_line_must_carry_the_log_origin() {
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_A);
            let entry = Fixture::entry(
                &logs.log_a.id,
                &format!("{note}\n{}", logs.log_a.sign("someone-else.example", &note)),
            );
            logs.verify_default(&entry).unwrap();
            assert_checkpoint_error(
                logs.verify_with_binding(&entry),
                "checkpoint has no valid signature from the entry's log",
            );
        }

        #[test]
        fn test_rekor_v1_binding_covers_the_key_but_not_the_origin() {
            // Rekor v1 origins carry a tree ID that the trusted root does not
            // record, so for v1 entries only the signing key is bound: a
            // checkpoint from A's key under another origin is accepted, while
            // B's key is still rejected.
            let logs = Fixture::new();
            let v1 = |checkpoint: &str| {
                let mut entry = Fixture::entry(&logs.log_a.id, checkpoint);
                entry.kind_version = sigstore_types::KindVersion::HashedRekordV001;
                entry
            };
            let note = Fixture::note("other-origin.example.com - 42");
            let entry = v1(&format!(
                "{note}\n{}",
                logs.log_a.sign("other-origin.example.com", &note)
            ));
            logs.verify_with_binding(&entry).unwrap();
            let entry = v1(&format!("{note}\n{}", logs.log_b.sign(ORIGIN_B, &note)));
            logs.verify_default(&entry).unwrap();
            assert_checkpoint_error(
                logs.verify_with_binding(&entry),
                "checkpoint has no valid signature from the entry's log",
            );
        }

        #[test]
        fn test_entry_naming_an_untrusted_log_is_rejected() {
            let logs = Fixture::new();
            let note = Fixture::note(ORIGIN_A);
            let unknown = sigstore_crypto::sha256(b"unknown");
            let entry = Fixture::entry(
                &unknown,
                &format!("{note}\n{}", logs.log_a.sign(ORIGIN_A, &note)),
            );
            logs.verify_default(&entry).unwrap();
            assert!(matches!(
                logs.verify_with_binding(&entry),
                Err(Error::TransparencyLog(
                    crate::error::TransparencyLogError::UnknownLog { .. }
                ))
            ));
        }
    }

    #[test]
    fn test_log_origin_is_the_base_url_host() {
        for (url, origin) in [
            (
                "https://log2025-1.rekor.sigstore.dev",
                Some("log2025-1.rekor.sigstore.dev"),
            ),
            (
                "https://log2025-alpha3.rekor.sigstage.dev/",
                Some("log2025-alpha3.rekor.sigstage.dev"),
            ),
            // Port, path, query and fragment are ignored; case is normalized.
            ("https://Example.COM:8443/path?q#logs", Some("example.com")),
            ("http://log.example", Some("log.example")),
            ("https://[2001:db8::1]:443/", Some("2001:db8::1")),
            ("https://192.0.2.1", Some("192.0.2.1")),
            ("https://bücher.example", Some("xn--bcher-kva.example")),
            // Not an absolute http(s) URL with a host and without user info.
            ("https://user@host.example", None),
            ("https://user:pass@host.example", None),
            ("host.example/api", None),
            ("not a valid URL", None),
            ("https://", None),
            ("file:///etc/passwd", None),
            ("ftp://host.example", None),
            ("", None),
        ] {
            assert_eq!(log_origin(url).as_deref(), origin, "{url:?}");
        }
    }
}
