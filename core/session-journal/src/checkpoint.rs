//! Canonical SQJ anchor checkpoint codec and journal binding.
//!
//! This module deliberately does not perform filesystem writes or key custody.
//! The platform adapter must atomically persist the checkpoint, sync the file
//! and parent directory, and preserve prior evidence on failure.
use crate::{
    anchor_verifier::{
        JournalAnchorVerificationResult, JournalSignatureAnchor, P256Sha256SignatureProvider,
        verify_journal_anchor,
    },

};

const MAGIC: &[u8; 4] = b"SQAC";
const VERSION: u16 = 1;
const MAX_SIGNATURE_BYTES: usize = 80;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ALGORITHM_BYTES: usize = 64;
const FIXED_BYTES: usize = 4 + 2 + 8 + 32 + 8 + 8 + 2 + 2 + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointCodecError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
    InvalidMetadata,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCheckpointVerification {
    Valid,
    InvalidCheckpoint,
    JournalDamaged,
    JournalSequenceMismatch,
    JournalDigestMismatch,
    AnchorInvalid(JournalAnchorVerificationResult),
}

/// Encodes the full signed anchor. The anchor signature is preserved verbatim
/// (DER); no lossy timestamp, integer, or key-ID conversion is performed.
pub fn encode_checkpoint(anchor: &JournalSignatureAnchor) -> Result<Vec<u8>, CheckpointCodecError> {
    validate_anchor(anchor)?;
    let algorithm = anchor.signature_algorithm_id.as_bytes();
    let key_id = anchor.signing_key_id.as_bytes();
    let signature = &anchor.signature_der;
    let total = FIXED_BYTES
        .checked_add(algorithm.len())
        .and_then(|n| n.checked_add(key_id.len()))
        .and_then(|n| n.checked_add(signature.len()))
        .ok_or(CheckpointCodecError::InvalidLength)?;
    let mut bytes = Vec::new();

    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&anchor.sequence.to_le_bytes());
    bytes.extend_from_slice(&anchor.digest);
    bytes.extend_from_slice(&anchor.authentication_epoch.to_le_bytes());
    bytes.extend_from_slice(&anchor.monotonic_timestamp_ns.to_le_bytes());
    bytes.extend_from_slice(&(algorithm.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(key_id.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(signature.len() as u16).to_le_bytes());
    bytes.extend_from_slice(algorithm);
    bytes.extend_from_slice(key_id);
    bytes.extend_from_slice(signature);
    Ok(bytes)
}

/// Decodes exactly one checkpoint. Trailing bytes are rejected to prevent
/// ambiguous concatenation or accepting a prefix of a replaced checkpoint.
pub fn decode_checkpoint(bytes: &[u8]) -> Result<JournalSignatureAnchor, CheckpointCodecError> {
    if bytes.len() < FIXED_BYTES {
        return Err(CheckpointCodecError::InvalidLength);
    }
    if bytes.get(..4) != Some(MAGIC.as_slice()) {
        return Err(CheckpointCodecError::InvalidMagic);
    }
    if read_u16(bytes, 4) != VERSION {
        return Err(CheckpointCodecError::UnsupportedVersion);
    }
    let algorithm_len = usize::from(read_u16(bytes, 62));
    let key_id_len = usize::from(read_u16(bytes, 64));
    let signature_len = usize::from(read_u16(bytes, 66));

    {
        return Err(CheckpointCodecError::InvalidLength);
    }

        .and_then(|n| n.checked_add(key_id_len))
        .and_then(|n| n.checked_add(signature_len))
        .ok_or(CheckpointCodecError::InvalidLength)?;
    if bytes.len() != expected {
        return Err(CheckpointCodecError::InvalidLength);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[14..46]);
    let algorithm_start = FIXED_BYTES;
    let key_start = algorithm_start + algorithm_len;
    let signature_start = key_start + key_id_len;
    let anchor = JournalSignatureAnchor {
        format_version: VERSION,
        sequence: read_u64(bytes, 6),
        digest,
        signature_algorithm_id: core::str::from_utf8(&bytes[algorithm_start..key_start])

        signing_key_id: core::str::from_utf8(&bytes[key_start..signature_start])

        signature_der: bytes[signature_start..].to_vec(),
        authentication_epoch: read_u64(bytes, 46),
        monotonic_timestamp_ns: read_u64(bytes, 54),
    };
    validate_anchor(&anchor)?;
    Ok(anchor)
}

/// Verify the checkpoint's signature AND bind it to the complete, intact SQJ
/// byte stream supplied by the recovery adapter. A valid signature for a stale
/// or different journal is not accepted as a current checkpoint.
pub fn verify_checkpoint_binding<P: P256Sha256SignatureProvider>(
    anchor: &JournalSignatureAnchor,
    journal_bytes: &[u8],
    registry_bytes: &[u8],
    provider: &P,
) -> BoundCheckpointVerification {
    let journal = verify_journal(journal_bytes);
    if journal.status != JournalVerificationStatus::Valid
        || journal.valid_prefix_bytes != journal_bytes.len()
    {
        return BoundCheckpointVerification::JournalDamaged;
    }
    if journal.last_sequence != anchor.sequence {
        return BoundCheckpointVerification::JournalSequenceMismatch;
    }
    if journal.last_digest != anchor.digest {
        return BoundCheckpointVerification::JournalDigestMismatch;
    }
    match verify_journal_anchor(anchor, registry_bytes, provider) {
        JournalAnchorVerificationResult::Valid => BoundCheckpointVerification::Valid,
        other => BoundCheckpointVerification::AnchorInvalid(other),
    }
}

fn validate_anchor(anchor: &JournalSignatureAnchor) -> Result<(), CheckpointCodecError> {

        || anchor.signature_algorithm_id.is_empty()
        || anchor.signature_algorithm_id.len() > MAX_ALGORITHM_BYTES
        || anchor.signing_key_id.is_empty()
        || anchor.signing_key_id.len() > MAX_KEY_ID_BYTES
        || anchor.signature_der.is_empty()
        || anchor.signature_der.len() > MAX_SIGNATURE_BYTES
    {
        return Err(CheckpointCodecError::InvalidMetadata);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {

}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> JournalSignatureAnchor {
        JournalSignatureAnchor {
            format_version: 1,
            sequence: 42,
            digest: [0x5a; 32],
            signature_algorithm_id: "ecdsa-p256-sha256-v1".into(),
            signing_key_id: "ecdsa-p256-sha256-v1-0123456789abcdef0123456789abcdef".into(),
            signature_der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            authentication_epoch: 7,
            monotonic_timestamp_ns: 123_456,
        }
    }

    #[test]
    fn checkpoint_round_trip_preserves_signed_anchor_fields() {
        let anchor = fixture();
        let encoded = encode_checkpoint(&anchor).unwrap();
        assert_eq!(decode_checkpoint(&encoded).unwrap(), anchor);
    }

    #[test]
    fn checkpoint_rejects_truncation_and_trailing_data() {
        let encoded = encode_checkpoint(&fixture()).unwrap();

        let mut trailing = encoded;
        trailing.push(0);

    }

    #[test]
    fn checkpoint_rejects_wrong_magic_and_zero_sequence() {
        let mut encoded = encode_checkpoint(&fixture()).unwrap();
        encoded[0] = b'X';

        let mut anchor = fixture();
        anchor.sequence = 0;

    }
    struct AcceptSignature;
    impl P256Sha256SignatureProvider for AcceptSignature {

    }

    #[derive(Default)]
    struct JournalBytes(Vec<u8>);
    impl crate::JournalSink for JournalBytes {
        fn append_bytes(&mut self, bytes: &[u8]) -> Result<(), crate::JournalSinkError> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }

    }

    #[test]
    fn checkpoint_signature_must_bind_exact_complete_journal_head() {
        use crate::{JournalRecordInput, JournalRecordType, JournalWriter};
        let mut writer = JournalWriter::new(JournalBytes::default());

        let journal = writer.into_sink().0;

        let public_key = vec![0x30, 0x04, 0x02, 0x02, 0x11, 0x11];
        let mut registry_writer = crate::AnchorKeyRegistryWriter::new(JournalBytes::default());
        let retained = registry_writer.append_key(&public_key).unwrap();
        let registry = registry_writer.into_sink().0;
        let anchor = JournalSignatureAnchor {
            format_version: 1,
            sequence: receipt.sequence,
            digest: receipt.digest,
            signature_algorithm_id: crate::anchor_verifier::JOURNAL_ANCHOR_SIGNATURE_ID.into(),
            signing_key_id: retained.key_id,
            signature_der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            authentication_epoch: 1,
            monotonic_timestamp_ns: 100,
        };


        let mut stale = anchor.clone();
        stale.digest[0] ^= 0x80;

        stale = anchor;
        stale.sequence = 2;

    }

}
